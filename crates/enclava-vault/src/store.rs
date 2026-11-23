//! File-backed connection store.
//!
//! One `0600` TOML file per connection under `<dir>/connections`, written
//! atomically, plus a `generation` marker that changes on every mutation so
//! a running proxy can tell when to reload. The directory is meant to live
//! on storage the workload cannot read; this module only sets owner-only
//! modes and does not try to defend against a reader with the same UID.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::connection::{
    Connection, ConnectionError, ConnectionSpec, Origin, Position, Snapshot, new_placeholder,
    validate_name, validate_placeholder, validate_secret,
};

const CONNECTIONS_DIR: &str = "connections";
const GENERATION_FILE: &str = "generation";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    #[error("stored connection {file} is unreadable: {reason}")]
    Corrupt { file: String, reason: String },
    #[error("expose_as {key} is already used by connection {connection}")]
    ExposeAsTaken { key: String, connection: String },
}

/// On-disk form. `position` is last because TOML wants tables after values.
#[derive(Serialize, Deserialize)]
struct StoredConnection {
    name: String,
    origin: Origin,
    path_prefix: String,
    expose_as: Option<String>,
    placeholder: String,
    secret: String,
    position: Position,
}

impl Drop for StoredConnection {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.secret);
    }
}

#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    /// Opens the store, creating its directories owner-only if missing.
    pub fn open(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir.join(CONNECTIONS_DIR))?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Creates or updates a connection. An existing connection keeps its
    /// placeholder, so a credential can be rotated without the workload
    /// noticing.
    pub fn put(&self, spec: ConnectionSpec, secret: &str) -> Result<Connection, StoreError> {
        spec.validate()?;
        validate_secret(&spec.position, secret)?;

        let existing = self.snapshot()?;
        if let Some(key) = &spec.expose_as {
            let taken = existing
                .connections()
                .iter()
                .find(|c| c.spec.name != spec.name && c.spec.expose_as.as_ref() == Some(key));
            if let Some(other) = taken {
                return Err(StoreError::ExposeAsTaken {
                    key: key.clone(),
                    connection: other.spec.name.clone(),
                });
            }
        }
        let placeholder = existing
            .connections()
            .iter()
            .find(|c| c.spec.name == spec.name)
            .map(|c| c.placeholder.clone())
            .unwrap_or_else(|| new_placeholder(&spec.name));

        let stored = StoredConnection {
            name: spec.name.clone(),
            origin: spec.origin.clone(),
            path_prefix: spec.path_prefix.clone(),
            expose_as: spec.expose_as.clone(),
            placeholder: placeholder.clone(),
            secret: secret.to_owned(),
            position: spec.position.clone(),
        };
        let body = Zeroizing::new(toml::to_string(&stored).map_err(|e| StoreError::Corrupt {
            file: spec.name.clone(),
            reason: e.to_string(),
        })?);
        write_atomic(&self.connection_path(&spec.name), body.as_bytes())?;
        self.bump_generation()?;

        Ok(Connection {
            spec,
            placeholder,
            secret: Zeroizing::new(secret.to_owned()),
        })
    }

    /// Removes a connection. Returns whether it existed.
    pub fn remove(&self, name: &str) -> Result<bool, StoreError> {
        validate_name(name)?;
        match fs::remove_file(self.connection_path(name)) {
            Ok(()) => {
                self.bump_generation()?;
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Loads every connection. Any unreadable or inconsistent file is an
    /// error: a half-understood store must not serve traffic.
    pub fn snapshot(&self) -> Result<Snapshot, StoreError> {
        let mut connections = Vec::new();
        for entry in fs::read_dir(self.dir.join(CONNECTIONS_DIR))? {
            let path = entry?.path();
            let Some(file) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            // In-flight temp files from `write_atomic`.
            if file.starts_with('.') {
                continue;
            }
            connections.push(load(&path, file)?);
        }
        connections.sort_by(|a, b| a.spec.name.cmp(&b.spec.name));
        Ok(Snapshot::new(connections))
    }

    /// Opaque marker that changes whenever the store is mutated. Empty for
    /// a store that was never written.
    pub fn generation(&self) -> io::Result<String> {
        match fs::read_to_string(self.dir.join(GENERATION_FILE)) {
            Ok(value) => Ok(value),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(String::new()),
            Err(e) => Err(e),
        }
    }

    fn connection_path(&self, name: &str) -> PathBuf {
        self.dir.join(CONNECTIONS_DIR).join(format!("{name}.toml"))
    }

    fn bump_generation(&self) -> io::Result<()> {
        let mut random = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut random);
        write_atomic(
            &self.dir.join(GENERATION_FILE),
            hex::encode(random).as_bytes(),
        )
    }
}

fn load(path: &Path, file: &str) -> Result<Connection, StoreError> {
    let corrupt = |reason: String| StoreError::Corrupt {
        file: file.to_owned(),
        reason,
    };
    let body = Zeroizing::new(fs::read_to_string(path)?);
    // toml's error can quote the offending line, which may be the secret.
    let mut stored: StoredConnection =
        toml::from_str(&body).map_err(|_| corrupt("not a valid connection file".into()))?;
    if file.strip_suffix(".toml") != Some(stored.name.as_str()) {
        return Err(corrupt("file name does not match connection name".into()));
    }
    let spec = ConnectionSpec {
        name: stored.name.clone(),
        origin: stored.origin.clone(),
        path_prefix: stored.path_prefix.clone(),
        position: stored.position.clone(),
        expose_as: stored.expose_as.clone(),
    };
    spec.validate().map_err(|e| corrupt(e.to_string()))?;
    validate_placeholder(&spec.name, &stored.placeholder).map_err(|e| corrupt(e.to_string()))?;
    validate_secret(&spec.position, &stored.secret).map_err(|e| corrupt(e.to_string()))?;
    Ok(Connection {
        spec,
        placeholder: stored.placeholder.clone(),
        secret: Zeroizing::new(std::mem::take(&mut stored.secret)),
    })
}

/// Writes `bytes` to a `0600` temp file next to `path`, syncs it and renames
/// it into place.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let mut random = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let tmp = dir.join(format!(".{name}.{}.tmp", hex::encode(random)));

    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn spec(name: &str, expose_as: Option<&str>) -> ConnectionSpec {
        ConnectionSpec {
            name: name.into(),
            origin: Origin::parse("https://api.example.com").unwrap(),
            path_prefix: "/".into(),
            position: Position::Header {
                name: "authorization".into(),
            },
            expose_as: expose_as.map(Into::into),
        }
    }

    #[test]
    fn put_then_snapshot_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.generation().unwrap(), "");

        let created = store
            .put(spec("github", Some("GITHUB_TOKEN")), "ghp_real")
            .unwrap();
        let basic = ConnectionSpec {
            position: Position::BasicAuth,
            ..spec("registry", None)
        };
        store.put(basic, "pässword").unwrap();

        let snapshot = Store::open(dir.path()).unwrap().snapshot().unwrap();
        let names: Vec<_> = snapshot
            .connections()
            .iter()
            .map(|c| &c.spec.name)
            .collect();
        assert_eq!(names, ["github", "registry"]);
        let github = &snapshot.connections()[0];
        assert_eq!(github.spec, created.spec);
        assert_eq!(github.placeholder, created.placeholder);
        assert_eq!(github.secret.as_str(), "ghp_real");
        assert_eq!(snapshot.connections()[1].secret.as_str(), "pässword");
        assert_eq!(snapshot.connections()[1].spec.position, Position::BasicAuth);
    }

    #[test]
    fn rotation_keeps_the_placeholder_and_changes_the_generation() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let first = store.put(spec("github", None), "old").unwrap();
        let generation = store.generation().unwrap();
        let second = store.put(spec("github", None), "new").unwrap();
        assert_eq!(first.placeholder, second.placeholder);
        assert_ne!(generation, store.generation().unwrap());
        assert_eq!(
            store.snapshot().unwrap().connections()[0].secret.as_str(),
            "new"
        );
    }

    #[test]
    fn files_and_directories_are_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("vault")).unwrap();
        store.put(spec("github", None), "ghp_real").unwrap();
        let mode = |path: PathBuf| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(store.dir().join(CONNECTIONS_DIR)), 0o700);
        assert_eq!(mode(store.connection_path("github")), 0o600);
        assert_eq!(mode(store.dir().join(GENERATION_FILE)), 0o600);
    }

    #[test]
    fn invalid_input_is_rejected_before_anything_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        assert!(store.put(spec("../escape", None), "x").is_err());
        assert!(store.put(spec("github", None), "").is_err());
        assert!(store.put(spec("github", None), "bad\nsecret").is_err());
        assert!(store.snapshot().unwrap().connections().is_empty());
        assert_eq!(store.generation().unwrap(), "");
    }

    #[test]
    fn expose_as_must_be_unique_across_connections() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.put(spec("github", Some("TOKEN")), "a").unwrap();
        store.put(spec("github", Some("TOKEN")), "b").unwrap();
        let err = store.put(spec("gitlab", Some("TOKEN")), "c").unwrap_err();
        assert!(matches!(err, StoreError::ExposeAsTaken { .. }));
    }

    #[test]
    fn remove_reports_whether_the_connection_existed() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.put(spec("github", None), "a").unwrap();
        assert!(store.remove("github").unwrap());
        assert!(!store.remove("github").unwrap());
        assert!(store.remove("../escape").is_err());
        assert!(store.snapshot().unwrap().connections().is_empty());
    }

    #[test]
    fn corrupt_files_fail_the_snapshot_without_echoing_their_content() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.put(spec("github", None), "ghp_real").unwrap();

        let stray = store.dir().join(CONNECTIONS_DIR).join("stray.toml");
        fs::write(&stray, "secret = \"hunter2-leak\"\nthis is not toml").unwrap();
        let err = store.snapshot().unwrap_err().to_string();
        assert!(err.contains("stray.toml"), "{err}");
        assert!(!err.contains("hunter2-leak"), "{err}");

        // A valid file under the wrong name is refused too.
        fs::copy(store.connection_path("github"), &stray).unwrap();
        assert!(matches!(
            store.snapshot().unwrap_err(),
            StoreError::Corrupt { .. }
        ));
    }
}
