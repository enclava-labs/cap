use chrono::Utc;
use enclava_cli::config::CliPaths;
use enclava_cli::keyring::{
    Role, load_keyring_envelope, load_trusted_owner, member_allows_deploy, sign_keyring,
    single_member_keyring, store_keyring_envelope, store_trusted_owner, verify_keyring,
};
use enclava_cli::keys;
use std::sync::Mutex;
use uuid::Uuid;

static HOME_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn clean_state_backup_restore_recreates_owner_and_app_keys() {
    let _guard = HOME_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let prev_home = std::env::var_os("HOME");
    unsafe {
        std::env::set_var("HOME", tmp.path());
    }

    let original = CliPaths::from_root(tmp.path().join("original")).unwrap();
    let restored = CliPaths::from_root(tmp.path().join("restored")).unwrap();
    let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
    let org_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();

    let seed = keys::load_or_create_recovery_seed(&original).unwrap();
    let owner = keys::derive_org_owner_key(user_id, org_id, &seed).unwrap();
    let keyring = single_member_keyring(org_id, 1, &owner, Role::Owner, Utc::now());
    let envelope = sign_keyring(&owner, keyring);
    store_trusted_owner(&org_id, &owner.public).unwrap();
    store_keyring_envelope(&org_id, &envelope).unwrap();

    let trusted_owner = load_trusted_owner(&org_id).unwrap().unwrap();
    let cached = load_keyring_envelope(&org_id).unwrap();
    let verified = verify_keyring(&cached, &trusted_owner).unwrap();
    assert!(member_allows_deploy(verified, &owner.public));

    let app_seed = keys::derive_app_bootstrap_seed(org_id, "demo", &seed).unwrap();
    let backup = keys::encrypt_recovery_backup(&seed, "passphrase").unwrap();
    let restored_seed = keys::decrypt_recovery_backup(&backup, "passphrase").unwrap();
    keys::store_seed_at(&restored.recovery_seed, &restored_seed, false).unwrap();

    let loaded = keys::load_recovery_seed(&restored).unwrap().unwrap();
    let restored_owner = keys::derive_org_owner_key(user_id, org_id, &loaded).unwrap();
    let restored_app_seed = keys::derive_app_bootstrap_seed(org_id, "demo", &loaded).unwrap();

    assert_eq!(restored_owner.public.to_bytes(), owner.public.to_bytes());
    assert_eq!(restored_app_seed, app_seed);

    unsafe {
        match prev_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }
}
