//! Credential vault: a forward proxy that keeps real API credentials away
//! from the workload that uses them.
//!
//! The workload holds a placeholder (`encv_<connection>_<random>`) and sends
//! its requests through this proxy. For an origin that has a connection, the
//! proxy terminates the workload's TLS with a leaf minted from its own CA,
//! swaps the placeholder for the real credential in the one position the
//! connection declares, and forwards the request over a new, publicly
//! verified TLS connection. A placeholder is only ever honoured for the
//! exact origin and path prefix of its connection; anywhere else the request
//! is refused.
//!
//! Design: enclava-labs/enclava-paas#435.

pub mod ca;
pub mod connection;
pub mod proxy;
pub mod store;
pub mod substitute;

pub use ca::VaultCa;
pub use connection::{Connection, ConnectionSpec, Origin, Position, Snapshot};
pub use proxy::{Proxy, ProxyConfig};
pub use store::Store;
