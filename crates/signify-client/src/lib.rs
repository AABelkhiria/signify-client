//! High-level Signify client and KERIA endpoint families.
//!
//! [`config`] validates what a client is built from, [`client`] boots an agent, reads its state,
//! connects to it, and sends signed requests, and [`random`] generates the two values a client
//! draws from the operating system. [`endpoint`] holds the endpoint families, and [`operation`]
//! waits for a long-running agent operation to finish.
//!
//! Nothing in this crate implements protocol logic of its own. Events come from `signify-keys`,
//! credentials from `keri-acdc` signed through `signify-keys`, and the whole signed-request
//! mechanism from `signify-http`; what the client adds is which URL to send to, which prefix to
//! stamp, and which key to verify against.
//!
//! This crate is also the SDK's single entry point. The crates it is built on are re-exported at
//! the root — [`keys`], [`http`], [`protocol`], [`acdc`], [`cesr`], [`crypto`], [`auth`] and
//! [`types`] — so an application depends on `signify-client` alone and never names a `keri-*`
//! crate directly. The `http-client` feature turns on `signify-http`'s production transport.

#![forbid(unsafe_code)]

/// ACDC credentials: the container, issuance and revocation events, and IPEX messages.
pub use keri_acdc as acdc;
/// CESR primitives.
pub use keri_cesr as cesr;
/// Cryptographic operations.
pub use keri_cesr::crypto;
/// KERI HTTP message signatures and request authentication.
pub use keri_http_auth as auth;
/// KERI protocol messages: events, SAIDs, prefixes, thresholds and attachments.
pub use keri_protocol as protocol;
/// KERIA agent API record types.
pub use keria_types as types;
/// HTTP transport and authentication.
pub use signify_http as http;
/// Signify key management: keepers, identifier habitats, and the client identity.
pub use signify_keys as keys;

pub mod client;
pub mod config;
pub mod endpoint;
pub mod error;
pub mod multisig;
pub mod operation;
pub mod presentation;
pub mod random;
