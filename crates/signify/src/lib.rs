//! Rust SDK for signing at the edge with KERI, ACDC, and KERIA.

#![forbid(unsafe_code)]

/// CESR primitives.
pub use keri_cesr as cesr;
/// Cryptographic operations.
pub use keri_cesr::crypto;
/// ACDC credential protocol support.
pub use signify_acdc as acdc;
/// High-level Signify client.
pub use signify_client as client;
/// HTTP transport and authentication.
pub use signify_http as http;
/// KERI protocol support.
pub use signify_keri as keri;
/// Shared API types.
pub use signify_types as types;
