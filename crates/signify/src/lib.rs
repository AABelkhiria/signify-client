//! Rust SDK for signing at the edge with KERI, ACDC, and KERIA.

#![forbid(unsafe_code)]

/// ACDC credential protocol support.
pub use signify_acdc as acdc;
/// CESR primitives.
pub use signify_cesr as cesr;
/// High-level Signify client.
pub use signify_client as client;
/// Cryptographic operations.
pub use signify_crypto as crypto;
/// HTTP transport and authentication.
pub use signify_http as http;
/// KERI protocol support.
pub use signify_keri as keri;
/// Shared API types.
pub use signify_types as types;
