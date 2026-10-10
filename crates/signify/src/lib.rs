//! Rust SDK for signing at the edge with KERI, ACDC, and KERIA.

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
/// Signing ACDC artifacts with a Signify keeper.
pub use signify_acdc as acdc_signing;
/// High-level Signify client.
pub use signify_client as client;
/// HTTP transport and authentication.
pub use signify_http as http;
/// Signify key management: keepers, identifier habitats, and the client identity.
pub use signify_keys as keys;
