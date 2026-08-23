//! ACDC credential issuance, presentation, verification, and revocation logic.
//!
//! The crate currently holds Roadmap 6.1: the credential container itself and the two
//! self-addressing identifiers that give it its identity. Issuance and revocation artifacts
//! (Roadmap 6.2) and IPEX messages (Roadmap 6.3) join it here; nothing in this crate performs
//! networking or knows a KERIA endpoint.

#![forbid(unsafe_code)]

pub mod credential;
