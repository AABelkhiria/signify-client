//! ACDC credential issuance, presentation, verification, and revocation logic.
//!
//! Roadmap 6.1 contributes [`credential`]: the container itself and the two self-addressing
//! identifiers that give it its identity. Roadmap 6.2 adds what makes that container *valid* —
//! [`issuance`] and [`revocation`], the transaction events that record a credential's status in
//! its registry's log, together with the [`transaction`] machinery both share and the CESR
//! attachments binding each artifact to the next.
//!
//! IPEX messages (Roadmap 6.3) join them here. Nothing in this crate performs networking or knows
//! a KERIA endpoint; submitting any of these artifacts is `signify-client`'s.

#![forbid(unsafe_code)]

pub mod credential;
pub mod error;
pub mod issuance;
pub mod revocation;
pub mod transaction;
