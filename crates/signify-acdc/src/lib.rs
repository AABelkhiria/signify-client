//! Signing ACDC artifacts with a Signify keeper: issuing and revoking a credential against the
//! issuer's KERIA key state, and the IPEX messages a client sends, on top of the builders in
//! keri-acdc.
//!
//! keri-acdc builds every artifact unsigned and knows nothing about keepers or agents. This crate
//! reads the issuer's [`KeyState`](keria_types::api::KeyState) as KERIA reports it, builds the
//! artifact through keri-acdc, and signs it through an
//! [`IdentifierKeeper`](signify_keri::manager::keeper::IdentifierKeeper). Submitting the result is
//! `signify-client`'s.

#![forbid(unsafe_code)]

pub mod error;
pub mod ipex;
pub mod issuance;
pub mod revocation;
pub mod transaction;

/// The credential container, its attribute block, and its identifiers.
pub use keri_acdc::credential;
