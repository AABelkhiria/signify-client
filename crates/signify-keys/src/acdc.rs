//! Signing ACDC artifacts with a keeper: issuing and revoking a credential against the issuer's
//! KERIA key state, and the IPEX messages a client sends, on top of the builders in keri-acdc.
//!
//! keri-acdc builds every artifact unsigned and knows nothing about keepers or agents. This module
//! reads the issuer's [`KeyState`](keria_types::api::KeyState) as KERIA reports it, builds the
//! artifact through keri-acdc, and signs it through an
//! [`IdentifierKeeper`](crate::manager::keeper::IdentifierKeeper). Submitting the result is
//! `signify-client`'s.

pub mod error;
pub mod ipex;
pub mod issuance;
pub mod revocation;
pub mod transaction;
