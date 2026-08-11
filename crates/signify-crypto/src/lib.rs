//! Signing, verification, digest, key derivation, and encryption operations.

#![forbid(unsafe_code)]

pub mod digest;
pub mod error;

pub use error::CryptoError;
