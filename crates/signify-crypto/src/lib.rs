//! Signing, verification, digest, key derivation, and encryption operations.

#![forbid(unsafe_code)]

pub mod digest;
pub mod error;
pub mod signature;
pub mod signer;
pub mod verifier;

pub use error::CryptoError;
