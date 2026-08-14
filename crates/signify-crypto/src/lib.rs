//! Signing, verification, digest, key derivation, and encryption operations.

#![forbid(unsafe_code)]

pub mod cipher;
pub mod digest;
pub mod error;
pub mod salt;
pub mod signature;
pub mod signer;
pub mod verifier;

pub use error::CryptoError;
