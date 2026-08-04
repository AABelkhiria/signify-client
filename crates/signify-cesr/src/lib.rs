//! Pure CESR parsing, encoding, and qualified-material primitives.

#![forbid(unsafe_code)]

pub mod base64;
pub mod bytes;
pub mod code;
pub mod error;
pub mod matter;

pub use error::CesrError;
