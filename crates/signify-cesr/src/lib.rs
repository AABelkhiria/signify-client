//! Pure CESR parsing, encoding, and qualified-material primitives.

#![forbid(unsafe_code)]

pub mod base64;
pub mod bytes;
pub mod code;
pub mod counter;
pub mod error;
pub mod indexer;
pub mod matter;
pub mod number;
pub mod sequence;

pub use error::CesrError;
