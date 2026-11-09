//! Transport abstractions, HTTP signatures, request construction, and response handling.

#![forbid(unsafe_code)]

/// Validated HTTP header names, values, and collections, from keri-http-auth.
pub use keri_http_auth::header;
pub mod request;
pub mod response;
pub mod retry;
pub mod signature;
pub mod transport;

#[cfg(test)]
pub(crate) mod test_support;
