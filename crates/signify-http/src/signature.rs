//! HTTP message signatures.
//!
//! The primitives come from keri-http-auth: [`fields`] formats and parses the `Signature` header,
//! which carries the signature material; [`input`] formats and parses the `Signature-Input` header
//! and derives the exact bytes a signature covers; [`authentication`] composes both with a key, to
//! sign a request and to verify a response; and [`timestamp`] formats the `Signify-Timestamp` header.
//! [`transport`] is this crate's composition of them around a request in flight.

pub use keri_http_auth::{authentication, fields, input, timestamp};
pub mod transport;
