//! HTTP message signatures.
//!
//! The three modules are the three halves of one operation. [`fields`] (Roadmap 3.9) formats and
//! parses the `Signature` header, which carries the signature material. [`input`] (Roadmap 3.10)
//! formats and parses the `Signature-Input` header and derives the exact bytes a signature covers.
//! [`authentication`] (Roadmap 3.10) composes both with a key, to sign a request and to verify a
//! response.

pub mod authentication;
pub mod fields;
pub mod input;
