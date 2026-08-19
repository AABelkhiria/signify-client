//! HTTP message signatures.
//!
//! Roadmap 3.9 contributes [`fields`], the `Signature` header format KERI uses to carry signature
//! material alongside a request. Roadmap 3.10 will add the signature-input canonicalization that
//! decides *what* those signatures cover.

pub mod fields;
