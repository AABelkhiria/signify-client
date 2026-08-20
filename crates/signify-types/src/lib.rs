//! Shared, serialization-oriented protocol and KERIA API data types.
//!
//! This crate is data-only. It holds the request and response records the KERIA agent exchanges
//! with an edge signer, curated from the pinned reference's generated
//! `src/types/keria-api-schema.ts` and its hand-written `src/keri/core/keyState.ts` wrapper. It
//! performs no cryptography, builds no KERI events, and knows nothing about HTTP or endpoint
//! paths: those belong to `signify-crypto`, `signify-keri`, and `signify-http` respectively.
//!
//! Everything lives under [`api`].
//!
//! # Relationship to the protocol crates
//!
//! A record here is the *decoded shape of a document a KERIA agent sent*, not the authoritative
//! protocol artifact. In particular, re-serializing a [`api::KeyEvent`] reproduces the schema's
//! field order but is **not** guaranteed to reproduce the exact bytes the agent transmitted, so a
//! SAID must be verified against received bytes with `signify-keri`, never against a record that
//! has made a round trip through this crate. See [`api`] for the full rule.

#![forbid(unsafe_code)]

pub mod api;
