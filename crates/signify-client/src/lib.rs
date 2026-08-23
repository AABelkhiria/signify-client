//! High-level Signify client and KERIA endpoint families.
//!
//! Roadmap 6.4 opens the crate with the client lifecycle: [`config`] validates what a client is
//! built from, [`client`] boots an agent, reads its state, connects to it, and sends signed
//! requests, and [`random`] generates the two values a client draws from the operating system.
//! Endpoint families join them here as their roadmap items land.
//!
//! Nothing in this crate implements protocol logic of its own. Events come from `signify-keri`,
//! credentials from `signify-acdc`, and the whole signed-request mechanism from `signify-http`;
//! what the client adds is which URL to send to, which prefix to stamp, and which key to verify
//! against.

#![forbid(unsafe_code)]

pub mod client;
pub mod config;
pub mod error;
pub mod random;
