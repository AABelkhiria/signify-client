//! High-level Signify client and KERIA endpoint families.
//!
//! Roadmap 6.4 opens the crate with the client lifecycle: [`config`] validates what a client is
//! built from, [`client`] boots an agent, reads its state, connects to it, and sends signed
//! requests, and [`random`] generates the two values a client draws from the operating system.
//! Roadmap 6.5 opens [`endpoint`] with the operations family; the rest join it as their items
//! land. Roadmap 7.2 adds [`operation`], the first *workflow* here rather than an address: waiting
//! for a long-running agent operation to finish.
//!
//! Nothing in this crate implements protocol logic of its own. Events come from `signify-keri`,
//! credentials from `signify-acdc`, and the whole signed-request mechanism from `signify-http`;
//! what the client adds is which URL to send to, which prefix to stamp, and which key to verify
//! against.

#![forbid(unsafe_code)]

pub mod client;
pub mod config;
pub mod endpoint;
pub mod error;
pub mod multisig;
pub mod operation;
pub mod random;
