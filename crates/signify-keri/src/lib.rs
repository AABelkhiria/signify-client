//! Signify key management: keepers, identifier habitats, and the client's own identity, on top of
//! the KERI protocol messages from keri-protocol, which callers reach directly.

#![forbid(unsafe_code)]

pub mod controller;
pub mod identifier;
pub mod manager;
