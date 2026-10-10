//! Signify key management: keepers, identifier habitats, and the client's own identity, on top of
//! the KERI protocol messages from keri-protocol.

#![forbid(unsafe_code)]

pub mod controller;
pub mod identifier;
pub mod manager;

/// CESR attachments composed around a message.
pub use keri_protocol::attachment;
/// Event kinds, key event builders, exchange and reply messages, timestamps and witness configuration.
pub use keri_protocol::event;
/// Identifier prefixes.
pub use keri_protocol::prefix;
/// The TEL registry inception event.
pub use keri_protocol::registry;
/// Self-addressing identifiers.
pub use keri_protocol::said;
/// Protocol versions, the self-addressing-data codec, and the message serializer and parser.
pub use keri_protocol::serialization;
/// Exact signing thresholds.
pub use keri_protocol::threshold;
