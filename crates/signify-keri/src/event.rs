//! KERI and ACDC event structures and builders.
//!
//! Roadmap 3.1 contributes the typed event-kind (ilk) table. Roadmap 3.5 adds the establishment
//! and interaction event builders: [`inception`] creates an identifier, [`rotation`] replaces its
//! keys, and [`interaction`] anchors data without changing them. Every builder produces a
//! [`KeyEvent`] carrying the exact wire bytes together with the identifier and SAID a caller needs
//! for the next event in the log.
//!
//! Receipt, query, reply, and exchange events arrive with Roadmap 3.6, and CESR attachments with
//! Roadmap 3.7.

pub mod config;
mod error;
pub mod inception;
pub mod interaction;
mod key_event;
pub mod kind;
pub mod rotation;
pub mod witness;

pub use config::ConfigurationTrait;
pub use error::EventError;
pub use key_event::{KeyEvent, ThresholdEncoding};
