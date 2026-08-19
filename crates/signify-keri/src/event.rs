//! KERI and ACDC event structures and builders.
//!
//! Roadmap 3.1 contributes the typed event-kind (ilk) table. Roadmap 3.5 adds the establishment
//! and interaction event builders: [`inception`] creates an identifier, [`rotation`] replaces its
//! keys, and [`interaction`] anchors data without changing them. Every builder produces a
//! [`KeyEvent`] carrying the exact wire bytes together with the identifier and SAID a caller needs
//! for the next event in the log.
//!
//! Roadmap 3.6 adds [`reply`], the only supporting event builder the pinned reference exports.
//! Receipt, validator-receipt, and key-state messages have no builder there at all, and the `qry`
//! ilk is absent from its table entirely, so those are recorded `N/A` in `PORTING.md` §5.3 rather
//! than invented here.
//!
//! Roadmap 3.8 adds [`exchange`], the routed message controllers send each other, together with
//! the embedded messages and transposed attachments it carries. CESR attachments themselves are
//! Roadmap 3.7's [`attachment`](crate::attachment) module.

pub mod config;
mod error;
pub mod exchange;
pub mod inception;
pub mod interaction;
mod key_event;
pub mod kind;
pub mod reply;
pub mod rotation;
pub mod timestamp;
pub mod witness;

pub use config::ConfigurationTrait;
pub use error::EventError;
pub use key_event::{KeyEvent, ThresholdEncoding};
pub use timestamp::{Timestamp, TimestampError};
