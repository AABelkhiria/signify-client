//! Local identifier habitats and the registry that creates them.
//!
//! This ports the pinned reference's `src/keri/app/habery.ts`: a [`Habery`] wraps one
//! [`KeyManager`](crate::manager::KeyManager) and turns key-manager inceptions into complete,
//! serialized inception events, each held as a [`Habitat`] under a caller-chosen name. It is pure
//! client-side state — nothing here talks to KERIA, signs requests, or reads a clock.
//!
//! The reference's `TraitCodex`/`TraitDex` were already ported by Roadmap 3.5 as
//! [`ConfigurationTrait`](crate::event::ConfigurationTrait), whose first consumer was the
//! inception builder this module now drives.

pub mod error;
pub mod habitat;

pub use error::IdentifierError;
pub use habitat::{Habery, HaberyBuilder, Habitat, HabitatRequest};
