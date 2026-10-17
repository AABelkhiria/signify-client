//! Local identifier habitats and the registry that creates them.
//!
//! This ports the pinned reference's `src/keri/app/habery.ts`: a [`Habery`] wraps one
//! [`KeyManager`](crate::manager::KeyManager) and turns key-manager inceptions into complete,
//! serialized inception events, each held as a [`Habitat`] under a caller-chosen name. It is pure
//! client-side state — nothing here talks to KERIA, signs requests, or reads a clock.
//!
//! The reference's `TraitCodex`/`TraitDex` were already ported in `keri-protocol` as
//! [`ConfigurationTrait`](keri_protocol::event::ConfigurationTrait), whose first consumer was the
//! inception builder this module now drives.

pub mod artifact;
pub mod error;
pub mod habitat;

pub use artifact::{
    CreateAlgorithm, CreateIdentifierRequest, DEFAULT_LOCATION_SCHEME, END_ROLE_ROUTE, IdentifierArtifact,
    LOCATION_SCHEME_ROUTE, RotateIdentifierRequest, SignedReply, end_role_reply, incept_identifier,
    interact_identifier, location_scheme_reply, rotate_identifier, sign_reply,
};
pub use error::IdentifierError;
pub use habitat::{Habery, HaberyBuilder, Habitat, HabitatRequest};
