//! The client controller and its KERIA agent, as pure state.
//!
//! This ports the pinned reference's `src/keri/app/controller.ts`: the [`Controller`] that derives
//! the client's own signing identity from a passcode and builds its inception, delegation
//! approval, and passcode-rotation artifacts, and the [`Agent`] that validates the KERIA agent's
//! delegated key state. Everything here is pure — nothing performs I/O, reads a clock, or knows a
//! KERIA endpoint; the boot/connect orchestration that consumes these types is `signify-client`'s.

pub mod agent;
pub mod client;
pub mod error;
pub mod rotation;

pub use agent::Agent;
pub use client::{CONTROLLER_STEM, Controller, ControllerOptions};
pub use error::ControllerError;
pub use rotation::{PasscodeRotation, PlannedPasscodeRotation, ReEncryptedKeyState};
