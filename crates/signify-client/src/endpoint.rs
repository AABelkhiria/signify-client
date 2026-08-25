//! KERIA endpoint families.
//!
//! Each family is a lightweight handle borrowed from a [`ConnectedClient`](crate::client::ConnectedClient):
//! it knows a resource's paths, its query parameters, and the shape of what comes back, and
//! nothing else. Protocol logic lives below — events in `signify-keri`, credentials in
//! `signify-acdc`, the signed request itself in `signify-http` — and a family only decides which
//! URL to address and how to read the answer.
//!
//! Roadmap 6.5 opens the module with [`operations`], which is the family every other one depends
//! on: a KERIA agent answers most writes with a long-running operation rather than a result.
//! Roadmap 6.6 adds [`identifiers`], the family that creates and rotates what everything else
//! speaks for; Roadmap 6.7 adds [`key_events`] and [`key_states`], which are what a client knows
//! about identifiers that are not its own; Roadmap 6.8 adds [`config`], the smallest of them.
//! Roadmap 6.9 adds [`registries`] and 6.10 [`schemas`], the two halves of what a credential needs
//! before it exists; Roadmap 6.11 adds [`credentials`], the family that issues and revokes them,
//! and Roadmap 6.12 [`ipex`], the family that discloses one to somebody else. Roadmap 7.1 opens
//! Phase 7 with [`oobis`], which is how two identifiers that have never met learn about each
//! other at all.

pub(crate) mod body;
pub mod config;
pub mod credentials;
pub mod identifiers;
pub mod ipex;
pub mod key_events;
pub mod key_states;
pub mod oobis;
pub mod operations;
pub mod registries;
pub mod schemas;

/// Decodes one JSON document from a response body.
///
/// Every family reads its answers this way, so the failure a caller sees for a body that is not
/// what it should have been is the same shape whichever resource produced it.
pub(crate) fn decode_json<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, crate::error::ClientError> {
    serde_json::from_slice(body).map_err(|source| crate::error::ClientError::Api {
        source: Box::new(signify_types::api::ApiError::Json {
            source: Box::new(source),
        }),
    })
}
