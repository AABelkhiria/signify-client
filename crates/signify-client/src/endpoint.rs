//! KERIA endpoint families.
//!
//! Each family is a lightweight handle borrowed from a [`ConnectedClient`](crate::client::ConnectedClient):
//! it knows a resource's paths, its query parameters, and the shape of what comes back, and
//! nothing else. Protocol logic lives below — events in `keri-protocol`, keys in `signify-keys`,
//! credentials in `keri-acdc` and their signing in `signify-acdc`, the signed request itself in
//! `signify-http` — and a family only decides which URL to address and how to read the answer.
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
//! other at all, 7.3 [`contacts`], which is what a client remembers about them afterwards, and 7.4
//! [`challenges`], which is how it comes to believe any of it. Roadmap 7.5 adds
//! [`notifications`], which is how the agent tells the controller there is something to do, and 7.6
//! [`escrows`], which is what the agent received and could not yet accept, and 7.7 [`exchanges`],
//! which is how one controller says something to another that is not a key event. Roadmap 8.1
//! adds the route table and classifiers inside [`exchanges`], and 8.2 opens **Phase 8**'s
//! endpoint work with [`groups`], the round of messages a multisig group decides through.

pub(crate) mod body;
pub mod challenges;
pub mod config;
pub mod contacts;
pub mod credentials;
pub mod delegations;
pub mod escrows;
pub mod exchanges;
pub mod groups;
pub mod identifiers;
pub mod ipex;
pub mod key_events;
pub mod key_states;
pub mod notifications;
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
        source: Box::new(keria_types::api::ApiError::Json {
            source: Box::new(source),
        }),
    })
}
