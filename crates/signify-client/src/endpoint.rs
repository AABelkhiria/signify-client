//! KERIA endpoint families.
//!
//! Each family is a lightweight handle borrowed from a [`ConnectedClient`](crate::client::ConnectedClient):
//! it knows a resource's paths, its query parameters, and the shape of what comes back, and
//! nothing else. Protocol logic lives below — events in `keri-protocol`, keys in `signify-keys`,
//! credentials in `keri-acdc` and their signing in `signify-keys`, the signed request itself in
//! `signify-http` — and a family only decides which URL to address and how to read the answer.
//!
//! [`operations`] is the family every other one depends on: a KERIA agent answers most writes with
//! a long-running operation rather than a result. [`identifiers`] is the family that creates and
//! rotates what everything else speaks for; [`key_events`] and [`key_states`] are what a client
//! knows about identifiers that are not its own; [`config`] is the smallest of them. [`registries`]
//! and [`schemas`] are the two halves of what a credential needs before it exists; [`credentials`]
//! is the family that issues and revokes them, and [`ipex`] the family that discloses one to
//! somebody else. [`oobis`] is how two identifiers that have never met learn about each other at
//! all, [`contacts`] is what a client remembers about them afterwards, and [`challenges`] is how it
//! comes to believe any of it. [`notifications`] is how the agent tells the controller there is
//! something to do, [`escrows`] is what the agent received and could not yet accept, and
//! [`exchanges`] is how one controller says something to another that is not a key event; it also
//! holds the route table and classifiers. [`groups`] is the round of messages a multisig group
//! decides through.

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
