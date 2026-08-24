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

pub mod operations;
