//! The operations endpoint: what a KERIA agent is still doing, and how it went.
//!
//! A KERIA agent answers most write requests with a *long-running operation* rather than a result:
//! a named handle a caller comes back to. This family is the three calls that read and remove
//! them — `get`, `list`, and `delete` — plus the failure surfacing the reference performs when a
//! completed operation carries an error.
//!
//! This ports `Operations` from the pinned `src/keri/app/coring.ts`, minus `wait`. Polling is
//! Roadmap 7.2, and Roadmap 5.4 already pinned this function's own delay schedule by executing it.
//!
//! # The union is already a type
//!
//! `get` upstream returns a fourteen-way union that a caller narrows by inspecting `metadata` at
//! run time — the reference's own `hasDepends` is a `'depends' in op.metadata`. Roadmap 4.1
//! replaced that with [`Operation<M, R>`] and an [`UntypedOperation`], so [`Operations::get`]
//! returns the untyped form and [`Operations::get_typed`] narrows it by decoding. A narrowing that
//! does not fit is a decode failure rather than a silently wrong branch.

use serde::de::DeserializeOwned;
use signify_http::request::ResourcePath;
use signify_http::transport::Method;
use signify_types::api::{Operation, OperationOutcome, UntypedOperation};

use crate::client::{ClientRequest, ConnectedClient};
use crate::endpoint::decode_json as decode;
use crate::error::ClientError;

/// Path segment the operations resource lives under.
pub const OPERATIONS_SEGMENT: &str = "operations";

/// Query parameter that filters a listing by family; the reference's `type`.
pub const TYPE_PARAMETER: &str = "type";

/// Largest failure message this port keeps from an agent, in bytes.
///
/// The message is remote text that a caller may log or display, so it is bounded. The reference
/// interpolates it whole.
pub const MAX_FAILURE_MESSAGE_BYTES: usize = 512;

/// The operations endpoint family.
///
/// Borrowed from a connected client, so it costs nothing to hold and cannot outlive the client it
/// speaks through.
#[derive(Debug)]
pub struct Operations<'client> {
    client: &'client ConnectedClient,
}

impl<'client> Operations<'client> {
    /// Binds this family to a connected client.
    #[must_use]
    pub const fn new(client: &'client ConnectedClient) -> Self {
        Self { client }
    }

    /// Reads one operation's current state.
    ///
    /// The result is untyped, because the agent's answer names its family only in its metadata.
    /// Use [`Self::get_typed`] when the family is known.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer, [`ClientError::Decode`] when the
    /// body is not an operation, and the request, transport, and authentication failures
    /// [`ConnectedClient::fetch`] returns.
    pub async fn get(&self, name: &str) -> Result<UntypedOperation, ClientError> {
        let response = self
            .client
            .fetch(ClientRequest::new(Method::Get, Self::path(name)?))
            .await?;
        decode(response.body())
    }

    /// Reads one operation and narrows it to a known family.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::get`] returns, plus [`ClientError::Decode`] when the metadata or
    /// the response does not fit the requested family.
    pub async fn get_typed<M, R>(&self, name: &str) -> Result<Operation<M, R>, ClientError>
    where
        M: DeserializeOwned,
        R: DeserializeOwned,
    {
        self.get(name).await?.into_typed().map_err(|source| ClientError::Api {
            source: Box::new(source),
        })
    }

    /// Lists the agent's operations, optionally filtered by family.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::get`] returns.
    pub async fn list(&self, kind: Option<&str>) -> Result<Vec<UntypedOperation>, ClientError> {
        let path = ResourcePath::builder()
            .segment(OPERATIONS_SEGMENT)
            .optional_parameter(TYPE_PARAMETER, kind)
            .build()?;
        let response = self.client.fetch(ClientRequest::new(Method::Get, path)).await?;
        decode(response.body())
    }

    /// Removes one operation from the agent.
    ///
    /// The agent's answer carries nothing a caller can use, so nothing is returned — which is what
    /// the reference does too.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::get`] returns, apart from the decode failures.
    pub async fn delete(&self, name: &str) -> Result<(), ClientError> {
        self.client
            .fetch(ClientRequest::new(Method::Delete, Self::path(name)?))
            .await
            .map(|_| ())
    }

    /// Builds the path `get` and `delete` share.
    fn path(name: &str) -> Result<ResourcePath, ClientError> {
        Ok(ResourcePath::builder()
            .segment(OPERATIONS_SEGMENT)
            .segment(name)
            .build()?)
    }
}

/// Returns a completed operation's response, or the failure it carries.
///
/// This is the reference's `throwIfFailed`, with the two states it does not distinguish told
/// apart: an operation that has not finished is [`ClientError::OperationPending`] rather than
/// returned as though it had.
///
/// The rendered detail block's keys are sorted rather than in the order the agent sent them,
/// because the map they decode into is ordered. Nothing depends on that — it is an error message,
/// not wire bytes.
///
/// # Errors
///
/// Returns [`ClientError::OperationPending`] when the operation is still running and
/// [`ClientError::OperationFailed`] when it finished unsuccessfully.
pub fn completed<M, R>(operation: Operation<M, R>) -> Result<R, ClientError> {
    match operation.outcome {
        OperationOutcome::Completed(response) => Ok(response),
        OperationOutcome::Pending => Err(ClientError::OperationPending { name: operation.name }),
        OperationOutcome::Failed(status) => {
            let details = status.details().and_then(|details| serde_json::to_string(details).ok());
            Err(ClientError::OperationFailed {
                name: operation.name,
                code: status.code,
                message: bounded(&status.message),
                details,
            })
        }
    }
}

/// Truncates remote text on a character boundary.
fn bounded(value: &str) -> String {
    value
        .char_indices()
        .take_while(|(index, character)| index.saturating_add(character.len_utf8()) <= MAX_FAILURE_MESSAGE_BYTES)
        .map(|(_, character)| character)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use signify_types::api::{OperationStatus, WitnessMetadata};
    use std::error::Error;

    fn operation(outcome: OperationOutcome<String>) -> Operation<WitnessMetadata, String> {
        Operation {
            name: "witness.EABC.0".to_owned(),
            metadata: None,
            outcome,
        }
    }

    #[test]
    fn a_completed_operation_yields_its_response() -> Result<(), Box<dyn Error>> {
        let response = completed(operation(OperationOutcome::Completed("done".to_owned())))?;
        assert_eq!(response, "done");
        Ok(())
    }

    #[test]
    fn a_pending_operation_is_told_apart_from_a_failed_one() {
        let outcome = completed(operation(OperationOutcome::Pending));
        assert!(matches!(
            outcome,
            Err(ClientError::OperationPending { ref name }) if name == "witness.EABC.0"
        ));
        // The reference has no such state: its `throwIfFailed` returns a pending operation
        // unchanged, and only `wait` notices.
        assert!(
            outcome
                .err()
                .is_some_and(|error| error.to_string().contains("still running"))
        );
    }

    #[test]
    fn a_failed_operation_keeps_its_parts_apart() -> Result<(), Box<dyn Error>> {
        let status: OperationStatus = serde_json::from_str(
            r#"{"code":408,"message":"Timed out waiting for witness receipts","details":{"received":2,"expected":3}}"#,
        )?;
        let outcome = completed(operation(OperationOutcome::Failed(status)));
        let Err(ClientError::OperationFailed {
            name,
            code,
            message,
            details,
        }) = outcome
        else {
            return Err("a failed operation was not reported as one".into());
        };
        assert_eq!(name, "witness.EABC.0");
        assert_eq!(code, 408);
        assert_eq!(message, "Timed out waiting for witness receipts");
        // The detail block's keys are sorted rather than kept in the order the agent sent them:
        // `serde_json::Map` is a `BTreeMap` here, so the order is already gone at decode time.
        // Nothing depends on it — this is an error message, not wire bytes — and ADR `0008`
        // already declined to reproduce JavaScript's insertion order where bytes *did* depend on
        // it.
        assert_eq!(details.as_deref(), Some(r#"{"expected":3,"received":2}"#));
        Ok(())
    }

    #[test]
    fn a_failure_without_details_carries_none() -> Result<(), Box<dyn Error>> {
        let status: OperationStatus = serde_json::from_str(r#"{"code":500,"message":"Internal error"}"#)?;
        let Err(ClientError::OperationFailed { details, code, .. }) =
            completed(operation(OperationOutcome::Failed(status)))
        else {
            return Err("a failed operation was not reported as one".into());
        };
        assert_eq!(code, 500);
        assert_eq!(details, None);
        Ok(())
    }

    #[test]
    fn a_failure_message_is_bounded_on_a_character_boundary() -> Result<(), Box<dyn Error>> {
        let long = "\u{1f510}".repeat(400);
        let status: OperationStatus = serde_json::from_str(&format!(
            r#"{{"code":500,"message":{}}}"#,
            serde_json::to_string(&long)?
        ))?;
        let Err(ClientError::OperationFailed { message, .. }) = completed(operation(OperationOutcome::Failed(status)))
        else {
            return Err("a failed operation was not reported as one".into());
        };
        assert!(message.len() <= MAX_FAILURE_MESSAGE_BYTES);
        assert!(message.chars().all(|character| character == '\u{1f510}'));
        Ok(())
    }

    #[test]
    fn the_path_constants_are_the_references_own() {
        assert_eq!(OPERATIONS_SEGMENT, "operations");
        assert_eq!(TYPE_PARAMETER, "type");
    }
}
