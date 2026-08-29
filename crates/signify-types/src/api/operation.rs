//! Long-running KERIA operations.
//!
//! KERIA answers a request that cannot complete immediately — resolving an OOBI, waiting for
//! witness receipts, waiting for a delegator's approval — with an *operation*: a named handle whose
//! state a client polls. The schema spells each of the fourteen operation families as three
//! interchangeable objects, `Pending…`, `Completed…`, and `Failed…`, distinguished by a `done`
//! constant and by whether a `response` or an `error` is present: forty-two types describing one
//! shape.
//!
//! Here that shape is [`Operation<M, R>`], whose [`OperationOutcome`] makes the three states a
//! `match`. The fourteen families are type aliases fixing the metadata and response types.
//!
//! # Why there is no single decodable `Operation`
//!
//! The schema also declares a union of all fourteen families, and upstream types both
//! `Operations.get` and `Operations.list` as returning it. That union has no runtime discriminant:
//! four families share `{pre, sn}` metadata and several share a response shape, and TypeScript
//! never checks — every response body reaches application code through an unchecked
//! `await res.json()` cast, so the declared type is a claim about what the caller asked for, not
//! something the document proves.
//!
//! Rust cannot honestly reproduce that as one decodable type, so it does what upstream's callers
//! effectively do: the caller names the family. [`UntypedOperation`] decodes the envelope with the
//! metadata and response left as JSON for a caller that does not yet know, and
//! [`UntypedOperation::into_typed`] narrows it once it does.

use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use super::error::ApiError;
use super::key_state::KeyState;
use super::message::{AcdcRecord, Anchor, ExchangeRecord, KeyEvent, ReplyRecord, Seal};

/// Why a KERIA operation failed.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct OperationStatus {
    /// Status code, following HTTP status conventions.
    pub code: i64,
    /// Human-readable message. Not to be echoed to an end user unexamined.
    pub message: String,
    /// Structured detail.
    ///
    /// The schema declares this optional *and* nullable, so the two are kept apart: `None` is an
    /// absent field and `Some(None)` an explicit `null`. [`OperationStatus::details`] flattens
    /// them for callers that do not care.
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub details: Option<Option<Map<String, Value>>>,
}

impl OperationStatus {
    /// Returns the detail block, treating an absent field and an explicit `null` alike.
    #[must_use]
    pub fn details(&self) -> Option<&Map<String, Value>> {
        self.details.as_ref().and_then(Option::as_ref)
    }
}

/// What has become of a long-running operation.
#[derive(Clone, Debug, PartialEq)]
pub enum OperationOutcome<R> {
    /// Still running; the wire form carries `done: false`.
    Pending,
    /// Finished successfully, carrying its result.
    Completed(R),
    /// Finished unsuccessfully, carrying why.
    Failed(OperationStatus),
}

impl<R> OperationOutcome<R> {
    /// Returns whether KERIA considers this operation finished, successfully or not.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        !matches!(self, Self::Pending)
    }

    /// Returns the result of a successful operation.
    #[must_use]
    pub const fn response(&self) -> Option<&R> {
        match self {
            Self::Completed(response) => Some(response),
            _ => None,
        }
    }

    /// Returns why an operation failed.
    #[must_use]
    pub const fn error(&self) -> Option<&OperationStatus> {
        match self {
            Self::Failed(status) => Some(status),
            _ => None,
        }
    }
}

/// One long-running KERIA operation.
///
/// `M` is the family's metadata and `R` its successful result; the type aliases below fix both.
///
/// ```
/// use signify_types::api::{KeyEvent, Operation, OperationOutcome, WitnessMetadata};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let body = br#"{"name":"witness.EABC","metadata":{"pre":"EABC","sn":0},"done":false}"#;
/// let operation: Operation<WitnessMetadata, KeyEvent> = serde_json::from_slice(body)?;
///
/// assert!(!operation.outcome.is_done());
/// assert_eq!(operation.metadata.map(|metadata| metadata.sn), Some(0));
/// assert!(matches!(operation.outcome, OperationOutcome::Pending));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct Operation<M, R> {
    /// Operation name, which is also its path segment under `/operations`.
    pub name: String,
    /// Family-specific metadata describing what is being waited on.
    pub metadata: Option<M>,
    /// Current state.
    pub outcome: OperationOutcome<R>,
}

/// Serialization view of an operation, borrowing rather than cloning.
#[derive(Serialize)]
struct OperationRef<'operation, M, R> {
    name: &'operation str,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<&'operation M>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<&'operation R>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'operation OperationStatus>,
    done: bool,
}

impl<M: Serialize, R: Serialize> Serialize for Operation<M, R> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (response, error) = match &self.outcome {
            OperationOutcome::Pending => (None, None),
            OperationOutcome::Completed(response) => (Some(response), None),
            OperationOutcome::Failed(status) => (None, Some(status)),
        };
        OperationRef {
            name: &self.name,
            metadata: self.metadata.as_ref(),
            response,
            error,
            done: self.outcome.is_done(),
        }
        .serialize(serializer)
    }
}

/// Deserialization view of an operation, before the three states are told apart.
#[derive(Deserialize)]
struct OperationRepr<M, R> {
    name: String,
    #[serde(default = "none")]
    metadata: Option<M>,
    #[serde(default = "none")]
    response: Option<R>,
    #[serde(default = "none")]
    error: Option<OperationStatus>,
    done: bool,
}

/// `Option::default` cannot be named for a generic without requiring `M: Default`.
const fn none<T>() -> Option<T> {
    None
}

/// Marks a field as present, so an explicit `null` is told apart from an absent field.
///
/// `Option<Option<T>>` alone cannot: serde reads a `null` into the outer `Option`, which is what an
/// absent field also produces. This runs only when the field is there.
fn present<'de, T: Deserialize<'de>, D: Deserializer<'de>>(deserializer: D) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

/// Decodes one buffered JSON value into a named type.
fn convert<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, ApiError> {
    serde_json::from_value(value).map_err(|source| ApiError::Json {
        source: Box::new(source),
    })
}

impl<'de, M: Deserialize<'de>, R: Deserialize<'de>> Deserialize<'de> for Operation<M, R> {
    /// Reads the three states apart by `done`, `response`, and `error`.
    ///
    /// # Errors
    ///
    /// A finished operation carrying neither a response nor an error, a finished operation carrying
    /// both, and a running operation carrying either are all refused. The schema admits none of
    /// them, and each would leave the outcome undecided.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let repr = OperationRepr::<M, R>::deserialize(deserializer)?;
        let outcome = match (repr.done, repr.response, repr.error) {
            (false, None, None) => OperationOutcome::Pending,
            (true, Some(response), None) => OperationOutcome::Completed(response),
            (true, None, Some(status)) => OperationOutcome::Failed(status),
            (true, None, None) => {
                return Err(de::Error::custom(
                    "a finished operation carries neither a response nor an error",
                ));
            }
            (true, Some(_), Some(_)) => {
                return Err(de::Error::custom(
                    "a finished operation carries both a response and an error",
                ));
            }
            (false, ..) => {
                return Err(de::Error::custom("a running operation carries a response or an error"));
            }
        };
        Ok(Self {
            name: repr.name,
            metadata: repr.metadata,
            outcome,
        })
    }
}

/// One operation whose metadata and response have not yet been given a type.
///
/// This is what a caller decodes when it polls `/operations` without knowing the family, and it is
/// the closest honest equivalent of the schema's fourteen-way `Operation` union. Narrow it with
/// [`UntypedOperation::into_typed`].
pub type UntypedOperation = Operation<Value, Value>;

impl UntypedOperation {
    /// Narrows an operation once its family is known.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Json`] when the metadata or the response does not match the requested
    /// family.
    pub fn into_typed<M, R>(self) -> Result<Operation<M, R>, ApiError>
    where
        M: serde::de::DeserializeOwned,
        R: serde::de::DeserializeOwned,
    {
        let metadata = self.metadata.map(convert::<M>).transpose()?;
        let outcome = match self.outcome {
            OperationOutcome::Pending => OperationOutcome::Pending,
            OperationOutcome::Completed(response) => OperationOutcome::Completed(convert::<R>(response)?),
            OperationOutcome::Failed(status) => OperationOutcome::Failed(status),
        };
        Ok(Operation {
            name: self.name,
            metadata,
            outcome,
        })
    }
}

/// Metadata naming a position in a key event log.
///
/// The schema spells this shape four times, once per family — witness, delegation, group, and
/// submit — with identical fields. The aliases below record the four names.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LogPositionMetadata {
    /// Identifier prefix whose log is being waited on.
    pub pre: String,
    /// Sequence number being waited for.
    pub sn: u64,
}

/// Metadata of an operation waiting for witness receipts.
pub type WitnessMetadata = LogPositionMetadata;
/// Metadata of an operation waiting for a delegator's approval.
pub type DelegationMetadata = LogPositionMetadata;
/// Metadata of an operation waiting for a multisig group event.
pub type GroupMetadata = LogPositionMetadata;
/// Metadata of an operation waiting for an event to be submitted to witnesses.
pub type SubmitMetadata = LogPositionMetadata;

/// Metadata of an operation resolving an OOBI.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OobiMetadata {
    /// The OOBI URL being resolved.
    pub oobi: String,
}

/// A sequence number as an agent echoed it back.
///
/// A query's metadata is not the agent's own description of what it is doing: KERIA copies the
/// request's `sn` into it verbatim, so the spelling that comes back is the *caller's*. That makes
/// the field's JSON type whatever the caller sent, and the two sources disagree about what that
/// is — the reference's generated schema declares `QueryMetadata.sn` a `number`, while its own
/// `query(pre, sn?: string, …)` can only ever send a string, and a live KERIA 1.0.1 returns the
/// string it was given (`"metadata": {"pre": "EEbP…", "sn": "a"}`).
///
/// Typing this as `u64` alone made every live query response undecodable. Both spellings are
/// accepted, and neither is rewritten into the other, so what an agent sent can be read back
/// exactly as it was written.
///
/// No numeric accessor is offered for [`Self::Text`]: the base of an echoed string is the
/// caller's choice, not something this type can recover. See
/// [`QuerySequence`](../../../signify_client/endpoint/key_states/enum.QuerySequence.html).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum EchoedSequence {
    /// A JSON string, which is what a live KERIA returns.
    Text(String),
    /// A JSON number, which is what the reference's generated schema declares.
    Number(u64),
}

impl EchoedSequence {
    /// Returns the sequence number exactly as it was written on the wire.
    #[must_use]
    pub fn to_text(&self) -> String {
        match self {
            Self::Text(text) => text.clone(),
            Self::Number(value) => value.to_string(),
        }
    }
}

/// An anchor as an agent echoed it back.
///
/// A key-state query's metadata is the caller's own request copied verbatim, exactly as
/// [`EchoedSequence`] records for `sn`. A query **by anchor** sends the caller's seal — `{i, s,
/// d}`, which is what `KeyStateQuery` builds and the reference's own `singlesig-dip` integration
/// case passes — and a live KERIA 1.0.1 echoes that seal back unchanged, while the reference's
/// generated schema and this crate's other operation families spell an anchor `{pre, sn, d}`.
/// Typing the field as [`Anchor`] alone made every live anchor-query answer undecodable — found
/// by Roadmap 9.2c's wave 10, the first anchor query ever driven against a deployment. Both
/// shapes are accepted and neither is rewritten into the other; they are disjoint, since one
/// requires `pre` and `sn` and the other requires `s`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum EchoedAnchor {
    /// The `{pre, sn, d}` shape the reference's schema declares.
    Anchor(Anchor),
    /// The caller's own `{i, s, d}` seal, echoed back verbatim.
    Seal(Seal),
}

/// Metadata of an operation querying another identifier's key state.
///
/// The agent copies the request into this record verbatim, so exactly the fields the caller sent
/// come back: a sequence query carries `sn` and no `anchor`, an anchor query carries `anchor` and
/// **no `sn`** — which is why both are optional, found live by Roadmap 9.2c's wave 10 after the
/// required `sn` refused the first anchor-query answer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueryMetadata {
    /// Identifier prefix being queried.
    pub pre: String,
    /// Sequence number being waited for, as the agent echoed it back; absent on an anchor query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sn: Option<EchoedSequence>,
    /// Event the query is waiting to see anchored, as the agent echoed it back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<EchoedAnchor>,
}

/// Metadata of an operation authorizing an endpoint role.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EndRoleMetadata {
    /// Identifier prefix granting the role, wire label `cid`.
    pub cid: String,
    /// Role being granted.
    pub role: String,
    /// Identifier prefix receiving the role, wire label `eid`.
    pub eid: String,
}

/// Metadata of an operation creating a credential registry.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RegistryMetadata {
    /// Identifier prefix that owns the registry.
    pub pre: String,
    /// The key-event operation this one is waiting on.
    pub depends: Box<KelOperation>,
    /// Event the registry inception is waiting to see anchored.
    pub anchor: Anchor,
}

/// The result of a completed registry operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistryResponse {
    /// The anchoring event.
    pub anchor: Anchor,
}

/// Metadata of an operation publishing a location scheme.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LocationSchemeMetadata {
    /// Identifier prefix of the endpoint, wire label `eid`.
    pub eid: String,
    /// URL scheme.
    pub scheme: String,
    /// Endpoint URL.
    pub url: String,
}

/// Metadata of an operation answering a challenge.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChallengeMetadata {
    /// The challenge words being waited for.
    pub words: Vec<String>,
}

/// The result of a completed challenge operation.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct ChallengeResponse {
    /// The exchange message carrying the answer.
    pub exn: ExchangeRecord,
}

/// Metadata of an operation delivering an exchange message.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExchangeMetadata {
    /// SAID of the exchange message.
    pub said: String,
}

/// Metadata of an operation that had already finished when it was created.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct DoneMetadata {
    /// The message that completed it.
    pub response: KelResponse,
    /// Identifier prefix it belongs to, or `null`.
    pub pre: Option<String>,
}

/// Metadata of an operation issuing or revoking a credential.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct CredentialMetadata {
    /// The credential being issued, wire label `ced`.
    pub ced: AcdcRecord,
    /// The key-event operation this one is waiting on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depends: Option<Box<KelOperation>>,
}

/// The result of a completed credential operation.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct CredentialResponse {
    /// The issued credential, wire label `ced`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ced: Option<AcdcRecord>,
}

/// Metadata of an operation waiting on a delegator.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct DelegatorMetadata {
    /// Delegator identifier prefix.
    pub pre: String,
    /// Delegated identifier prefix, wire label `teepre`.
    pub teepre: String,
    /// Event the delegation is waiting to see anchored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<Anchor>,
    /// The key-event operation this one is waiting on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depends: Option<Box<KelOperation>>,
}

/// What a key-event operation returns when it completes.
///
/// The four families the schema groups as `KelOperation` return a key event between them, except
/// the already-finished family, which may also return an exchange message. The `t` field tells them
/// apart.
#[derive(Clone, Debug, PartialEq)]
pub enum KelResponse {
    /// A key event.
    ///
    /// Boxed to keep the two variants a similar size.
    Event(Box<KeyEvent>),
    /// An exchange message.
    Exchange(Box<ExchangeRecord>),
}

impl Serialize for KelResponse {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Event(event) => event.serialize(serializer),
            Self::Exchange(message) => message.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for KelResponse {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let document = Value::deserialize(deserializer)?;
        let ilk = document
            .get("t")
            .and_then(Value::as_str)
            .ok_or_else(|| de::Error::missing_field("t"))?;
        if ilk == "exn" {
            return serde_json::from_value(document)
                .map(|message| Self::Exchange(Box::new(message)))
                .map_err(de::Error::custom);
        }
        serde_json::from_value(document)
            .map(|event| Self::Event(Box::new(event)))
            .map_err(de::Error::custom)
    }
}

/// Metadata of one of the four key-event operation families.
///
/// Three of them describe a position in a log and the fourth an already-finished message; the
/// presence of `sn` or of `response` tells them apart.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum KelMetadata {
    /// A position in a key event log.
    Log(LogPositionMetadata),
    /// An operation that had already finished.
    Done(Box<DoneMetadata>),
}

/// An operation that resolves an OOBI, returning the key state it discovered.
pub type OobiOperation = Operation<OobiMetadata, KeyState>;
/// An operation that queries another identifier's key state.
pub type QueryOperation = Operation<QueryMetadata, KeyState>;
/// An operation that authorizes an endpoint role, returning the reply that granted it.
pub type EndRoleOperation = Operation<EndRoleMetadata, ReplyRecord>;
/// An operation that waits for witness receipts.
pub type WitnessOperation = Operation<WitnessMetadata, KeyEvent>;
/// An operation that waits for a delegator's approval.
pub type DelegationOperation = Operation<DelegationMetadata, KeyEvent>;
/// An operation that creates a credential registry.
pub type RegistryOperation = Operation<RegistryMetadata, RegistryResponse>;
/// An operation that publishes a location scheme.
pub type LocationSchemeOperation = Operation<LocationSchemeMetadata, LocationSchemeMetadata>;
/// An operation that answers a challenge.
pub type ChallengeOperation = Operation<ChallengeMetadata, ChallengeResponse>;
/// An operation that delivers an exchange message.
pub type ExchangeOperation = Operation<ExchangeMetadata, ExchangeMetadata>;
/// An operation that submits an event to witnesses.
pub type SubmitOperation = Operation<SubmitMetadata, KeyState>;
/// An operation that had already finished when it was created.
pub type DoneOperation = Operation<DoneMetadata, KelResponse>;
/// An operation that issues or revokes a credential.
pub type CredentialOperation = Operation<CredentialMetadata, CredentialResponse>;
/// An operation that waits for a multisig group event.
pub type GroupOperation = Operation<GroupMetadata, KeyEvent>;
/// An operation that waits on a delegator, returning the delegated prefix.
pub type DelegatorOperation = Operation<DelegatorMetadata, String>;
/// Any of the four operations another operation may depend on.
pub type KelOperation = Operation<KelMetadata, KelResponse>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const PENDING: &str = r#"{"name":"witness.EABC","metadata":{"pre":"EABC","sn":0},"done":false}"#;

    #[test]
    fn the_three_operation_states_round_trip() -> Result<(), Box<dyn Error>> {
        let pending: WitnessOperation = serde_json::from_str(PENDING)?;
        assert!(!pending.outcome.is_done());
        assert!(pending.outcome.response().is_none());
        assert!(pending.outcome.error().is_none());
        assert_eq!(serde_json::to_string(&pending)?, PENDING);

        let event = r#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"EAB","i":"EABC","s":"1","p":"EEF","a":[]}"#;
        let completed_source =
            format!(r#"{{"name":"witness.EABC","metadata":{{"pre":"EABC","sn":0}},"response":{event},"done":true}}"#);
        let completed: WitnessOperation = serde_json::from_str(&completed_source)?;
        assert!(completed.outcome.is_done());
        assert_eq!(completed.outcome.response().map(KeyEvent::kind), Some("ixn"));
        assert_eq!(serde_json::to_string(&completed)?, completed_source);

        let failed_source =
            r#"{"name":"witness.EABC","error":{"code":408,"message":"timed out","details":null},"done":true}"#;
        let failed: WitnessOperation = serde_json::from_str(failed_source)?;
        assert!(failed.metadata.is_none());
        assert_eq!(failed.outcome.error().map(|status| status.code), Some(408));
        // An explicit `null` detail is a value, so it is written back.
        assert_eq!(serde_json::to_string(&failed)?, failed_source);
        Ok(())
    }

    #[test]
    fn an_undecidable_outcome_is_refused() {
        for document in [
            // `done` with no result at all: the shape upstream's own test mock returns.
            r#"{"name":"a","done":true}"#,
            // Both a result and a failure.
            r#"{"name":"a","response":{},"error":{"code":1,"message":"m"},"done":true}"#,
            // Still running, yet carrying a result.
            r#"{"name":"a","response":{},"done":false}"#,
            r#"{"name":"a","error":{"code":1,"message":"m"},"done":false}"#,
            // No `done` field at all.
            r#"{"name":"a"}"#,
        ] {
            assert!(
                serde_json::from_str::<UntypedOperation>(document).is_err(),
                "{document} was accepted"
            );
        }
    }

    #[test]
    fn operation_status_keeps_absent_and_null_details_apart() -> Result<(), Box<dyn Error>> {
        let absent: OperationStatus = serde_json::from_str(r#"{"code":500,"message":"m"}"#)?;
        assert_eq!(absent.details, None);
        assert_eq!(absent.details(), None);
        assert_eq!(serde_json::to_string(&absent)?, r#"{"code":500,"message":"m"}"#);

        let null: OperationStatus = serde_json::from_str(r#"{"code":500,"message":"m","details":null}"#)?;
        assert_eq!(null.details, Some(None));
        assert_eq!(null.details(), None);
        assert_eq!(
            serde_json::to_string(&null)?,
            r#"{"code":500,"message":"m","details":null}"#
        );

        let present: OperationStatus = serde_json::from_str(r#"{"code":500,"message":"m","details":{"a":1}}"#)?;
        assert_eq!(present.details().map(Map::len), Some(1));
        assert_eq!(
            serde_json::to_string(&present)?,
            r#"{"code":500,"message":"m","details":{"a":1}}"#
        );
        Ok(())
    }

    #[test]
    fn an_untyped_operation_narrows_to_its_family() -> Result<(), Box<dyn Error>> {
        let untyped: UntypedOperation = serde_json::from_str(PENDING)?;
        let typed: WitnessOperation = untyped.clone().into_typed()?;
        assert_eq!(typed.metadata.map(|metadata| metadata.pre), Some("EABC".to_owned()));
        // The wrong family is a typed failure rather than a silent misreading.
        assert!(untyped.into_typed::<OobiMetadata, KeyState>().is_err());
        Ok(())
    }

    #[test]
    fn an_anchor_query_echoes_the_callers_seal_and_no_sequence() -> Result<(), Box<dyn Error>> {
        // The exact shape a live KERIA 1.0.1 answered the first anchor query ever driven against
        // a deployment — Roadmap 9.2c's wave 10. The metadata is the caller's request copied
        // verbatim: the anchor is the caller's own `{i, s, d}` seal, not the schema's
        // `{pre, sn, d}` shape, and there is no `sn` at all. Typing `anchor` as `Anchor` alone
        // and `sn` as required made this body undecodable.
        let answer = r#"{"name":"query.EHS5.EAUv","metadata":{"pre":"EHS5","anchor":{"i":"EAUv","s":"0","d":"EAUv"}},"done":false,"error":null,"response":null}"#;
        let operation: QueryOperation = serde_json::from_str(answer)?;
        let metadata = operation.metadata.ok_or("the anchor query carried no metadata")?;
        assert_eq!(metadata.sn, None);
        let Some(EchoedAnchor::Seal(seal)) = &metadata.anchor else {
            return Err("the echoed seal decoded as something else".into());
        };
        assert_eq!(seal.identifier.as_deref(), Some("EAUv"));
        assert_eq!(seal.sequence_number, "0");
        assert_eq!(seal.digest, "EAUv");

        // The schema's own shape still decodes, and the two are disjoint: one requires `pre` and
        // `sn`, the other requires `s`.
        let schema_shaped = r#"{"name":"query.EHS5","metadata":{"pre":"EHS5","sn":1,"anchor":{"pre":"EABC","sn":1,"d":"EAB"}},"done":false}"#;
        let operation: QueryOperation = serde_json::from_str(schema_shaped)?;
        let metadata = operation
            .metadata
            .ok_or("the schema-shaped query carried no metadata")?;
        assert_eq!(metadata.sn, Some(EchoedSequence::Number(1)));
        assert!(matches!(metadata.anchor, Some(EchoedAnchor::Anchor(_))));
        Ok(())
    }

    #[test]
    fn a_dependent_operation_nests_its_dependency() -> Result<(), Box<dyn Error>> {
        let depends = r#"{"name":"witness.EABC","metadata":{"pre":"EABC","sn":0},"done":false}"#;
        let document = format!(
            r#"{{"name":"registry.EREG","metadata":{{"pre":"EABC","depends":{depends},"anchor":{{"pre":"EABC","sn":1,"d":"EAB"}}}},"done":false}}"#
        );
        let operation: RegistryOperation = serde_json::from_str(&document)?;
        let metadata = operation.metadata.as_ref().ok_or("registry metadata was dropped")?;
        assert_eq!(metadata.anchor.sn, 1);
        assert!(matches!(metadata.depends.metadata, Some(KelMetadata::Log(_))));
        assert_eq!(serde_json::to_string(&operation)?, document);
        Ok(())
    }

    #[test]
    fn a_key_event_operation_reads_both_metadata_shapes() -> Result<(), Box<dyn Error>> {
        let log = r#"{"name":"group.EABC","metadata":{"pre":"EABC","sn":2},"done":false}"#;
        let operation: KelOperation = serde_json::from_str(log)?;
        assert!(matches!(operation.metadata, Some(KelMetadata::Log(_))));
        assert_eq!(serde_json::to_string(&operation)?, log);

        let exchange = r#"{"v":"KERI10JSON000_","t":"exn","d":"EAB","i":"ECD","rp":"ERP","p":"","dt":"2023-08-19T21:04:57.948863+00:00","r":"/ipex/grant","q":{},"a":{},"e":{}}"#;
        let done = format!(r#"{{"name":"done.EABC","metadata":{{"response":{exchange},"pre":null}},"done":false}}"#);
        let operation: KelOperation = serde_json::from_str(&done)?;
        let Some(KelMetadata::Done(metadata)) = &operation.metadata else {
            return Err("an already-finished operation decoded as a log position".into());
        };
        assert!(matches!(metadata.response, KelResponse::Exchange(_)));
        assert_eq!(metadata.pre, None);
        assert_eq!(serde_json::to_string(&operation)?, done);
        Ok(())
    }

    #[test]
    fn a_key_event_response_tells_an_event_from_an_exchange() -> Result<(), Box<dyn Error>> {
        let event = r#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"EAB","i":"ECD","s":"1","p":"EEF","a":[]}"#;
        let response: KelResponse = serde_json::from_str(event)?;
        assert!(matches!(response, KelResponse::Event(_)));
        assert_eq!(serde_json::to_string(&response)?, event);

        // A message with no ilk at all names neither.
        assert!(serde_json::from_str::<KelResponse>(r#"{"v":"KERI10JSON000_"}"#).is_err());
        // An ilk outside both sets is refused rather than guessed at.
        assert!(serde_json::from_str::<KelResponse>(r#"{"t":"rpy","v":"x"}"#).is_err());
        Ok(())
    }
}
