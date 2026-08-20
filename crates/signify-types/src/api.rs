//! KERIA API request and response records.
//!
//! These types are curated from two pinned upstream files:
//!
//! - `src/types/keria-api-schema.ts`, which upstream generates from a running KERIA agent's
//!   `OpenAPI` document with `scripts/generate-types.js`;
//! - `src/keri/core/keyState.ts`, which renames a subset of those schemas and narrows two of them
//!   by hand.
//!
//! The generated TypeScript is the pinned artifact this port is verified against. The `OpenAPI`
//! document it came from is *not* checked in anywhere upstream — the generator fetches it from
//! `http://localhost:3902/spec.yaml`, a live agent — so regeneration from the original source is
//! not reproducible from the pinned checkout. These Rust records are therefore curated against the
//! generated TypeScript, and `fixtures/types-keria-api/v1.json` pins that file's exact structure,
//! extracted from it by the TypeScript compiler, so a drift becomes a failing test rather than a
//! silent incompatibility. See `docs/adr/0012-keria-api-record-types.md`.
//!
//! # Decoding
//!
//! [`from_json_slice`] is the bounded entry point: it refuses a document above
//! [`MAX_DOCUMENT_BYTES`] before handing anything to the JSON parser, which in turn refuses
//! nesting beyond [`MAX_NESTING_DEPTH`]. Callers that already bound their input may use `serde_json`
//! directly.
//!
//! ```
//! use signify_types::api::{KeyState, from_json_slice};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let body = br#"{"vn":[1,0],"i":"EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei","s":"0","p":"",
//!   "d":"EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei","f":"0","dt":"2023-08-19T21:04:57.948863+00:00",
//!   "et":"dip","kt":"1","k":["DMZh_y-H5C3cSbZZST-fqnsmdNTReZxIh0t2xSTOJQ8a"],"nt":"1",
//!   "n":["EM9M2EQNCBK0MyAhVYBvR98Q0tefpvHgE-lHLs82XgqC"],"bt":"0","b":[],"c":[],
//!   "ee":{"s":"0","d":"EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei","br":[],"ba":[]},
//!   "di":"ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"}"#;
//!
//! let state: KeyState = from_json_slice(body)?;
//! assert_eq!(state.sequence_number, "0");
//! assert_eq!(state.signing_keys.len(), 1);
//! # Ok(())
//! # }
//! ```
//!
//! # Forward compatibility
//!
//! KERIA is developed alongside signify, and its `OpenAPI` document changes without a version
//! negotiation. The reference tolerates that by not validating at all: every response body reaches
//! application code through an unchecked `await res.json()` cast, so an unknown field is retained
//! and ignored and an unknown enum value is simply the string the agent sent. This crate keeps the
//! useful half of that behavior and drops the unsafe half:
//!
//! - **Unknown object fields are ignored** on every record, so a newer agent adding a field does
//!   not break an older client. Where the schema itself declares an index signature — the ACDC
//!   attribute block, an external key-manager state, a contact, and a notification payload — the
//!   unknown fields are *captured* instead, so they survive a round trip.
//! - **Unknown values of a closed code table are refused.** A `t`, `et`, or `tier` outside its
//!   declared set selects which shape the rest of the document has, so accepting one would mean
//!   accepting a document this crate cannot interpret. These are [`KeyEvent`], [`IssuanceKind`],
//!   [`RegistryEventKind`], [`UnbackedCredentialStatus`], [`BackedCredentialStatus`], and
//!   [`KeyTier`].
//! - **An open registry keeps an escape hatch.** [`Role`] carries the nine roles the schema names
//!   plus [`Role::Other`], because the KERI role registry is extensible and the schema itself types
//!   an end role's `role` as a bare string while typing an OOBI's as an enum.
//!
//! # Bytes and field order
//!
//! Each record declares its fields in the schema's order, so re-serializing produces the schema's
//! spelling. That is *not* a byte-parity guarantee: a field the schema types as `unknown` is held
//! as [`serde_json::Value`], whose objects re-serialize in sorted key order rather than the order
//! received. A SAID or a signature must therefore be verified against the bytes a response
//! actually carried, using `signify-keri`, and never against a record that has round-tripped
//! through this crate.

use serde::Serialize;
use serde::de::DeserializeOwned;

pub mod contact;
pub mod credential;
pub mod error;
pub mod exchange;
pub mod identifier;
pub mod key_state;
pub mod message;
pub mod operation;

pub use contact::{
    AgentConfig, AidRecord, Challenge, Contact, EndRole, GroupMember, MemberEnds, Notification, NotificationData, Oobi,
    Role, RoleEndpoints, WellKnown,
};
pub use credential::{
    BackedCredentialState, BackedCredentialStatus, CREDENTIAL_STATUS_KINDS, Credential, CredentialState, EmptyObject,
    IssuanceEvent, IssuanceKind, Registry, RegistryEventKind, RegistryState, RevocationAnchor, UnbackedCredentialState,
    UnbackedCredentialStatus,
};
pub use error::ApiError;
pub use exchange::{
    ExchangeEmbed, ExchangeEmbeds, ExchangeResource, MultisigExchangeEmbed, MultisigExchangeResource,
    MultisigInceptionEmbed, MultisigInteractionEmbed, MultisigIssuanceEmbed, MultisigRegistryInceptionEmbed,
    MultisigReplyEmbed, MultisigRevocationEmbed, MultisigRotationEmbed,
};
pub use identifier::{
    AcceptedHab, ExternState, GroupState, Hab, HabCommon, KeyManagerState, KeyTier, PendingHab, RandyState, SaltyState,
};
pub use key_state::{AgentResourceResult, Controller, EstablishmentState, KeyState};
pub use message::{
    AcdcAttributes, AcdcRecord, Anchor, DelegatedInceptionIlk, DelegatedInceptionRecord, DelegatedRotationIlk,
    ExchangeIlk, ExchangeRecord, InceptionIlk, InceptionRecord, InteractionIlk, InteractionRecord, KEY_EVENT_ILKS,
    KeyEvent, KeyEventRecord, RegistryInceptionIlk, RegistryInceptionRecord, ReplyIlk, ReplyRecord, RevocationIlk,
    RevocationRecord, RotationIlk, RotationRecord, Schema, Seal, Threshold,
};
pub use operation::{
    ChallengeMetadata, ChallengeResponse, CredentialMetadata, CredentialOperation, CredentialResponse,
    DelegationMetadata, DelegationOperation, DelegatorMetadata, DelegatorOperation, DoneMetadata, DoneOperation,
    EndRoleMetadata, EndRoleOperation, ExchangeMetadata, ExchangeOperation, GroupMetadata, GroupOperation, KelMetadata,
    KelOperation, KelResponse, LocationSchemeMetadata, LocationSchemeOperation, LogPositionMetadata, OobiMetadata,
    OobiOperation, Operation, OperationOutcome, OperationStatus, QueryMetadata, QueryOperation, RegistryMetadata,
    RegistryOperation, RegistryResponse, SubmitMetadata, SubmitOperation, UntypedOperation, WitnessMetadata,
    WitnessOperation,
};

/// Largest JSON document [`from_json_slice`] will decode, in bytes.
///
/// KERIA's largest single document is a credential carrying its schema, its issuance event, and
/// its chain of edges; nothing observed approaches a mebibyte. Four mebibytes leaves ample room for
/// a long credential list while keeping a hostile body from being materialized in full. A caller
/// that needs a different bound uses [`from_json_slice_with_limit`].
pub const MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;

/// Deepest JSON nesting any record accepts.
///
/// This is `serde_json`'s own recursion limit, restated here because it is part of this crate's
/// hostile-input contract: a document nested beyond it is a typed error, never a stack overflow.
pub const MAX_NESTING_DEPTH: usize = 128;

/// Decodes one KERIA document, refusing anything above [`MAX_DOCUMENT_BYTES`].
///
/// # Errors
///
/// Returns [`ApiError::DocumentTooLarge`] before parsing when the input exceeds the bound, and
/// [`ApiError::Json`] when the document is not valid JSON, does not match the record, or nests
/// beyond [`MAX_NESTING_DEPTH`].
pub fn from_json_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ApiError> {
    from_json_slice_with_limit(bytes, MAX_DOCUMENT_BYTES)
}

/// Decodes one KERIA document against a caller-chosen size bound.
///
/// # Errors
///
/// Returns [`ApiError::DocumentTooLarge`] before parsing when the input exceeds `limit`, and
/// [`ApiError::Json`] when the document is not valid JSON, does not match the record, or nests
/// beyond [`MAX_NESTING_DEPTH`].
pub fn from_json_slice_with_limit<T: DeserializeOwned>(bytes: &[u8], limit: usize) -> Result<T, ApiError> {
    if bytes.len() > limit {
        return Err(ApiError::DocumentTooLarge {
            length: bytes.len(),
            limit,
        });
    }
    serde_json::from_slice(bytes).map_err(|source| ApiError::Json {
        source: Box::new(source),
    })
}

/// Encodes one KERIA document in the schema's field order.
///
/// # Errors
///
/// Returns [`ApiError::Json`] when a value cannot be represented as JSON.
pub fn to_json_string<T: Serialize + ?Sized>(value: &T) -> Result<String, ApiError> {
    serde_json::to_string(value).map_err(|source| ApiError::Json {
        source: Box::new(source),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_documents_are_refused_before_parsing() {
        let oversized = vec![b' '; MAX_DOCUMENT_BYTES + 1];
        assert!(matches!(
            from_json_slice::<KeyState>(&oversized).map(|_| ()),
            Err(ApiError::DocumentTooLarge { length, limit })
                if length == MAX_DOCUMENT_BYTES + 1 && limit == MAX_DOCUMENT_BYTES
        ));

        let body = vec![b' '; 33];
        assert!(matches!(
            from_json_slice_with_limit::<KeyState>(&body, 32).map(|_| ()),
            Err(ApiError::DocumentTooLarge { length: 33, limit: 32 })
        ));
        // A document exactly at the bound is still parsed, and then fails on its content.
        assert!(matches!(
            from_json_slice_with_limit::<KeyState>(&body, 33).map(|_| ()),
            Err(ApiError::Json { .. })
        ));
    }

    #[test]
    fn deep_nesting_is_a_typed_error_rather_than_a_crash() {
        // `a` is a schema-declared `unknown`, so its depth is whatever a hostile agent sends.
        let depth = MAX_NESTING_DEPTH + 8;
        let body = format!(
            r#"{{"v":"KERI10JSON0000cb_","t":"ixn","d":"E","i":"E","s":"1","p":"E","a":{}{}}}"#,
            "[".repeat(depth),
            "]".repeat(depth),
        );
        assert!(matches!(
            from_json_slice::<InteractionRecord>(body.as_bytes()).map(|_| ()),
            Err(ApiError::Json { .. })
        ));
    }

    #[test]
    fn malformed_documents_are_typed_errors() {
        assert!(matches!(
            from_json_slice::<KeyState>(b"not json").map(|_| ()),
            Err(ApiError::Json { .. })
        ));
        assert!(matches!(
            from_json_slice::<KeyState>(b"{}").map(|_| ()),
            Err(ApiError::Json { .. })
        ));
    }
}
