//! Exact KERIA API type vectors taken from the pinned TypeScript reference.
//!
//! The reference for this module is the TypeScript compiler: `keria-api-schema.ts` declares types,
//! which do not exist at run time and cannot be called. The fixture therefore carries two kinds of
//! evidence, and this file checks the Rust model against both.
//!
//! - The **declaration**, read from the pinned file's syntax tree: every schema, its fields, and
//!   which of them are optional. The Rust records are asserted against it, so a schema drifting out
//!   from under this port fails a test rather than producing a silent incompatibility.
//! - The **verdicts** the pinned compiler returns for 82 documents. Each is decoded here with the
//!   Rust type the fixture names, and the result compared with what the fixture records — including
//!   the thirteen documents the two implementations deliberately decide differently.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use signify_types::api::credential::{BackedCredentialStatus, RegistryEventKind, UnbackedCredentialStatus};
use signify_types::api::{
    AcceptedHab, AcdcAttributes, AcdcRecord, AgentConfig, AgentResourceResult, AidRecord, Anchor, Challenge, Contact,
    Controller, Credential, CredentialState, DoneOperation, EmptyObject, EndRole, EstablishmentState, ExchangeEmbeds,
    ExchangeRecord, ExchangeResource, GroupMember, Hab, IssuanceEvent, IssuanceKind, KeyEvent, KeyEventRecord,
    KeyState, KeyTier, MemberEnds, MultisigExchangeResource, MultisigInceptionEmbed, MultisigReplyEmbed, Notification,
    Oobi, OperationStatus, PendingHab, RegistryInceptionRecord, RegistryOperation, RegistryState, ReplyRecord,
    RevocationRecord, Role, SaltyState, Schema, Seal, UntypedOperation, WellKnown, WitnessOperation, from_json_slice,
    message,
};
use signify_types::api::{Registry, to_json_string};

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/types-keria-api/v1.json");

/// Documents this port and the reference deliberately decide differently.
///
/// Each is explained in `fixtures/types-keria-api/README.md` and `PORTING.md` §9. The list is
/// asserted exactly, so a new disagreement cannot appear unnoticed.
const EXPECTED_DIVERGENCES: [(&str, bool, bool); 14] = [
    ("key_state_unknown_field", false, true),
    ("agent_resource_result_upstream_mock", false, true),
    ("key_event_receipt_ilk", true, false),
    ("issuance_event", false, true),
    ("credential_status_unbacked", false, true),
    ("credential_status_backed", false, true),
    ("credential", false, true),
    ("registry", false, true),
    ("hab_salty", false, true),
    ("hab_two_key_managers", true, false),
    ("member_ends_missing_a_role", false, true),
    ("oobi", false, true),
    ("oobi_unknown_role", false, true),
    ("anchor_fractional_sequence_number", true, false),
];

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    upstream: String,
    reference_sha: String,
    generated_on: String,
    sources: Vec<String>,
    typescript_version: String,
    generation: Generation,
    schema_count: usize,
    schema_names: Vec<String>,
    schemas: BTreeMap<String, Shape>,
    enums: BTreeMap<String, Vec<EnumMember>>,
    key_state_exports: BTreeMap<String, String>,
    key_state_functions: Vec<String>,
    documents: Vec<Document>,
    divergences: Vec<Divergence>,
}

#[derive(Debug, Deserialize)]
struct Generation {
    upstream_command: String,
    upstream_spec_url: String,
    upstream_spec_checked_in: bool,
    note: String,
}

#[derive(Debug, Deserialize)]
struct EnumMember {
    name: String,
    value: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Document {
    name: String,
    schema: String,
    json: Value,
    literal_accepted: bool,
    structural_accepted: bool,
    rust_type: String,
    rust_expected: String,
    #[serde(default)]
    provenance: Option<String>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    literal_diagnostics: Vec<String>,
    #[serde(default)]
    structural_diagnostics: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Divergence {
    name: String,
    reference_accepts: bool,
    rust_accepts: bool,
}

/// One schema's structure, exactly as the pinned declaration writes it.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum Shape {
    Object {
        fields: Vec<Field>,
        #[serde(default)]
        index: Option<String>,
    },
    Union {
        members: Vec<Shape>,
    },
    Intersection {
        members: Vec<Shape>,
    },
    Array {
        element: Box<Shape>,
    },
    Ref {
        name: String,
    },
    Named {
        name: String,
    },
    Other {
        text: String,
    },
}

#[derive(Debug, Deserialize)]
struct Field {
    name: String,
    optional: bool,
    #[serde(rename = "type")]
    declared: Shape,
}

/// One way a schema's fields may be spelled: their declared order, and whether extras are allowed.
#[derive(Clone, Debug)]
struct Alternative {
    order: Vec<String>,
    open: bool,
}

/// Enumerates every ordered field list a shape admits, resolving references up to `depth`.
fn alternatives(shape: &Shape, schemas: &BTreeMap<String, Shape>, depth: u8) -> Vec<Alternative> {
    if depth == 0 {
        return Vec::new();
    }
    match shape {
        Shape::Object { fields, index } => vec![Alternative {
            order: fields.iter().map(|field| field.name.clone()).collect(),
            open: index.is_some(),
        }],
        Shape::Union { members } => members
            .iter()
            .flat_map(|member| alternatives(member, schemas, depth - 1))
            .collect(),
        Shape::Intersection { members } => {
            let mut combined = vec![Alternative {
                order: Vec::new(),
                open: false,
            }];
            for member in members {
                let next = alternatives(member, schemas, depth - 1);
                if next.is_empty() {
                    return Vec::new();
                }
                combined = combined
                    .iter()
                    .flat_map(|prefix| {
                        next.iter().map(move |suffix| Alternative {
                            order: prefix.order.iter().chain(&suffix.order).cloned().collect(),
                            open: prefix.open || suffix.open,
                        })
                    })
                    .collect();
            }
            combined
        }
        Shape::Ref { name } => schemas
            .get(name)
            .map_or_else(Vec::new, |resolved| alternatives(resolved, schemas, depth - 1)),
        Shape::Named { .. } | Shape::Array { .. } | Shape::Other { .. } => Vec::new(),
    }
}

/// Returns whether `keys` appear in the declared order of at least one alternative.
///
/// An open alternative — one whose schema declares an index signature — additionally admits keys the
/// schema does not name, anywhere.
fn keys_follow_declared_order(keys: &[String], alternatives: &[Alternative]) -> bool {
    alternatives.iter().any(|alternative| {
        let mut declared = alternative.order.iter();
        keys.iter().all(|key| {
            if declared.any(|candidate| candidate == key) {
                return true;
            }
            // The key was not found at or after the current position. It is acceptable only if the
            // schema is open and the key is one it never declares.
            alternative.open && !alternative.order.contains(key)
        })
    })
}

/// Returns the top-level keys of a JSON object in the order they were written.
///
/// A parsed `serde_json::Map` cannot answer this: it sorts. The order a record writes its fields in
/// is exactly what this test is checking, so the encoded text is read directly.
fn top_level_keys(json: &str) -> Vec<String> {
    let bytes = json.as_bytes();
    let mut keys = Vec::new();
    let mut depth = 0_usize;
    let mut index = 0_usize;
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'{' | b'[' => {
                depth += 1;
                index += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                index += 1;
            }
            b'"' => {
                let start = index + 1;
                let mut end = start;
                while let Some(&inner) = bytes.get(end) {
                    if inner == b'\\' {
                        end += 2;
                        continue;
                    }
                    if inner == b'"' {
                        break;
                    }
                    end += 1;
                }
                let mut after = end + 1;
                while matches!(bytes.get(after), Some(b' ')) {
                    after += 1;
                }
                if depth == 1
                    && matches!(bytes.get(after), Some(b':'))
                    && let Some(text) = json.get(start..end)
                {
                    keys.push(text.to_owned());
                }
                index = end + 1;
            }
            _ => index += 1,
        }
    }
    keys
}

/// Decodes one document with a named Rust record, returning the keys it writes back, in order.
fn decode<T: DeserializeOwned + serde::Serialize>(json: &Value) -> Result<Vec<String>, Box<dyn Error>> {
    let body = serde_json::to_vec(json)?;
    let record: T = from_json_slice(&body)?;
    Ok(top_level_keys(&to_json_string(&record)?))
}

/// Dispatches a document to the Rust record the fixture names for it.
fn decode_named(rust_type: &str, json: &Value) -> Result<Result<Vec<String>, String>, Box<dyn Error>> {
    macro_rules! dispatch {
        ($($label:literal => $record:ty,)*) => {
            match rust_type {
                $($label => decode::<$record>(json).map_err(|error| error.to_string()),)*
                other => return Err(format!("the fixture names an unmapped Rust type {other}").into()),
            }
        };
    }

    Ok(dispatch! {
        "AcceptedHab" => AcceptedHab,
        "AcdcAttributes" => AcdcAttributes,
        "AcdcRecord" => AcdcRecord,
        "AgentConfig" => AgentConfig,
        "AgentResourceResult" => AgentResourceResult,
        "AidRecord" => AidRecord,
        "Anchor" => Anchor,
        "Challenge" => Challenge,
        "Contact" => Contact,
        "Controller" => Controller,
        "Credential" => Credential,
        "CredentialState" => CredentialState,
        "DoneOperation" => DoneOperation,
        "EmptyObject" => EmptyObject,
        "EndRole" => EndRole,
        "EstablishmentState" => EstablishmentState,
        "ExchangeEmbeds" => ExchangeEmbeds,
        "ExchangeRecord" => ExchangeRecord,
        "ExchangeResource" => ExchangeResource,
        "GroupMember" => GroupMember,
        "Hab" => Hab,
        "IssuanceEvent" => IssuanceEvent,
        "KeyEvent" => KeyEvent,
        "KeyEventRecord" => KeyEventRecord,
        "KeyState" => KeyState,
        "MemberEnds" => MemberEnds,
        "MultisigExchangeResource" => MultisigExchangeResource,
        "MultisigInceptionEmbed" => MultisigInceptionEmbed,
        "MultisigReplyEmbed" => MultisigReplyEmbed,
        "Notification" => Notification,
        "Oobi" => Oobi,
        "OperationStatus" => OperationStatus,
        "PendingHab" => PendingHab,
        "Registry" => Registry,
        "RegistryInceptionRecord" => RegistryInceptionRecord,
        "RegistryOperation" => RegistryOperation,
        "RegistryState" => RegistryState,
        "ReplyRecord" => ReplyRecord,
        "RevocationRecord" => RevocationRecord,
        "SaltyState" => SaltyState,
        "Schema" => Schema,
        "Seal" => Seal,
        "UntypedOperation" => UntypedOperation,
        "WellKnown" => WellKnown,
        "WitnessOperation" => WitnessOperation,
    })
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    Ok(serde_json::from_str(FIXTURE)?)
}

#[test]
fn the_fixture_records_the_pinned_baseline_and_how_it_was_made() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert_eq!(fixture.upstream, "https://github.com/WebOfTrust/signify-ts.git");
    assert_eq!(fixture.generated_on, "2026-08-20");
    assert_eq!(fixture.typescript_version, "5.9.2");
    assert!(
        fixture
            .sources
            .iter()
            .any(|source| source == "src/types/keria-api-schema.ts")
    );
    assert!(
        fixture
            .sources
            .iter()
            .any(|source| source == "src/keri/core/keyState.ts")
    );

    // The `PORTING.md` §10 question this item closes: there is no OpenAPI revision to pin, because
    // the upstream generator fetches the document from a live agent and checks in nothing.
    assert_eq!(fixture.generation.upstream_command, "node scripts/generate-types.js");
    assert_eq!(fixture.generation.upstream_spec_url, "http://localhost:3902/spec.yaml");
    assert!(!fixture.generation.upstream_spec_checked_in);
    assert!(!fixture.generation.note.is_empty());
    Ok(())
}

#[test]
fn the_schema_inventory_is_complete_and_named_as_the_reference_names_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_count, 150);
    assert_eq!(fixture.schema_names.len(), fixture.schema_count);
    assert_eq!(fixture.schemas.len(), fixture.schema_count);

    // Every schema this port models by name must still exist upstream.
    for name in [
        "KeyStateRecord",
        "StateEERecord",
        "Controller",
        "AgentResourceResult",
        "HabState",
        "SaltyState",
        "RandyKeyState",
        "GroupKeyState",
        "ExternState",
        "KeyEvent",
        "KeyEventRecord",
        "Credential",
        "CredentialState",
        "Registry",
        "RegistryState",
        "IssEvent",
        "Schema",
        "Anchor",
        "Seal",
        "EmptyDict",
        "MemberEnds",
        "Contact",
        "Challenge",
        "WellKnown",
        "AidRecord",
        "GroupMember",
        "Notification",
        "OOBI",
        "EndRole",
        "AgentConfig",
        "OperationStatus",
        "ExchangeResource",
        "ExnEmbeds",
        "ExnMultisig",
    ] {
        assert!(fixture.schemas.contains_key(name), "the schema {name} has disappeared");
    }

    // Every operation family the port models is present in all three of its upstream spellings.
    for family in [
        "OOBI",
        "Query",
        "EndRole",
        "Witness",
        "Delegation",
        "Registry",
        "LocScheme",
        "Challenge",
        "Exchange",
        "Submit",
        "Done",
        "Credential",
        "Group",
        "Delegator",
    ] {
        for prefix in ["Pending", "Completed", "Failed"] {
            let name = format!("{prefix}{family}Operation");
            assert!(fixture.schemas.contains_key(&name), "{name} has disappeared");
        }
    }
    Ok(())
}

#[test]
fn the_key_event_union_holds_exactly_the_five_ilks_rust_names() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let Some(Shape::Union { members }) = fixture.schemas.get("KeyEvent") else {
        return Err("the KeyEvent schema is no longer a union".into());
    };

    // Each member is a reference such as `ICP_V_1`; the ilk is its lowercased stem.
    let mut ilks = BTreeSet::new();
    for member in members {
        let Shape::Ref { name } = member else {
            return Err("a KeyEvent union member is no longer a schema reference".into());
        };
        let stem = name.split("_V_").next().unwrap_or(name);
        ilks.insert(stem.to_lowercase());
    }
    assert_eq!(members.len(), 10, "five ilks in two protocol versions");
    assert_eq!(
        ilks,
        message::KEY_EVENT_ILKS.iter().map(|ilk| (*ilk).to_owned()).collect()
    );
    Ok(())
}

#[test]
fn every_closed_code_table_matches_the_reference_enum() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.enums.len(), 6);

    let values = |name: &str| -> Vec<String> {
        fixture
            .enums
            .get(name)
            .map(|members| {
                members
                    .iter()
                    .map(|member| member.value.clone().unwrap_or_else(|| member.name.clone()))
                    .collect()
            })
            .unwrap_or_default()
    };

    assert_eq!(
        values("Tier"),
        KeyTier::ALL
            .iter()
            .map(|tier| tier.as_str().to_owned())
            .collect::<Vec<_>>()
    );
    assert_eq!(values("IssEventT"), ["iss", "bis"]);
    assert_eq!(values("CredentialStateIssOrRevEt"), ["iss", "rev"]);
    assert_eq!(values("CredentialStateBisOrBrvEt"), ["bis", "brv"]);
    assert_eq!(values("RegistryStateEt"), ["vcp", "vrt"]);
    assert_eq!(
        values("OOBIRole"),
        Role::DECLARED.iter().map(Role::as_str).collect::<Vec<_>>()
    );

    // Every declared value must decode into its Rust counterpart, and nothing else may.
    for value in values("Tier") {
        assert!(serde_json::from_str::<KeyTier>(&format!("\"{value}\"")).is_ok());
    }
    for value in values("IssEventT") {
        assert!(serde_json::from_str::<IssuanceKind>(&format!("\"{value}\"")).is_ok());
    }
    for value in values("CredentialStateIssOrRevEt") {
        assert!(serde_json::from_str::<UnbackedCredentialStatus>(&format!("\"{value}\"")).is_ok());
    }
    for value in values("CredentialStateBisOrBrvEt") {
        assert!(serde_json::from_str::<BackedCredentialStatus>(&format!("\"{value}\"")).is_ok());
    }
    for value in values("RegistryStateEt") {
        assert!(serde_json::from_str::<RegistryEventKind>(&format!("\"{value}\"")).is_ok());
    }
    Ok(())
}

#[test]
fn the_hand_written_key_state_aliases_are_accounted_for() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;

    // The two guards this port replaces with a `match` on `Hab`.
    assert_eq!(fixture.key_state_functions, ["isAccepted", "requireKeyState"]);

    // The aliases whose Rust names deliberately differ from the schema's.
    assert_eq!(
        fixture.key_state_exports.get("KeyState").map(String::as_str),
        Some("components['schemas']['KeyStateRecord']")
    );
    assert_eq!(
        fixture.key_state_exports.get("EstablishmentState").map(String::as_str),
        Some("components['schemas']['StateEERecord']")
    );

    // The split this item's `Hab` enum models.
    for name in [
        "HabState",
        "PendingHabState",
        "GroupKeyState",
        "SaltyKeyState",
        "RandyKeyState",
        "ExternState",
    ] {
        assert!(
            fixture.key_state_exports.contains_key(name),
            "keyState.ts no longer exports {name}"
        );
    }
    let group = fixture
        .key_state_exports
        .get("GroupKeyState")
        .ok_or("keyState.ts no longer exports GroupKeyState")?;
    // Upstream narrows the group's local member to the accepted form by hand; so does Rust.
    assert!(group.contains("mhab: HabState"), "{group}");
    Ok(())
}

#[test]
fn every_document_decodes_exactly_as_recorded() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.documents.len(), 82);

    let mut accepted = 0_usize;
    for document in &fixture.documents {
        let outcome = decode_named(&document.rust_type, &document.json)?;
        let expected = document.rust_expected == "accept";
        assert!(
            expected || document.rust_expected == "reject",
            "{} records an unknown expectation {}",
            document.name,
            document.rust_expected,
        );
        assert_eq!(
            outcome.is_ok(),
            expected,
            "{} decoded as {} unexpectedly: {outcome:?}",
            document.name,
            document.rust_type,
        );
        if outcome.is_ok() {
            accepted += 1;
        }

        // A refused document must say why in a typed error, never in an empty message.
        if let Err(message) = &outcome {
            assert!(!message.is_empty(), "{} was refused without a reason", document.name);
        }
    }
    assert!(accepted > 50, "only {accepted} documents were accepted");
    Ok(())
}

#[test]
fn every_accepted_document_is_written_back_in_the_declared_field_order() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let mut checked = 0_usize;

    for document in &fixture.documents {
        if document.rust_expected != "accept" {
            continue;
        }
        let Ok(keys) = decode_named(&document.rust_type, &document.json)? else {
            return Err(format!("{} was expected to decode", document.name).into());
        };

        // `PendingHabState` is a hand-written alias over the `HabState` schema, so its fields are
        // the schema's minus the key state Rust does not write for it.
        let schema_name = if document.schema == "PendingHabState" {
            "HabState"
        } else {
            document.schema.as_str()
        };
        let Some(shape) = fixture.schemas.get(schema_name) else {
            continue;
        };
        let alternatives = alternatives(shape, &fixture.schemas, 8);
        if alternatives.is_empty() {
            continue;
        }
        assert!(
            keys_follow_declared_order(&keys, &alternatives),
            "{} wrote {keys:?}, which no spelling of {schema_name} declares in that order",
            document.name,
        );
        checked += 1;
    }
    assert!(checked > 40, "only {checked} documents had an order to check");
    Ok(())
}

#[test]
fn the_recorded_divergences_are_exactly_the_ones_that_were_reviewed() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let found: Vec<(String, bool, bool)> = fixture
        .divergences
        .iter()
        .map(|divergence| {
            (
                divergence.name.clone(),
                divergence.reference_accepts,
                divergence.rust_accepts,
            )
        })
        .collect();
    let expected: Vec<(String, bool, bool)> = EXPECTED_DIVERGENCES
        .iter()
        .map(|(name, reference, rust)| ((*name).to_owned(), *reference, *rust))
        .collect();
    assert_eq!(found, expected);

    // Each one must carry the reference's own diagnostic or an explanatory note, so the record is
    // evidence rather than an assertion.
    for divergence in &fixture.divergences {
        let document = fixture
            .documents
            .iter()
            .find(|document| document.name == divergence.name)
            .ok_or_else(|| format!("{} is not a recorded document", divergence.name))?;
        assert!(
            !document.literal_diagnostics.is_empty() || document.note.is_some(),
            "{} diverges with neither a diagnostic nor a note",
            document.name,
        );
    }
    Ok(())
}

#[test]
fn the_reference_refuses_its_own_test_mocks() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // Three KERIA-shaped documents in the pinned repository do not satisfy the schema they are
    // written against. This port follows the schema, so it refuses them too — the agreement is
    // what makes following the schema rather than the mocks defensible.
    for name in [
        "hab_upstream_mock_without_inception_stamp",
        "operation_done_without_result",
    ] {
        let document = fixture
            .documents
            .iter()
            .find(|document| document.name == name)
            .ok_or_else(|| format!("{name} is not a recorded document"))?;
        assert!(!document.literal_accepted, "{name} is accepted by the reference");
        assert_eq!(document.rust_expected, "reject");
        assert!(document.provenance.is_some() || document.note.is_some());
        assert!(decode_named(&document.rust_type, &document.json)?.is_err());
    }
    Ok(())
}

#[test]
fn a_typescript_enum_makes_its_schema_unsatisfiable_by_any_document() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // A string is not assignable to a TypeScript enum, so no decoded response can satisfy a schema
    // whose field is typed as one — including the schemas upstream casts responses to. Rust accepts
    // these documents; the divergence is against a compile-time artifact its own run time ignores.
    for name in [
        "issuance_event",
        "credential_status_unbacked",
        "hab_salty",
        "oobi",
        "registry",
    ] {
        let document = fixture
            .documents
            .iter()
            .find(|document| document.name == name)
            .ok_or_else(|| format!("{name} is not a recorded document"))?;
        assert!(!document.literal_accepted);
        assert!(!document.structural_accepted);
        assert!(
            document
                .literal_diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("is not assignable to type")),
            "{name} was refused for some other reason: {:?}",
            document.literal_diagnostics,
        );
        assert_eq!(document.rust_expected, "accept");
        assert!(decode_named(&document.rust_type, &document.json)?.is_ok());
    }
    Ok(())
}

#[test]
fn an_unknown_field_is_kept_only_where_the_schema_declares_an_index_signature() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let document = |name: &str| -> Result<&Document, Box<dyn Error>> {
        fixture
            .documents
            .iter()
            .find(|document| document.name == name)
            .ok_or_else(|| format!("{name} is not a recorded document").into())
    };

    // A closed record: the excess-property check refuses the field, the structural check keeps it,
    // and Rust accepts and drops it.
    let closed = document("key_state_unknown_field")?;
    assert!(!closed.literal_accepted);
    assert!(closed.structural_accepted);
    let state: KeyState = from_json_slice(&serde_json::to_vec(&closed.json)?)?;
    assert!(!to_json_string(&state)?.contains("zz"));

    // An open record: both checks accept, and Rust keeps the field.
    let open = document("acdc_attributes_open_block")?;
    assert!(open.literal_accepted);
    assert!(open.structural_accepted);
    let attributes: AcdcAttributes = from_json_slice(&serde_json::to_vec(&open.json)?)?;
    assert!(to_json_string(&attributes)?.contains("LEI"));

    let contact = document("contact_open_block")?;
    let decoded: Contact = from_json_slice(&serde_json::to_vec(&contact.json)?)?;
    assert!(to_json_string(&decoded)?.contains("company"));
    Ok(())
}

#[test]
fn the_operation_union_is_usable_only_for_a_literal() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // `done: false` widens to `boolean` through a variable, so no operation arm accepts a value
    // that was not written out in place. That is why this port takes the family from the caller
    // rather than modelling the fourteen-way union as one decodable type.
    let document = fixture
        .documents
        .iter()
        .find(|document| document.name == "operation_pending")
        .ok_or("operation_pending is not a recorded document")?;
    assert!(document.literal_accepted);
    assert!(!document.structural_accepted);
    assert!(
        document
            .structural_diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("done")),
        "{:?}",
        document.structural_diagnostics,
    );

    // The Rust equivalent decodes, and narrowing an untyped operation to the wrong family fails.
    let body = serde_json::to_vec(&document.json)?;
    let typed: WitnessOperation = from_json_slice(&body)?;
    assert!(!typed.outcome.is_done());
    let untyped: UntypedOperation = from_json_slice(&body)?;
    assert!(untyped.clone().into_typed::<WitnessMetadataAlias, KeyEvent>().is_ok());
    assert!(
        untyped
            .into_typed::<signify_types::api::OobiMetadata, KeyState>()
            .is_err()
    );
    Ok(())
}

/// Named so the dispatch table above and this test read the same way.
type WitnessMetadataAlias = signify_types::api::WitnessMetadata;

/// Returns whether a declared type admits `null`.
fn admits_null(shape: &Shape) -> bool {
    match shape {
        Shape::Other { text } => text == "null",
        Shape::Union { members } => members.iter().any(admits_null),
        _ => false,
    }
}

/// Collects every distinct shape kind in the catalogue, so an unmodelled one cannot appear quietly.
fn walk(shape: &Shape, named: &mut BTreeSet<String>, other: &mut BTreeSet<String>, arrays: &mut usize) {
    match shape {
        Shape::Object { fields, .. } => {
            for field in fields {
                walk(&field.declared, named, other, arrays);
            }
        }
        Shape::Union { members } | Shape::Intersection { members } => {
            for member in members {
                walk(member, named, other, arrays);
            }
        }
        Shape::Array { element } => {
            *arrays += 1;
            walk(element, named, other, arrays);
        }
        Shape::Named { name } => {
            named.insert(name.clone());
        }
        Shape::Other { text } => {
            other.insert(text.clone());
        }
        Shape::Ref { .. } => {}
    }
}

/// Fields the schema requires that this port makes optional, with the reason.
///
/// Both belong to the KERI 1 spelling of an exchange message and have no counterpart in the KERI 2
/// spelling, which one Rust record covers. `PORTING.md` §9 records the collapse.
const VERSION_COLLAPSED_FIELDS: [(&str, &str); 2] = [("EXN_V_1", "rp"), ("EXN_V_1", "e")];

#[test]
fn the_schema_catalogue_uses_only_the_shapes_this_port_models() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let mut named = BTreeSet::new();
    let mut other = BTreeSet::new();
    let mut arrays = 0_usize;
    for shape in fixture.schemas.values() {
        walk(shape, &mut named, &mut other, &mut arrays);
    }

    // The only type references the schemas make are the six closed code tables and the
    // empty-object alias; every one has a Rust counterpart asserted above.
    assert_eq!(
        named.iter().map(String::as_str).collect::<Vec<_>>(),
        [
            "CredentialStateBisOrBrvEt",
            "CredentialStateIssOrRevEt",
            "IssEventT",
            "OOBIRole",
            "Record<string, never>",
            "RegistryStateEt",
            "Tier",
        ]
    );
    // Every one of them is an enum the fixture also records, except the structural alias.
    for name in &named {
        assert!(
            fixture.enums.contains_key(name) || name == "Record<string, never>",
            "{name} is referenced but is not a recorded enum"
        );
    }
    // The only non-object, non-reference types are JSON primitives and the two literal `done` flags.
    assert_eq!(
        other.iter().map(String::as_str).collect::<Vec<_>>(),
        ["boolean", "false", "null", "number", "string", "true", "unknown"]
    );
    assert!(arrays > 50, "only {arrays} array types were found");
    Ok(())
}

#[test]
fn a_field_is_optional_in_rust_exactly_when_the_schema_says_so() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let mut checked = 0_usize;

    for document in &fixture.documents {
        if document.rust_expected != "accept" {
            continue;
        }
        let Some(Shape::Object { fields, .. }) = fixture.schemas.get(&document.schema) else {
            continue;
        };
        let Value::Object(object) = &document.json else {
            continue;
        };

        for field in fields {
            if !object.contains_key(&field.name) {
                continue;
            }
            let mut reduced = object.clone();
            reduced.remove(&field.name);
            let outcome = decode_named(&document.rust_type, &Value::Object(reduced))?;

            // A nullable field is treated as optional: an absent value and an explicit null say the
            // same thing, and refusing the first would break a client against an agent that omits
            // it. A field the schema declares in only one protocol version is optional too.
            let collapsed = VERSION_COLLAPSED_FIELDS
                .iter()
                .any(|(schema, name)| *schema == document.schema && *name == field.name);
            let expected_optional = field.optional || admits_null(&field.declared) || collapsed;

            assert_eq!(
                outcome.is_ok(),
                expected_optional,
                "{}: removing {} from {} gave {outcome:?}, but the schema calls it {}",
                document.name,
                field.name,
                document.rust_type,
                if field.optional { "optional" } else { "required" },
            );
            checked += 1;
        }
    }
    assert!(checked > 100, "only {checked} fields were checked");
    Ok(())
}
