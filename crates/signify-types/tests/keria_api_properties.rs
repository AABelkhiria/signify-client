//! Invariants of the KERIA API records.
//!
//! These records decode documents an agent sends, so the properties that matter are about what
//! survives a round trip, what a document can and cannot make the decoder believe, and that hostile
//! input is always a typed error.

use proptest::prelude::*;
use serde_json::{Map, Value, json};
use signify_types::api::{
    ApiError, Contact, Hab, KeyEvent, KeyManagerState, KeyState, MAX_DOCUMENT_BYTES, OperationOutcome, Role, Threshold,
    UntypedOperation, WitnessOperation, from_json_slice, to_json_string,
};

/// The pinned agent key state, which every key-state property starts from.
fn key_state() -> Value {
    json!({
        "vn": [1, 0],
        "i": "EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei",
        "s": "0",
        "p": "",
        "d": "EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei",
        "f": "0",
        "dt": "2023-08-19T21:04:57.948863+00:00",
        "et": "dip",
        "kt": "1",
        "k": ["DMZh_y-H5C3cSbZZST-fqnsmdNTReZxIh0t2xSTOJQ8a"],
        "nt": "1",
        "n": ["EM9M2EQNCBK0MyAhVYBvR98Q0tefpvHgE-lHLs82XgqC"],
        "bt": "0",
        "b": [],
        "c": [],
        "ee": { "s": "0", "d": "EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei", "br": [], "ba": [] },
        "di": "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose",
    })
}

/// An identifier record carrying one named key-manager state.
fn hab(manager: &str) -> Value {
    let state = match manager {
        "salty" => json!({
            "tier": "low", "sxlt": "1AAH", "pidx": 0, "kidx": 0, "stem": "signify:aid",
            "dcode": "E", "icodes": ["A"], "ncodes": ["A"], "transferable": true,
        }),
        "randy" => json!({ "prxs": [], "nxts": [] }),
        "extern" => json!({ "extern_type": "module", "pidx": 0 }),
        _ => json!({
            "mhab": {
                "name": "member", "prefix": "EMEM", "icp_dt": "2023-12-01T10:05:25.062609+00:00",
                "state": key_state(), "randy": { "prxs": [], "nxts": [] },
            },
            "keys": [],
            "ndigs": [],
        }),
    };
    json!({
        "name": "identifier",
        "prefix": "EPRE",
        "icp_dt": "2023-12-01T10:05:25.062609+00:00",
        manager: state,
    })
}

/// Decodes a JSON value through the crate's bounded entry point.
fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, ApiError> {
    let body = serde_json::to_vec(value).map_err(|source| ApiError::Json {
        source: Box::new(source),
    })?;
    from_json_slice(&body)
}

/// The pinned agent key state as a field map, so a test can rewrite one field.
fn key_state_fields() -> Map<String, Value> {
    match key_state() {
        Value::Object(object) => object,
        _ => Map::new(),
    }
}

/// Field names a KERIA document never uses, for generating unknown ones.
fn unknown_name() -> impl Strategy<Value = String> {
    "zz[a-z]{1,8}".prop_map(|name| name)
}

proptest! {
    /// A record decoded from a document re-encodes to something that decodes to the same record.
    ///
    /// This is the property a caller relies on when it stores a response and reads it back. It is
    /// stated as decode-encode-decode rather than as byte equality, because a block the schema
    /// leaves open re-encodes in sorted key order.
    #[test]
    fn a_decoded_key_state_survives_re_encoding(
        witnesses in prop::collection::vec("E[A-Za-z0-9_-]{5,20}", 0..6),
        threshold in prop_oneof![
            Just(json!("1")),
            Just(json!("2")),
            Just(json!(["1/2", "1/2", "1/2"])),
        ],
        delegator in prop_oneof![Just(String::new()), Just("EDEL".to_owned())],
    ) {
        let mut object = key_state_fields();
        object.insert("b".to_owned(), json!(witnesses));
        object.insert("kt".to_owned(), threshold);
        object.insert("di".to_owned(), json!(delegator));
        let document = Value::Object(object);

        let first: KeyState = decode(&document)?;
        let encoded = to_json_string(&first)?;
        let second: KeyState = from_json_slice(encoded.as_bytes())?;
        prop_assert_eq!(&first, &second);
        prop_assert_eq!(to_json_string(&second)?, encoded);

        // The delegator accessor never reports the empty string as a prefix.
        prop_assert_eq!(first.delegator().is_some(), !delegator.is_empty());
        prop_assert_eq!(first.witnesses.len(), witnesses.len());
        let threshold_shape = matches!(first.signing_threshold, Threshold::Simple(_) | Threshold::Clause(_));
        prop_assert!(threshold_shape, "a simple or clause threshold decoded as something else");
    }

    /// A field the schema does not declare never changes what a closed record decodes to.
    #[test]
    fn an_unknown_field_never_changes_a_closed_record(
        name in unknown_name(),
        value in prop_oneof![
            Just(json!(1)),
            Just(json!("text")),
            Just(json!(null)),
            Just(json!([1, 2])),
            Just(json!({"nested": true})),
        ],
    ) {
        let base: KeyState = decode(&key_state())?;
        let mut object = key_state_fields();
        object.insert(name.clone(), value);
        let extended: KeyState = decode(&Value::Object(object))?;
        prop_assert_eq!(&base, &extended);
        // It is dropped rather than echoed back, because the schema declares no index signature.
        prop_assert!(!to_json_string(&extended)?.contains(&name));
    }

    /// A field the schema does not declare is kept where the schema declares an index signature.
    #[test]
    fn an_unknown_field_survives_an_open_record(
        name in unknown_name(),
        value in prop_oneof![Just(json!(1)), Just(json!("text")), Just(json!([1]))],
    ) {
        let mut object = Map::new();
        object.insert("id".to_owned(), json!("ECON"));
        object.insert(name.clone(), value.clone());
        let document = Value::Object(object);
        let contact: Contact = decode(&document)?;
        prop_assert_eq!(contact.additional.get(&name), Some(&value));

        let reencoded: Contact = from_json_slice(to_json_string(&contact)?.as_bytes())?;
        prop_assert_eq!(&contact, &reencoded);
    }

    /// An identifier record names exactly one key manager, or it does not decode.
    #[test]
    fn an_identifier_names_exactly_one_key_manager(
        chosen in prop::collection::hash_set(
            prop::sample::select(vec!["salty", "randy", "group", "extern"]),
            0..5,
        ),
    ) {
        let mut object = Map::new();
        object.insert("name".to_owned(), json!("identifier"));
        object.insert("prefix".to_owned(), json!("EPRE"));
        object.insert("icp_dt".to_owned(), json!("2023-12-01T10:05:25.062609+00:00"));
        for manager in &chosen {
            if let Value::Object(source) = hab(manager)
                && let Some(state) = source.get(*manager)
            {
                object.insert((*manager).to_owned(), state.clone());
            }
        }
        let document = Value::Object(object);

        let decoded = decode::<Hab>(&document);
        prop_assert_eq!(decoded.is_ok(), chosen.len() == 1);
        if let Ok(hab) = decoded {
            let label = hab.common().key_manager.label();
            prop_assert!(chosen.contains(label), "the decoded key manager was not the one supplied");
            // A record with no key state is pending, and one with key state is accepted.
            let pending = matches!(hab, Hab::Pending(_));
            prop_assert!(pending, "a record with no key state decoded as accepted");
            prop_assert_eq!(hab.key_state(), None);
        }
    }

    /// Key state decides whether an identifier is accepted or pending, and nothing else does.
    #[test]
    fn key_state_alone_decides_acceptance(
        manager in prop::sample::select(vec!["salty", "randy", "group", "extern"]),
        accepted in any::<bool>(),
    ) {
        let mut document = hab(manager);
        if accepted && let Value::Object(object) = &mut document {
            object.insert("state".to_owned(), key_state());
        }
        let hab: Hab = decode(&document)?;
        prop_assert_eq!(hab.key_state().is_some(), accepted);
        prop_assert_eq!(matches!(hab, Hab::Accepted(_)), accepted);
        prop_assert_eq!(hab.common().key_manager.label(), manager);
        let variant_matches_label = match &hab.common().key_manager {
            KeyManagerState::Salty(_) => manager == "salty",
            KeyManagerState::Randy(_) => manager == "randy",
            KeyManagerState::Group(_) => manager == "group",
            KeyManagerState::Extern(_) => manager == "extern",
        };
        prop_assert!(variant_matches_label, "the decoded variant does not match its wire label");

        let reencoded: Hab = from_json_slice(to_json_string(&hab)?.as_bytes())?;
        prop_assert_eq!(&hab, &reencoded);
    }

    /// An operation decodes exactly when `done`, `response`, and `error` describe one outcome.
    #[test]
    fn an_operation_decodes_only_a_decided_outcome(
        done in any::<bool>(),
        response in any::<bool>(),
        error in any::<bool>(),
    ) {
        let mut document = Map::new();
        document.insert("name".to_owned(), json!("witness.EABC"));
        document.insert("metadata".to_owned(), json!({ "pre": "EABC", "sn": 0 }));
        document.insert("done".to_owned(), json!(done));
        if response {
            document.insert(
                "response".to_owned(),
                json!({
                    "v": "KERI10JSON0000cb_", "t": "ixn", "d": "EAB",
                    "i": "EABC", "s": "1", "p": "EEF", "a": [],
                }),
            );
        }
        if error {
            document.insert("error".to_owned(), json!({ "code": 408, "message": "timed out" }));
        }
        let document = Value::Object(document);

        let legal = matches!(
            (done, response, error),
            (false, false, false) | (true, true, false) | (true, false, true)
        );
        let decoded = decode::<WitnessOperation>(&document);
        prop_assert_eq!(decoded.is_ok(), legal, "{}", document);

        if let Ok(operation) = decoded {
            prop_assert_eq!(operation.outcome.is_done(), done);
            prop_assert_eq!(operation.outcome.response().is_some(), response);
            prop_assert_eq!(operation.outcome.error().is_some(), error);
            let outcome_matches = match &operation.outcome {
                OperationOutcome::Pending => !done,
                OperationOutcome::Completed(_) => done && response,
                OperationOutcome::Failed(_) => done && error,
            };
            prop_assert!(outcome_matches, "the outcome does not match the flags it was built from");

            // The same document read without a family narrows back to it.
            let untyped: UntypedOperation = decode(&document)?;
            let narrowed = untyped
                .into_typed::<signify_types::api::WitnessMetadata, KeyEvent>()
                .is_ok();
            prop_assert!(narrowed, "an untyped operation would not narrow to its own family");
        }
    }

    /// Only the five ilks the union declares select a key event, and the record matches the ilk.
    #[test]
    fn only_a_declared_ilk_selects_a_key_event(ilk in "[a-z]{2,4}") {
        let document = json!({
            "v": "KERI10JSON0000cb_", "t": ilk.clone(), "d": "EAB",
            "i": "ECD", "s": "1", "p": "EEF", "a": [],
        });
        let decoded = decode::<KeyEvent>(&document);
        // Only `ixn` has this shape; the other four declared ilks carry key lists this body lacks.
        prop_assert_eq!(decoded.is_ok(), ilk == "ixn");
        if let Ok(event) = decoded {
            prop_assert_eq!(event.kind(), ilk.as_str());
            prop_assert_eq!(event.identifier(), "ECD");
            prop_assert!(!event.is_establishment(), "an interaction reported itself as establishment");
            // A key event always writes back the ilk it was chosen by.
            let spelling = format!("\"t\":\"{ilk}\"");
            prop_assert!(to_json_string(&event)?.contains(&spelling), "the ilk was not written back");
        }
    }

    /// A role always survives a round trip, whether or not the schema names it.
    #[test]
    fn a_role_is_preserved_exactly(text in ".{0,40}") {
        let role = Role::from(text.as_str());
        prop_assert_eq!(role.as_str(), text.as_str());
        prop_assert_eq!(role.to_string(), text.clone());

        let encoded = to_json_string(&role)?;
        let decoded: Role = from_json_slice(encoded.as_bytes())?;
        prop_assert_eq!(&decoded, &role);
        prop_assert_eq!(
            role.is_declared(),
            Role::DECLARED.iter().any(|declared| declared.as_str() == text),
        );
    }

    /// A threshold keeps the shape it arrived in.
    #[test]
    fn a_threshold_round_trips(
        threshold in prop_oneof![
            "[0-9]{1,3}".prop_map(|value| json!(value)),
            prop::collection::vec("[0-9]/[0-9]", 0..5).prop_map(|clause| json!(clause)),
            prop::collection::vec(prop::collection::vec("[0-9]/[0-9]", 0..3), 0..3)
                .prop_map(|clauses| json!(clauses)),
        ],
    ) {
        let decoded: Threshold = decode(&threshold)?;
        let encoded = to_json_string(&decoded)?;
        prop_assert_eq!(serde_json::from_str::<Value>(&encoded)?, threshold);
    }

    /// The order a record writes its fields in never depends on the order they arrived in.
    #[test]
    fn field_order_out_is_independent_of_field_order_in(seed in any::<u64>()) {
        // `serde_json::Map` is sorted, so shuffle by re-encoding the pairs in a rotated order.
        let pairs: Vec<(String, Value)> = key_state_fields().into_iter().collect();
        let rotation = usize::try_from(seed).unwrap_or(0) % pairs.len().max(1);
        let mut shuffled = String::from("{");
        for (offset, index) in (0..pairs.len()).enumerate() {
            let Some((name, value)) = pairs.get((index + rotation) % pairs.len()) else { continue };
            if offset > 0 {
                shuffled.push(',');
            }
            shuffled.push_str(&serde_json::to_string(name)?);
            shuffled.push(':');
            shuffled.push_str(&serde_json::to_string(value)?);
        }
        shuffled.push('}');

        let decoded: KeyState = from_json_slice(shuffled.as_bytes())?;
        let canonical: KeyState = decode(&key_state())?;
        prop_assert_eq!(&decoded, &canonical);
        prop_assert_eq!(to_json_string(&decoded)?, to_json_string(&canonical)?);
    }

    /// Arbitrary input is always a typed error, never a panic and never a silent acceptance.
    #[test]
    fn hostile_input_is_always_a_typed_error(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        // Every record reachable from a response body is driven with the same bytes.
        let outcomes: [Result<(), ApiError>; 6] = [
            from_json_slice::<KeyState>(&bytes).map(drop),
            from_json_slice::<Hab>(&bytes).map(drop),
            from_json_slice::<KeyEvent>(&bytes).map(drop),
            from_json_slice::<UntypedOperation>(&bytes).map(drop),
            from_json_slice::<Contact>(&bytes).map(drop),
            from_json_slice::<Threshold>(&bytes).map(drop),
        ];
        for outcome in outcomes {
            if let Err(error) = outcome {
                prop_assert!(!error.to_string().is_empty(), "a rejection carried no reason");
                let typed = matches!(
                    error,
                    ApiError::Json { .. }
                        | ApiError::DocumentTooLarge { .. }
                        | ApiError::MissingKeyManagerState
                        | ApiError::AmbiguousKeyManagerState { .. }
                        | ApiError::MissingKeyState
                        | ApiError::UnexpectedKeyState
                        | ApiError::UnexpectedEventKind { .. }
                );
                prop_assert!(typed, "a rejection was not one of the expected variants");
            }
        }
    }

    /// Nothing above the byte bound is parsed, whatever it contains.
    #[test]
    fn an_oversized_document_is_refused_before_parsing(
        excess in 1_usize..64,
        filler in prop::sample::select(vec![b' ', b'{', b'0', b'"']),
    ) {
        let bytes = vec![filler; MAX_DOCUMENT_BYTES + excess];
        let outcome = from_json_slice::<KeyState>(&bytes).map(drop);
        let refused = matches!(
            outcome,
            Err(ApiError::DocumentTooLarge { length, limit })
                if length == MAX_DOCUMENT_BYTES + excess && limit == MAX_DOCUMENT_BYTES
        );
        prop_assert!(refused, "an oversized document was parsed");
    }
}
