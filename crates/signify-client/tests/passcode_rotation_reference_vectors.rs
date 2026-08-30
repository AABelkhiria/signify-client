//! Exact vectors for the passcode-rotation workflow, against both references.
//!
//! Roadmap 8.9 ports `SignifyClient.rotate` — the client half of moving to a new passcode. The
//! artifact half is Roadmap 4.5's `Controller.rotate`, recorded in `fixtures/keri-controller/`.
//!
//! **The finding is one variable.** `Controller.rotate` computes `nbran` and `nsalter` from the new
//! passcode and then writes `const nsigner = this.salter.signer(undefined, false)` — the *old*
//! salter — and feeds it to both the decrypter, which is right, and the encrypter, which is not.
//! Driven, the controller salt and both identifiers' key material come back sealed to the passcode
//! being left behind: they open under the old one and under the new one not at all. A client that
//! rotated and reconnected could not read its own identifiers, and whoever holds the old passcode
//! still can.
//!
//! keripy does the opposite. `Manager.updateAeid` builds its encrypter from the **new** key, checks
//! the new seed belongs to it, then opens each secret with the old decrypter and seals it with the
//! new one. This port follows keripy; ADR `0033` records the divergence, which was a maintainer
//! decision of 2026-08-27 closing `PORTING.md` §10's open row.
//!
//! Nothing upstream exercises any of it: the one pinned call passes an **empty** identifier list.

mod support;

use std::error::Error;

use serde::Deserialize;
use serde_json::Value;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const KERIPY_SHA: &str = "4ce4cc79e06653f77342be1bf604086b89b1f090";
const FIXTURE: &str = include_str!("../../../fixtures/client-passcode-rotation/v1.json");

// ---------------------------------------------------------------------------
// Fixture model.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    upstream: String,
    reference_sha: String,
    secondary_reference: SecondaryReference,
    generated_on: String,
    sources: Vec<String>,
    provenance: Provenance,
    declarations: Declarations,
    request: RecordedRequest,
    identifiers: Identifiers,
    sealing: Sealing,
    reference_quirks: Value,
}

#[derive(Debug, Deserialize)]
struct SecondaryReference {
    upstream: String,
    commit: String,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    passcode: String,
    second_passcode: String,
    fixed_clock_ms: u64,
    controller_prefix: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    client_rotate: String,
    controller_rotate: String,
    nbran_declaration: String,
    nsalter_declaration: String,
    nsigner_declaration: String,
    sealed_salt_declaration: String,
    cipher_construction: Vec<CipherConstruction>,
    unit_test_calls: Vec<RotateCall>,
    keripy: Keripy,
    notes: Value,
}

#[derive(Debug, Deserialize)]
struct CipherConstruction {
    kind: String,
    argument: String,
}

#[derive(Debug, Deserialize)]
struct RotateCall {
    text: String,
    identifiers: String,
    identifier_count: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct Keripy {
    commit: String,
    file: String,
    symbol: String,
    encrypter_from_new_key: String,
    verifies_new_seed: bool,
    docstring_claim: String,
    cipher_lines: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RecordedRequest {
    path: String,
    method: String,
    signed: bool,
    body_fields: Vec<String>,
    key_entries: Vec<String>,
    salty_entry_fields: Vec<String>,
    randy_entry_fields: Vec<String>,
    rotation: Value,
    signature_count: usize,
}

#[derive(Debug, Deserialize)]
struct Identifiers {
    salty: SaltyIdentifier,
    randy: RandyIdentifier,
}

#[derive(Debug, Deserialize)]
struct SaltyIdentifier {
    prefix: String,
    salt: String,
    state_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RandyIdentifier {
    prefix: String,
    seeds: Vec<String>,
    next_seed: String,
    state_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Sealing {
    controller_salt: SealedValue,
    salty_identifier: SealedValue,
    randy_identifier: SealedValue,
}

#[derive(Debug, Deserialize)]
struct SealedValue {
    opens_under_old: Option<String>,
    opens_under_new: Option<String>,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    Ok(serde_json::from_str(FIXTURE)?)
}

fn quirk<'a>(fixture: &'a Fixture, name: &str) -> Result<&'a Value, Box<dyn Error>> {
    fixture
        .reference_quirks
        .get(name)
        .ok_or_else(|| format!("no recorded divergence named {name}").into())
}

// ---------------------------------------------------------------------------
// Provenance.
// ---------------------------------------------------------------------------

#[test]
fn the_manifest_matches_both_pinned_references() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert_eq!(fixture.upstream, "https://github.com/WebOfTrust/signify-ts.git");
    assert_eq!(fixture.secondary_reference.commit, KERIPY_SHA);
    assert_eq!(
        fixture.secondary_reference.upstream,
        "https://github.com/WebOfTrust/keripy.git"
    );
    assert_eq!(fixture.generated_on, "2026-08-27");
    assert!(fixture.sources.iter().any(|source| source.starts_with("keripy:")));

    assert_eq!(fixture.provenance.passcode.len(), 21);
    assert_eq!(fixture.provenance.second_passcode.len(), 21);
    assert_ne!(fixture.provenance.passcode, fixture.provenance.second_passcode);
    assert_eq!(fixture.provenance.fixed_clock_ms, 1_700_000_000_123);
    assert_eq!(fixture.provenance.controller_prefix.len(), 44);
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));
    assert!(
        fixture.provenance.note.contains("opens to"),
        "the fixture no longer says it records plaintexts rather than ciphertexts"
    );
    assert!(fixture.declarations.notes.get("finding").is_some());
    Ok(())
}

// ---------------------------------------------------------------------------
// The finding, from the syntax tree and from the wire.
// ---------------------------------------------------------------------------

#[test]
fn the_encrypter_is_built_from_the_salter_being_replaced() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    // Two of the three `n`-prefixed locals are the new passcode's; the third is not.
    assert!(declarations.nbran_declaration.contains("bran.substring(0, 21)"));
    assert!(declarations.nsalter_declaration.contains("nbran"));
    assert!(
        declarations.nsigner_declaration.contains("this.salter"),
        "`nsigner` no longer derives from the old salter; the finding is stale"
    );
    assert!(!declarations.nsigner_declaration.contains("nsalter"));

    // And that one signer feeds both ciphers: the decrypter, correctly, and the encrypter, not.
    assert_eq!(declarations.cipher_construction.len(), 2);
    for construction in &declarations.cipher_construction {
        assert!(
            construction.argument.contains("nsigner"),
            "{} is built from {}",
            construction.kind,
            construction.argument
        );
    }
    let kinds: Vec<&str> = declarations
        .cipher_construction
        .iter()
        .map(|construction| construction.kind.as_str())
        .collect();
    assert_eq!(kinds, ["Encrypter", "Decrypter"]);

    // The sealed controller salt is `this.bran`, which the rotation never updates.
    assert!(declarations.sealed_salt_declaration.contains("this.bran"));
    Ok(())
}

#[test]
fn the_recorded_payload_opens_under_the_passcode_being_left_behind() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let old_salt = format!("0AA{}", fixture.provenance.passcode);

    // All three sealed values open under the old passcode, and none under the new one.
    for (name, sealed) in [
        ("the controller salt", &fixture.sealing.controller_salt),
        ("the salty identifier", &fixture.sealing.salty_identifier),
        ("the randy identifier", &fixture.sealing.randy_identifier),
    ] {
        assert!(
            sealed.opens_under_old.is_some(),
            "{name} does not open under the old passcode"
        );
        assert!(
            sealed.opens_under_new.is_none(),
            "{name} now opens under the new passcode; the finding is stale"
        );
    }

    // The controller's sealed salt is the *old* salt, not the new one.
    assert_eq!(
        fixture.sealing.controller_salt.opens_under_old.as_deref(),
        Some(old_salt.as_str())
    );
    assert_ne!(
        fixture.sealing.controller_salt.opens_under_old.as_deref(),
        Some(format!("0AA{}", fixture.provenance.second_passcode).as_str())
    );

    // And each identifier's material is unchanged by the round trip — only its key is wrong.
    assert_eq!(
        fixture.sealing.salty_identifier.opens_under_old.as_deref(),
        Some(fixture.identifiers.salty.salt.as_str())
    );
    assert_eq!(
        fixture.sealing.randy_identifier.opens_under_old.as_deref(),
        fixture.identifiers.randy.seeds.first().map(String::as_str)
    );

    // Both identifiers name the keys their stored material must re-derive — the check the
    // reference performs inside its loop, and this port performs before anything is sealed.
    assert_eq!(fixture.identifiers.salty.state_keys.len(), 1);
    assert_eq!(
        fixture.identifiers.salty.state_keys.first().map(String::as_str),
        Some(fixture.identifiers.salty.prefix.as_str()),
        "the salty identifier's prefix is its own signing key"
    );
    assert_eq!(
        fixture.identifiers.randy.state_keys.len(),
        fixture.identifiers.randy.seeds.len()
    );
    Ok(())
}

#[test]
fn keripy_seals_under_the_new_key() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let keripy = &fixture.declarations.keripy;

    assert_eq!(keripy.commit, KERIPY_SHA);
    assert_eq!(keripy.file, "src/keri/app/keeping.py");
    assert_eq!(keripy.symbol, "Manager.updateAeid");

    // The line this port follows, and the check that comes with it.
    assert_eq!(
        keripy.encrypter_from_new_key,
        "self.encrypter = core.Encrypter(verkey=aeid)"
    );
    assert!(
        keripy.verifies_new_seed,
        "keripy no longer checks the new seed belongs to the new key"
    );
    assert!(keripy.docstring_claim.contains("reencrypts"));

    // Its cipher lines decrypt with the old and encrypt with the new, which is the whole contrast.
    assert!(!keripy.cipher_lines.is_empty());
    assert!(
        keripy
            .cipher_lines
            .iter()
            .any(|line| line.contains("self.decrypter.decrypt")),
        "{:?}",
        keripy.cipher_lines
    );
    assert!(
        keripy
            .cipher_lines
            .iter()
            .any(|line| line.contains("self.encrypter.encrypt")),
        "{:?}",
        keripy.cipher_lines
    );
    Ok(())
}

#[test]
fn nothing_upstream_exercises_the_re_encryption() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "nothing_upstream_exercises_the_re_encryption")?;

    // One call in the whole pinned tree, and it rotates no identifiers at all.
    assert_eq!(fixture.declarations.unit_test_calls.len(), 1);
    let call = fixture.declarations.unit_test_calls.first().ok_or("no recorded call")?;
    assert_eq!(call.identifier_count, Some(0));
    assert_eq!(call.identifiers, "[]");
    assert!(call.text.contains("client.rotate("));

    // So the payload it produces carries an empty `keys` map: every branch below is dead.
    let entries = recorded
        .get("empty_payload_keys")
        .and_then(Value::as_array)
        .ok_or("no recorded key entries")?;
    assert!(entries.is_empty(), "the empty rotation re-sealed something");
    Ok(())
}

#[test]
fn a_second_rotation_upstream_commits_to_the_original_passcode_again() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "a_second_rotation_derives_from_the_original_salt")?;

    // The controller's salt never moves, so both rotations commit to the same old key.
    assert_eq!(recorded.get("identical").and_then(Value::as_bool), Some(true));
    assert_eq!(recorded.get("bran_moved").and_then(Value::as_bool), Some(false));
    assert_eq!(
        recorded.get("first_old_key").and_then(Value::as_str),
        recorded.get("second_old_key").and_then(Value::as_str)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The request itself.
// ---------------------------------------------------------------------------

#[test]
fn the_rotation_is_one_unsigned_put_to_the_agent() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let request = &fixture.request;

    assert_eq!(request.method, "PUT");
    assert_eq!(request.path, format!("/agent/{}", fixture.provenance.controller_prefix));

    // Unsigned, as upstream: the reference calls the global `fetch` here rather than its own
    // signed pipeline, so the request carrying every re-sealed secret has no HTTP signature.
    assert!(!request.signed);
    let recorded = quirk(&fixture, "the_rotation_travels_unsigned")?;
    assert_eq!(recorded.get("signed").and_then(Value::as_bool), Some(false));

    // The body's four fields, in the reference's own order.
    assert_eq!(request.body_fields, ["rot", "sigs", "sxlt", "keys"]);
    assert_eq!(request.signature_count, 2);
    assert_eq!(request.key_entries.len(), 2);
    assert!(request.key_entries.contains(&fixture.identifiers.salty.prefix));
    assert!(request.key_entries.contains(&fixture.identifiers.randy.prefix));

    // A salty entry carries its sealed salt; a randy entry carries both key lists.
    assert_eq!(request.salty_entry_fields, ["sxlt"]);
    assert_eq!(request.randy_entry_fields, ["prxs", "nxts"]);
    Ok(())
}

#[test]
fn the_rotation_event_is_the_shape_the_reference_sends() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let rotation = &fixture.request.rotation;

    assert_eq!(rotation.get("t").and_then(Value::as_str), Some("rot"));
    // Always sequence one: the reference never passes a sequence number, which Roadmap 4.5 pinned.
    assert_eq!(rotation.get("s").and_then(Value::as_str), Some("1"));
    assert_eq!(
        rotation.get("i").and_then(Value::as_str),
        Some(fixture.provenance.controller_prefix.as_str())
    );

    // Two keys under a weighted threshold: the new key carries all the weight, the old none.
    let keys = rotation.get("k").and_then(Value::as_array).ok_or("no keys")?;
    assert_eq!(keys.len(), 2);
    let threshold = rotation.get("kt").and_then(Value::as_array).ok_or("no threshold")?;
    assert_eq!(threshold.len(), 2);
    assert_eq!(threshold.first().and_then(Value::as_str), Some("1"));
    assert_eq!(threshold.get(1).and_then(Value::as_str), Some("0"));
    Ok(())
}

#[test]
fn every_recorded_divergence_names_its_reason_and_its_rust_decision() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = fixture
        .reference_quirks
        .as_object()
        .ok_or("the divergences are not an object")?;
    assert_eq!(quirks.len(), 5);
    for (name, recorded) in quirks {
        let note = recorded.get("note").and_then(Value::as_str).unwrap_or_default();
        let decision = recorded
            .get("rust_decision")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(note.len() > 80, "{name} explains too little");
        assert!(decision.len() > 40, "{name} does not say what this port does");
    }

    // Both methods' text is recorded whole, so a reader can check the claims against the source.
    assert!(
        fixture
            .declarations
            .client_rotate
            .contains("controller.rotate(nbran, aids)")
    );
    assert!(fixture.declarations.controller_rotate.contains("nsigner"));
    assert!(fixture.declarations.controller_rotate.contains("Invalid Salty AID"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Driven: this client, through the same rotation.
// ---------------------------------------------------------------------------

mod driven {
    use super::{Fixture, fixture};

    use std::error::Error;

    use std::sync::Arc;

    use serde_json::Value;
    use signify_client::client::{ConnectedClient, SignifyClient};
    use signify_client::config::{ClientConfig, Passcode};
    use signify_client::error::ClientError;
    use signify_crypto::cipher::{Ciphertext, Decrypter, Encrypter};
    use signify_crypto::salt::{Salt, SecurityTier};
    use signify_crypto::signer::Signer;
    use signify_crypto::verifier::KeyTransferability;

    use crate::support::{ADMIN, AGENT, AgentTransport, BOOT, agent_state, block_on, clock};
    use signify_http::transport::Transport;
    use signify_keri::manager::{DerivationCost, KeyIndices, SaltyKeyCreator, Stem};
    use signify_types::api::AcceptedHab;

    fn connected(passcode: &str, bodies: &[&[u8]]) -> Result<(ConnectedClient, Arc<AgentTransport>), Box<dyn Error>> {
        let configuration = || {
            ClientConfig::new(ADMIN, passcode)
                .and_then(|config| config.with_boot_url(BOOT))
                .map(|config| config.with_derivation_cost(DerivationCost::Ephemeral))
        };
        let probe = SignifyClient::new(
            configuration()?,
            AgentTransport::new(&[]) as Arc<dyn Transport>,
            clock(),
        )?;
        let prefix = probe.controller().prefix().qb64()?;
        let inception = core::str::from_utf8(probe.controller().current_event().raw())?.to_owned();

        let state = agent_state(&prefix, &inception);
        let mut answers: Vec<&[u8]> = vec![state.as_bytes(), b"{}"];
        answers.extend_from_slice(bodies);
        let transport = AgentTransport::new(&answers);

        let client = SignifyClient::new(configuration()?, Arc::clone(&transport) as Arc<dyn Transport>, clock())?;
        Ok((block_on(client.connect())?, transport))
    }

    /// The encryption key one passcode derives — what every keeper here seals to.
    ///
    /// At the driven client's own derivation cost, so the key matches the one its controller
    /// derives; a production-cost derivation of the same passcode is a different key entirely.
    fn encryption(passcode: &str) -> Result<(Encrypter, Decrypter), Box<dyn Error>> {
        let salt = Salt::from_qb64(&format!("0AA{passcode}"), SecurityTier::Low)?;
        let signer = salt.derive_signer_with_profile(
            "",
            KeyTransferability::NonTransferable,
            DerivationCost::Ephemeral.profile(SecurityTier::Low),
        )?;
        Ok((
            Encrypter::from_verification_key(signer.verifier())?,
            Decrypter::from_signer(&signer),
        ))
    }

    /// Assembles one accepted identifier record around a key-manager section.
    fn hab_record(prefix: &str, key_manager: Value, keys: &[String]) -> Result<AcceptedHab, Box<dyn Error>> {
        let record = serde_json::json!({
            "name": "aid",
            "prefix": prefix,
            "icp_dt": "2023-12-01T10:05:25.062609+00:00",
            "state": {
                "i": AGENT, "s": "0", "p": "", "d": AGENT, "f": "0",
                "dt": "2023-12-01T10:05:25.062609+00:00", "et": "icp",
                "kt": "1", "k": keys, "nt": "1",
                "n": ["ENBWnU8wNHqq9oqJIimWhxUtNDHReUXtiCwwtjg9zKY0"],
                "bt": "0", "b": [], "c": [],
                "ee": {"s": "0", "d": AGENT, "br": [], "ba": []},
                "di": ""
            }
        });
        let Value::Object(mut record) = record else {
            return Err("the record is not an object".into());
        };
        if let Value::Object(section) = key_manager {
            record.extend(section);
        }
        Ok(serde_json::from_value(Value::Object(record))?)
    }

    /// The fixture's salty and randy identifiers, sealed to the old passcode's key.
    fn identifiers(fixture: &Fixture, encrypter: &Encrypter) -> Result<Vec<AcceptedHab>, Box<dyn Error>> {
        let salty = &fixture.identifiers.salty;
        let salt = Salt::from_qb64(&salty.salt, SecurityTier::Low)?;

        // The identifier's own signing keys, derived at this client's cost. The fixture's were
        // derived at the reference's production cost, and a cost is part of a key's identity — so
        // reusing them here would fail the check this rotation performs, correctly.
        let derived = SaltyKeyCreator::new(&salt, Stem::new("signify:aid")?).create(
            1,
            KeyTransferability::Transferable,
            KeyIndices::new(0, 0, 0),
            DerivationCost::Ephemeral.profile(SecurityTier::Low),
        )?;
        let state_keys = derived.public_keys()?;

        let salty_record = hab_record(
            &salty.prefix,
            serde_json::json!({ "salty": {
                "sxlt": encrypter.encrypt_salt(&salt)?.qb64()?,
                "pidx": 0, "kidx": 0, "stem": "signify:aid", "tier": "low",
                "icodes": ["A"], "ncodes": ["A"], "transferable": true, "dcode": "E"
            }}),
            &state_keys,
        )?;

        let randy = &fixture.identifiers.randy;
        let mut sealed = Vec::new();
        for seed in &randy.seeds {
            let signer = Signer::from_qb64(seed, KeyTransferability::Transferable)?;
            sealed.push(encrypter.encrypt_signer(&signer)?.qb64()?);
        }
        let next = Signer::from_qb64(&randy.next_seed, KeyTransferability::Transferable)?;
        let randy_record = hab_record(
            &randy.prefix,
            serde_json::json!({ "randy": { "prxs": sealed, "nxts": [encrypter.encrypt_signer(&next)?.qb64()?] }}),
            &randy.state_keys,
        )?;
        Ok(vec![salty_record, randy_record])
    }

    /// The body of the last request the transport recorded.
    fn last_body(transport: &AgentTransport) -> Result<Value, Box<dyn Error>> {
        let requests = transport.requests();
        let last = requests.last().ok_or("no request was made")?;
        let bytes = last.body().ok_or("the request carried no body")?;
        Ok(serde_json::from_slice(bytes)?)
    }

    #[test]
    fn the_rotation_reaches_the_agent_in_the_reference_shape() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let (encrypter, _) = encryption(&fixture.provenance.passcode)?;
        let (mut client, transport) = connected(&fixture.provenance.passcode, &[b"{}"])?;
        let records = identifiers(&fixture, &encrypter)?;

        let new_passcode = Passcode::new(fixture.provenance.second_passcode.clone())?;
        block_on(client.rotate_passcode(&new_passcode, &records))?;

        // One PUT, to the agent's own resource, unsigned as upstream.
        let requests = transport.requests();
        let last = requests.last().ok_or("no request was made")?;
        assert_eq!(last.method(), fixture.request.method);
        // The agent's own resource, addressed by this controller's prefix. The fixture's prefix is
        // the reference's, derived at production cost; this client runs at the ephemeral cost, so
        // the shape is what compares, not the identifier.
        let expected = format!("/agent/{}", client.controller().prefix().qb64()?);
        assert!(last.path().ends_with(&expected), "{}", last.path());
        assert!(fixture.request.path.starts_with("/agent/"));
        assert!(last.header("signature").is_none(), "the rotation was signed");

        // And the same four fields in the same order, with the same per-identifier shapes. The
        // order is read off the bytes that left the transport: decoding and re-encoding would sort
        // them and prove nothing.
        let written = core::str::from_utf8(last.body().ok_or("the request carried no body")?)?.to_owned();
        let body = last_body(&transport)?;
        let mut previous = 0;
        for field in &fixture.request.body_fields {
            let at = written.find(&format!(r#""{field}":"#)).ok_or("a field is missing")?;
            assert!(at >= previous, "the body's fields are out of the reference's order");
            previous = at;
        }
        let keys = body.get("keys").and_then(Value::as_object).ok_or("no keys map")?;
        assert_eq!(keys.len(), fixture.request.key_entries.len());
        let salty = keys.get(&fixture.identifiers.salty.prefix).ok_or("no salty entry")?;
        let randy = keys.get(&fixture.identifiers.randy.prefix).ok_or("no randy entry")?;
        assert!(salty.get("sxlt").is_some() && salty.get("prxs").is_none());
        assert!(randy.get("prxs").is_some() && randy.get("nxts").is_some());
        Ok(())
    }

    #[test]
    fn everything_the_rotation_seals_opens_under_the_new_passcode() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let (encrypter, old_decrypter) = encryption(&fixture.provenance.passcode)?;
        let (_, new_decrypter) = encryption(&fixture.provenance.second_passcode)?;
        let (mut client, transport) = connected(&fixture.provenance.passcode, &[b"{}"])?;
        let records = identifiers(&fixture, &encrypter)?;

        let new_passcode = Passcode::new(fixture.provenance.second_passcode.clone())?;
        block_on(client.rotate_passcode(&new_passcode, &records))?;
        let body = last_body(&transport)?;

        // The controller's sealed salt is the NEW salt under the NEW key — where the reference
        // seals the old salt under the old key, which this fixture records.
        let sealed = body.get("sxlt").and_then(Value::as_str).ok_or("no sealed salt")?;
        let opened = new_decrypter.decrypt_salt(&Ciphertext::from_qb64(sealed)?, SecurityTier::Low)?;
        assert_eq!(
            opened.expose_qb64()?.as_str(),
            format!("0AA{}", fixture.provenance.second_passcode)
        );
        assert_eq!(
            fixture.sealing.controller_salt.opens_under_old.as_deref(),
            Some(format!("0AA{}", fixture.provenance.passcode).as_str()),
            "the reference sealed something else"
        );

        // The identifiers' material is unchanged, and now sealed to the new passcode.
        let keys = body.get("keys").and_then(Value::as_object).ok_or("no keys map")?;
        let salty_sealed = keys
            .get(&fixture.identifiers.salty.prefix)
            .and_then(|entry| entry.get("sxlt"))
            .and_then(Value::as_str)
            .ok_or("no salty salt")?;
        let salty_opened = new_decrypter.decrypt_salt(&Ciphertext::from_qb64(salty_sealed)?, SecurityTier::Low)?;
        assert_eq!(salty_opened.expose_qb64()?.as_str(), fixture.identifiers.salty.salt);

        // And the passcode being left behind opens none of it, which the reference's does.
        for sealed in [sealed, salty_sealed] {
            assert!(
                old_decrypter
                    .decrypt_salt(&Ciphertext::from_qb64(sealed)?, SecurityTier::Low)
                    .is_err(),
                "the old passcode still opens the rotated payload"
            );
        }
        assert!(fixture.sealing.salty_identifier.opens_under_new.is_none());
        Ok(())
    }

    #[test]
    fn a_refused_rotation_leaves_the_client_untouched() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let (encrypter, _) = encryption(&fixture.provenance.passcode)?;
        let (mut client, transport) = connected(&fixture.provenance.passcode, &[b"{}", b"{}"])?;
        let records = identifiers(&fixture, &encrypter)?;
        let before = client.controller().current_keys().to_vec();
        let passcode_before = client.config().passcode().expose().to_owned();

        transport.refuse();
        let new_passcode = Passcode::new(fixture.provenance.second_passcode.clone())?;
        let refused = matches!(
            block_on(client.rotate_passcode(&new_passcode, &records)),
            Err(ClientError::Status { .. })
        );
        assert!(refused, "a refused rotation was reported as success");

        // Nothing moved: the controller still holds its old keys and the client its old passcode.
        // The reference advances its controller before it sends, so a failure there leaves a client
        // signing with a key the agent has never seen.
        assert_eq!(client.controller().current_keys(), before.as_slice());
        assert_eq!(client.config().passcode().expose(), passcode_before);
        Ok(())
    }

    #[test]
    fn an_identifier_whose_keys_do_not_match_is_refused_before_anything_is_sent() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let (encrypter, _) = encryption(&fixture.provenance.passcode)?;
        let (mut client, transport) = connected(&fixture.provenance.passcode, &[b"{}"])?;
        let mut records = identifiers(&fixture, &encrypter)?;
        let Some(first) = records.first_mut() else {
            return Err("no records were built".into());
        };
        first.state.signing_keys = vec!["DAQVURvW74OJH1Q0C6YLim_tdBYoXABwg6GsAlPaUJXE".to_owned()];

        let sent_before = transport.requests().len();
        let new_passcode = Passcode::new(fixture.provenance.second_passcode.clone())?;
        let refused = matches!(
            block_on(client.rotate_passcode(&new_passcode, &records)),
            Err(ClientError::Controller { .. })
        );
        assert!(refused, "an identifier with the wrong keys was rotated anyway");

        // Refused before the request: the check the reference performs inside its loop, after it
        // has already re-sealed everything before it.
        assert_eq!(
            transport.requests().len(),
            sent_before,
            "a refused rotation still sent something"
        );
        Ok(())
    }
}
