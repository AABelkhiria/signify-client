//! Exact vectors for the passcode-rotation workflow, against both references.
//!
//! The reference's rotation and its recorded divergences; keripy's verdict on this port's rotation is in
//! `passcode_rotation_keripy_vectors.rs`.

mod support;

use std::error::Error;

use serde::Deserialize;
use serde_json::Value;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const KERIPY_SHA: &str = "4ce4cc79e06653f77342be1bf604086b89b1f090";
const FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/client-passcode-rotation/v1.json"
));

// --- Fixture model ---
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
    unit_test_calls: Vec<RotateCall>,
    notes: Value,
}

#[derive(Debug, Deserialize)]
struct RotateCall {
    text: String,
    identifiers: String,
    identifier_count: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct RecordedRequest {
    path: String,
    method: String,
    body_fields: Vec<String>,
    key_entries: Vec<String>,
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

// --- Provenance ---
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
    assert_eq!(fixture.generated_on, "2026-09-16");
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

// --- The finding, from the syntax tree and from the wire ---

#[test]
fn nothing_upstream_exercises_the_re_encryption() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "nothing_upstream_exercises_the_re_encryption")?;

    assert_eq!(fixture.declarations.unit_test_calls.len(), 1);
    let call = fixture.declarations.unit_test_calls.first().ok_or("no recorded call")?;
    assert_eq!(call.identifier_count, Some(0));
    assert_eq!(call.identifiers, "[]");
    assert!(call.text.contains("client.rotate("));

    let entries = recorded
        .get("empty_payload_keys")
        .and_then(Value::as_array)
        .ok_or("no recorded key entries")?;
    assert!(entries.is_empty(), "the empty rotation re-sealed something");
    Ok(())
}

// --- The request itself ---

#[test]
fn every_recorded_divergence_names_its_reason_and_its_rust_decision() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = fixture
        .reference_quirks
        .as_object()
        .ok_or("the divergences are not an object")?;
    assert_eq!(quirks.len(), 6);
    for (name, recorded) in quirks {
        let note = recorded.get("note").and_then(Value::as_str).unwrap_or_default();
        let decision = recorded
            .get("rust_decision")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(note.len() > 80, "{name} explains too little");
        assert!(decision.len() > 40, "{name} does not say what this port does");
    }

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

// --- Driven: this client, through the same rotation ---
mod driven {
    use super::{Fixture, fixture};

    use std::error::Error;

    use std::sync::Arc;

    use keri_cesr::crypto::cipher::{Ciphertext, Decrypter, Encrypter};
    use keri_cesr::crypto::salt::{Salt, SecurityTier};
    use keri_cesr::crypto::signer::Signer;
    use keri_cesr::crypto::verifier::{KeyTransferability, VerificationKey};
    use serde_json::Value;
    use signify_client::client::{ConnectedClient, SignifyClient};
    use signify_client::config::{ClientConfig, Passcode};
    use signify_client::error::ClientError;
    use signify_http::signature::authentication::ResponseVerifier;
    use signify_http::signature::input::RequestTarget;

    use crate::support::{ADMIN, AGENT, AgentTransport, BOOT, agent_state, block_on, clock};
    use keri_protocol::prefix::IdentifierPrefix;
    use keria_types::api::AcceptedHab;
    use signify_http::transport::Transport;
    use signify_keys::manager::{DerivationCost, KeyIndices, SaltyKeyCreator, Stem};

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

    fn identifiers(fixture: &Fixture, encrypter: &Encrypter) -> Result<Vec<AcceptedHab>, Box<dyn Error>> {
        let salty = &fixture.identifiers.salty;
        let salt = Salt::from_qb64(&salty.salt, SecurityTier::Low)?;

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

        let requests = transport.requests();
        let last = requests.last().ok_or("no request was made")?;
        assert_eq!(last.method(), fixture.request.method);
        let expected = format!("/agent/{}", client.controller().prefix().qb64()?);
        assert!(last.path().ends_with(&expected), "{}", last.path());
        assert!(fixture.request.path.starts_with("/agent/"));

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

    /// The rotation event a request carried.
    fn sent_rotation(transport: &AgentTransport) -> Result<Value, Box<dyn Error>> {
        last_body(transport)?
            .get("rot")
            .cloned()
            .ok_or_else(|| "the request carried no rotation".into())
    }

    fn text<'a>(document: &'a Value, label: &str) -> &'a str {
        document.get(label).and_then(Value::as_str).unwrap_or_default()
    }

    fn first_key(rotation: &Value) -> Result<VerificationKey, Box<dyn Error>> {
        let key = rotation
            .get("k")
            .and_then(Value::as_array)
            .and_then(|keys| keys.first())
            .and_then(Value::as_str)
            .ok_or("the rotation names no key")?;
        Ok(VerificationKey::from_qb64(key)?)
    }

    /// Whether a recorded request's HTTP signature verifies under `key`.
    fn signed_by(request: &crate::support::Recorded, key: VerificationKey) -> Result<bool, Box<dyn Error>> {
        let target = RequestTarget::new(request.method(), request.path())?;
        Ok(ResponseVerifier::new(key)
            .verify(&target, request.request().headers())
            .is_ok())
    }

    #[test]
    fn the_rotation_follows_the_log_and_is_signed_with_the_key_it_introduces() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let (encrypter, _) = encryption(&fixture.provenance.passcode)?;
        let (mut client, transport) = connected(&fixture.provenance.passcode, &[b"{}"])?;
        let records = identifiers(&fixture, &encrypter)?;

        // Connecting approved the delegation, so the log is at the interaction, sequence one.
        assert_eq!(client.controller().current_sequence_number(), 1);
        let interaction = client.controller().current_said().qb64()?;
        let old_key = VerificationKey::from_qb64(
            client
                .controller()
                .current_keys()
                .first()
                .ok_or("the controller has no key")?,
        )?;

        let new_passcode = Passcode::new(fixture.provenance.second_passcode.clone())?;
        block_on(client.rotate_passcode(&new_passcode, &records))?;

        // The next event after the interaction, where the reference writes one again.
        let rotation = sent_rotation(&transport)?;
        assert_eq!(text(&rotation, "s"), "2");
        assert_eq!(text(&rotation, "p"), interaction);

        // An agent checks this request against the controller's keys after applying the rotation,
        // so it is signed with the rotation's first key — and not with the key being replaced.
        let requests = transport.requests();
        let sent = requests.last().ok_or("no request was made")?;
        assert!(sent.header("signature-input").is_some(), "the rotation was not signed");
        assert!(
            signed_by(sent, first_key(&rotation)?)?,
            "the rotation is not signed with its new key"
        );
        assert!(
            !signed_by(sent, old_key)?,
            "the rotation is signed with the key it replaces"
        );

        // And the controller moved onto it.
        assert_eq!(client.controller().current_sequence_number(), 2);
        assert_eq!(client.controller().current_said().qb64()?, text(&rotation, "d"));
        Ok(())
    }

    #[test]
    fn a_rotated_client_signs_what_it_sends_next_with_its_new_key() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let (mut client, transport) = connected(&fixture.provenance.passcode, &[b"{}", b"{}"])?;
        let new_passcode = Passcode::new(fixture.provenance.second_passcode.clone())?;
        block_on(client.rotate_passcode(&new_passcode, &[]))?;
        let rotation = sent_rotation(&transport)?;

        // Whatever the agent answers, the request was made and signed.
        let _ = block_on(client.identifiers().get("aid1"));
        let requests = transport.requests();
        let next = requests.last().ok_or("no request was made")?;
        assert!(next.path().starts_with("/identifiers/"), "{}", next.path());
        assert!(
            signed_by(next, first_key(&rotation)?)?,
            "the session still signs with the key it rotated away from"
        );
        Ok(())
    }

    #[test]
    fn a_second_rotation_chains_on_the_first() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let (mut client, transport) = connected(&fixture.provenance.passcode, &[b"{}", b"{}"])?;

        block_on(client.rotate_passcode(&Passcode::new(fixture.provenance.second_passcode.clone())?, &[]))?;
        let first = sent_rotation(&transport)?;
        block_on(client.rotate_passcode(&Passcode::new(fixture.provenance.passcode.clone())?, &[]))?;
        let second = sent_rotation(&transport)?;

        assert_eq!(text(&second, "s"), "3");
        assert_eq!(text(&second, "p"), text(&first, "d"));
        // The second reveals the key the first committed to, and is signed with its own new key.
        let revealed = second
            .get("k")
            .and_then(Value::as_array)
            .and_then(|keys| keys.get(1))
            .and_then(Value::as_str)
            .ok_or("the second rotation reveals nothing")?;
        let digest = keri_cesr::crypto::digest::Digest::derive(
            keri_cesr::crypto::digest::DigestAlgorithm::Blake3_256,
            revealed.as_bytes(),
        );
        assert_eq!(
            first
                .get("n")
                .and_then(Value::as_array)
                .and_then(|n| n.first())
                .and_then(Value::as_str),
            Some(digest.qb64()?.as_str())
        );
        let requests = transport.requests();
        let sent = requests.last().ok_or("no request was made")?;
        assert!(signed_by(sent, first_key(&second)?)?);
        Ok(())
    }

    /// A rotated client, and what its agent reports afterwards: the rotation as the latest
    /// establishment event, from the event's own bytes — a JSON value would re-sort its labels and
    /// lose the version-first order a KERI event requires.
    fn rotated(fixture: &Fixture) -> Result<(ConnectedClient, String, String), Box<dyn Error>> {
        let (mut client, _) = connected(&fixture.provenance.passcode, &[b"{}"])?;
        block_on(client.rotate_passcode(&Passcode::new(fixture.provenance.second_passcode.clone())?, &[]))?;
        let prefix = client.controller().prefix().qb64()?;
        let raw = core::str::from_utf8(client.controller().current_event().raw())?.to_owned();
        let state = agent_state(&prefix, &raw);
        Ok((client, prefix, state))
    }

    fn fresh_config(passcode: &str) -> Result<ClientConfig, Box<dyn Error>> {
        Ok(ClientConfig::new(ADMIN, passcode)?
            .with_boot_url(BOOT)?
            .with_derivation_cost(DerivationCost::Ephemeral))
    }

    #[test]
    fn a_rotated_client_reconnects_with_its_new_passcode_and_its_prefix() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let (client, prefix, state) = rotated(&fixture)?;

        // The rotated client's configuration carries the value to persist.
        let persisted = client
            .config()
            .controller_prefix()
            .ok_or("the rotated client's configuration names no controller")?
            .clone();
        assert_eq!(persisted.qb64()?, prefix);
        let first_key = client
            .controller()
            .current_keys()
            .first()
            .cloned()
            .ok_or("the rotated controller has no key")?;

        let fresh = AgentTransport::new(&[state.as_bytes()]);
        let configuration = fresh_config(&fixture.provenance.second_passcode)?.with_controller_prefix(persisted);
        let reconnected =
            block_on(SignifyClient::new(configuration, Arc::clone(&fresh) as Arc<dyn Transport>, clock())?.connect())?;

        // The agent is asked about the controller by its own prefix — the one the first passcode
        // incepted — and not by the prefix the new passcode would incept.
        let requests = fresh.requests();
        assert_eq!(requests.len(), 1, "reconnecting approved the delegation again");
        let asked = requests.first().ok_or("nothing was asked")?;
        assert_eq!(asked.path(), format!("/agent/{prefix}"));

        // Restored at the rotation, holding the key the rotation put first.
        assert_eq!(reconnected.controller().current_sequence_number(), 2);
        assert_eq!(reconnected.controller().prefix().qb64()?, prefix);
        assert_eq!(
            reconnected.controller().derive_signing_key()?.verifier().qb64()?,
            first_key
        );
        assert_eq!(
            reconnected
                .config()
                .controller_prefix()
                .map(IdentifierPrefix::qb64)
                .transpose()?,
            Some(prefix)
        );
        Ok(())
    }

    #[test]
    fn the_new_passcode_alone_asks_for_an_agent_that_does_not_exist() -> Result<(), Box<dyn Error>> {
        // The gap the prefix closes, and the reference's too: a controller keeps the prefix its
        // first passcode incepted, and the new passcode incepts another.
        let fixture = fixture()?;
        let (_, prefix, state) = rotated(&fixture)?;
        let fresh = AgentTransport::new(&[state.as_bytes()]);
        let client = SignifyClient::new(
            fresh_config(&fixture.provenance.second_passcode)?,
            Arc::clone(&fresh) as Arc<dyn Transport>,
            clock(),
        )?;
        let incepted = client.controller().prefix().qb64()?;
        assert_ne!(incepted, prefix);

        let _ = block_on(client.state());
        let requests = fresh.requests();
        let asked = requests.first().ok_or("nothing was asked")?;
        assert_eq!(asked.path(), format!("/agent/{incepted}"));
        Ok(())
    }

    #[test]
    fn the_passcode_a_rotation_replaced_is_refused_at_connect() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let (_, prefix, state) = rotated(&fixture)?;
        let fresh = AgentTransport::new(&[state.as_bytes()]);
        let configuration =
            fresh_config(&fixture.provenance.passcode)?.with_controller_prefix(IdentifierPrefix::from_qb64(&prefix)?);

        let outcome =
            block_on(SignifyClient::new(configuration, Arc::clone(&fresh) as Arc<dyn Transport>, clock())?.connect());
        assert!(
            matches!(&outcome, Err(ClientError::ControllerKeyMismatch { controller, .. }) if *controller == prefix),
            "{outcome:?}"
        );
        // Refused before anything but the state read was sent.
        assert_eq!(fresh.requests().len(), 1);
        Ok(())
    }

    #[test]
    fn an_agent_reporting_another_controller_is_refused() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let (_, prefix, state) = rotated(&fixture)?;
        let fresh = AgentTransport::new(&[state.as_bytes()]);
        // Configured for a different controller than the one the agent reports.
        let other = IdentifierPrefix::from_qb64(crate::support::AGENT)?;
        let configuration = fresh_config(&fixture.provenance.second_passcode)?.with_controller_prefix(other.clone());

        let outcome =
            block_on(SignifyClient::new(configuration, Arc::clone(&fresh) as Arc<dyn Transport>, clock())?.connect());
        let expected = other.qb64()?;
        assert!(
            matches!(&outcome, Err(ClientError::ControllerPrefixMismatch { configured, reported })
                if *configured == expected && *reported == prefix),
            "{outcome:?}"
        );
        Ok(())
    }

    #[test]
    fn connecting_records_the_controller_prefix() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let (client, _) = connected(&fixture.provenance.passcode, &[])?;
        assert_eq!(
            client
                .config()
                .controller_prefix()
                .map(IdentifierPrefix::qb64)
                .transpose()?,
            Some(client.controller().prefix().qb64()?)
        );
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

        let keys = body.get("keys").and_then(Value::as_object).ok_or("no keys map")?;
        let salty_sealed = keys
            .get(&fixture.identifiers.salty.prefix)
            .and_then(|entry| entry.get("sxlt"))
            .and_then(Value::as_str)
            .ok_or("no salty salt")?;
        let salty_opened = new_decrypter.decrypt_salt(&Ciphertext::from_qb64(salty_sealed)?, SecurityTier::Low)?;
        assert_eq!(salty_opened.expose_qb64()?.as_str(), fixture.identifiers.salty.salt);

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

        assert_eq!(
            transport.requests().len(),
            sent_before,
            "a refused rotation still sent something"
        );
        Ok(())
    }
}
