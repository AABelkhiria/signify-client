//! Hermetic assertions over the recorded salty identifier lifecycle.
//!
//! `test-integration/salty.test.ts` is the richest golden-vector scenario in the upstream suite:
//! from two pinned passcodes it asserts exact prefixes, signing keys, next-key digests, and event
//! SAIDs. Wave 3 drove that lifecycle through this port against a live deployment; this file
//! re-checks the recording from its own bytes — the pinned literals are declared *here*, and every
//! event is re-parsed and re-verified rather than trusting any flag the scenario wrote.
//!
//! One divergence is deliberate and asserted as such: the upstream interaction anchors the bare
//! string `[icp.pre]`, which the port's `Vec<Sad>` anchors cannot spell (Roadmap 4.6), so the
//! recording anchors a seal of the same inception and its SAID differs from the pinned literal.
//!
//! Not ignored: it reads a checked-in recording and never touches a network.

use std::error::Error;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;
use signify_keri::prefix::{IdentifierPrefix, PrefixVerification};
use signify_keri::said::{Said, SaidVerification};
use signify_keri::serialization::Sad;

/// The passcodes the upstream case derives its pinned identifiers from. Published test constants.
const AID1_PASSCODE: &str = "0123456789abcdefghijk";
const AID2_PASSCODE: &str = "0123456789lmnopqrstuv";

/// The literals `salty.test.ts` pins, declared here so the fixture cannot vouch for itself.
const AID1_PREFIX: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const AID1_VERFER: &str = "DPmhSfdhCPxr3EqjxzEtF8TVy0YX7ATo0Uc8oo2cnmY9";
const AID1_DIGER: &str = "EAORnRtObOgNiOlMolji-KijC_isa3lRDpHCsol79cOc";
const AID2_PREFIX: &str = "EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX";
const AID2_VERFERS: [&str; 3] = [
    "DGBw7C7AfC7jbD3jLLRS3SzIWFndM947TyNWKQ52iQx5",
    "DD_bHYFsgWXuCbz3SD0HjCIe_ITjRvEoCGuZ4PcNFFDz",
    "DEe9u8k0fm1wMFAuOIsCtCNrpduoaV5R21rAcJl0awze",
];
const AID2_DIGERS: [&str; 3] = [
    "EML5FrjCpz8SEl4dh0U15l8bMRhV_O5iDcR1opLJGBSH",
    "EJpKquuibYTqpwMDqEFAFs0gwq0PASAHZ_iDmSF3I2Vg",
    "ELplTAiEKdobFhlf-dh1vUb2iVDW0dYOSzs1dR7fQo60",
];
const ROTATION_SAID: &str = "EBQABdRgaxJONrSLcgrdtbASflkvLxJkiDO0H-XmuhGg";
const ROTATION_VERFER: &str = "DHgomzINlGJHr-XP3sv2ZcR9QsIEYS3LJhs4KRaZYKly";
const ROTATION_DIGER: &str = "EJMovBlrBuD6BVeUsGSxLjczbLEbZU9YnTSud9K4nVzk";
const UPSTREAM_INTERACTION_SAID: &str = "ENsmRAg_oM7Hl1S-GTRMA7s4y760lQMjzl0aqOQ2iTce";

#[derive(Debug, Deserialize)]
struct Captured {
    scenario: String,
    preset: String,
    creations: Vec<Creation>,
    listings: Vec<Listing>,
    rotation: Rotation,
    interaction: Interaction,
    state: StateCapture,
    log_saids: Vec<String>,
    rename: Rename,
    operations_remaining: usize,
    transcript: Vec<Observation>,
}

#[derive(Debug, Deserialize)]
struct Creation {
    alias: String,
    passcode: Option<String>,
    derived_event: String,
    derived_prefix: String,
    agent_event: String,
    key_pair_index: u32,
    stem: String,
}

#[derive(Debug, Deserialize)]
struct Listing {
    start: u64,
    end: u64,
    names: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Rotation {
    derived_event: String,
    derived_said: String,
    agent_event: String,
}

#[derive(Debug, Deserialize)]
struct Interaction {
    upstream_anchor: String,
    upstream_said: String,
    port_anchor: String,
    derived_event: String,
    derived_said: String,
    agent_event: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct StateCapture {
    sequence: String,
    first_seen: String,
    establishment_kind: String,
    digest: String,
    establishment_digest: String,
}

#[derive(Debug, Deserialize)]
struct Rename {
    from: String,
    to: String,
    updated_name: String,
    fetched_name: String,
}

#[derive(Debug, Deserialize)]
struct Observation {
    method: String,
    resource: String,
    request_body: Option<String>,
    status: u16,
}

fn captured() -> Result<Option<Captured>, Box<dyn Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("the workspace root is not two levels above the manifest")?
        .join("fixtures/keria-integration/observations/salty_lifecycle.json");
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&fs::read_to_string(path)?)?))
}

/// Reads one text field out of a JSON document, by label.
fn text_field(document: &Value, label: &str) -> Result<String, Box<dyn Error>> {
    document
        .get(label)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("the document carries no text field {label}").into())
}

/// Reads one array of text out of a JSON document, by label.
fn text_array(document: &Value, label: &str) -> Result<Vec<String>, Box<dyn Error>> {
    document
        .get(label)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .map(|value| value.as_str().map(ToOwned::to_owned))
                .collect::<Option<Vec<_>>>()
        })
        .and_then(|texts| texts)
        .ok_or_else(|| format!("the document carries no text array {label}").into())
}

/// Returns the creation for one alias, or says which one is missing.
fn creation<'capture>(captured: &'capture Captured, alias: &str) -> Result<&'capture Creation, Box<dyn Error>> {
    captured
        .creations
        .iter()
        .find(|creation| creation.alias == alias)
        .ok_or_else(|| format!("the recording never created {alias}").into())
}

#[test]
fn the_recording_is_the_whole_scenario() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };
    assert_eq!(captured.scenario, "salty_lifecycle");
    assert!(!captured.preset.is_empty());
    assert!(!captured.transcript.is_empty(), "the recording kept no transcript");

    // The three creations, in the upstream case's order, with its passcodes: two pinned, one from
    // entropy — and the prefix index reserved in creation order under the shared stem.
    let aliases: Vec<&str> = captured.creations.iter().map(|c| c.alias.as_str()).collect();
    assert_eq!(aliases, ["aid1", "aid2", "aid3"]);
    for (index, creation) in captured.creations.iter().enumerate() {
        assert_eq!(
            u32::try_from(index)?,
            creation.key_pair_index,
            "{} pidx",
            creation.alias
        );
        assert_eq!(creation.stem, "signify:aid", "{} stem", creation.alias);
    }
    assert_eq!(creation(&captured, "aid1")?.passcode.as_deref(), Some(AID1_PASSCODE));
    assert_eq!(creation(&captured, "aid2")?.passcode.as_deref(), Some(AID2_PASSCODE));
    assert_eq!(creation(&captured, "aid3")?.passcode, None);

    // The upstream postcondition: every operation was waited out and deleted.
    assert_eq!(captured.operations_remaining, 0);
    Ok(())
}

#[test]
fn the_pinned_inception_vectors_reproduce() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    // Decoded here again from the recorded agent answers rather than trusting the scenario's own
    // comparison: a recording that merely reports its conclusion proves nothing.
    let aid1 = creation(&captured, "aid1")?;
    assert_eq!(aid1.derived_prefix, AID1_PREFIX);
    let event: Value = serde_json::from_str(&aid1.agent_event)?;
    assert_eq!(text_field(&event, "i")?, AID1_PREFIX);
    assert_eq!(text_field(&event, "d")?, AID1_PREFIX);
    assert_eq!(text_array(&event, "k")?, [AID1_VERFER]);
    assert_eq!(text_array(&event, "n")?, [AID1_DIGER]);
    assert_eq!(text_field(&event, "kt")?, "1");
    assert_eq!(text_field(&event, "nt")?, "1");

    let aid2 = creation(&captured, "aid2")?;
    assert_eq!(aid2.derived_prefix, AID2_PREFIX);
    let event: Value = serde_json::from_str(&aid2.agent_event)?;
    assert_eq!(text_field(&event, "i")?, AID2_PREFIX);
    assert_eq!(text_array(&event, "k")?, AID2_VERFERS);
    assert_eq!(text_array(&event, "n")?, AID2_DIGERS);
    assert_eq!(text_field(&event, "kt")?, "2");
    assert_eq!(text_field(&event, "nt")?, "2");

    // And every derived inception re-derives its own prefix, the third one included even though
    // its salt came from entropy and pins nothing.
    for creation in &captured.creations {
        let sad = Sad::from_json_bytes(creation.derived_event.as_bytes())?;
        let prefix = IdentifierPrefix::from_qb64(&creation.derived_prefix)?;
        prefix.verify(&sad, PrefixVerification::Strict)?;
    }
    Ok(())
}

#[test]
fn the_agent_accepted_the_ports_exact_bytes() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    // Byte-level, from the transcript: each derived event appears verbatim inside a successful
    // POST body, so what the agent accepted is what the port serialized — not a re-encoding.
    let embedded = |resource: &str, needle: &str| -> bool {
        captured.transcript.iter().any(|observation| {
            observation.method == "POST"
                && observation.resource == resource
                && (200..300).contains(&observation.status)
                && observation
                    .request_body
                    .as_deref()
                    .is_some_and(|body| body.contains(needle))
        })
    };
    for creation in &captured.creations {
        assert!(
            embedded("/identifiers", &creation.derived_event),
            "{}'s exact inception bytes were never accepted by the agent",
            creation.alias
        );
    }
    assert!(
        embedded("/identifiers/aid1/events", &captured.rotation.derived_event),
        "the exact rotation bytes were never accepted by the agent"
    );
    assert!(
        embedded("/identifiers/aid1/events", &captured.interaction.derived_event),
        "the exact interaction bytes were never accepted by the agent"
    );
    Ok(())
}

#[test]
fn the_rotation_reproduces_the_pinned_vector() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };
    assert_eq!(captured.rotation.derived_said, ROTATION_SAID);

    let event: Value = serde_json::from_str(&captured.rotation.agent_event)?;
    assert_eq!(text_field(&event, "d")?, ROTATION_SAID);
    assert_eq!(text_field(&event, "i")?, AID1_PREFIX);
    assert_eq!(text_field(&event, "s")?, "1");
    assert_eq!(text_array(&event, "k")?, [ROTATION_VERFER]);
    assert_eq!(text_array(&event, "n")?, [ROTATION_DIGER]);

    // The SAID re-verified over the derived bytes, strictly.
    let sad = Sad::from_json_bytes(captured.rotation.derived_event.as_bytes())?;
    Said::from_qb64(ROTATION_SAID)?.verify(&sad, "d", SaidVerification::strict())?;
    Ok(())
}

#[test]
fn the_interaction_diverges_exactly_where_the_anchor_type_says_it_must() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };
    let interaction = &captured.interaction;

    // The divergence, pinned from both sides: the upstream literal is recorded unchanged, the
    // run's SAID differs from it, and the reason is stated.
    assert_eq!(interaction.upstream_said, UPSTREAM_INTERACTION_SAID);
    assert_eq!(interaction.upstream_anchor, AID1_PREFIX);
    assert_ne!(interaction.derived_said, UPSTREAM_INTERACTION_SAID);
    assert!(
        interaction.note.contains("Vec<Sad>"),
        "the divergence does not name its cause"
    );

    // What was anchored instead: one seal of aid1's own inception, and nothing else.
    let event: Value = serde_json::from_str(&interaction.derived_event)?;
    assert_eq!(text_field(&event, "s")?, "2");
    let anchors = event
        .get("a")
        .and_then(Value::as_array)
        .ok_or("the interaction carries no anchor list")?;
    let seal = match anchors.as_slice() {
        [seal] => seal,
        other => return Err(format!("expected exactly one anchored seal, found {}", other.len()).into()),
    };
    assert_eq!(text_field(seal, "i")?, AID1_PREFIX);
    assert_eq!(text_field(seal, "s")?, "0");
    assert_eq!(text_field(seal, "d")?, AID1_PREFIX);
    let recorded_anchor: Value = serde_json::from_str(&interaction.port_anchor)?;
    assert_eq!(seal, &recorded_anchor);

    // The event is still a valid interaction: its SAID verifies strictly over the derived bytes,
    // and the agent echoed the same document.
    let sad = Sad::from_json_bytes(interaction.derived_event.as_bytes())?;
    Said::from_qb64(&interaction.derived_said)?.verify(&sad, "d", SaidVerification::strict())?;
    let echoed: Value = serde_json::from_str(&interaction.agent_event)?;
    assert_eq!(text_field(&echoed, "d")?, interaction.derived_said);
    Ok(())
}

#[test]
fn the_lifecycle_reads_back_as_upstream_asserts() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    // The key state after rotation and interaction, field for field as the upstream case reads it.
    assert_eq!(captured.state.sequence, "2");
    assert_eq!(captured.state.first_seen, "2");
    assert_eq!(captured.state.establishment_kind, "ixn");
    assert_eq!(captured.state.digest, captured.interaction.derived_said);
    assert_eq!(captured.state.establishment_digest, ROTATION_SAID);

    // The three-event log, by SAID, in log order.
    assert_eq!(
        captured.log_saids,
        [
            AID1_PREFIX.to_owned(),
            ROTATION_SAID.to_owned(),
            captured.interaction.derived_said.clone()
        ]
    );

    // The listing ladder: one, two, three, then the two paged windows, then the window that shows
    // the rename — exactly the calls the upstream case makes, answered with the names it asserts.
    let names: Vec<(u64, u64, Vec<String>)> = captured
        .listings
        .iter()
        .map(|listing| (listing.start, listing.end, listing.names.clone()))
        .collect();
    let expected: Vec<(u64, u64, Vec<String>)> = vec![
        (0, 24, vec!["aid1".to_owned()]),
        (0, 24, vec!["aid1".to_owned(), "aid2".to_owned()]),
        (0, 24, vec!["aid1".to_owned(), "aid2".to_owned(), "aid3".to_owned()]),
        (1, 2, vec!["aid2".to_owned(), "aid3".to_owned()]),
        (2, 2, vec!["aid3".to_owned()]),
        (2, 2, vec!["aid4".to_owned()]),
    ];
    assert_eq!(names, expected);

    // The rename round.
    assert_eq!(captured.rename.from, "aid3");
    assert_eq!(captured.rename.to, "aid4");
    assert_eq!(captured.rename.updated_name, "aid4");
    assert_eq!(captured.rename.fetched_name, "aid4");
    Ok(())
}
