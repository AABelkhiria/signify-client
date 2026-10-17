//! Hermetic assertions over the `Content-Range` values a live KERIA actually sent.
//!
//! Five values a deployment actually sent, including `aids 100-0/4`, whose start exceeds its end.

use std::error::Error;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use signify_http::request::RangeUnit;
use signify_http::response::ContentRange;

#[derive(Debug, Deserialize)]
struct Captured {
    scenario: String,
    preset: String,
    note: String,
    unrepresentable: Vec<String>,
    captures: Vec<Capture>,
}

#[derive(Debug, Deserialize)]
struct Capture {
    case: String,
    resource: String,
    request_range: Option<String>,
    status: u16,
    content_range: Option<String>,
    records: Option<usize>,
}

fn captured() -> Result<Option<Captured>, Box<dyn Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("the workspace root is not two levels above the manifest")?
        .join("fixtures/keria-integration/observations/content_range.json");
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&fs::read_to_string(path)?)?))
}

#[test]
fn every_value_the_deployment_sent_is_one_this_port_accepts() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };
    assert_eq!(captured.scenario, "content_range");
    assert_ne!(captured.preset, "");
    assert!(captured.note.len() > 80);

    let mut refused = Vec::new();
    for capture in &captured.captures {
        let Some(value) = capture.content_range.as_deref() else {
            continue;
        };
        let unit = if capture.resource.starts_with("/notifications") {
            RangeUnit::new("notes")?
        } else {
            RangeUnit::new("aids")?
        };
        if ContentRange::parse(value, &unit).is_err() {
            refused.push(format!("{}: {value}", capture.case));
        }
    }
    assert!(
        refused.is_empty(),
        "a live KERIA sent values this port refuses, so the grammar is too strict: {refused:#?}"
    );
    Ok(())
}

#[test]
fn a_real_deployment_sends_a_start_greater_than_its_end() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    let inverted: Vec<&Capture> = captured
        .captures
        .iter()
        .filter(|capture| {
            capture.content_range.as_deref().is_some_and(|value| {
                value
                    .split_once(' ')
                    .and_then(|(_, rest)| rest.split_once('/'))
                    .and_then(|(range, _)| range.split_once('-'))
                    .and_then(|(start, end)| Some((start.parse::<u64>().ok()?, end.parse::<u64>().ok()?)))
                    .is_some_and(|(start, end)| start > end)
            })
        })
        .collect();

    assert!(
        !inverted.is_empty(),
        "no inverted range was recorded; either the deployment changed or the scenario stopped \
         asking past the end of the collection, and the `Content-Range` question is open again"
    );

    for capture in &inverted {
        let value = capture
            .content_range
            .as_deref()
            .ok_or("an inverted capture has no value")?;
        let parsed = ContentRange::parse(value, &RangeUnit::new("aids")?)?;
        assert!(
            parsed.start() > parsed.end(),
            "{value} was parsed into something ordered"
        );

        let requested = capture
            .request_range
            .as_deref()
            .ok_or("an inverted answer was recorded without the request that provoked it")?;
        let start: u64 = requested
            .rsplit_once('=')
            .map_or(requested, |(_, rest)| rest)
            .split_once('-')
            .and_then(|(start, _)| start.parse().ok())
            .ok_or_else(|| format!("the recorded request range {requested} has no start"))?;
        assert!(
            start > parsed.total(),
            "{requested} does not start past the collection's {} records, so the inverted answer \
             is not explained by asking past the end",
            parsed.total()
        );
    }
    Ok(())
}

#[test]
fn the_two_listing_endpoints_disagree_about_an_empty_collection() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    let empty: Vec<&Capture> = captured
        .captures
        .iter()
        .filter(|capture| capture.records == Some(0) && capture.case.contains("empty"))
        .collect();
    assert_eq!(
        empty.len(),
        2,
        "both listings should have been asked about an empty collection"
    );

    let totals: Vec<Option<u64>> = empty
        .iter()
        .map(|capture| {
            capture
                .content_range
                .as_deref()
                .and_then(|value| value.rsplit_once('/'))
                .and_then(|(_, total)| total.parse().ok())
        })
        .collect();
    assert!(totals.iter().all(Option::is_some), "an empty listing sent no total");
    assert_ne!(
        totals.first(),
        totals.get(1),
        "the two listings now agree about an empty collection, so this finding is stale"
    );

    let statuses: Vec<u16> = empty.iter().map(|capture| capture.status).collect();
    assert_ne!(
        statuses.first(),
        statuses.get(1),
        "the two listings now agree about the status of an empty page"
    );
    Ok(())
}

#[test]
fn the_malformed_request_is_unrepresentable_rather_than_merely_unsent() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    assert_ne!(captured.unrepresentable, [] as [String; 0]);
    assert!(
        captured
            .unrepresentable
            .iter()
            .any(|note| note.contains("ItemRange::new")),
        "the recording does not say why the inverted request was never sent"
    );

    let refused = signify_http::request::ItemRange::new(10, 1);
    assert!(refused.is_err(), "an inverted range can now be built");
    Ok(())
}
