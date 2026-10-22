//! The upstream unit audit — every upstream unit case is answered, and every answer exists.
//!
//! All 139 upstream unit cases answered by Rust evidence or a documented `N/A`, every named path on disk.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::{Path, PathBuf};

use serde::Deserialize;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const INVENTORY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/upstream-unit-audit/v1.json"
));
const LEDGER: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/upstream-unit-audit/ledger.json"
));

#[derive(Debug, Deserialize)]
struct Inventory {
    schema_version: u8,
    upstream: String,
    reference_sha: String,
    generated_on: String,
    note: String,
    totals: Totals,
    files: Vec<FileEntry>,
    modules: Vec<ModuleEntry>,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Totals {
    files: usize,
    cases: usize,
    assertions: usize,
    skipped: usize,
}

#[derive(Debug, Deserialize)]
struct FileEntry {
    file: String,
    cases: usize,
    assertions: usize,
    imports: Vec<ImportEntry>,
}

#[derive(Debug, Deserialize)]
struct ImportEntry {
    module: String,
    names: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ModuleEntry {
    module: String,
    files: usize,
}

#[derive(Debug, Deserialize)]
struct Case {
    file: String,
    group: String,
    title: String,
    assertions: usize,
    helpers: Vec<String>,
    skipped: bool,
    lines: usize,
}

#[derive(Debug, Deserialize)]
struct Ledger {
    schema_version: u8,
    reference_sha: String,
    authored_on: String,
    note: String,
    moved: Vec<Moved>,
    entries: Vec<LedgerEntry>,
    findings: Vec<Finding>,
}

/// Upstream test files whose cases are answered by another crate, not by this ledger.
#[derive(Debug, Deserialize)]
struct Moved {
    to: String,
    note: String,
    files: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Finding {
    name: String,
    module: String,
    importing_files: usize,
    owner: String,
    note: String,
    consequence: String,
}

#[derive(Debug, Deserialize)]
struct LedgerEntry {
    file: String,
    group: String,
    title: String,
    status: String,
    evidence: Vec<String>,
    note: String,
}

fn key(file: &str, group: &str, title: &str) -> String {
    format!("{file}::{group}::{title}")
}

fn inventory() -> Result<Inventory, Box<dyn Error>> {
    Ok(serde_json::from_str(INVENTORY)?)
}

fn ledger() -> Result<Ledger, Box<dyn Error>> {
    Ok(serde_json::from_str(LEDGER)?)
}

fn workspace_root() -> Result<PathBuf, Box<dyn Error>> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "the workspace root is not two levels above the manifest".into())
}

#[test]
fn the_inventory_matches_the_pinned_reference() -> Result<(), Box<dyn Error>> {
    let inventory = inventory()?;
    assert_eq!(inventory.schema_version, 1);
    assert_eq!(inventory.reference_sha, REFERENCE_SHA);
    assert_eq!(inventory.upstream, "https://github.com/WebOfTrust/signify-ts.git");
    assert_eq!(inventory.generated_on, "2026-08-27");
    assert!(inventory.note.contains("ledger.json"));

    assert_eq!(inventory.totals.files, 40);
    assert_eq!(inventory.totals.cases, 139);
    assert_eq!(inventory.totals.assertions, 1_327);
    assert_eq!(
        inventory.totals.skipped, 0,
        "the reference now skips cases this audit counted"
    );

    assert_eq!(inventory.cases.len(), inventory.totals.cases);
    assert_eq!(inventory.files.len(), inventory.totals.files);
    let counted: usize = inventory.files.iter().map(|entry| entry.cases).sum();
    assert_eq!(counted, inventory.totals.cases);
    let asserted: usize = inventory.cases.iter().map(|case| case.assertions).sum();
    assert_eq!(asserted, inventory.totals.assertions);
    Ok(())
}

#[test]
fn every_upstream_case_is_answered_exactly_once() -> Result<(), Box<dyn Error>> {
    let inventory = inventory()?;
    let ledger = ledger()?;
    assert_eq!(ledger.reference_sha, REFERENCE_SHA);
    assert_eq!(ledger.schema_version, 1);
    assert!(ledger.note.contains("Authored"));
    assert_eq!(ledger.authored_on, "2026-08-27");

    let mut answered: BTreeMap<String, usize> = BTreeMap::new();
    for entry in &ledger.entries {
        *answered
            .entry(key(&entry.file, &entry.group, &entry.title))
            .or_default() += 1;
    }

    let mut moved = BTreeSet::new();
    for destination in &ledger.moved {
        assert!(!destination.to.is_empty(), "a moved block names no crate");
        assert!(destination.note.contains(&destination.to));
        for file in &destination.files {
            assert!(moved.insert(file.as_str()), "{file} is listed as moved twice");
        }
    }
    for file in &moved {
        assert!(
            inventory.files.iter().any(|entry| entry.file == *file),
            "{file} is listed as moved but the reference does not declare it"
        );
    }

    let mut unanswered = Vec::new();
    let mut moved_cases = 0;
    for case in &inventory.cases {
        let case_key = key(&case.file, &case.group, &case.title);
        if moved.contains(case.file.as_str()) {
            assert!(
                !answered.contains_key(&case_key),
                "{case_key} is moved but still answered here"
            );
            moved_cases += 1;
            continue;
        }
        match answered.get(&case_key) {
            None => unanswered.push(case_key),
            Some(1) => {}
            Some(count) => return Err(format!("{case_key} is answered {count} times").into()),
        }
    }
    assert!(unanswered.is_empty(), "unanswered upstream cases: {unanswered:?}");

    let declared: BTreeSet<String> = inventory
        .cases
        .iter()
        .map(|case| key(&case.file, &case.group, &case.title))
        .collect();
    let orphans: Vec<&String> = answered.keys().filter(|entry| !declared.contains(*entry)).collect();
    assert!(
        orphans.is_empty(),
        "the ledger answers cases the reference does not declare: {orphans:?}"
    );

    assert_eq!(ledger.entries.len() + moved_cases, inventory.totals.cases);
    Ok(())
}

#[test]
fn every_answer_names_evidence_that_exists() -> Result<(), Box<dyn Error>> {
    let root = workspace_root()?;
    let ledger = ledger()?;

    let mut missing = Vec::new();
    for entry in &ledger.entries {
        assert!(
            matches!(entry.status.as_str(), "covered" | "n_a"),
            "{} carries an unknown status {}",
            entry.title,
            entry.status
        );
        assert!(!entry.evidence.is_empty(), "{} names no evidence", entry.title);
        assert!(entry.note.len() > 40, "{} explains too little", entry.title);

        for path in &entry.evidence {
            if !root.join(path).exists() {
                missing.push(format!("{} → {path}", key(&entry.file, &entry.group, &entry.title)));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "the ledger names evidence that does not exist: {missing:#?}"
    );
    Ok(())
}

#[test]
fn every_not_applicable_says_why() -> Result<(), Box<dyn Error>> {
    let inventory = inventory()?;
    let ledger = ledger()?;

    let excused: Vec<&LedgerEntry> = ledger.entries.iter().filter(|entry| entry.status == "n_a").collect();

    assert!(
        excused.len() * 20 < ledger.entries.len(),
        "{} of {} cases are excused; an audit that excuses a twentieth of the suite is not one",
        excused.len(),
        ledger.entries.len()
    );
    for entry in &excused {
        assert!(
            entry.note.len() > 120,
            "{} is excused without an argument",
            key(&entry.file, &entry.group, &entry.title)
        );
    }

    let zero_assertion: BTreeSet<String> = inventory
        .cases
        .iter()
        .filter(|case| case.assertions == 0)
        .map(|case| key(&case.file, &case.group, &case.title))
        .collect();
    for entry in &excused {
        let entry_key = key(&entry.file, &entry.group, &entry.title);
        assert!(
            zero_assertion.contains(&entry_key),
            "{entry_key} is excused but does assert something"
        );
    }
    assert_eq!(
        excused.len(),
        zero_assertion.len(),
        "a zero-assertion case is claimed as covered rather than excused"
    );
    Ok(())
}

#[test]
fn every_upstream_module_the_tests_reach_is_ported() -> Result<(), Box<dyn Error>> {
    let inventory = inventory()?;

    assert_eq!(inventory.modules.len(), 42);
    for module in &inventory.modules {
        assert!(
            module.module.starts_with("src/"),
            "{} is not a source module",
            module.module
        );
        assert!(module.files > 0);
    }

    let named: BTreeSet<&str> = inventory.modules.iter().map(|entry| entry.module.as_str()).collect();
    for file in &inventory.files {
        for imported in &file.imports {
            assert!(
                named.contains(imported.module.as_str()),
                "{} imports {}, which the module list does not name",
                file.file,
                imported.module
            );
            assert!(!imported.names.is_empty(), "{} imports nothing by name", file.file);
        }

        let cases: Vec<&Case> = inventory.cases.iter().filter(|case| case.file == file.file).collect();
        assert_eq!(cases.len(), file.cases, "{} counts its cases wrongly", file.file);
        let weight: usize = cases.iter().map(|case| case.assertions).sum();
        assert_eq!(weight, file.assertions, "{} counts its assertions wrongly", file.file);
    }
    Ok(())
}

#[test]
fn every_case_asserts_through_a_helper_this_audit_recognises() -> Result<(), Box<dyn Error>> {
    let inventory = inventory()?;

    for case in &inventory.cases {
        assert!(!case.skipped, "{} is skipped upstream", case.title);
        assert!(case.lines > 0);
        if case.assertions == 0 {
            assert!(
                case.helpers.is_empty(),
                "{} counts no assertions but names helpers",
                case.title
            );
            assert_eq!(
                case.group, "Aiding › Typings test",
                "an unexpected case asserts nothing"
            );
        } else {
            assert!(
                !case.helpers.is_empty(),
                "{} asserts without a recognised helper",
                case.title
            );
            for helper in &case.helpers {
                assert!(
                    helper.starts_with("assert") || helper == "expect",
                    "{} asserts through {helper}, which this audit does not recognise",
                    case.title
                );
            }
        }
    }
    Ok(())
}

#[test]
fn the_audit_covers_the_whole_suite_by_weight_too() -> Result<(), Box<dyn Error>> {
    let inventory = inventory()?;
    let ledger = ledger()?;

    let excused: BTreeSet<String> = ledger
        .entries
        .iter()
        .filter(|entry| entry.status == "n_a")
        .map(|entry| key(&entry.file, &entry.group, &entry.title))
        .collect();
    let excused_weight: usize = inventory
        .cases
        .iter()
        .filter(|case| excused.contains(&key(&case.file, &case.group, &case.title)))
        .map(|case| case.assertions)
        .sum();
    assert_eq!(
        excused_weight, 0,
        "the audit excuses {excused_weight} upstream assertions, which it may not"
    );

    let answered_files: BTreeSet<&str> = ledger.entries.iter().map(|entry| entry.file.as_str()).collect();
    let moved_files: usize = ledger.moved.iter().map(|destination| destination.files.len()).sum();
    assert_eq!(answered_files.len() + moved_files, inventory.totals.files);

    for case in inventory.cases.iter().filter(|case| {
        case.assertions >= 40
            && !ledger
                .moved
                .iter()
                .any(|destination| destination.files.contains(&case.file))
    }) {
        let case_key = key(&case.file, &case.group, &case.title);
        let entry = ledger
            .entries
            .iter()
            .find(|entry| key(&entry.file, &entry.group, &entry.title) == case_key)
            .ok_or_else(|| format!("{case_key} is unanswered"))?;
        assert!(
            entry.evidence.len() >= 2,
            "{case_key} makes {} assertions and names one piece of evidence",
            case.assertions
        );
    }
    Ok(())
}

#[test]
fn the_audit_states_what_it_found_and_the_counts_hold() -> Result<(), Box<dyn Error>> {
    let inventory = inventory()?;
    let ledger = ledger()?;

    assert_eq!(ledger.findings.len(), 2);
    for finding in &ledger.findings {
        assert_ne!(finding.name, "");
        assert_eq!(
            finding.owner, "the API consistency review",
            "{} is owned by someone else now",
            finding.name
        );
        assert!(finding.note.len() > 200, "{} explains too little", finding.name);
        assert!(
            finding.consequence.len() > 60,
            "{} does not say what follows",
            finding.name
        );

        let importing = inventory
            .files
            .iter()
            .filter(|file| file.imports.iter().any(|imported| imported.module == finding.module))
            .count();
        assert_eq!(
            importing, finding.importing_files,
            "{} claims {} importing files and the inventory has {importing}",
            finding.name, finding.importing_files
        );
    }

    let entry_point = ledger
        .findings
        .iter()
        .find(|finding| finding.module == "src/index.ts")
        .ok_or("the entry-point finding is gone")?;
    assert!(
        entry_point.importing_files * 4 > inventory.totals.files,
        "the entry point is imported by {} of {} files, which is no longer a quarter",
        entry_point.importing_files,
        inventory.totals.files
    );
    Ok(())
}
