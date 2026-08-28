//! Roadmap 9.2 — the integration matrix, and the checks that keep it honest.
//!
//! The pinned reference's integration suite is 22 files, 35 cases, and 7,070 lines. Roadmap 9.1
//! audited the *unit* suite by case, one row per case, and that worked because its 139 cases were
//! each a few lines long. **It would not work here.** Four of these files are a single case each —
//! `multisig.test.ts` is 1,343 lines, one case, thirteen assertions, and a hundred and thirty-four
//! API calls. Counting cases would report "35 of 35 answered" while hundreds of behaviours went
//! unexamined: an audit that passes while certifying almost nothing.
//!
//! So the inventory beside this test records a finer unit — every `client.<family>().<method>()`
//! call site — and this test weighs the matrix by that unit as well as by case. It also requires
//! every path the ledger names to exist, every unanswered row to name what would settle it from a
//! closed set of reasons, and every count to be recomputed from the inventory rather than believed.
//! The equivalent check in 9.1 rejected two numbers that had been written from memory.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::{Path, PathBuf};

use serde::Deserialize;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const INVENTORY: &str = include_str!("../../../fixtures/keria-integration/v1.json");
const LEDGER: &str = include_str!("../../../fixtures/keria-integration/ledger.json");

// ---------------------------------------------------------------------------
// The generated inventory.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Inventory {
    schema_version: u8,
    upstream: String,
    reference_sha: String,
    generated_on: String,
    note: String,
    totals: Totals,
    runner: Runner,
    files: Vec<FileEntry>,
    families: Vec<Family>,
    defect_counts: BTreeMap<String, usize>,
    defects: Vec<Defect>,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Totals {
    files: usize,
    support_files: usize,
    cases: usize,
    lines: usize,
    assertions: usize,
    api_calls: usize,
    defects: usize,
}

#[derive(Debug, Deserialize)]
struct Runner {
    file: String,
    file_parallelism: bool,
    bail: Option<String>,
    test_timeout_ms: Option<String>,
    note: String,
}

#[derive(Debug, Deserialize)]
struct FileEntry {
    file: String,
    cases: usize,
    lines: usize,
    assertions: usize,
    api_calls: Vec<ApiCall>,
    shared_helpers_used: Vec<String>,
    infrastructure: Infrastructure,
    shared_state: Vec<String>,
    defects: usize,
}

#[derive(Debug, Deserialize)]
struct ApiCall {
    family: String,
    method: String,
    count: usize,
}

#[derive(Debug, Deserialize)]
struct Infrastructure {
    clients: usize,
    #[serde(flatten)]
    witnesses: Witnesses,
    vlei: bool,
    oobis: bool,
}

/// Whether a scenario needs witnesses, and how it comes to need them.
///
/// A scenario may name them, or inherit them from `getOrCreateIdentifier`'s defaults. Counting only
/// the first under-reports the suite, so both are recorded and `witnesses` is their union.
#[derive(Debug, Deserialize)]
struct Witnesses {
    #[serde(rename = "witnesses")]
    needed: bool,
    #[serde(rename = "witnesses_named")]
    named: bool,
    #[serde(rename = "witnesses_inherited")]
    inherited: bool,
}

#[derive(Debug, Deserialize)]
struct Family {
    family: String,
    calls: usize,
}

#[derive(Debug, Deserialize)]
struct Defect {
    kind: String,
    file: String,
    line: usize,
    text: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    file: String,
    group: String,
    title: String,
    line: usize,
    lines: usize,
    assertions: usize,
    helpers: Vec<String>,
    steps: Vec<String>,
    api_calls: Vec<ApiCall>,
}

// ---------------------------------------------------------------------------
// The authored ledger.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Ledger {
    schema_version: u8,
    reference_sha: String,
    authored_on: String,
    note: String,
    reasons: Vec<String>,
    statuses: Vec<String>,
    scenarios: Vec<Scenario>,
    open_questions: Vec<OpenQuestion>,
    obligations: Vec<Obligation>,
}

#[derive(Debug, Deserialize)]
struct Scenario {
    row: String,
    #[serde(default)]
    outcome: Option<String>,
    roadmap_gates: Vec<String>,
    upstream_files: Vec<String>,
    cases: usize,
    api_calls: usize,
    assertions: usize,
    clients: usize,
    needs_witnesses: bool,
    needs_vlei: bool,
    rust_evidence: Vec<String>,
    status: String,
    reason: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct OpenQuestion {
    topic: String,
    porting_line: usize,
    due: String,
    experiment: String,
    observation: String,
    outcome: Option<String>,
    status: String,
    reason: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Obligation {
    porting_line: usize,
    record: String,
    claim: String,
    status: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    moves_to: Option<String>,
    settling_observation: Option<String>,
    note: String,
}

fn inventory() -> Result<Inventory, Box<dyn Error>> {
    Ok(serde_json::from_str(INVENTORY)?)
}

fn ledger() -> Result<Ledger, Box<dyn Error>> {
    Ok(serde_json::from_str(LEDGER)?)
}

fn workspace_root() -> Result<PathBuf, Box<dyn Error>> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "the workspace root is not two levels above the manifest".into())
}

// ---------------------------------------------------------------------------
// Provenance and arithmetic.
// ---------------------------------------------------------------------------

#[test]
fn the_inventory_matches_the_pinned_reference() -> Result<(), Box<dyn Error>> {
    let inventory = inventory()?;
    assert_eq!(inventory.schema_version, 1);
    assert_eq!(inventory.reference_sha, REFERENCE_SHA);
    assert_eq!(inventory.upstream, "https://github.com/WebOfTrust/signify-ts.git");
    assert_eq!(inventory.generated_on, "2026-08-28");
    assert!(inventory.note.contains("ledger.json"));

    assert_eq!(inventory.totals.files, 22);
    assert_eq!(inventory.totals.support_files, 6);
    assert_eq!(inventory.totals.cases, 35);

    // Every total is the parts added up, not a number someone wrote down.
    assert_eq!(inventory.files.len(), inventory.totals.files);
    assert_eq!(inventory.cases.len(), inventory.totals.cases);
    assert_eq!(
        inventory.files.iter().map(|file| file.cases).sum::<usize>(),
        inventory.totals.cases
    );
    assert_eq!(
        inventory.files.iter().map(|file| file.lines).sum::<usize>(),
        inventory.totals.lines
    );
    assert_eq!(
        inventory.cases.iter().map(|case| case.assertions).sum::<usize>(),
        inventory.totals.assertions
    );
    let calls: usize = inventory
        .files
        .iter()
        .flat_map(|file| &file.api_calls)
        .map(|call| call.count)
        .sum();
    assert_eq!(calls, inventory.totals.api_calls);
    assert_eq!(inventory.defects.len(), inventory.totals.defects);
    assert_eq!(
        inventory.defect_counts.values().sum::<usize>(),
        inventory.totals.defects
    );
    Ok(())
}

#[test]
fn the_suite_is_serial_by_construction() -> Result<(), Box<dyn Error>> {
    let inventory = inventory()?;
    // `fileParallelism: false` with `bail: 1` — the first failure aborts everything, and nothing is
    // designed to run in parallel against one agent. A recording run must do the same, which is why
    // the deployment manifest records the run policy.
    assert_eq!(inventory.runner.file, "vitest.integration.ts");
    assert!(!inventory.runner.file_parallelism);
    assert_eq!(inventory.runner.bail.as_deref(), Some("1"));
    assert_eq!(inventory.runner.test_timeout_ms.as_deref(), Some("60000"));
    assert!(inventory.runner.note.contains("parallel"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Why the case is the wrong unit here.
// ---------------------------------------------------------------------------

#[test]
fn the_monoliths_are_decomposed_rather_than_counted() -> Result<(), Box<dyn Error>> {
    let inventory = inventory()?;

    // Files that are one enormous case. Counting cases would call each of these "one behaviour".
    let monoliths: Vec<&FileEntry> = inventory
        .files
        .iter()
        .filter(|file| file.cases == 1 && file.lines >= 400)
        .collect();
    assert!(monoliths.len() >= 4, "the suite's shape changed: {}", monoliths.len());

    for file in &monoliths {
        let calls: usize = file.api_calls.iter().map(|call| call.count).sum();
        assert!(
            calls > 0 || !file.shared_helpers_used.is_empty(),
            "{} is a monolith this audit cannot decompose",
            file.file
        );
    }

    // The headline, asserted rather than asserted-about: the largest scenario in the suite performs
    // far more operations than it checks.
    let largest = inventory
        .files
        .iter()
        .max_by_key(|file| file.lines)
        .ok_or("the inventory is empty")?;
    let calls: usize = largest.api_calls.iter().map(|call| call.count).sum();
    assert!(
        calls > largest.assertions * 5,
        "{} makes {calls} calls against {} assertions",
        largest.file,
        largest.assertions
    );
    Ok(())
}

#[test]
fn the_defects_are_recorded_with_a_line_each() -> Result<(), Box<dyn Error>> {
    let inventory = inventory()?;

    // Every claim this port makes about doing better than upstream cites one of these, so each has
    // to name a file and a line rather than being prose.
    assert!(inventory.defects.len() >= 20);
    for defect in &inventory.defects {
        assert!(defect.file.starts_with("test-integration/"));
        assert!(defect.line > 0, "{} names no line", defect.kind);
        assert!(!defect.text.is_empty());
    }

    // The kinds this audit knows how to find. A kind vanishing means either the reference improved
    // or the detector broke, and both are worth a failing test.
    for kind in [
        "bare_sleep",
        "commented_assertion",
        "module_scope_timestamp",
        "wall_clock_identifier",
        "swallowing_catch",
        "local_reimplementation",
        "no_operation_teardown",
    ] {
        assert!(
            inventory.defect_counts.get(kind).copied().unwrap_or_default() > 0,
            "no {kind} found; the detector or the reference changed"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The matrix itself.
// ---------------------------------------------------------------------------

#[test]
fn every_scenario_row_is_answered_once_and_names_real_files() -> Result<(), Box<dyn Error>> {
    let inventory = inventory()?;
    let ledger = ledger()?;
    assert_eq!(ledger.schema_version, 1);
    assert_eq!(ledger.reference_sha, REFERENCE_SHA);
    assert_eq!(ledger.authored_on, "2026-08-28");
    assert!(ledger.note.contains("Authored"));

    // `PORTING.md` §7 had nineteen rows and needed twenty: this audit found `challenge.test.ts`
    // claimed by none of them, so the table omitted a whole capability. The row was added.
    assert_eq!(ledger.scenarios.len(), 20);
    let rows: BTreeSet<&str> = ledger.scenarios.iter().map(|entry| entry.row.as_str()).collect();
    assert_eq!(rows.len(), 20, "two scenario rows share a title");
    assert!(
        rows.contains("Challenge and response"),
        "the row this audit added is gone again"
    );

    let known: BTreeSet<&str> = inventory.files.iter().map(|file| file.file.as_str()).collect();
    let mut claimed: BTreeSet<&str> = BTreeSet::new();
    for scenario in &ledger.scenarios {
        assert!(
            !scenario.upstream_files.is_empty(),
            "{} names no upstream file",
            scenario.row
        );
        for file in &scenario.upstream_files {
            assert!(
                known.contains(file.as_str()),
                "{} names {file}, which is not in the suite",
                scenario.row
            );
            claimed.insert(file.as_str());
        }
        assert!(!scenario.roadmap_gates.is_empty());
        assert!(scenario.note.len() > 60, "{} explains too little", scenario.row);
    }

    // And no scenario file is left unclaimed by every row.
    let unclaimed: Vec<&&str> = known.iter().filter(|file| !claimed.contains(*file)).collect();
    assert!(unclaimed.is_empty(), "upstream scenarios nobody answers: {unclaimed:?}");
    Ok(())
}

#[test]
fn every_scenarios_counts_are_recomputed_from_the_inventory() -> Result<(), Box<dyn Error>> {
    let inventory = inventory()?;
    let ledger = ledger()?;
    let by_file: BTreeMap<&str, &FileEntry> = inventory.files.iter().map(|file| (file.file.as_str(), file)).collect();

    // The check that earned its keep in 9.1: a number in the ledger must be derivable, not written.
    for scenario in &ledger.scenarios {
        let files: Vec<&&FileEntry> = scenario
            .upstream_files
            .iter()
            .filter_map(|name| by_file.get(name.as_str()))
            .collect();
        assert_eq!(files.len(), scenario.upstream_files.len());

        let cases: usize = files.iter().map(|file| file.cases).sum();
        assert_eq!(cases, scenario.cases, "{} miscounts its cases", scenario.row);

        let assertions: usize = files.iter().map(|file| file.assertions).sum();
        assert_eq!(
            assertions, scenario.assertions,
            "{} miscounts its assertions",
            scenario.row
        );

        let calls: usize = files
            .iter()
            .flat_map(|file| &file.api_calls)
            .map(|call| call.count)
            .sum();
        assert_eq!(calls, scenario.api_calls, "{} miscounts its API calls", scenario.row);

        let vlei = files.iter().any(|file| file.infrastructure.vlei);
        assert_eq!(
            vlei, scenario.needs_vlei,
            "{} misreports its schema needs",
            scenario.row
        );
        let witnesses = files.iter().any(|file| file.infrastructure.witnesses.needed);
        assert_eq!(
            witnesses, scenario.needs_witnesses,
            "{} misreports its witness needs",
            scenario.row
        );
        let clients = files
            .iter()
            .map(|file| file.infrastructure.clients)
            .max()
            .unwrap_or_default();
        assert_eq!(
            clients, scenario.clients,
            "{} misreports how many clients it needs",
            scenario.row
        );
    }
    Ok(())
}

#[test]
fn nothing_is_answered_without_evidence_that_exists() -> Result<(), Box<dyn Error>> {
    let root = workspace_root()?;
    let ledger = ledger()?;

    let statuses: BTreeSet<&str> = ledger.statuses.iter().map(String::as_str).collect();
    let reasons: BTreeSet<&str> = ledger.reasons.iter().map(String::as_str).collect();

    let mut missing = Vec::new();
    for scenario in &ledger.scenarios {
        assert!(
            statuses.contains(scenario.status.as_str()),
            "{} has an unknown status",
            scenario.row
        );

        if scenario.status == "partly_observed" {
            // A row may be half answered — but then it must name both the evidence and the half
            // that is missing, or "partly" becomes a way to record a win and drop the shortfall.
            assert!(
                !scenario.rust_evidence.is_empty(),
                "{} is partly observed and names no evidence",
                scenario.row
            );
            let outcome = scenario
                .outcome
                .as_deref()
                .ok_or("a partly observed scenario records no outcome")?;
            assert!(
                outcome.contains("Still to do"),
                "{} is partly observed and does not say what remains",
                scenario.row
            );
            for path in &scenario.rust_evidence {
                if !root.join(path).exists() {
                    missing.push(format!("{} \u{2192} {path}", scenario.row));
                }
            }
        } else if scenario.status == "observed" {
            // A row may only claim to be answered if it names evidence, and the evidence must be
            // on disk. This is the check that stops a renamed test reading as coverage.
            assert!(
                !scenario.rust_evidence.is_empty(),
                "{} claims to be observed and names no evidence",
                scenario.row
            );
            for path in &scenario.rust_evidence {
                if !root.join(path).exists() {
                    missing.push(format!("{} \u{2192} {path}", scenario.row));
                }
            }
        } else {
            // And a row that is *not* answered must say why, from a closed set — so "TODO" is
            // unspellable and a reason cannot be invented per row.
            assert_ne!(
                scenario.reason, "settled",
                "{} is unanswered and claims to be settled",
                scenario.row
            );
            assert!(
                reasons.contains(scenario.reason.as_str()),
                "{} is unanswered for the unrecognised reason {}",
                scenario.row,
                scenario.reason
            );
            assert!(
                scenario.rust_evidence.is_empty(),
                "{} names evidence while claiming to be unanswered",
                scenario.row
            );
        }
    }
    assert!(
        missing.is_empty(),
        "the ledger names evidence that does not exist: {missing:#?}"
    );
    Ok(())
}

#[test]
fn a_blocked_row_is_blocked_for_a_reason_the_inventory_agrees_with() -> Result<(), Box<dyn Error>> {
    let ledger = ledger()?;

    // A row excused for want of schemas must actually need schemas. Otherwise "vlei_unavailable"
    // becomes a place to park anything inconvenient.
    for scenario in ledger
        .scenarios
        .iter()
        .filter(|entry| entry.reason == "vlei_unavailable")
    {
        assert!(
            scenario.needs_vlei,
            "{} is excused for want of a schema server it does not need",
            scenario.row
        );
    }

    // Exactly one row is blocked on this port rather than on infrastructure, and it says so.
    let api_missing: Vec<&Scenario> = ledger
        .scenarios
        .iter()
        .filter(|entry| entry.reason == "api_missing")
        .collect();
    assert_eq!(api_missing.len(), 1);
    let blocked = api_missing.first().ok_or("no row is blocked on the port")?;
    assert_eq!(blocked.row, "External module behavior");
    assert!(
        blocked.note.contains("KeeperFactory") && blocked.note.contains("9.5"),
        "the blocked row does not name the gap or its owner"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The open questions and the collected obligations.
// ---------------------------------------------------------------------------

#[test]
fn every_open_question_names_the_experiment_that_would_settle_it() -> Result<(), Box<dyn Error>> {
    let ledger = ledger()?;

    // The four §10 rows owed to 9.2, plus the residual left on a fifth that is already RESOLVED.
    assert_eq!(ledger.open_questions.len(), 5);
    let lines: BTreeSet<usize> = ledger.open_questions.iter().map(|entry| entry.porting_line).collect();
    assert_eq!(lines.len(), 5, "two questions cite one line");

    // Keyed on the topic rather than on the line. `PORTING.md` is excluded from the repository, so
    // no test can read it to check that a cited line still says what the ledger claims — and the
    // numbers move whenever anything above them is edited. Asserting them here would pin values
    // nothing can verify and would fail for a reason that has nothing to do with the matrix.
    // Topics are stable text, so they are what identifies a row.
    let topics: Vec<&str> = ledger.open_questions.iter().map(|entry| entry.topic.as_str()).collect();
    for expected in [
        "Target KERIA integration version",
        "Content-Range",
        "sequence-number base",
        "two declared types",
        "required fields",
    ] {
        assert!(
            topics.iter().any(|topic| topic.contains(expected)),
            "no question covers {expected}; the questions present are {topics:#?}"
        );
    }

    for question in &ledger.open_questions {
        assert!(question.porting_line > 0);
        assert!(!question.due.is_empty());
        assert!(
            question.experiment.len() > 150,
            "{} does not describe an experiment",
            question.topic
        );
        assert!(
            !question.observation.is_empty(),
            "{} names no observation",
            question.topic
        );
        assert!(question.note.len() > 80, "{} explains too little", question.topic);
        assert!(
            ledger.reasons.contains(&question.reason),
            "{} is pending for the unrecognised reason {}",
            question.topic,
            question.reason
        );

        // `settled` and `observed` mean the same thing and must travel together. Without this an
        // answered question keeps whatever reason it was pending for, which reads as though the
        // observation never happened — the state the `Content-Range` row was actually left in
        // after it was closed.
        assert_eq!(
            question.status == "observed",
            question.reason == "settled",
            "{} is {} but pending for the reason {}",
            question.topic,
            question.status,
            question.reason
        );

        // An outcome exists only once the question has been answered, and a question that is only
        // *partly* answered must say in its outcome what remains — otherwise "partly" becomes a
        // place to record a win without recording the shortfall.
        if question.status == "partly_observed" {
            let outcome = question
                .outcome
                .as_deref()
                .ok_or("a partly observed question records no outcome")?;
            assert!(
                outcome.contains("still to do") || outcome.contains("Not closed"),
                "{} is partly observed and does not say what remains",
                question.topic
            );
        }
        if question.status == "unobserved" {
            assert!(
                question.outcome.is_none(),
                "{} is unobserved and has an outcome",
                question.topic
            );
        } else {
            assert!(
                question.outcome.is_some(),
                "{} is observed and has no outcome",
                question.topic
            );
        }
    }
    Ok(())
}

#[test]
fn every_scattered_obligation_is_tracked_or_argued_away() -> Result<(), Box<dyn Error>> {
    let ledger = ledger()?;
    let statuses: BTreeSet<&str> = ledger.statuses.iter().map(String::as_str).collect();

    // The maintainer decision of 2026-08-28 was to collect these rather than leave them in prose.
    assert!(
        ledger.obligations.len() >= 30,
        "only {} obligations were collected",
        ledger.obligations.len()
    );

    let mut lines = BTreeSet::new();
    for obligation in &ledger.obligations {
        assert!(statuses.contains(obligation.status.as_str()));
        assert!(obligation.porting_line > 0, "an obligation cites no line");
        assert!(lines.insert(obligation.porting_line), "two obligations cite one line");
        assert!(!obligation.record.is_empty(), "an obligation names no owning record");
        assert!(!obligation.claim.is_empty());

        if obligation.status == "out_of_scope" {
            // Moving work elsewhere is allowed; doing it silently is not.
            assert!(
                obligation.moves_to.is_some(),
                "PORTING.md:{} is out of scope and names no destination",
                obligation.porting_line
            );
            assert!(
                obligation.note.len() > 120,
                "PORTING.md:{} is moved without an argument",
                obligation.porting_line
            );
        } else {
            assert!(
                obligation.settling_observation.is_some(),
                "PORTING.md:{} names nothing that would settle it",
                obligation.porting_line
            );
            let reason = obligation
                .reason
                .as_deref()
                .ok_or("an outstanding obligation names no reason")?;
            assert!(
                ledger.reasons.iter().any(|known| known == reason),
                "PORTING.md:{} is outstanding for the unrecognised reason {reason}",
                obligation.porting_line
            );

            // The same rule the open questions carry: `settled` and `observed` mean one thing and
            // must travel together, so a settled obligation cannot keep the reason it was pending
            // for and read as though nothing was ever recorded.
            assert_eq!(
                obligation.status == "observed",
                reason == "settled",
                "PORTING.md:{} is {} but outstanding for the reason {reason}",
                obligation.porting_line,
                obligation.status
            );
        }
    }

    // Not everything a live run touches is an integration question, and pretending otherwise would
    // make the matrix dishonest. A few are argued out, and the argument is required above.
    let moved = ledger
        .obligations
        .iter()
        .filter(|entry| entry.status == "out_of_scope")
        .count();
    assert!(
        moved > 0 && moved * 4 < ledger.obligations.len(),
        "{moved} obligations were moved"
    );
    Ok(())
}

#[test]
fn the_matrix_says_how_much_of_the_item_is_left() -> Result<(), Box<dyn Error>> {
    let ledger = ledger()?;

    // The point of 9.2b: "how much of 9.2 remains" is a number this test prints rather than a
    // judgement someone makes. While every row is unobserved, that number is all of it.
    let answered = ledger
        .scenarios
        .iter()
        .filter(|entry| entry.status == "observed")
        .count();
    let settled = ledger
        .open_questions
        .iter()
        .filter(|entry| entry.status == "observed")
        .count();
    let discharged = ledger
        .obligations
        .iter()
        .filter(|entry| entry.status != "unobserved")
        .count();

    assert!(answered <= ledger.scenarios.len());
    assert!(settled <= ledger.open_questions.len());
    assert!(discharged <= ledger.obligations.len());

    // Every row still carries a reason, so nothing is silently pending.
    for scenario in ledger.scenarios.iter().filter(|entry| entry.status == "unobserved") {
        assert!(!scenario.reason.is_empty());
    }
    Ok(())
}

#[test]
fn the_suites_own_shape_is_recorded_faithfully() -> Result<(), Box<dyn Error>> {
    let inventory = inventory()?;

    // The families the suite reaches are the client's, and only the client's — `Date.now()` and
    // `new Date().toISOString()` are the same `x().y()` shape and must not be counted as endpoints.
    let known: BTreeSet<&str> = [
        "challenges",
        "config",
        "contacts",
        "credentials",
        "delegations",
        "escrows",
        "exchanges",
        "groups",
        "identifiers",
        "ipex",
        "keyEvents",
        "keyStates",
        "notifications",
        "oobis",
        "operations",
        "registries",
        "schemas",
    ]
    .into_iter()
    .collect();
    assert!(!inventory.families.is_empty());
    for family in &inventory.families {
        assert!(
            known.contains(family.family.as_str()),
            "{} is not an endpoint family",
            family.family
        );
        assert!(family.calls > 0);
    }

    // Every call recorded against a file names one of those families and a method.
    for file in &inventory.files {
        for call in &file.api_calls {
            assert!(
                known.contains(call.family.as_str()),
                "{} calls {}",
                file.file,
                call.family
            );
            assert!(!call.method.is_empty());
            assert!(call.count > 0);
        }

        // Witness need is the union of naming them and inheriting them from a helper's defaults.
        let infrastructure = &file.infrastructure;
        assert_eq!(
            infrastructure.witnesses.needed,
            infrastructure.witnesses.named || infrastructure.witnesses.inherited,
            "{} reports its witness need inconsistently",
            file.file
        );
        assert!(infrastructure.clients >= 1);
        if infrastructure.vlei {
            assert!(
                infrastructure.oobis,
                "{} needs schemas without resolving an OOBI",
                file.file
            );
        }

        // A file's defect count agrees with the defects recorded against it.
        let counted = inventory
            .defects
            .iter()
            .filter(|defect| defect.file == file.file)
            .count();
        assert_eq!(counted, file.defects, "{} miscounts its defects", file.file);
    }

    // Shared mutable scope is how state leaks between cases upstream, so it is recorded per file
    // rather than described. Several files carry a great deal of it.
    let leaky: Vec<&FileEntry> = inventory
        .files
        .iter()
        .filter(|file| file.cases > 1 && !file.shared_state.is_empty())
        .collect();
    assert!(
        !leaky.is_empty(),
        "no multi-case file shares mutable state; the detector or the reference changed"
    );

    Ok(())
}

#[test]
fn the_suites_cases_are_recorded_faithfully() -> Result<(), Box<dyn Error>> {
    let inventory = inventory()?;

    // Four of the twenty-two files label their internal steps; the other eighteen narrate with
    // `console.log` or not at all. That is why steps cannot key the matrix and API calls must.
    let stepped: BTreeSet<&str> = inventory
        .cases
        .iter()
        .filter(|case| !case.steps.is_empty())
        .map(|case| case.file.as_str())
        .collect();
    assert_eq!(stepped.len(), 4, "the suite's use of `step()` changed: {stepped:?}");
    assert!(stepped.contains("test-integration/credentials.test.ts"));
    assert!(
        stepped.len() * 4 < inventory.totals.files,
        "most of the suite now labels its steps, so the matrix could key on them"
    );

    // Each case knows where it is and what it asserts through.
    for case in &inventory.cases {
        assert!(case.line > 0 && case.lines > 0, "{} has no position", case.title);
        assert!(!case.title.is_empty());
        if case.assertions > 0 {
            assert!(
                !case.helpers.is_empty(),
                "{} asserts through nothing recognised",
                case.title
            );
        }
        assert!(!case.group.is_empty() || case.file.ends_with(".test.ts"));

        // A case's own calls are a subset of its file's — the rest live in helpers declared
        // outside the case body, which is why the file-level count is the one the matrix uses.
        let within: usize = case.api_calls.iter().map(|call| call.count).sum();
        let whole: usize = inventory
            .files
            .iter()
            .find(|file| file.file == case.file)
            .map(|file| file.api_calls.iter().map(|call| call.count).sum())
            .unwrap_or_default();
        assert!(within <= whole, "{} makes more calls than its file does", case.title);
    }
    Ok(())
}
