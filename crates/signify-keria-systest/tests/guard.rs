//! The one test in this crate that is **not** ignored.
//!
//! That every live scenario carries `#[ignore]`, checked by reading the crate's own test sources.

use std::error::Error;
use std::fs;
use std::path::Path;

fn scenario_sources() -> Result<Vec<(String, String)>, Box<dyn Error>> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut sources = Vec::new();
    for entry in fs::read_dir(&directory)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        let is_rust = path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"));
        if !name.starts_with("wave") || !is_rust {
            continue;
        }
        sources.push((name, fs::read_to_string(&path)?));
    }
    sources.sort();
    Ok(sources)
}

#[test]
fn every_live_test_is_ignored_by_default() -> Result<(), Box<dyn Error>> {
    let mut unguarded = Vec::new();

    for (name, source) in scenario_sources()? {
        let lines: Vec<&str> = source.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if !(trimmed.starts_with("fn ") || trimmed.starts_with("async fn ")) {
                continue;
            }
            let mut attributes = Vec::new();
            let mut cursor = index;
            while cursor > 0 {
                cursor -= 1;
                let above = lines.get(cursor).map(|line| line.trim()).unwrap_or_default();
                if above.starts_with("#[") || above.starts_with("//") || above.is_empty() {
                    if above.starts_with("#[") {
                        attributes.push(above);
                    }
                    if above.is_empty() && !attributes.is_empty() {
                        break;
                    }
                } else {
                    break;
                }
            }
            let is_test = attributes
                .iter()
                .any(|attribute| attribute.contains("#[test]") || attribute.contains("test]"));
            if !is_test {
                continue;
            }
            let ignored = attributes.iter().any(|attribute| attribute.contains("#[ignore"));
            if !ignored {
                unguarded.push(format!("{name}:{} — {trimmed}", index + 1));
            }
        }
    }

    assert!(
        unguarded.is_empty(),
        "these tests talk to a live KERIA and would run in the default suite: {unguarded:#?}"
    );
    Ok(())
}

#[test]
fn the_live_scenarios_are_named_so_the_guard_can_find_them() -> Result<(), Box<dyn Error>> {
    let live = scenario_sources()?;
    assert!(
        !live.is_empty(),
        "no `wave*.rs` scenarios exist, so the guard checks nothing"
    );
    for (name, source) in &live {
        assert!(
            source.contains("#[ignore"),
            "{name} is a live scenario file with no ignored test in it"
        );
    }
    Ok(())
}

#[test]
fn the_crate_documents_how_to_run_its_tests() -> Result<(), Box<dyn Error>> {
    let lib = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))?;
    assert!(lib.contains("--ignored"), "the crate does not say how to run its tests");
    assert!(
        lib.contains("--test-threads=1"),
        "the crate does not say that recording runs must be serial"
    );
    assert!(
        lib.contains("SIGNIFY_KERIA_PRESET"),
        "the crate does not name the variable that selects a deployment"
    );
    Ok(())
}

#[test]
fn every_scenario_says_how_to_run_itself() -> Result<(), Box<dyn Error>> {
    // A scenario is run one file at a time, so the crate-level invocation is not enough: a reader
    // opening one needs the `--test` target that runs *it*. These were lost once to a comment
    // sweep and restored, which is why the convention is checked rather than remembered.
    let mut wrong = Vec::new();
    for (name, source) in scenario_sources()? {
        let stem = name.strip_suffix(".rs").unwrap_or(&name);
        if !source.contains("```text") {
            wrong.push(format!("{name} does not say how to run itself"));
        } else if !source.contains(&format!("--test {stem}")) {
            wrong.push(format!("{name} names a --test target that is not its own"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
    Ok(())
}
