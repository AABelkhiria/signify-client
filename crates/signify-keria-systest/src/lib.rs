//! Opt-in system tests against a live KERIA, and the fixtures they record.
//!
//! Every other crate in this workspace is proven against the pinned reference's own recorded
//! traffic. This one is the exception: it talks to a deployment. `ARCHITECTURE.md` §11 provides for
//! exactly one such layer — "KERIA system tests, Docker/test deployment, opt-in" — and
//! `AGENTS.md` §16 forbids live network services in default tests outright.
//!
//! # How both hold at once
//!
//! **A live run's product is a fixture, not a green tick.** Each scenario records what it asked and
//! what the deployment answered into `fixtures/keria-integration/observations/`, and hermetic tests
//! in `signify-client` then assert against those recordings. That is the same generator/fixture
//! split the rest of the port already uses, pointed at a deployment instead of at Node — and it is
//! what turns "passes against latest", which `PORTING.md` §7 rejects, into something diffable.
//!
//! # How these tests stay out of the default suite
//!
//! Two mechanisms, because one is not enough.
//!
//! The `live` feature carries the production transport and, with it, a TLS stack. It is off by
//! default: this crate is the first to depend on both `keri-cesr` and `rustls`, and `ring`
//! pins a `getrandom` the workspace does not otherwise use, so an unconditional dependency would
//! put a duplicate in every build graph and `clippy::cargo` would rightly object.
//!
//! **The feature alone hides nothing**, because `cargo test --workspace --all-features` turns it
//! on. So every network test also carries `#[ignore]`, which no feature flag can override. Ignored
//! tests are still compiled and linked under `--all-features`, so they are covered by
//! `cargo clippy --all-targets` and cannot rot.
//!
//! `tests/guard.rs` is **not** ignored: it reads this crate's own test sources and fails if a live
//! test is missing its `#[ignore]`. `AGENTS.md` §16's prohibition is thereby enforced rather than
//! remembered.
//!
//! Run them deliberately:
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local cargo test -p signify-keria-systest --features live \
//!     -- --ignored --test-threads=1
//! ```
//!
//! Add `SIGNIFY_RECORD=1` to write what the run observed back into
//! `fixtures/keria-integration/`, which is what makes a run evidence rather than a green tick.
//!
//! The credential and IPEX scenarios additionally need a schema source — any host answering
//! `/oobi/{said}`, named by `SIGNIFY_KERIA_SCHEMA_URL`. The preset defaults to the vLEI container
//! the reference's compose file uses; `SIGNIFY_KERIA_SCHEMA_URL=http://localhost:3001` points at a
//! Veridian credential server instead. Which schemas a source serves decides which scenarios can
//! run, and `fixtures/keria-integration/README.md` carries that table.
//!
//! `--test-threads=1` is not decoration. The reference runs its own suite with
//! `fileParallelism: false` and `bail: 1` because scenarios share one agent's contacts and
//! notifications; a recording that raced is not evidence, and the manifest records the policy.

pub mod preset;
pub mod recorder;

/// Operation and notification plumbing. Live-only: it reaches a deployment.
#[cfg(feature = "live")]
pub mod operation;

/// The credential lifecycle driven by one identifier.
#[cfg(feature = "live")]
pub mod singlesig;

/// The same lifecycle driven by a multisig group, one propose/accept round per step.
#[cfg(feature = "live")]
pub mod group;

use std::error::Error;

pub use preset::{Environment, Preset};
pub use recorder::{Observation, Recorder};

#[cfg(feature = "live")]
pub use operation::{
    agent_oobi, await_notification, await_proposals, resolve_oobi, resolve_schema, wait_and_delete, witness_prefixes,
};

/// Environment variable that turns a run into a recording run.
pub const RECORD_VARIABLE: &str = "SIGNIFY_RECORD";

/// Whether this run should write its observations back to the fixtures.
#[must_use]
pub fn recording() -> bool {
    std::env::var(RECORD_VARIABLE).is_ok_and(|value| value == "1")
}

/// Says on stderr what a scenario is doing, stamped with seconds since the first call.
///
/// A live scenario spends most of its time waiting on operations, and the harness captures test
/// output, so a run looks hung unless invoked with `--nocapture`. The elapsed stamp is what makes
/// the lines useful: it shows which wait is the slow one.
#[expect(
    clippy::print_stderr,
    reason = "progress reporting for opt-in live runs in a test-only crate; \
              AGENTS.md §2.2 restricts printing in public libraries, which this is not"
)]
pub fn progress(message: &str) {
    static STARTED: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let elapsed = STARTED.get_or_init(std::time::Instant::now).elapsed();
    eprintln!("[{:>7.1}s] {message}", elapsed.as_secs_f64());
}

#[cfg(feature = "live")]
mod live {
    //! The half that needs a TLS stack, and so a feature.
    //!
    //! `live` is off by default because most builds of this workspace never run a scenario, and
    //! carrying hyper and rustls for them would put a duplicate `getrandom` in every graph — the
    //! duplicate `ring` pins and nothing here can resolve.

    use std::error::Error;
    use std::sync::Arc;

    use keri_cesr::crypto::salt::SecurityTier;
    use keri_protocol::prefix::IdentifierPrefix;
    use keria_types::api::Role;
    use signify_client::client::{ConnectedClient, SignifyClient};
    use signify_client::config::ClientConfig;
    use signify_client::endpoint::oobis::OobiResolution;
    use signify_http::retry::TokioClock;
    use signify_http::transport::RequestUrl;
    use signify_http::transport::{HttpTransport, Transport};
    use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest};
    use signify_keri::manager::DerivationCost;

    use crate::preset::Environment;
    use crate::recorder::Recorder;

    /// Builds a client against `environment`, recording every exchange.
    ///
    /// The transport is the production one — this is the only place in the workspace where
    /// [`HttpTransport`] meets a real server other than the loopback test that binds its own socket —
    /// and the clock is [`TokioClock`], which closes the `PORTING.md` obligation that it is "wired but
    /// not exercised against real time".
    ///
    /// # Errors
    ///
    /// Returns whatever configuring the client, building the transport, or connecting returns.
    pub async fn connect(
        environment: &Environment,
        passcode: &str,
        recorder: &Arc<Recorder>,
    ) -> Result<ConnectedClient, Box<dyn Error>> {
        let config = ClientConfig::new(&environment.admin_url, passcode)?.with_boot_url(&environment.boot_url)?;
        let transport = Arc::clone(recorder) as Arc<dyn Transport>;
        let client = SignifyClient::new(config, transport, Arc::new(TokioClock))?;
        client.boot().await?;
        let connected = client.connect().await?;
        Ok(connected)
    }

    /// Connects to an agent that already exists, without booting it.
    ///
    /// What a client does the second time it starts — and the only way to prove a passcode rotation
    /// took, since the new passcode has to derive the controller the agent now holds. `controller`
    /// is the prefix a client must persist with its passcode: a rotated controller keeps the prefix
    /// its first passcode incepted, which the new passcode does not derive. `None` connects by the
    /// prefix the passcode incepts, as a client that never rotated does.
    ///
    /// # Errors
    ///
    /// Returns whatever building the configuration, the client, or the connection returns.
    pub async fn reconnect(
        environment: &Environment,
        passcode: &str,
        controller: Option<&IdentifierPrefix>,
        recorder: &Arc<Recorder>,
    ) -> Result<ConnectedClient, Box<dyn Error>> {
        let mut config = ClientConfig::new(&environment.admin_url, passcode)?.with_boot_url(&environment.boot_url)?;
        if let Some(controller) = controller {
            config = config.with_controller_prefix(controller.clone());
        }
        let transport = Arc::clone(recorder) as Arc<dyn Transport>;
        let client = SignifyClient::new(config, transport, Arc::new(TokioClock))?;
        Ok(client.connect().await?)
    }

    /// Creates a single-signature identifier and authorises the agent to speak for it.
    ///
    /// Two steps, always together. An identifier that has not authorised its agent **publishes no
    /// OOBI**, so a second client cannot learn it — which is how the first draft of the
    /// `sequence_base` scenario failed, with "the owner published no OOBI" and nothing to say why.
    ///
    /// The end role is added **immediately after inception**, before any interaction advances the
    /// log. Added later, a live KERIA refuses the reply with
    /// `400 "unable to verify end role reply message"`. That ordering is recorded here rather than
    /// explained, because nothing observed so far establishes the cause.
    ///
    /// The passcode is `None` deliberately: an explicit one derives from the passcode alone, so
    /// several identifiers created for one client would all land on the same prefix and the second
    /// would be refused with "Already incepted".
    ///
    /// # Errors
    ///
    /// Returns whatever creating the identifier, waiting on either operation, or authorising the
    /// role returns.
    pub async fn ready_identifier(client: &ConnectedClient, alias: &str) -> Result<IdentifierPrefix, Box<dyn Error>> {
        let request = CreateIdentifierRequest::new(CreateAlgorithm::Salty {
            passcode: None,
            tier: SecurityTier::Low,
            current_count: 1,
            next_count: 1,
            cost: DerivationCost::Production,
        });
        crate::progress(&format!("{alias}: creating an identifier"));
        let created = client.identifiers().create(alias, &request).await?;
        client.poller().wait(created.operation()?).await?;
        let prefix = created.artifact().event.identifier().clone();

        crate::progress(&format!(
            "{alias}: incepted as {prefix}, authorising the agent end role"
        ));
        let agent = client.agent().prefix().clone();
        let authorised = client
            .identifiers()
            .add_end_role(alias, &Role::Agent, Some(&agent), crate::now()?)
            .await?;
        client.poller().wait(authorised.operation()?).await?;
        crate::progress(&format!("{alias}: agent end role authorised"));
        Ok(prefix)
    }

    /// Introduces one client's identifier to another, the way a stranger would learn it.
    ///
    /// Fetches the agent OOBI `alias` publishes and resolves it on `to`. Scenarios that ask an
    /// agent about a prefix need this: a query about an identifier the agent already owns may be
    /// answered from its local key event log, without the exchange the scenario is about happening
    /// at all.
    ///
    /// # Errors
    ///
    /// Returns an error when the identifier publishes no OOBI, and whatever resolving it returns.
    pub async fn introduce(from: &ConnectedClient, alias: &str, to: &ConnectedClient) -> Result<(), Box<dyn Error>> {
        crate::progress(&format!("introducing {alias} to the other client"));
        let published = from.oobis().get(alias, &Role::Agent).await?;
        let url = published
            .oobis
            .first()
            .ok_or_else(|| format!("{alias} published no OOBI, so it cannot be introduced"))?;
        crate::progress(&format!("{alias}: URL {url}"));
        let resolution = OobiResolution {
            url: RequestUrl::new(url.clone())?,
            alias: Some(alias.to_owned()),
        };
        crate::progress(&format!("resolving {alias}'s OOBI on the other client"));
        let resolved = to.oobis().resolve(&resolution).await?;
        to.poller().wait(resolved).await?;
        crate::progress(&format!("{alias} introduced"));
        Ok(())
    }

    /// Builds a recorder over the production transport.
    ///
    /// # Errors
    ///
    /// Returns whatever building the transport returns.
    pub fn recorder(scenario: &str) -> Result<Arc<Recorder>, Box<dyn Error>> {
        // On macOS the first read of the platform trust store in a fresh process has failed with
        // `errSecIO` (-36) while every later read in the same process succeeded — observed on
        // 2026-09-16 across three wave-16 runs, the first test of each binary failing at connect
        // and the second passing. One retry is the harness's answer; the deployment is plain HTTP
        // and never presents a certificate.
        let transport = match HttpTransport::new() {
            Ok(transport) => transport,
            Err(first) => {
                crate::progress(&format!("the transport failed to build once ({first}); retrying"));
                HttpTransport::new()?
            }
        };
        Ok(Recorder::new(scenario, Arc::new(transport)))
    }

    /// Prints the tail of every recorder's transcript, for a scenario that failed mid-way.
    ///
    /// A live failure's error names a decoder or a status and nothing else; the exchange that
    /// produced it is in the transcript, which a failed run never writes out.
    pub fn dump_tails(recorders: &[&Recorder], count: usize) {
        for recorder in recorders {
            let observations = recorder.observations();
            let start = observations.len().saturating_sub(count);
            for observation in observations.iter().skip(start) {
                let body = observation.response_body.as_deref().unwrap_or_default();
                let shown: String = body.chars().take(600).collect();
                crate::progress(&format!(
                    "{} {} -> {} {shown}",
                    observation.method, observation.resource, observation.status
                ));
                if observation.status >= 400 {
                    for (name, value) in &observation.request_headers {
                        crate::progress(&format!("  > {name}: {value}"));
                    }
                    let sent = observation.request_body.as_deref().unwrap_or_default();
                    crate::progress(&format!("  > body: {}", sent.chars().take(900).collect::<String>()));
                }
            }
        }
    }
}

#[cfg(feature = "live")]
pub use live::{connect, dump_tails, introduce, ready_identifier, reconnect, recorder};

/// Returns the current instant as a KERI timestamp.
///
/// The port deliberately has no `Timestamp::now()`: every artifact that commits to a timestamp
/// takes it as an argument, so a caller cannot produce two artifacts that disagree about when they
/// were made. A live scenario is exactly the caller that needs the real clock, and it is the only
/// place in this workspace that reads it.
///
/// # Errors
///
/// Returns an error when the system clock is before the Unix epoch or the rendered text is not a
/// KERI timestamp.
pub fn now() -> Result<keri_protocol::event::Timestamp, Box<dyn Error>> {
    let elapsed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let seconds = i64::try_from(elapsed.as_secs())?;
    let micros = elapsed.subsec_micros();

    // Days since the epoch, then civil date, by Howard Hinnant's algorithm — no date dependency
    // for one timestamp in one test-only crate.
    let days = seconds.div_euclid(86_400);
    let time_of_day = seconds.rem_euclid(86_400);
    let era_days = days + 719_468;
    let era = era_days.div_euclid(146_097);
    let day_of_era = era_days.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);

    let text = format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{micros:06}+00:00",
        time_of_day / 3_600,
        (time_of_day % 3_600) / 60,
        time_of_day % 60,
    );
    Ok(text.parse::<keri_protocol::event::Timestamp>()?)
}

/// Where a recording run writes its evidence.
///
/// # Errors
///
/// Returns an error when the workspace root cannot be located from this crate's manifest.
pub fn fixtures_root() -> Result<std::path::PathBuf, Box<dyn Error>> {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .map(|root| root.join("fixtures/keria-integration"))
        .ok_or_else(|| "the workspace root is not two levels above the manifest".into())
}

/// Writes `value` under the fixtures directory, pretty-printed, when this is a recording run.
///
/// A run that is not recording returns `Ok(false)` and writes nothing, so the same scenario can be
/// used to check a deployment without rewriting the evidence.
///
/// # Errors
///
/// Returns an error when the directory cannot be created or the file cannot be written.
pub fn record<T: serde::Serialize>(relative: &str, value: &T) -> Result<bool, Box<dyn Error>> {
    if !recording() {
        return Ok(false);
    }
    let path = fixtures_root()?.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(true)
}
