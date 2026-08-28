//! Which deployment a system test runs against.
//!
//! The reference has the same idea in `test-integration/utils/resolve-env.ts`: a `local` preset and
//! a `docker` one. This mirrors it, with two deliberate differences.
//!
//! **There is no default.** The reference falls back to `docker` when `TEST_ENVIRONMENT` is unset,
//! and an unset variable that silently means something is how a run ends up describing a deployment
//! it was not talking to. Here the variable is required, and a missing one is an error naming it.
//!
//! **Every effective value is recorded.** A per-field override makes an unusual deployment
//! expressible without inventing a third preset, and the manifest carries what the run actually
//! used rather than leaving it in a shell history.
//!
//! # Why the two presets differ only in hostnames
//!
//! KERIA is `127.0.0.1` in both, which reads like an oversight and is not. The witness and schema
//! URLs are handed *to KERIA*, which resolves them itself: a KERIA in a container reaches its
//! neighbours by service name, one on the host reaches them on `localhost`. The reference's own
//! file does not say so anywhere.

use std::env;
use std::fmt;

/// Environment variable naming the preset. Required; there is no default.
pub const PRESET_VARIABLE: &str = "SIGNIFY_KERIA_PRESET";

/// The three witnesses the demo configuration serves.
///
/// One place, where the reference inlines this triple in nine files despite exporting it from
/// `resolve-env.ts`.
pub const WITNESS_PREFIXES: [&str; 3] = [
    "BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha",
    "BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM",
    "BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX",
];

/// Which deployment the URLs describe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Preset {
    /// KERIA runs on this host, and reaches its witnesses on `localhost`.
    Local,
    /// KERIA runs in a container, and reaches its neighbours by service name.
    Docker,
}

impl Preset {
    /// Returns the preset's name as the environment variable spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Docker => "docker",
        }
    }
}

impl fmt::Display for Preset {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Everything a system test needs to reach a deployment.
#[derive(Clone, Debug)]
pub struct Environment {
    /// Which preset produced these values.
    pub preset: Preset,
    /// KERIA's administrative interface.
    pub admin_url: String,
    /// KERIA's boot interface.
    pub boot_url: String,
    /// Where KERIA's own `OpenAPI` document is served.
    pub spec_url: String,
    /// The witness URLs **as KERIA resolves them**, not as this process would.
    pub witness_urls: Vec<String>,
    /// The witness prefixes those URLs should serve.
    pub witness_prefixes: Vec<String>,
    /// Where the vLEI schema server is, as KERIA resolves it.
    pub schema_url: String,
}

/// Why an environment could not be resolved.
#[derive(Clone, Debug)]
pub struct PresetError {
    message: String,
}

impl fmt::Display for PresetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PresetError {}

/// Reads one override, or falls back to the preset's value.
fn overridden(name: &str, fallback: &str) -> String {
    env::var(name).unwrap_or_else(|_| fallback.to_owned())
}

impl Environment {
    /// Resolves the environment named by [`PRESET_VARIABLE`].
    ///
    /// # Errors
    ///
    /// Returns [`PresetError`] when the variable is unset or names a preset this does not know.
    /// Unset is an error rather than a default: a run that guessed which deployment it was talking
    /// to could not honestly describe it afterwards.
    pub fn from_environment() -> Result<Self, PresetError> {
        let named = env::var(PRESET_VARIABLE).map_err(|_| PresetError {
            message: format!(
                "{PRESET_VARIABLE} is unset. Set it to `local` for a KERIA on this host, or \
                 `docker` for one in a container; there is deliberately no default."
            ),
        })?;
        let preset = match named.as_str() {
            "local" => Preset::Local,
            "docker" => Preset::Docker,
            other => {
                return Err(PresetError {
                    message: format!("{PRESET_VARIABLE} is `{other}`; it must be `local` or `docker`"),
                });
            }
        };
        Ok(Self::for_preset(preset))
    }

    /// Builds the environment one preset describes, applying any per-field overrides.
    #[must_use]
    pub fn for_preset(preset: Preset) -> Self {
        // KERIA is on this host either way — what changes is how *KERIA* reaches its neighbours.
        let host = match preset {
            Preset::Local => "localhost",
            Preset::Docker => "witness-demo",
        };
        let schema_host = match preset {
            Preset::Local => "localhost",
            Preset::Docker => "vlei-server",
        };
        Self {
            preset,
            admin_url: overridden("SIGNIFY_KERIA_ADMIN_URL", "http://127.0.0.1:3901"),
            boot_url: overridden("SIGNIFY_KERIA_BOOT_URL", "http://127.0.0.1:3903"),
            spec_url: overridden("SIGNIFY_KERIA_SPEC_URL", "http://127.0.0.1:3902/spec.yaml"),
            witness_urls: env::var("SIGNIFY_KERIA_WITNESS_URLS").map_or_else(
                |_| (5642..=5644).map(|port| format!("http://{host}:{port}")).collect(),
                |value| value.split(',').map(|url| url.trim().to_owned()).collect(),
            ),
            witness_prefixes: WITNESS_PREFIXES.iter().map(|prefix| (*prefix).to_owned()).collect(),
            schema_url: overridden("SIGNIFY_KERIA_SCHEMA_URL", &format!("http://{schema_host}:7723")),
        }
    }

    /// Returns the environment variables this run actually used, for the manifest.
    ///
    /// §7 asks a system test to record its environment variables. Reading them back here means the
    /// manifest describes the run rather than the shell that started it.
    #[must_use]
    pub fn recorded_variables(&self) -> Vec<(String, String)> {
        let mut recorded = vec![(PRESET_VARIABLE.to_owned(), self.preset.to_string())];
        for name in [
            "SIGNIFY_KERIA_ADMIN_URL",
            "SIGNIFY_KERIA_BOOT_URL",
            "SIGNIFY_KERIA_SPEC_URL",
            "SIGNIFY_KERIA_WITNESS_URLS",
            "SIGNIFY_KERIA_SCHEMA_URL",
        ] {
            if let Ok(value) = env::var(name) {
                recorded.push((name.to_owned(), value));
            }
        }
        recorded
    }
}
