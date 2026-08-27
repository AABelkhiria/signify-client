//! What a client needs before it can talk to anything: two URLs, a passcode, and a security tier.
//!
//! This ports the `SignifyClient` constructor of the pinned `src/keri/app/clienting.ts`, whose
//! whole validation is one length check on the passcode. Here the URLs are validated too, because
//! Roadmap 5.3's [`BaseUrl`] can refuse a malformed one before any request is built rather than
//! after one has failed.

use core::fmt;

use signify_crypto::salt::SecurityTier;
use signify_http::request::BaseUrl;
use signify_keri::manager::DerivationCost;

use crate::error::ClientError;

/// Boot URL a client uses when none is given; the reference's `DEFAULT_BOOT_URL`.
pub const DEFAULT_BOOT_URL: &str = "http://localhost:3903";

/// Exact length of a client passcode, in characters.
///
/// The reference checks `bran.length < 21` and then slices the first 21 characters, so a longer
/// one is silently truncated. Here the length is exact, because a passcode that derives different
/// keys from the one a caller typed is worse than one that is refused.
pub const PASSCODE_LENGTH: usize = 21;

/// A validated client passcode; the reference's `bran`.
///
/// This is the only secret a client configuration holds, so it redacts its `Debug` and its
/// `Display` and exposes its characters through one narrowly named accessor.
#[derive(Clone)]
pub struct Passcode {
    text: String,
}

impl Passcode {
    /// Validates one passcode.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidPasscodeLength`] unless the input is exactly
    /// [`PASSCODE_LENGTH`] characters, and [`ClientError::PasscodeNotBase64`] when a character is
    /// outside the URL-safe Base64 alphabet the reference's own `randomPasscode` produces.
    pub fn new(text: impl Into<String>) -> Result<Self, ClientError> {
        let text = text.into();
        let length = text.chars().count();
        if length != PASSCODE_LENGTH {
            return Err(ClientError::InvalidPasscodeLength {
                expected: PASSCODE_LENGTH,
                actual: length,
            });
        }
        if let Some(position) = text
            .chars()
            .position(|character| !character.is_ascii_alphanumeric() && character != '-' && character != '_')
        {
            return Err(ClientError::PasscodeNotBase64 { position });
        }
        Ok(Self { text })
    }

    /// Returns the passcode's characters.
    ///
    /// Named to make a call site read as the disclosure it is.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.text
    }
}

impl fmt::Debug for Passcode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Passcode(<redacted>)")
    }
}

/// Everything a client is configured with.
///
/// ```
/// use signify_client::config::{ClientConfig, DEFAULT_BOOT_URL};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = ClientConfig::new("http://127.0.0.1:3901", "0123456789abcdefghijk")?;
/// assert_eq!(config.admin_url().as_str(), "http://127.0.0.1:3901");
/// assert_eq!(config.boot_url().as_str(), DEFAULT_BOOT_URL);
///
/// // The reference's only validation, kept: a passcode is exactly 21 characters.
/// assert!(ClientConfig::new("http://127.0.0.1:3901", "short").is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct ClientConfig {
    admin_url: BaseUrl,
    boot_url: BaseUrl,
    passcode: Passcode,
    tier: SecurityTier,
    derivation_cost: DerivationCost,
}

impl ClientConfig {
    /// Builds a configuration against the default boot URL and security tier.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Request`] for an unusable URL and the passcode failures listed on
    /// [`Passcode::new`].
    pub fn new(admin_url: &str, passcode: &str) -> Result<Self, ClientError> {
        Ok(Self {
            admin_url: BaseUrl::new(admin_url)?,
            boot_url: BaseUrl::new(DEFAULT_BOOT_URL)?,
            passcode: Passcode::new(passcode)?,
            tier: SecurityTier::Low,
            derivation_cost: DerivationCost::Production,
        })
    }

    /// Points the client at a different boot interface.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Request`] for an unusable URL.
    pub fn with_boot_url(mut self, boot_url: &str) -> Result<Self, ClientError> {
        self.boot_url = BaseUrl::new(boot_url)?;
        Ok(self)
    }

    /// Sets the security tier the controller's keys derive under.
    #[must_use]
    pub const fn with_tier(mut self, tier: SecurityTier) -> Self {
        self.tier = tier;
        self
    }

    /// Sets how much key derivation costs.
    ///
    /// The reference has no equivalent — it always pays the production profile. The cheap profile
    /// exists for tests and derives **different keys**, so a client configured with it cannot talk
    /// to an agent booted without it.
    #[must_use]
    pub const fn with_derivation_cost(mut self, cost: DerivationCost) -> Self {
        self.derivation_cost = cost;
        self
    }

    /// Returns the KERIA admin interface URL.
    #[must_use]
    pub const fn admin_url(&self) -> &BaseUrl {
        &self.admin_url
    }

    /// Returns the KERIA boot interface URL.
    #[must_use]
    pub const fn boot_url(&self) -> &BaseUrl {
        &self.boot_url
    }

    /// Returns the passcode.
    #[must_use]
    pub const fn passcode(&self) -> &Passcode {
        &self.passcode
    }

    /// Replaces the passcode, for a client that has rotated to a new one.
    ///
    /// Every other setting is kept, so a rotated client speaks to the same agent with the same
    /// tier and derivation cost.
    #[must_use]
    pub fn with_passcode(mut self, passcode: Passcode) -> Self {
        self.passcode = passcode;
        self
    }

    /// Returns the security tier.
    #[must_use]
    pub const fn tier(&self) -> SecurityTier {
        self.tier
    }

    /// Returns the derivation cost.
    #[must_use]
    pub const fn derivation_cost(&self) -> DerivationCost {
        self.derivation_cost
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const PASSCODE: &str = "0123456789abcdefghijk";
    const ADMIN: &str = "http://127.0.0.1:3901";

    #[test]
    fn a_passcode_is_exactly_twenty_one_characters() {
        assert!(Passcode::new(PASSCODE).is_ok());
        assert!(matches!(
            Passcode::new("short"),
            Err(ClientError::InvalidPasscodeLength {
                expected: 21,
                actual: 5
            })
        ));
        // The reference silently truncates a longer one; here it is refused.
        assert!(matches!(
            Passcode::new("0123456789abcdefghijkl"),
            Err(ClientError::InvalidPasscodeLength {
                expected: 21,
                actual: 22
            })
        ));
    }

    #[test]
    fn a_passcode_holds_only_url_safe_base64_characters() {
        assert!(Passcode::new("0123456789abcdefghi-_").is_ok());
        assert!(matches!(
            Passcode::new("0123456789abcdefghi+/"),
            Err(ClientError::PasscodeNotBase64 { position: 19 })
        ));
        assert!(matches!(
            Passcode::new("0123456789abcdefghij "),
            Err(ClientError::PasscodeNotBase64 { position: 20 })
        ));
    }

    #[test]
    fn a_passcode_never_prints_itself() -> Result<(), Box<dyn Error>> {
        let passcode = Passcode::new(PASSCODE)?;
        let rendered = format!("{passcode:?}");
        assert!(!rendered.contains(PASSCODE), "{rendered}");
        assert_eq!(rendered, "Passcode(<redacted>)");
        assert_eq!(passcode.expose(), PASSCODE);
        Ok(())
    }

    #[test]
    fn a_configuration_never_prints_its_passcode() -> Result<(), Box<dyn Error>> {
        let config = ClientConfig::new(ADMIN, PASSCODE)?;
        let rendered = format!("{config:?}");
        assert!(!rendered.contains(PASSCODE), "{rendered}");
        assert!(rendered.contains("<redacted>"));
        Ok(())
    }

    #[test]
    fn the_defaults_are_the_references_own() -> Result<(), Box<dyn Error>> {
        let config = ClientConfig::new(ADMIN, PASSCODE)?;
        assert_eq!(config.admin_url().as_str(), ADMIN);
        assert_eq!(config.boot_url().as_str(), DEFAULT_BOOT_URL);
        assert_eq!(config.tier(), SecurityTier::Low);
        assert_eq!(config.derivation_cost(), DerivationCost::Production);
        Ok(())
    }

    #[test]
    fn the_overrides_take_effect() -> Result<(), Box<dyn Error>> {
        let config = ClientConfig::new(ADMIN, PASSCODE)?
            .with_boot_url("http://127.0.0.1:3903")?
            .with_tier(SecurityTier::High)
            .with_derivation_cost(DerivationCost::Ephemeral);
        assert_eq!(config.boot_url().as_str(), "http://127.0.0.1:3903");
        assert_eq!(config.tier(), SecurityTier::High);
        assert_eq!(config.derivation_cost(), DerivationCost::Ephemeral);
        Ok(())
    }

    #[test]
    fn a_malformed_url_is_refused_before_any_request_is_built() {
        assert!(ClientConfig::new("not a url", PASSCODE).is_err());
        assert!(matches!(
            ClientConfig::new(ADMIN, PASSCODE).and_then(|config| config.with_boot_url("also not a url")),
            Err(ClientError::Request { .. })
        ));
    }
}
