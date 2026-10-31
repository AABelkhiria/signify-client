//! The passcode an identifier's own salt derives from.

use core::fmt;

use zeroize::Zeroizing;

/// A passcode; the reference's `bran`.
///
/// Redacts its `Debug`, and wipes its characters on drop.
#[derive(Clone)]
pub struct IdentifierPasscode(Zeroizing<String>);

impl IdentifierPasscode {
    /// Returns the passcode's characters.
    ///
    /// Named to make a call site read as the disclosure it is.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<String> for IdentifierPasscode {
    fn from(text: String) -> Self {
        Self(Zeroizing::new(text))
    }
}

impl From<&str> for IdentifierPasscode {
    fn from(text: &str) -> Self {
        Self(Zeroizing::new(text.to_owned()))
    }
}

impl fmt::Debug for IdentifierPasscode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdentifierPasscode(<redacted>)")
    }
}
