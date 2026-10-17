//! A validated absolute request URL that preserves its bytes exactly.
//!
//! # Why this does not normalize
//!
//! The request signature covers the `@path` derived component, so the bytes of a request's path are
//! part of what a signature covers. A WHATWG-style URL type normalizes as it parses — lowercasing
//! the host, resolving dot segments, adding a trailing slash to an empty path, re-encoding percent
//! escapes — and any of those would let the path that was *signed* differ from the path that is
//! *sent*. This type therefore validates without rewriting: what a caller supplies is what
//! [`RequestUrl::as_str`] returns and what a transport must put on the wire.

use core::fmt;

use crate::transport::error::TransportError;

/// Largest accepted URL, in bytes.
///
/// Well below what any server accepts, and far above any KERIA endpoint: the longest path in the
/// pinned reference is an identifier name inside `/identifiers/{name}/endroles`.
pub const MAX_URL_BYTES: usize = 2_048;

/// An absolute `http` or `https` URL, validated and preserved byte for byte.
///
/// ```
/// use signify_http::transport::RequestUrl;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let url = RequestUrl::new("https://keria.example/identifiers/aid1?limit=10")?;
/// assert_eq!(url.scheme(), "https");
/// assert_eq!(url.authority(), "keria.example");
/// assert_eq!(url.path(), "/identifiers/aid1");
/// assert_eq!(url.query(), Some("limit=10"));
///
/// // A fragment is never sent to a server, so a URL carrying one is refused rather than
/// // silently truncated.
/// assert!(RequestUrl::new("https://keria.example/path#fragment").is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequestUrl {
    text: String,
    /// Byte offset where the authority begins.
    authority_start: usize,
    /// Byte offset where the path begins, which is also where the authority ends.
    path_start: usize,
    /// Byte offset of the `?`, when there is a query.
    query_start: Option<usize>,
}

impl RequestUrl {
    /// Validates one absolute URL.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::InvalidUrl`] when the URL is empty or above [`MAX_URL_BYTES`],
    /// does not begin with an `http://` or `https://` scheme, has an empty authority, carries a
    /// fragment, or holds a byte outside visible ASCII.
    pub fn new(text: impl Into<String>) -> Result<Self, TransportError> {
        let text = text.into();
        let invalid = |reason: &'static str| TransportError::InvalidUrl { reason };

        if text.is_empty() {
            return Err(invalid("a URL may not be empty"));
        }
        if text.len() > MAX_URL_BYTES {
            return Err(invalid("a URL exceeds the accepted length"));
        }
        // Visible ASCII only: a space, a control byte, or a newline in a URL is how a request
        // line or a signed component gets forged.
        if !text.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(invalid("a URL may hold only visible ASCII"));
        }
        if text.contains('#') {
            return Err(invalid("a URL may not carry a fragment"));
        }

        let authority_start = if let Some(rest) = text.strip_prefix("http://") {
            let _ = rest;
            "http://".len()
        } else if text.starts_with("https://") {
            "https://".len()
        } else {
            return Err(invalid("a URL must begin with http:// or https://"));
        };

        let after_scheme = text.get(authority_start..).unwrap_or_default();
        let authority_length = after_scheme.find(['/', '?']).unwrap_or(after_scheme.len());
        if authority_length == 0 {
            return Err(invalid("a URL must name an authority"));
        }
        let path_start = authority_start.saturating_add(authority_length);
        let query_start = text
            .get(path_start..)
            .and_then(|rest| rest.find('?').map(|offset| path_start.saturating_add(offset)));

        Ok(Self {
            text,
            authority_start,
            path_start,
            query_start,
        })
    }

    /// Returns the URL exactly as supplied.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the scheme, without the `://`.
    #[must_use]
    pub fn scheme(&self) -> &str {
        self.text
            .get(..self.authority_start.saturating_sub("://".len()))
            .unwrap_or_default()
    }

    /// Returns the authority: host, and port when one is given.
    #[must_use]
    pub fn authority(&self) -> &str {
        self.text.get(self.authority_start..self.path_start).unwrap_or_default()
    }

    /// Returns the path, which is `/` when the URL carries none.
    ///
    /// This is the value a signature's `@path` component covers, so it never carries the query.
    #[must_use]
    pub fn path(&self) -> &str {
        let end = self.query_start.unwrap_or(self.text.len());
        match self.text.get(self.path_start..end) {
            Some("") | None => "/",
            Some(path) => path,
        }
    }

    /// Returns the query without its `?`, when the URL carries one.
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        let start = self.query_start?.checked_add(1)?;
        self.text.get(start..)
    }
}

impl fmt::Display for RequestUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn a_url_is_split_without_being_rewritten() -> Result<(), Box<dyn Error>> {
        let cases: [(&str, &str, &str, &str, Option<&str>); 6] = [
            (
                "https://keria.example/identifiers?limit=10",
                "https",
                "keria.example",
                "/identifiers",
                Some("limit=10"),
            ),
            ("http://localhost:3901/boot", "http", "localhost:3901", "/boot", None),
            // No path at all: the path reads as `/`, but the text keeps its own bytes.
            ("https://keria.example", "https", "keria.example", "/", None),
            ("https://keria.example?a=1", "https", "keria.example", "/", Some("a=1")),
            // An empty query is a query, and a trailing `?` survives.
            ("https://keria.example/p?", "https", "keria.example", "/p", Some("")),
            // Percent escapes and mixed case are preserved exactly, because a signature covers them.
            (
                "https://KERIA.Example/identifiers/a%20name%20with%20%C3%B1!",
                "https",
                "KERIA.Example",
                "/identifiers/a%20name%20with%20%C3%B1!",
                None,
            ),
        ];
        for (text, scheme, authority, path, query) in cases {
            let url = RequestUrl::new(text)?;
            assert_eq!(url.as_str(), text, "{text}");
            assert_eq!(url.to_string(), text, "{text}");
            assert_eq!(url.scheme(), scheme, "{text}");
            assert_eq!(url.authority(), authority, "{text}");
            assert_eq!(url.path(), path, "{text}");
            assert_eq!(url.query(), query, "{text}");
        }
        Ok(())
    }

    #[test]
    fn malformed_urls_are_refused() {
        for text in [
            "",
            "keria.example/path",
            "ftp://keria.example/path",
            "https://",
            "http://",
            // A fragment never reaches the server; truncating it silently would change the request.
            "https://keria.example/path#fragment",
            // Whitespace and control bytes are how a request line or signed component is forged.
            "https://keria.example/pa th",
            "https://keria.example/path\n",
            "https://keria.example/path\r\nHost: evil",
            "https://keria.example/path\t",
            // Non-ASCII must be percent-encoded before it reaches a URL.
            "https://keria.example/ñ",
        ] {
            assert!(RequestUrl::new(text).is_err(), "{text:?} was accepted");
        }
        assert!(RequestUrl::new("h".repeat(MAX_URL_BYTES + 1)).is_err());
    }

    #[test]
    fn the_length_bound_is_inclusive() -> Result<(), Box<dyn Error>> {
        let prefix = "https://keria.example/";
        let padding = MAX_URL_BYTES - prefix.len();
        let url = RequestUrl::new(format!("{prefix}{}", "a".repeat(padding)))?;
        assert_eq!(url.as_str().len(), MAX_URL_BYTES);
        assert!(RequestUrl::new(format!("{prefix}{}", "a".repeat(padding + 1))).is_err());
        Ok(())
    }
}
