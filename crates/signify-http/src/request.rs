//! Building one request: a URL from a base and typed components, and a body that names its type.
//!
//! The pinned reference has no request builder. `SignifyClient.fetch` concatenates a base URL with
//! a path string its endpoint modules already assembled, and those modules assemble it with
//! template literals — `` `/identifiers/${encodeURIComponent(name)}` `` in two places and
//! `` `/operations/${name}` `` in forty-one others. This module is the typed replacement: a
//! [`ResourcePath`] is a list of components, and **every dynamic component is encoded exactly
//! once**.
//!
//! # Why encoding is not optional here
//!
//! Only `app/aiding.ts`'s `get` and `update` call `encodeURIComponent`. Everywhere else a caller's
//! value goes into the path or the query raw, so a value holding `/`, `?`, `#`, or `..` changes
//! which resource is addressed: the reference's own `operations().get("../identifiers")` sends
//! `GET /operations/../identifiers`, and its `keyStates().get("a&b=c")` sends
//! `GET /states?pre=a&b=c` with a second parameter the caller never wrote. Roadmap 3.10 signs the
//! `@path` component, so this also changes what a signature covers. Those requests are recorded in
//! `fixtures/http-request-response/v1.json` and deliberately not reproduced.
//!
//! # What this module does not do
//!
//! It does not sign: applying the `Signature`, `Signature-Input`, `Signify-Resource`, and
//! `Signify-Timestamp` headers to a finished request is Roadmap 5.5's, which is why the header
//! order a request leaves here with is this builder's own and not the reference's wire order.
//! Header order does not affect a signature — the base's order comes from the covered-fields list
//! in [`crate::signature::input`], not from the collection.
//!
//! It also does not serialize: a JSON body arrives here as bytes a caller already produced, so no
//! serialization dependency reaches this crate and the domain records stay in `signify-types`.

use core::fmt;
use std::error::Error;
use std::str::FromStr;

use crate::header::{HeaderError, HeaderName, HeaderValue};
use crate::transport::{Method, Request, RequestUrl, TransportError};

/// Largest number of path components one resource path holds.
///
/// The deepest path in the pinned reference is four components,
/// `/identifiers/{name}/registries/{registryName}`.
pub const MAX_PATH_SEGMENTS: usize = 16;

/// Largest accepted path component after encoding, in bytes.
pub const MAX_SEGMENT_BYTES: usize = 512;

/// Largest accepted path after encoding, in bytes.
pub const MAX_PATH_BYTES: usize = 1_024;

/// Largest number of query parameters one resource path holds.
pub const MAX_QUERY_PARAMETERS: usize = 32;

/// Largest accepted query after encoding, in bytes.
pub const MAX_QUERY_BYTES: usize = 1_024;

/// Largest accepted media type, in bytes.
pub const MAX_MEDIA_TYPE_BYTES: usize = 128;

/// Largest accepted range unit, in bytes.
pub const MAX_RANGE_UNIT_BYTES: usize = 32;

// ---------------------------------------------------------------------------
// Percent-encoding
// ---------------------------------------------------------------------------

/// Returns whether a byte survives `encodeURIComponent` unescaped.
///
/// The set is the ASCII alphanumerics plus `-_.!~*'()`, which is what ECMAScript's
/// `encodeURIComponent` leaves alone. Note that `.` is in it, so a component of `..` is **not**
/// escaped by the reference; this crate never puts an unencoded component in a path, but the
/// encoding function itself must still match the reference byte for byte where it is used.
const fn is_component_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')')
}

/// Returns whether a byte survives `application/x-www-form-urlencoded` serialization unescaped.
///
/// The set is the ASCII alphanumerics plus `*-._`, which is what the WHATWG URL standard's
/// urlencoded serializer — and therefore `URLSearchParams.toString`, which the reference builds
/// its queries with — leaves alone. A space becomes `+` rather than `%20`.
const fn is_form_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'*' | b'-' | b'.' | b'_')
}

/// Appends the two uppercase hexadecimal digits of one byte after a `%`.
fn push_escape(target: &mut String, byte: u8) {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let high = usize::from(byte >> 4);
    let low = usize::from(byte & 0x0f);
    target.push('%');
    for index in [high, low] {
        if let Some(digit) = DIGITS.get(index) {
            target.push(char::from(*digit));
        }
    }
}

/// Percent-encodes one path component exactly as `encodeURIComponent` does.
///
/// ```
/// use signify_http::request::encode_path_component;
///
/// assert_eq!(encode_path_component("a name with ñ!"), "a%20name%20with%20%C3%B1!");
/// assert_eq!(encode_path_component("a/b"), "a%2Fb");
/// // Already-escaped input is escaped again, exactly as the reference does.
/// assert_eq!(encode_path_component("%41"), "%2541");
/// ```
#[must_use]
pub fn encode_path_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if is_component_unreserved(byte) {
            encoded.push(char::from(byte));
        } else {
            push_escape(&mut encoded, byte);
        }
    }
    encoded
}

/// Percent-encodes one query name or value exactly as `URLSearchParams` does.
///
/// ```
/// use signify_http::request::encode_query_component;
///
/// assert_eq!(encode_query_component("a b"), "a+b");
/// assert_eq!(encode_query_component("/multisig/icp"), "%2Fmultisig%2Ficp");
/// // A real plus is escaped, because an unescaped one would decode as a space.
/// assert_eq!(encode_query_component("a+b"), "a%2Bb");
/// ```
#[must_use]
pub fn encode_query_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if is_form_unreserved(byte) {
            encoded.push(char::from(byte));
        } else if byte == b' ' {
            encoded.push('+');
        } else {
            push_escape(&mut encoded, byte);
        }
    }
    encoded
}

// ---------------------------------------------------------------------------
// Resource paths
// ---------------------------------------------------------------------------

/// A request path and query, with every component already encoded exactly once.
///
/// This is the typed replacement for the reference's `path` local: the value its endpoint modules
/// assemble, `SignifyClient.fetch` appends to a base URL, and Roadmap 3.10 signs as `@path` after
/// splitting the query off.
///
/// ```
/// use signify_http::request::ResourcePath;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let path = ResourcePath::builder()
///     .segment("identifiers")
///     .segment("a name with ñ!")
///     .build()?;
/// assert_eq!(path.path(), "/identifiers/a%20name%20with%20%C3%B1!");
/// assert_eq!(path.query(), None);
///
/// let filtered = ResourcePath::builder()
///     .segment("contacts")
///     .parameter("group", "a b")
///     .build()?;
/// assert_eq!(filtered.as_str(), "/contacts?group=a+b");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourcePath {
    text: String,
    /// Byte offset of the `?`, when there is a query.
    query_start: Option<usize>,
}

impl ResourcePath {
    /// Starts building a path.
    #[must_use]
    pub fn builder() -> ResourcePathBuilder {
        ResourcePathBuilder {
            segments: Vec::new(),
            parameters: Vec::new(),
        }
    }

    /// Returns the path and query together, which is what a base URL is joined with.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the path alone, without the query.
    ///
    /// This is the value a signature's `@path` component covers.
    #[must_use]
    pub fn path(&self) -> &str {
        let end = self.query_start.unwrap_or(self.text.len());
        self.text.get(..end).unwrap_or("/")
    }

    /// Returns the query without its `?`, when the path carries one.
    ///
    /// A path built with no parameters has no query and no delimiter, where the reference emits a
    /// bare trailing `?`.
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        let start = self.query_start?.checked_add(1)?;
        self.text.get(start..)
    }
}

impl fmt::Display for ResourcePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// Assembles a [`ResourcePath`] from components that are encoded as they are added.
///
/// Every setter is infallible; [`ResourcePathBuilder::build`] applies the count and length bounds
/// at once.
#[derive(Clone, Debug, Default)]
pub struct ResourcePathBuilder {
    segments: Vec<String>,
    parameters: Vec<(String, String)>,
}

impl ResourcePathBuilder {
    /// Adds one path component, percent-encoding it exactly once.
    ///
    /// A literal such as `identifiers` survives encoding unchanged, so there is deliberately no
    /// second method that skips it: a component that needs escaping can never reach the path raw.
    ///
    /// # A component of exactly `.` or `..` is preserved
    ///
    /// `.` is unreserved, so `encodeURIComponent` does not escape it and neither does this. A
    /// caller naming an identifier `..` therefore still produces `/identifiers/..`, byte for byte
    /// what the reference sends for the same alias. What a component can no longer do is
    /// *introduce* a dot segment: the reference's `operations().get("../identifiers")` becomes two
    /// components there and one — `..%2Fidentifiers` — here. Nothing in this crate's URL or
    /// transport stack resolves a dot segment (ADR `0019` and `0020`), so the path signed under
    /// Roadmap 3.10 is the path sent; an intermediary that normalizes would address a different
    /// resource, which is a deployment concern Roadmap 9.2 confirms against a live KERIA.
    #[must_use]
    pub fn segment(mut self, value: &str) -> Self {
        self.segments.push(encode_path_component(value));
        self
    }

    /// Adds one query parameter, encoding its name and value exactly once.
    ///
    /// Repeating a name is allowed and preserved in order, because the reference's `keyStates`
    /// list builds `?pre=…&pre=…` that way.
    #[must_use]
    pub fn parameter(mut self, name: &str, value: &str) -> Self {
        self.parameters
            .push((encode_query_component(name), encode_query_component(value)));
        self
    }

    /// Adds one query parameter only when a value is present.
    ///
    /// The reference's optional filters are written this way — `if (group !== undefined)` — so an
    /// endpoint can pass its `Option` straight through.
    #[must_use]
    pub fn optional_parameter(self, name: &str, value: Option<&str>) -> Self {
        match value {
            Some(value) => self.parameter(name, value),
            None => self,
        }
    }

    /// Validates and assembles the path.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError::EmptyPath`] when no component was added,
    /// [`RequestError::TooManySegments`] above [`MAX_PATH_SEGMENTS`],
    /// [`RequestError::SegmentTooLong`] above [`MAX_SEGMENT_BYTES`],
    /// [`RequestError::PathTooLong`] above [`MAX_PATH_BYTES`],
    /// [`RequestError::TooManyParameters`] above [`MAX_QUERY_PARAMETERS`], and
    /// [`RequestError::QueryTooLong`] above [`MAX_QUERY_BYTES`].
    pub fn build(self) -> Result<ResourcePath, RequestError> {
        if self.segments.is_empty() {
            return Err(RequestError::EmptyPath);
        }
        if self.segments.len() > MAX_PATH_SEGMENTS {
            return Err(RequestError::TooManySegments {
                maximum: MAX_PATH_SEGMENTS,
                actual: self.segments.len(),
            });
        }
        if self.parameters.len() > MAX_QUERY_PARAMETERS {
            return Err(RequestError::TooManyParameters {
                maximum: MAX_QUERY_PARAMETERS,
                actual: self.parameters.len(),
            });
        }

        let mut text = String::new();
        for segment in &self.segments {
            if segment.len() > MAX_SEGMENT_BYTES {
                return Err(RequestError::SegmentTooLong {
                    maximum: MAX_SEGMENT_BYTES,
                    actual: segment.len(),
                });
            }
            text.push('/');
            text.push_str(segment);
        }
        if text.len() > MAX_PATH_BYTES {
            return Err(RequestError::PathTooLong {
                maximum: MAX_PATH_BYTES,
                actual: text.len(),
            });
        }

        let query_start = if self.parameters.is_empty() {
            None
        } else {
            let start = text.len();
            let mut query = String::new();
            for (index, (name, value)) in self.parameters.iter().enumerate() {
                if index > 0 {
                    query.push('&');
                }
                query.push_str(name);
                query.push('=');
                query.push_str(value);
            }
            if query.len() > MAX_QUERY_BYTES {
                return Err(RequestError::QueryTooLong {
                    maximum: MAX_QUERY_BYTES,
                    actual: query.len(),
                });
            }
            text.push('?');
            text.push_str(&query);
            Some(start)
        };

        Ok(ResourcePath { text, query_start })
    }
}

// ---------------------------------------------------------------------------
// Base URLs
// ---------------------------------------------------------------------------

/// The origin, and optional path prefix, that resource paths are joined onto.
///
/// A client holds two of these: the reference's `url` for the admin interface and its `bootUrl`
/// for the boot interface. Choosing between them is Roadmap 6.4's.
///
/// A single trailing `/` is removed so joining never doubles it. Nothing else is rewritten — the
/// host keeps its case and any percent escapes keep their bytes — for the same reason
/// [`RequestUrl`] does not normalize: Roadmap 3.10 signs the path.
///
/// ```
/// use signify_http::request::{BaseUrl, ResourcePath};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let base = BaseUrl::new("http://localhost:3901/")?;
/// assert_eq!(base.as_str(), "http://localhost:3901");
///
/// let url = base.join(&ResourcePath::builder().segment("identifiers").build()?)?;
/// assert_eq!(url.as_str(), "http://localhost:3901/identifiers");
/// assert_eq!(url.path(), "/identifiers");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BaseUrl {
    text: String,
}

impl BaseUrl {
    /// Validates one base URL.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError::InvalidBaseUrl`] when the value is not an absolute `http` or
    /// `https` URL, when it carries a query or a fragment, or when what remains after removing a
    /// trailing `/` is not a usable URL.
    pub fn new(text: impl Into<String>) -> Result<Self, RequestError> {
        let text = text.into();
        if text.contains('?') {
            return Err(RequestError::InvalidBaseUrl {
                reason: "a base URL may not carry a query",
            });
        }
        if text.contains('#') {
            return Err(RequestError::InvalidBaseUrl {
                reason: "a base URL may not carry a fragment",
            });
        }
        let trimmed = text.strip_suffix('/').unwrap_or(&text);
        // A base URL must itself be a URL this crate would send, so it is validated by the same
        // strict, non-normalizing parser a request uses.
        let url = RequestUrl::new(trimmed.to_owned())?;
        Ok(Self {
            text: url.as_str().to_owned(),
        })
    }

    /// Returns the base URL, without any trailing `/`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Joins one resource path onto this base.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError::Transport`] when the joined URL exceeds
    /// [`MAX_URL_BYTES`](crate::transport::MAX_URL_BYTES) or is otherwise unusable.
    pub fn join(&self, path: &ResourcePath) -> Result<RequestUrl, RequestError> {
        let mut text = String::with_capacity(self.text.len().saturating_add(path.as_str().len()));
        text.push_str(&self.text);
        text.push_str(path.as_str());
        Ok(RequestUrl::new(text)?)
    }
}

impl FromStr for BaseUrl {
    type Err = RequestError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::new(input)
    }
}

impl fmt::Display for BaseUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

// ---------------------------------------------------------------------------
// Media types
// ---------------------------------------------------------------------------

/// A validated media type, such as `application/json`.
///
/// The type and subtype are compared without regard to ASCII case, as HTTP requires, while the
/// original spelling is preserved. Parameters are kept and readable but never take part in a
/// comparison, so `application/json; charset=utf-8` is the same media type as `application/json`.
///
/// ```
/// use signify_http::request::MediaType;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let declared = MediaType::new("APPLICATION/JSON; charset=utf-8")?;
/// assert!(declared.matches(&MediaType::json()));
/// assert_eq!(declared.essence(), "APPLICATION/JSON");
/// assert_eq!(declared.parameter("CHARSET"), Some("utf-8"));
/// assert!(!declared.matches(&MediaType::json_cesr()));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct MediaType {
    text: String,
    /// Byte offset of the `/` separating type from subtype.
    slash: usize,
    /// Byte offset of the first `;`, when there are parameters.
    parameters_start: Option<usize>,
}

impl MediaType {
    /// The type every KERIA request declares and almost every response carries.
    #[must_use]
    pub fn json() -> Self {
        Self {
            text: "application/json".to_owned(),
            slash: "application".len(),
            parameters_start: None,
        }
    }

    /// The type `credentials().get(said, true)` asks for, whose body is a CESR stream.
    #[must_use]
    pub fn json_cesr() -> Self {
        Self {
            text: "application/json+cesr".to_owned(),
            slash: "application".len(),
            parameters_start: None,
        }
    }

    /// Validates one media type.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError::InvalidMediaType`] for an empty value, one above
    /// [`MAX_MEDIA_TYPE_BYTES`], one without exactly one `/` before its parameters, one whose type
    /// or subtype is empty or holds a byte outside the RFC 9110 token set, or one whose parameters
    /// are not `name=value` pairs.
    pub fn new(text: impl Into<String>) -> Result<Self, RequestError> {
        let text = text.into();
        let invalid = |reason: &'static str| RequestError::InvalidMediaType {
            value: bounded(&text),
            reason,
        };
        if text.is_empty() {
            return Err(invalid("a media type may not be empty"));
        }
        if text.len() > MAX_MEDIA_TYPE_BYTES {
            return Err(invalid("a media type exceeds the accepted length"));
        }
        let parameters_start = text.find(';');
        let essence = text.get(..parameters_start.unwrap_or(text.len())).unwrap_or_default();
        let essence = essence.trim_matches(|scalar| scalar == ' ' || scalar == '\t');
        if essence.len()
            != text
                .get(..parameters_start.unwrap_or(text.len()))
                .unwrap_or_default()
                .len()
        {
            return Err(invalid("a media type may not be padded with whitespace"));
        }
        let Some(slash) = essence.find('/') else {
            return Err(invalid("a media type must hold one `/`"));
        };
        let kind = essence.get(..slash).unwrap_or_default();
        let subtype = essence.get(slash.saturating_add(1)..).unwrap_or_default();
        if kind.is_empty() || subtype.is_empty() {
            return Err(invalid("a media type must name a type and a subtype"));
        }
        if subtype.contains('/') {
            return Err(invalid("a media type may hold only one `/`"));
        }
        if !kind.bytes().all(is_token_byte) || !subtype.bytes().all(is_token_byte) {
            return Err(invalid("a media type holds a byte outside the token set"));
        }
        if let Some(start) = parameters_start {
            let parameters = text.get(start.saturating_add(1)..).unwrap_or_default();
            for parameter in parameters.split(';') {
                let parameter = parameter.trim_matches(|scalar| scalar == ' ' || scalar == '\t');
                let Some((name, value)) = parameter.split_once('=') else {
                    return Err(invalid("a media-type parameter must be `name=value`"));
                };
                if name.is_empty() || !name.bytes().all(is_token_byte) {
                    return Err(invalid("a media-type parameter name is empty or not a token"));
                }
                if value.is_empty() {
                    return Err(invalid("a media-type parameter value may not be empty"));
                }
                if !is_parameter_value(value) {
                    return Err(invalid(
                        "a media-type parameter value is not a token or a quoted string",
                    ));
                }
            }
        }
        Ok(Self {
            text,
            slash,
            parameters_start,
        })
    }

    /// Returns the media type exactly as written, parameters included.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the type and subtype without any parameters, as written.
    #[must_use]
    pub fn essence(&self) -> &str {
        self.text
            .get(..self.parameters_start.unwrap_or(self.text.len()))
            .unwrap_or_default()
    }

    /// Returns the type, as written.
    #[must_use]
    pub fn kind(&self) -> &str {
        self.text.get(..self.slash).unwrap_or_default()
    }

    /// Returns the subtype, as written.
    #[must_use]
    pub fn subtype(&self) -> &str {
        let end = self.parameters_start.unwrap_or(self.text.len());
        self.text.get(self.slash.saturating_add(1)..end).unwrap_or_default()
    }

    /// Returns one parameter's value, matching the name without regard to ASCII case.
    ///
    /// A quoted value is returned without its quotes.
    #[must_use]
    pub fn parameter(&self, name: &str) -> Option<&str> {
        let start = self.parameters_start?.checked_add(1)?;
        self.text
            .get(start..)?
            .split(';')
            .filter_map(|parameter| {
                parameter
                    .trim_matches(|scalar| scalar == ' ' || scalar == '\t')
                    .split_once('=')
            })
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| {
                value
                    .strip_prefix('"')
                    .and_then(|rest| rest.strip_suffix('"'))
                    .unwrap_or(value)
            })
    }

    /// Returns whether two media types name the same essence, ignoring parameters and ASCII case.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.kind().eq_ignore_ascii_case(other.kind()) && self.subtype().eq_ignore_ascii_case(other.subtype())
    }

    /// Returns this media type as a header value.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError::Header`] when the value cannot be an HTTP field value. The token
    /// and parameter rules above make that unreachable for a constructed media type, and the fuzz
    /// target asserts it on every value it accepts; the `Result` remains because that is a
    /// property of this type's validation rather than of the header type's.
    pub fn header_value(&self) -> Result<HeaderValue, RequestError> {
        Ok(HeaderValue::new(&self.text)?)
    }
}

impl PartialEq for MediaType {
    /// Compares media types the way HTTP does: essence only, ignoring ASCII case.
    fn eq(&self, other: &Self) -> bool {
        self.matches(other)
    }
}

impl Eq for MediaType {}

impl FromStr for MediaType {
    type Err = RequestError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::new(input)
    }
}

impl fmt::Display for MediaType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// Returns whether a media-type parameter value is an RFC 9110 `token` or `quoted-string`.
///
/// Without this a parameter could hold any scalar at all, and a media type that cannot be written
/// as an HTTP field value would still construct — found by the fuzz target, which builds a header
/// value from every media type it accepts.
fn is_parameter_value(value: &str) -> bool {
    match value.strip_prefix('"').and_then(|rest| rest.strip_suffix('"')) {
        // `qdtext` without quoted pairs: a backslash and a quote are the two bytes that would let
        // a value end early or escape its own delimiter, and nothing needs them.
        Some(inner) => {
            !inner.is_empty()
                && inner
                    .bytes()
                    .all(|byte| matches!(byte, b'\t' | 0x20 | 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
        }
        None => value.bytes().all(is_token_byte),
    }
}

/// Returns whether a byte is an RFC 9110 `tchar`.
const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

// ---------------------------------------------------------------------------
// Ranges
// ---------------------------------------------------------------------------

/// The unit a KERIA range names, such as `aids` or `notes`.
///
/// KERIA counts items rather than bytes, and names the kind of item in the unit position. The
/// pinned reference uses exactly two: `aids` for `identifiers().list` and `notes` for
/// `notifications().list`. This is an open token rather than an enum because the unit is chosen by
/// the endpoint family, and adding one there should not require changing this crate.
///
/// ```
/// use signify_http::request::RangeUnit;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// assert_eq!(RangeUnit::new("aids")?.as_str(), "aids");
/// assert!(RangeUnit::new("a b").is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RangeUnit {
    text: String,
}

impl RangeUnit {
    /// Validates one range unit.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError::InvalidRangeUnit`] for an empty unit, one above
    /// [`MAX_RANGE_UNIT_BYTES`], or one holding a byte outside the RFC 9110 token set.
    pub fn new(text: impl Into<String>) -> Result<Self, RequestError> {
        let text = text.into();
        let invalid = |reason: &'static str| RequestError::InvalidRangeUnit {
            value: bounded(&text),
            reason,
        };
        if text.is_empty() {
            return Err(invalid("a range unit may not be empty"));
        }
        if text.len() > MAX_RANGE_UNIT_BYTES {
            return Err(invalid("a range unit exceeds the accepted length"));
        }
        if !text.bytes().all(is_token_byte) {
            return Err(invalid("a range unit holds a byte outside the token set"));
        }
        Ok(Self { text })
    }

    /// Returns the unit as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl FromStr for RangeUnit {
    type Err = RequestError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::new(input)
    }
}

impl fmt::Display for RangeUnit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// An inclusive range of item positions, as KERIA's `Range` header spells it.
///
/// The reference sends `` `${typ}=${start}-${end}` `` and defaults to `0-24`. It never checks that
/// the positions are ordered, so `list(30, 10)` sends `aids=30-10`; that is refused here, because
/// nothing in the protocol gives a descending range a meaning.
///
/// ```
/// use signify_http::request::{ItemRange, RangeUnit};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let range = ItemRange::new(0, 24)?;
/// assert_eq!(range.header_value(&RangeUnit::new("aids")?), "aids=0-24");
/// assert_eq!(ItemRange::DEFAULT, range);
/// assert!(ItemRange::new(30, 10).is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ItemRange {
    start: u64,
    end: u64,
}

impl ItemRange {
    /// The page the reference asks for when a caller names none.
    pub const DEFAULT: Self = Self { start: 0, end: 24 };

    /// Validates one inclusive range.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError::InvalidRange`] when `end` is below `start`.
    pub const fn new(start: u64, end: u64) -> Result<Self, RequestError> {
        if end < start {
            return Err(RequestError::InvalidRange { start, end });
        }
        Ok(Self { start, end })
    }

    /// Returns the first position.
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Returns the last position, which is included.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.end
    }

    /// Returns how many positions the range covers.
    #[must_use]
    pub const fn count(self) -> u64 {
        self.end.saturating_sub(self.start).saturating_add(1)
    }

    /// Returns the `Range` header value for one unit.
    #[must_use]
    pub fn header_value(self, unit: &RangeUnit) -> String {
        format!("{}={}-{}", unit.as_str(), self.start, self.end)
    }
}

// ---------------------------------------------------------------------------
// Request assembly
// ---------------------------------------------------------------------------

/// Assembles one resource [`Request`] with a typed body, accept, and range.
///
/// The headers it produces come first, in the order content type, accept, range; a caller's own
/// headers follow in the order they were added. Reproducing the reference's exact wire order also
/// needs the four authentication headers, which Roadmap 5.5 applies to a finished request.
///
/// ```
/// use signify_http::request::{BaseUrl, ItemRange, MediaType, RangeUnit, ResourceRequestBuilder};
/// use signify_http::request::ResourcePath;
/// use signify_http::transport::Method;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let base = BaseUrl::new("http://localhost:3901")?;
/// let url = base.join(&ResourcePath::builder().segment("identifiers").build()?)?;
///
/// let request = ResourceRequestBuilder::new(Method::Get, url)
///     .accept(MediaType::json())
///     .range(&RangeUnit::new("aids")?, ItemRange::DEFAULT)
///     .build()?;
///
/// assert_eq!(request.headers().get("accept"), Some("application/json"));
/// assert_eq!(request.headers().get("range"), Some("aids=0-24"));
/// assert_eq!(request.body(), None);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct ResourceRequestBuilder {
    method: Method,
    url: RequestUrl,
    content_type: Option<MediaType>,
    accept: Option<MediaType>,
    range: Option<String>,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: Option<Vec<u8>>,
    response_limit: Option<usize>,
}

impl ResourceRequestBuilder {
    /// Starts building a request for one resource.
    #[must_use]
    pub const fn new(method: Method, url: RequestUrl) -> Self {
        Self {
            method,
            url,
            content_type: None,
            accept: None,
            range: None,
            headers: Vec::new(),
            body: None,
            response_limit: None,
        }
    }

    /// Sets a JSON body and declares it.
    ///
    /// The bytes are a document a caller already serialized; this crate does not serialize, so no
    /// serialization dependency reaches it and the domain records stay in `signify-types`.
    #[must_use]
    pub fn json_body(self, body: impl Into<Vec<u8>>) -> Self {
        self.body(MediaType::json(), body)
    }

    /// Sets a body of some media type and declares it.
    #[must_use]
    pub fn body(mut self, media_type: MediaType, body: impl Into<Vec<u8>>) -> Self {
        self.content_type = Some(media_type);
        self.body = Some(body.into());
        self
    }

    /// Declares a content type without setting a body.
    ///
    /// The reference sets `Content-Type: application/json` on every request including a `GET` that
    /// carries nothing, so declaring one without the other stays expressible — but it is never
    /// implied, which is why it takes its own call.
    #[must_use]
    pub fn content_type(mut self, media_type: MediaType) -> Self {
        self.content_type = Some(media_type);
        self
    }

    /// Sets the media type the response should carry.
    #[must_use]
    pub fn accept(mut self, media_type: MediaType) -> Self {
        self.accept = Some(media_type);
        self
    }

    /// Asks for one page of items.
    #[must_use]
    pub fn range(mut self, unit: &RangeUnit, range: ItemRange) -> Self {
        self.range = Some(range.header_value(unit));
        self
    }

    /// Adds one further header, after the ones this builder derives.
    #[must_use]
    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }

    /// Sets how many response bytes this request will accept.
    #[must_use]
    pub const fn response_limit(mut self, limit: usize) -> Self {
        self.response_limit = Some(limit);
        self
    }

    /// Validates and assembles the request.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError::Header`] when a derived or supplied header is unusable — including
    /// a caller repeating a name this builder derives — and [`RequestError::Transport`] when the
    /// body or the response limit is out of bounds.
    pub fn build(self) -> Result<Request, RequestError> {
        let mut builder = Request::builder(self.method, self.url);
        if let Some(media_type) = &self.content_type {
            builder = builder.header(HeaderName::new("Content-Type")?, media_type.header_value()?);
        }
        if let Some(media_type) = &self.accept {
            builder = builder.header(HeaderName::new("Accept")?, media_type.header_value()?);
        }
        if let Some(range) = &self.range {
            builder = builder.header(HeaderName::new("Range")?, HeaderValue::new(range)?);
        }
        for (name, value) in self.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = self.body {
            builder = builder.body(body);
        }
        if let Some(limit) = self.response_limit {
            builder = builder.response_limit(limit);
        }
        builder.build().map_err(|error| match error {
            // A duplicate or oversized header is a header failure at this layer, whichever layer
            // noticed it: a caller repeating a name this builder derives is the common case.
            TransportError::Header { source } => RequestError::Header { source },
            other => RequestError::from(other),
        })
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Copies at most thirty-two characters of rejected text into an error.
fn bounded(text: &str) -> String {
    text.chars().take(32).collect()
}

/// Stable request-construction failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum RequestError {
    /// A base URL is not absolute, or carries a query or a fragment.
    InvalidBaseUrl {
        /// Why the base URL was refused.
        reason: &'static str,
    },
    /// A resource path names no components at all.
    EmptyPath,
    /// A path holds more than [`MAX_PATH_SEGMENTS`] components.
    TooManySegments {
        /// Accepted maximum.
        maximum: usize,
        /// Actual count.
        actual: usize,
    },
    /// An encoded path component exceeds [`MAX_SEGMENT_BYTES`].
    SegmentTooLong {
        /// Accepted maximum in bytes.
        maximum: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// An encoded path exceeds [`MAX_PATH_BYTES`].
    PathTooLong {
        /// Accepted maximum in bytes.
        maximum: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// A query holds more than [`MAX_QUERY_PARAMETERS`] parameters.
    TooManyParameters {
        /// Accepted maximum.
        maximum: usize,
        /// Actual count.
        actual: usize,
    },
    /// An encoded query exceeds [`MAX_QUERY_BYTES`].
    QueryTooLong {
        /// Accepted maximum in bytes.
        maximum: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// A media type is empty, oversized, or not `type/subtype` with token parameters.
    InvalidMediaType {
        /// Bounded copy of the rejected value.
        value: String,
        /// Why it was refused.
        reason: &'static str,
    },
    /// A range unit is empty, oversized, or holds a byte outside the token set.
    InvalidRangeUnit {
        /// Bounded copy of the rejected value.
        value: String,
        /// Why it was refused.
        reason: &'static str,
    },
    /// A range ends before it starts.
    InvalidRange {
        /// First position.
        start: u64,
        /// Last position.
        end: u64,
    },
    /// A header could not be built.
    Header {
        /// Underlying failure.
        source: Box<HeaderError>,
    },
    /// The transport refused the assembled request.
    Transport {
        /// Underlying failure.
        source: Box<TransportError>,
    },
}

impl fmt::Display for RequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBaseUrl { reason } => write!(formatter, "invalid base URL: {reason}"),
            Self::EmptyPath => formatter.write_str("a resource path names no components"),
            Self::TooManySegments { maximum, actual } => {
                write!(formatter, "a path of {actual} components exceeds maximum {maximum}")
            }
            Self::SegmentTooLong { maximum, actual } => write!(
                formatter,
                "an encoded path component of {actual} bytes exceeds maximum {maximum}"
            ),
            Self::PathTooLong { maximum, actual } => {
                write!(formatter, "an encoded path of {actual} bytes exceeds maximum {maximum}")
            }
            Self::TooManyParameters { maximum, actual } => {
                write!(formatter, "a query of {actual} parameters exceeds maximum {maximum}")
            }
            Self::QueryTooLong { maximum, actual } => {
                write!(
                    formatter,
                    "an encoded query of {actual} bytes exceeds maximum {maximum}"
                )
            }
            Self::InvalidMediaType { value, reason } => {
                write!(formatter, "invalid media type {value:?}: {reason}")
            }
            Self::InvalidRangeUnit { value, reason } => {
                write!(formatter, "invalid range unit {value:?}: {reason}")
            }
            Self::InvalidRange { start, end } => {
                write!(formatter, "a range from {start} to {end} ends before it starts")
            }
            Self::Header { source } => write!(formatter, "header construction failed: {source}"),
            Self::Transport { source } => write!(formatter, "the request could not be assembled: {source}"),
        }
    }
}

impl Error for RequestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Header { source } => Some(source),
            Self::Transport { source } => Some(source),
            _ => None,
        }
    }
}

impl From<HeaderError> for RequestError {
    fn from(source: HeaderError) -> Self {
        Self::Header {
            source: Box::new(source),
        }
    }
}

impl From<TransportError> for RequestError {
    fn from(source: TransportError) -> Self {
        Self::Transport {
            source: Box::new(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    fn base() -> Result<BaseUrl, Box<dyn Error>> {
        Ok(BaseUrl::new("http://localhost:3901")?)
    }

    #[test]
    fn path_components_are_encoded_exactly_once() {
        for (input, expected) in [
            ("aid1", "aid1"),
            ("a name with ñ!", "a%20name%20with%20%C3%B1!"),
            ("-_.!~*'()", "-_.!~*'()"),
            ("a/b", "a%2Fb"),
            ("a?b", "a%3Fb"),
            ("a#b", "a%23b"),
            ("%", "%25"),
            ("%41", "%2541"),
            ("..", ".."),
            ("", ""),
            ("日本", "%E6%97%A5%E6%9C%AC"),
            ("\u{1f600}", "%F0%9F%98%80"),
            ("a+b", "a%2Bb"),
        ] {
            assert_eq!(encode_path_component(input), expected, "{input:?}");
        }
    }

    #[test]
    fn query_components_use_the_form_encoding() {
        for (input, expected) in [
            ("g1", "g1"),
            ("a b", "a+b"),
            ("a+b", "a%2Bb"),
            ("/multisig/icp", "%2Fmultisig%2Ficp"),
            ("~*'()!-_.", "%7E*%27%28%29%21-_."),
            ("a&b=c", "a%26b%3Dc"),
            ("", ""),
            ("日本", "%E6%97%A5%E6%9C%AC"),
        ] {
            assert_eq!(encode_query_component(input), expected, "{input:?}");
        }
    }

    #[test]
    fn a_path_carries_its_components_and_query() -> Result<(), Box<dyn Error>> {
        let path = ResourcePath::builder()
            .segment("identifiers")
            .segment("a name with ñ!")
            .build()?;
        assert_eq!(path.path(), "/identifiers/a%20name%20with%20%C3%B1!");
        assert_eq!(path.as_str(), path.path());
        assert_eq!(path.query(), None);
        assert_eq!(path.to_string(), path.as_str());

        let filtered = ResourcePath::builder()
            .segment("contacts")
            .parameter("group", "group")
            .optional_parameter("filter_field", Some("field"))
            .optional_parameter("filter_value", None)
            .build()?;
        assert_eq!(filtered.as_str(), "/contacts?group=group&filter_field=field");
        assert_eq!(filtered.path(), "/contacts");
        assert_eq!(filtered.query(), Some("group=group&filter_field=field"));
        Ok(())
    }

    #[test]
    fn an_empty_query_has_no_delimiter() -> Result<(), Box<dyn Error>> {
        // The reference emits a bare `/contacts?` here.
        let path = ResourcePath::builder().segment("contacts").build()?;
        assert_eq!(path.as_str(), "/contacts");
        assert_eq!(path.query(), None);
        Ok(())
    }

    #[test]
    fn a_component_of_dots_is_preserved_but_can_never_be_introduced() -> Result<(), Box<dyn Error>> {
        // Found by the property test. `.` is unreserved, so an alias literally named `..` still
        // produces the reference's own bytes.
        let dotted = ResourcePath::builder().segment("identifiers").segment("..").build()?;
        assert_eq!(dotted.path(), "/identifiers/..");
        assert_eq!(ResourcePath::builder().segment(".").build()?.path(), "/.");

        // What is closed is the reference's actual defect: a component becoming two.
        let traversal = ResourcePath::builder()
            .segment("operations")
            .segment("../identifiers")
            .build()?;
        assert_eq!(traversal.path(), "/operations/..%2Fidentifiers");
        assert_eq!(traversal.path().split('/').skip(1).count(), 2);
        Ok(())
    }

    #[test]
    fn an_empty_component_is_a_component() -> Result<(), Box<dyn Error>> {
        // Found by the property test: an empty name is a real path component, and two of them
        // produce `//` rather than collapsing. Nothing is repaired, so what a caller asked for is
        // what a signature covers.
        let path = ResourcePath::builder().segment("").segment("").build()?;
        assert_eq!(path.path(), "//");
        assert_eq!(path.path().split('/').skip(1).count(), 2);
        let nested = ResourcePath::builder()
            .segment("identifiers")
            .segment("")
            .segment("x")
            .build()?;
        assert_eq!(nested.path(), "/identifiers//x");
        Ok(())
    }

    #[test]
    fn a_repeated_query_name_is_preserved_in_order() -> Result<(), Box<dyn Error>> {
        let path = ResourcePath::builder()
            .segment("states")
            .parameter("pre", "EPRE")
            .parameter("pre", "EOTHER")
            .build()?;
        assert_eq!(path.as_str(), "/states?pre=EPRE&pre=EOTHER");
        Ok(())
    }

    #[test]
    fn a_path_is_bounded_in_every_dimension() {
        assert!(matches!(ResourcePath::builder().build(), Err(RequestError::EmptyPath)));

        let mut builder = ResourcePath::builder();
        for _ in 0..=MAX_PATH_SEGMENTS {
            builder = builder.segment("a");
        }
        assert!(matches!(builder.build(), Err(RequestError::TooManySegments { .. })));

        assert!(matches!(
            ResourcePath::builder()
                .segment(&"a".repeat(MAX_SEGMENT_BYTES + 1))
                .build(),
            Err(RequestError::SegmentTooLong { .. })
        ));
        // The bound is inclusive, and applies to the *encoded* length.
        assert!(
            ResourcePath::builder()
                .segment(&"a".repeat(MAX_SEGMENT_BYTES))
                .build()
                .is_ok()
        );
        assert!(matches!(
            ResourcePath::builder().segment(&"ñ".repeat(MAX_SEGMENT_BYTES)).build(),
            Err(RequestError::SegmentTooLong { .. })
        ));

        let mut long = ResourcePath::builder();
        for _ in 0..3 {
            long = long.segment(&"a".repeat(MAX_SEGMENT_BYTES));
        }
        assert!(matches!(long.build(), Err(RequestError::PathTooLong { .. })));

        let mut many = ResourcePath::builder().segment("a");
        for index in 0..=MAX_QUERY_PARAMETERS {
            many = many.parameter("k", &index.to_string());
        }
        assert!(matches!(many.build(), Err(RequestError::TooManyParameters { .. })));

        let wide = ResourcePath::builder()
            .segment("a")
            .parameter("k", &"v".repeat(MAX_QUERY_BYTES))
            .build();
        assert!(matches!(wide, Err(RequestError::QueryTooLong { .. })));
    }

    #[test]
    fn a_base_url_drops_one_trailing_slash_and_nothing_else() -> Result<(), Box<dyn Error>> {
        for (input, expected) in [
            ("http://localhost:3901", "http://localhost:3901"),
            ("http://localhost:3901/", "http://localhost:3901"),
            ("https://KERIA.Example/keria", "https://KERIA.Example/keria"),
            ("https://KERIA.Example/keria/", "https://KERIA.Example/keria"),
        ] {
            let base = BaseUrl::new(input)?;
            assert_eq!(base.as_str(), expected, "{input}");
            assert_eq!(base.to_string(), expected, "{input}");
        }
        assert_eq!(BaseUrl::from_str("http://a")?, BaseUrl::new("http://a/")?);

        for input in [
            "http://localhost:3901?a=1",
            "http://localhost:3901#a",
            "localhost:3901",
            "ftp://localhost",
            "",
            "http://",
            "http://localhost:3901/pa th",
        ] {
            assert!(BaseUrl::new(input).is_err(), "{input:?} was accepted");
        }
        // Only one trailing slash is removed; the rest of the base keeps its bytes, so a caller
        // who wrote two gets an empty last component rather than a silent repair.
        assert_eq!(
            BaseUrl::new("http://localhost:3901//")?.as_str(),
            "http://localhost:3901/"
        );
        Ok(())
    }

    #[test]
    fn joining_produces_the_reference_url() -> Result<(), Box<dyn Error>> {
        let base = base()?;
        let url = base.join(&ResourcePath::builder().segment("identifiers").build()?)?;
        assert_eq!(url.as_str(), "http://localhost:3901/identifiers");

        let url = base.join(
            &ResourcePath::builder()
                .segment("contacts")
                .parameter("group", "group")
                .build()?,
        )?;
        assert_eq!(url.as_str(), "http://localhost:3901/contacts?group=group");
        assert_eq!(url.path(), "/contacts");
        assert_eq!(url.query(), Some("group=group"));

        // The joined URL is still bounded by the transport's own limit, which the path and
        // query bounds together can exceed.
        let long = ResourcePath::builder()
            .segment(&"a".repeat(MAX_SEGMENT_BYTES))
            .segment(&"b".repeat(MAX_PATH_BYTES - MAX_SEGMENT_BYTES - 2))
            .parameter("k", &"v".repeat(MAX_QUERY_BYTES - 2))
            .build()?;
        assert_eq!(long.as_str().len(), MAX_PATH_BYTES + MAX_QUERY_BYTES + 1);
        assert!(matches!(base.join(&long), Err(RequestError::Transport { .. })));
        Ok(())
    }

    #[test]
    fn media_types_compare_by_essence() -> Result<(), Box<dyn Error>> {
        let json = MediaType::json();
        assert_eq!(json.as_str(), "application/json");
        assert_eq!(json.kind(), "application");
        assert_eq!(json.subtype(), "json");
        assert_eq!(json.essence(), "application/json");
        assert_eq!(json.parameter("charset"), None);
        assert_eq!(json.to_string(), "application/json");

        let cesr = MediaType::json_cesr();
        assert_eq!(cesr.as_str(), "application/json+cesr");
        assert_eq!(cesr.subtype(), "json+cesr");
        assert!(!cesr.matches(&json));
        assert_ne!(cesr, json);

        let declared = MediaType::new("APPLICATION/JSON; charset=utf-8")?;
        assert!(declared.matches(&json));
        assert_eq!(declared, json);
        assert_eq!(declared.essence(), "APPLICATION/JSON");
        assert_eq!(declared.kind(), "APPLICATION");
        assert_eq!(declared.subtype(), "JSON");
        assert_eq!(declared.parameter("CHARSET"), Some("utf-8"));
        assert_eq!(declared.parameter("boundary"), None);

        let quoted = MediaType::new("text/plain;charset=\"utf-8\";format=flowed")?;
        assert_eq!(quoted.parameter("charset"), Some("utf-8"));
        assert_eq!(quoted.parameter("format"), Some("flowed"));
        assert_eq!(MediaType::from_str("text/plain")?.essence(), "text/plain");
        Ok(())
    }

    #[test]
    fn a_media_type_can_always_be_written_as_a_header_value() -> Result<(), Box<dyn Error>> {
        // Found by the fuzz target: `li/n;i=\u{fffd}` parsed, because a parameter value was only
        // checked for emptiness, but no HTTP field value can carry a scalar above Latin-1.
        assert!(matches!(
            MediaType::new("li/n;i=\u{fffd}"),
            Err(RequestError::InvalidMediaType { .. })
        ));
        for value in [
            "application/json",
            "application/json+cesr",
            "application/json; charset=utf-8",
            "text/plain;charset=\"utf-8\";format=flowed",
        ] {
            let media_type = MediaType::new(value)?;
            assert_eq!(media_type.header_value()?.as_str(), value);
        }
        for refused in [
            "a/b;c=\u{fffd}",
            "a/b;c=\u{e9}",
            "a/b;c=x y",
            "a/b;c=\"un\\terminated",
            "a/b;c=\"\"",
            "a/b;c=\"a\"b\"",
            "a/b;c=\"a\\b\"",
        ] {
            assert!(
                matches!(MediaType::new(refused), Err(RequestError::InvalidMediaType { .. })),
                "{refused:?} was accepted",
            );
        }
        Ok(())
    }

    #[test]
    fn malformed_media_types_are_refused() {
        for value in [
            "",
            "application",
            "/json",
            "application/",
            "application/json/extra",
            "application json",
            "app lication/json",
            " application/json",
            "application/json ",
            "application/json;",
            "application/json;charset",
            "application/json;=utf-8",
            "application/json;charset=",
            "application/@json",
        ] {
            assert!(
                matches!(MediaType::new(value), Err(RequestError::InvalidMediaType { .. })),
                "{value:?} was accepted",
            );
        }
        assert!(MediaType::new("a".repeat(MAX_MEDIA_TYPE_BYTES + 1)).is_err());
    }

    #[test]
    fn ranges_render_the_reference_header() -> Result<(), Box<dyn Error>> {
        let aids = RangeUnit::new("aids")?;
        assert_eq!(ItemRange::DEFAULT.header_value(&aids), "aids=0-24");
        assert_eq!(ItemRange::DEFAULT.start(), 0);
        assert_eq!(ItemRange::DEFAULT.end(), 24);
        assert_eq!(ItemRange::DEFAULT.count(), 25);
        assert_eq!(
            ItemRange::new(20, 40)?.header_value(&RangeUnit::new("notes")?),
            "notes=20-40"
        );
        assert_eq!(ItemRange::new(5, 5)?.count(), 1);
        assert_eq!(
            ItemRange::new(0, u64::MAX)?.header_value(&aids),
            format!("aids=0-{}", u64::MAX)
        );
        assert_eq!(aids.to_string(), "aids");
        assert_eq!(RangeUnit::from_str("notes")?.as_str(), "notes");

        // The reference sends `aids=30-10` for this; nothing gives it a meaning.
        assert!(matches!(ItemRange::new(30, 10), Err(RequestError::InvalidRange { .. })));
        for unit in ["", "a b", "aids ", "a/b", "a@b"] {
            assert!(RangeUnit::new(unit).is_err(), "{unit:?} was accepted");
        }
        assert!(RangeUnit::new("a".repeat(MAX_RANGE_UNIT_BYTES + 1)).is_err());
        Ok(())
    }

    #[test]
    fn a_request_carries_its_derived_headers_first() -> Result<(), Box<dyn Error>> {
        let url = base()?.join(&ResourcePath::builder().segment("identifiers").build()?)?;
        let request = ResourceRequestBuilder::new(Method::Get, url)
            .content_type(MediaType::json())
            .accept(MediaType::json_cesr())
            .range(&RangeUnit::new("aids")?, ItemRange::DEFAULT)
            .header(HeaderName::new("X-Extra")?, HeaderValue::new("1")?)
            .response_limit(4_096)
            .build()?;

        let names: Vec<&str> = request.headers().iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["Content-Type", "Accept", "Range", "X-Extra"]);
        assert_eq!(request.headers().get("accept"), Some("application/json+cesr"));
        assert_eq!(request.headers().get("range"), Some("aids=0-24"));
        assert_eq!(request.method(), Method::Get);
        assert_eq!(request.response_limit(), 4_096);
        // A content type without a body, exactly as the reference sends for a GET.
        assert_eq!(request.body(), None);
        Ok(())
    }

    #[test]
    fn a_json_body_declares_itself() -> Result<(), Box<dyn Error>> {
        let url = base()?.join(&ResourcePath::builder().segment("identifiers").build()?)?;
        let request = ResourceRequestBuilder::new(Method::Post, url.clone())
            .json_body(br#"{"name":"aid1"}"#.to_vec())
            .build()?;
        assert_eq!(request.headers().get("content-type"), Some("application/json"));
        assert_eq!(request.body(), Some(br#"{"name":"aid1"}"#.as_slice()));

        let cesr = ResourceRequestBuilder::new(Method::Post, url)
            .body(MediaType::json_cesr(), b"-FAB".to_vec())
            .build()?;
        assert_eq!(cesr.headers().get("content-type"), Some("application/json+cesr"));
        assert_eq!(cesr.body(), Some(b"-FAB".as_slice()));
        Ok(())
    }

    #[test]
    fn a_caller_may_not_shadow_a_derived_header() -> Result<(), Box<dyn Error>> {
        let url = base()?.join(&ResourcePath::builder().segment("identifiers").build()?)?;
        let refused = ResourceRequestBuilder::new(Method::Get, url)
            .accept(MediaType::json())
            .header(HeaderName::new("accept")?, HeaderValue::new("text/plain")?)
            .build();
        assert!(matches!(refused, Err(RequestError::Header { .. })), "{refused:?}");
        Ok(())
    }

    #[test]
    fn an_oversized_body_is_refused_by_the_transport_bound() -> Result<(), Box<dyn Error>> {
        use crate::transport::MAX_REQUEST_BODY_BYTES;
        let url = base()?.join(&ResourcePath::builder().segment("identifiers").build()?)?;
        let refused = ResourceRequestBuilder::new(Method::Post, url)
            .json_body(vec![b'a'; MAX_REQUEST_BODY_BYTES + 1])
            .build();
        assert!(matches!(refused, Err(RequestError::Transport { .. })));
        Ok(())
    }

    #[test]
    fn errors_carry_readable_text_and_their_sources() {
        let cases: Vec<(RequestError, bool)> = vec![
            (RequestError::InvalidBaseUrl { reason: "empty" }, false),
            (RequestError::EmptyPath, false),
            (RequestError::TooManySegments { maximum: 1, actual: 2 }, false),
            (RequestError::SegmentTooLong { maximum: 1, actual: 2 }, false),
            (RequestError::PathTooLong { maximum: 1, actual: 2 }, false),
            (RequestError::TooManyParameters { maximum: 1, actual: 2 }, false),
            (RequestError::QueryTooLong { maximum: 1, actual: 2 }, false),
            (
                RequestError::InvalidMediaType {
                    value: "x".to_owned(),
                    reason: "no slash",
                },
                false,
            ),
            (
                RequestError::InvalidRangeUnit {
                    value: "x y".to_owned(),
                    reason: "not a token",
                },
                false,
            ),
            (RequestError::InvalidRange { start: 3, end: 1 }, false),
            (RequestError::from(HeaderError::EmptyName), true),
            (RequestError::from(TransportError::InvalidUrl { reason: "empty" }), true),
        ];
        for (error, has_source) in cases {
            assert_ne!(error.to_string(), "");
            assert_eq!(error.source().is_some(), has_source, "{error}");
        }
    }

    #[test]
    fn rejected_text_in_an_error_is_bounded() {
        let long = "x".repeat(256);
        let rendered: Vec<String> = [
            MediaType::new(long.clone()).err().map(|error| error.to_string()),
            RangeUnit::new(long.clone()).err().map(|error| error.to_string()),
        ]
        .into_iter()
        .flatten()
        .collect();
        assert_eq!(rendered.len(), 2, "an oversized value was accepted");
        for message in rendered {
            assert!(message.len() < long.len(), "{message}");
        }
    }
}
