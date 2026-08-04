//! Canonical CESR material for self-addressing-data paths.
//!
//! The pinned TypeScript reference calls this material `Pather`. A path is encoded as Base64 text
//! beginning with `-`; each subsequent `-` separates one field label or numeric ordinal. The Rust
//! API models components explicitly and composes [`Base64Text`] instead of reproducing the
//! reference's inheritance hierarchy.

use std::{fmt, str::FromStr};

use crate::{
    CesrError,
    bexter::{Base64Text, MAX_BASE64_TEXT_CHARS, ParsedBase64Text},
    code::DerivationCode,
};

/// Largest component count accepted in one SAD path.
///
/// The bound limits pointer and per-component allocation independently of the shared Base64-text
/// byte ceiling.
pub const MAX_SAD_PATH_COMPONENTS: usize = 4_096;

/// One validated component in a self-addressing-data path.
///
/// Components are nonnumeric field labels, numeric ordinals, or empty identity steps. Ordinals
/// retain their original decimal spelling when parsed, so accepted material re-encodes byte-for-
/// byte even when it uses leading zeroes. `-` is rejected because the separator-based wire syntax
/// cannot preserve it inside one component.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PathComponent {
    text: String,
    ordinal: Option<usize>,
}

/// A validated self-addressing-data path encoded as CESR Base64-text material.
///
/// The empty component sequence is the root path and encodes from text `-` as qb64 `6AABAAA-`.
/// Qualified Base64 bytes are the attachment-path representation consumed by later KERI framing.
///
/// ```
/// use signify_cesr::{CesrError, path::SadPath};
///
/// # fn main() -> Result<(), CesrError> {
/// let path = SadPath::from_components(["e", "credential", "0"])?;
/// assert_eq!(path.text()?, "-e-credential-0");
/// assert_eq!(path.components().get(2).and_then(|part| part.ordinal()), Some(0));
/// assert_eq!(SadPath::from_qb64(&path.qb64()?)?, path);
/// # Ok(())
/// # }
/// ```
pub struct SadPath {
    text: Base64Text,
    components: Vec<PathComponent>,
}

/// One SAD path parsed from the front of a qb64 or qb2 stream.
#[derive(Debug)]
pub struct ParsedSadPath {
    value: SadPath,
    consumed: usize,
}

impl PathComponent {
    /// Constructs a nonnumeric field-label component.
    ///
    /// # Errors
    ///
    /// Returns a typed error when `label` is empty, contains a byte outside the unpadded URL-safe
    /// Base64 alphabet, contains the `-` path separator, or consists only of decimal digits.
    pub fn field(label: &str) -> Result<Self, CesrError> {
        let component = Self::parse_at(label, 0)?;
        if component.ordinal.is_some() || component.is_current() {
            Err(CesrError::InvalidPathComponent {
                component: 0,
                context: "empty or numeric text does not denote a field label",
            })
        } else {
            Ok(component)
        }
    }

    /// Constructs a numeric ordinal component with canonical decimal spelling.
    #[must_use]
    pub fn ordinal_value(ordinal: usize) -> Self {
        Self {
            text: ordinal.to_string(),
            ordinal: Some(ordinal),
        }
    }

    /// Constructs an empty identity component that leaves the current value unchanged.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            text: String::new(),
            ordinal: None,
        }
    }

    /// Parses a field label or numeric ordinal from canonical component text.
    ///
    /// # Errors
    ///
    /// Empty input constructs an identity component. Returns a typed error for a
    /// separator-containing, non-Base64, or overflowing component.
    pub fn parse(input: &str) -> Result<Self, CesrError> {
        Self::parse_at(input, 0)
    }

    /// Returns the exact component text used by the path encoding.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the numeric ordinal, or `None` for a field-label component.
    #[must_use]
    pub const fn ordinal(&self) -> Option<usize> {
        self.ordinal
    }

    /// Returns whether this component selects an ordered field by name.
    #[must_use]
    pub const fn is_field(&self) -> bool {
        self.ordinal.is_none() && !self.text.is_empty()
    }

    /// Returns whether this is an empty identity step.
    #[must_use]
    pub fn is_current(&self) -> bool {
        self.text.is_empty()
    }

    fn parse_at(input: &str, component: usize) -> Result<Self, CesrError> {
        if input.is_empty() {
            return Ok(Self::current());
        }
        for (index, byte) in input.bytes().enumerate() {
            if byte == b'-' {
                return Err(CesrError::InvalidPathComponent {
                    component,
                    context: "component contains the path separator",
                });
            }
            if !matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_') {
                return Err(CesrError::InvalidBase64Character { index, byte });
            }
        }

        let ordinal = if input.bytes().all(|byte| byte.is_ascii_digit()) {
            Some(input.parse::<usize>().map_err(|_| CesrError::IntegerOverflow {
                context: "SAD path ordinal",
            })?)
        } else {
            None
        };
        Ok(Self {
            text: input.to_owned(),
            ordinal,
        })
    }
}

impl FromStr for PathComponent {
    type Err = CesrError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

impl TryFrom<&str> for PathComponent {
    type Error = CesrError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Self::parse(input)
    }
}

impl fmt::Display for PathComponent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

impl fmt::Debug for SadPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SadPath")
            .field("components", &self.components)
            .field("code", &self.code())
            .field("raw_length", &self.raw().len())
            .finish_non_exhaustive()
    }
}

impl PartialEq for SadPath {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text && self.components == other.components
    }
}

impl Eq for SadPath {}

impl ParsedSadPath {
    /// Returns the parsed path.
    #[must_use]
    pub const fn value(&self) -> &SadPath {
        &self.value
    }

    /// Returns the number of input bytes or characters consumed.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Separates the parsed path from its consumed input length.
    #[must_use]
    pub fn into_parts(self) -> (SadPath, usize) {
        (self.value, self.consumed)
    }
}

impl SadPath {
    /// Constructs a path from validated components.
    ///
    /// # Errors
    ///
    /// Returns a typed length or material error when the complete encoded path exceeds the shared
    /// Base64-text bound.
    pub fn new(components: Vec<PathComponent>) -> Result<Self, CesrError> {
        validate_components(&components)?;
        let encoded = encode_components(&components)?;
        let text = Base64Text::new(&encoded)?;
        Ok(Self { text, components })
    }

    /// Parses and constructs a path from field-label or ordinal strings.
    ///
    /// # Errors
    ///
    /// Returns a typed component, size, or material error. Numeric strings become ordinal
    /// components; other strings become field labels.
    pub fn from_components<I, S>(components: I) -> Result<Self, CesrError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut parsed = Vec::new();
        for (index, component) in components.into_iter().enumerate() {
            if index >= MAX_SAD_PATH_COMPONENTS {
                return Err(CesrError::InputTooLarge {
                    context: "SAD path component count",
                    length: index.saturating_add(1),
                    maximum: MAX_SAD_PATH_COMPONENTS,
                });
            }
            parsed.push(PathComponent::parse_at(component.as_ref(), index)?);
        }
        Self::new(parsed)
    }

    /// Constructs a path from exact Base64 path text such as `-a-0-b`.
    ///
    /// # Errors
    ///
    /// Rejects text without a leading `-`, an ambiguous leading identity component, invalid
    /// component bytes, numeric overflow, and shared Base64-text failures.
    pub fn from_text(input: &str) -> Result<Self, CesrError> {
        let components = decode_components(input)?;
        let text = Base64Text::new(input)?;
        Ok(Self { text, components })
    }

    /// Constructs a path from exact raw bytes and a Base64-text derivation code.
    ///
    /// # Errors
    ///
    /// Returns a typed material error or rejects decoded text that is not a canonical SAD path.
    pub fn from_raw(code: DerivationCode, raw: &[u8]) -> Result<Self, CesrError> {
        Self::from_base64_text(Base64Text::from_raw(code, raw)?)
    }

    /// Parses one path from the beginning of a qb64 stream.
    ///
    /// # Errors
    ///
    /// Returns a typed qualified-material or SAD-path error.
    pub fn parse_qb64(input: &str) -> Result<ParsedSadPath, CesrError> {
        Self::from_parsed_base64_text(Base64Text::parse_qb64(input)?)
    }

    /// Parses exactly one canonical qb64 path.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64`] and rejects trailing characters.
    pub fn from_qb64(input: &str) -> Result<Self, CesrError> {
        let parsed = Self::parse_qb64(input)?;
        reject_trailing("SAD path qualified Base64", input.len(), parsed.consumed)?;
        Ok(parsed.value)
    }

    /// Parses one UTF-8 qb64 path from the beginning of a byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed UTF-8, material, or SAD-path error.
    pub fn parse_qb64_bytes(input: &[u8]) -> Result<ParsedSadPath, CesrError> {
        Self::from_parsed_base64_text(Base64Text::parse_qb64_bytes(input)?)
    }

    /// Parses exactly one UTF-8 qb64 path from bytes.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64_bytes`] and rejects trailing bytes.
    pub fn from_qb64_bytes(input: &[u8]) -> Result<Self, CesrError> {
        let parsed = Self::parse_qb64_bytes(input)?;
        reject_trailing("SAD path qualified Base64 bytes", input.len(), parsed.consumed)?;
        Ok(parsed.value)
    }

    /// Parses one path from the beginning of a qualified-binary (`qb2`) stream.
    ///
    /// # Errors
    ///
    /// Returns a typed qualified-material or SAD-path error.
    pub fn parse_qb2(input: &[u8]) -> Result<ParsedSadPath, CesrError> {
        Self::from_parsed_base64_text(Base64Text::parse_qb2(input)?)
    }

    /// Parses exactly one canonical qualified-binary (`qb2`) path.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb2`] and rejects trailing bytes.
    pub fn from_qb2(input: &[u8]) -> Result<Self, CesrError> {
        let parsed = Self::parse_qb2(input)?;
        reject_trailing("SAD path qualified binary", input.len(), parsed.consumed)?;
        Ok(parsed.value)
    }

    /// Returns the path components in traversal order.
    #[must_use]
    pub fn components(&self) -> &[PathComponent] {
        &self.components
    }

    /// Returns whether this is the empty root path.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.components.is_empty()
    }

    /// Returns whether `root` is a component-boundary prefix of this path.
    #[must_use]
    pub fn starts_with(&self, root: &Self) -> bool {
        self.components.starts_with(&root.components)
    }

    /// Returns this path anchored below `root`.
    ///
    /// # Errors
    ///
    /// Returns a typed size or material error if concatenating the component sequences exceeds the
    /// path bound.
    pub fn root(&self, root: &Self) -> Result<Self, CesrError> {
        let capacity = root
            .components
            .len()
            .checked_add(self.components.len())
            .ok_or(CesrError::LengthOverflow {
                context: "rooted SAD path components",
            })?;
        let mut components = Vec::with_capacity(capacity);
        components.extend(root.components.iter().cloned());
        components.extend(self.components.iter().cloned());
        Self::new(components)
    }

    /// Returns a path with `root` removed when it is a component-boundary prefix.
    ///
    /// A nonmatching root leaves the path unchanged. Equal components are removed only when they
    /// form a true prefix.
    ///
    /// # Errors
    ///
    /// Returns a typed material error only if reconstructing the validated path fails.
    pub fn strip(&self, root: &Self) -> Result<Self, CesrError> {
        let remaining = self
            .components
            .strip_prefix(root.components.as_slice())
            .unwrap_or(&self.components);
        Self::new(remaining.to_vec())
    }

    /// Resolves this path with caller-defined traversal over a SAD representation.
    ///
    /// `step` receives the current value and each validated component. Implementations over an
    /// ordered map should treat an ordinal as insertion-order selection; implementations over a
    /// sequence should treat it as an element index. This closure boundary keeps CESR independent
    /// of any JSON library or event representation.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError::PathResolutionFailed`] with the component position when `step` returns
    /// `None`.
    pub fn resolve<'a, T, F>(&self, root: &'a T, mut step: F) -> Result<&'a T, CesrError>
    where
        F: FnMut(&'a T, &PathComponent) -> Option<&'a T>,
    {
        let mut current = root;
        for (index, component) in self.components.iter().enumerate() {
            if component.is_current() {
                continue;
            }
            current = step(current, component).ok_or(CesrError::PathResolutionFailed { component: index })?;
        }
        Ok(current)
    }

    /// Returns the normalized Base64-text derivation code.
    #[must_use]
    pub const fn code(&self) -> DerivationCode {
        self.text.code()
    }

    /// Returns the unqualified raw bytes.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        self.text.raw()
    }

    /// Returns the encoded size in three-byte triplets.
    #[must_use]
    pub const fn variable_size(&self) -> Option<u32> {
        self.text.variable_size()
    }

    /// Returns the hard and soft Base64-text derivation-code leader.
    ///
    /// # Errors
    ///
    /// Returns a typed material error if a private invariant regresses.
    pub fn both(&self) -> Result<String, CesrError> {
        self.text.both()
    }

    /// Returns canonical SAD path text beginning with `-`.
    ///
    /// # Errors
    ///
    /// Returns a typed length error only if a private Base64-text invariant regresses.
    pub fn text(&self) -> Result<String, CesrError> {
        self.text.text()
    }

    /// Encodes the path as canonical qualified Base64 (`qb64`).
    ///
    /// # Errors
    ///
    /// Returns a typed material error if a private invariant regresses.
    pub fn qb64(&self) -> Result<String, CesrError> {
        self.text.qb64()
    }

    /// Encodes the path as UTF-8 qualified-Base64 attachment bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed material error if a private invariant regresses.
    pub fn qb64_bytes(&self) -> Result<Vec<u8>, CesrError> {
        self.text.qb64_bytes()
    }

    /// Encodes the path as canonical qualified binary (`qb2`).
    ///
    /// # Errors
    ///
    /// Returns a typed material error if a private invariant regresses.
    pub fn qb2(&self) -> Result<Vec<u8>, CesrError> {
        self.text.qb2()
    }

    fn from_base64_text(text: Base64Text) -> Result<Self, CesrError> {
        let path_text = text.text()?;
        let components = decode_components(&path_text)?;
        Ok(Self { text, components })
    }

    fn from_parsed_base64_text(parsed: ParsedBase64Text) -> Result<ParsedSadPath, CesrError> {
        let (text, consumed) = parsed.into_parts();
        Ok(ParsedSadPath {
            value: Self::from_base64_text(text)?,
            consumed,
        })
    }
}

impl FromStr for SadPath {
    type Err = CesrError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_text(input)
    }
}

impl TryFrom<&str> for SadPath {
    type Error = CesrError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Self::from_text(input)
    }
}

impl fmt::Display for SadPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.text() {
            Ok(text) => formatter.write_str(&text),
            Err(_) => Err(fmt::Error),
        }
    }
}

fn encode_components(components: &[PathComponent]) -> Result<String, CesrError> {
    validate_components(components)?;
    let text_length = components.iter().try_fold(1_usize, |length, component| {
        length
            .checked_add(1)
            .and_then(|value| value.checked_add(component.as_str().len()))
            .ok_or(CesrError::LengthOverflow {
                context: "SAD path text",
            })
    })?;
    if text_length > MAX_BASE64_TEXT_CHARS {
        return Err(CesrError::InputTooLarge {
            context: "SAD path text",
            length: text_length,
            maximum: MAX_BASE64_TEXT_CHARS,
        });
    }
    let mut encoded = String::with_capacity(text_length);
    encoded.push('-');
    for component in components {
        if encoded.len() > 1 {
            encoded.push('-');
        }
        encoded.push_str(component.as_str());
    }
    Ok(encoded)
}

fn decode_components(input: &str) -> Result<Vec<PathComponent>, CesrError> {
    if input.len() > MAX_BASE64_TEXT_CHARS {
        return Err(CesrError::InputTooLarge {
            context: "SAD path text",
            length: input.len(),
            maximum: MAX_BASE64_TEXT_CHARS,
        });
    }
    let tail = input.strip_prefix('-').ok_or(CesrError::InvalidPath {
        context: "text must begin with '-'",
    })?;
    if tail.is_empty() {
        return Ok(Vec::new());
    }
    let mut components = Vec::new();
    for (index, component) in tail.split('-').enumerate() {
        if index >= MAX_SAD_PATH_COMPONENTS {
            return Err(CesrError::InputTooLarge {
                context: "SAD path component count",
                length: index.saturating_add(1),
                maximum: MAX_SAD_PATH_COMPONENTS,
            });
        }
        components.push(PathComponent::parse_at(component, index)?);
    }
    validate_components(&components)?;
    Ok(components)
}

fn validate_components(components: &[PathComponent]) -> Result<(), CesrError> {
    let count = components.len();
    if count > MAX_SAD_PATH_COMPONENTS {
        return Err(CesrError::InputTooLarge {
            context: "SAD path component count",
            length: count,
            maximum: MAX_SAD_PATH_COMPONENTS,
        });
    }
    if components.first().is_some_and(PathComponent::is_current) {
        return Err(CesrError::InvalidPathComponent {
            component: 0,
            context: "a leading identity component is not canonical",
        });
    }
    Ok(())
}

fn reject_trailing(context: &'static str, input_length: usize, consumed: usize) -> Result<(), CesrError> {
    let trailing = input_length
        .checked_sub(consumed)
        .ok_or(CesrError::LengthOverflow { context })?;
    if trailing == 0 {
        Ok(())
    } else {
        Err(CesrError::TrailingMaterial {
            context,
            length: trailing,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error, str::FromStr};

    use serde_json::{Value, json};

    use super::{MAX_SAD_PATH_COMPONENTS, PathComponent, SadPath};
    use crate::CesrError;

    #[test]
    fn reference_examples_match_exact_bytes() -> Result<(), Box<dyn Error>> {
        let cases = [
            (Vec::<&str>::new(), "-", "3e", "6AABAAA-"),
            (vec!["a", "b", "c"], "-a-b-c", "0f9af9bf9c", "5AACAA-a-b-c"),
            (vec!["0", "1", "2"], "-0-1-2", "0fb4fb5fb6", "5AACAA-0-1-2"),
            (
                vec!["field0", "1", "0"],
                "-field0-1-0",
                "03e7e27a5774fb5fb4",
                "4AADA-field0-1-0",
            ),
        ];
        for (components, text, raw_hex, qb64) in cases {
            let path = SadPath::from_components(components.iter().copied())?;
            assert_eq!(path.text()?, text);
            assert_eq!(hex(path.raw())?, raw_hex);
            assert_eq!(path.qb64()?, qb64);
            assert_eq!(path.qb64_bytes()?, qb64.as_bytes());
            assert_eq!(SadPath::from_text(text)?, path);
            assert_eq!(SadPath::from_qb64(qb64)?, path);
            assert_eq!(SadPath::from_qb2(&path.qb2()?)?, path);
            assert_eq!(path.components().len(), components.len());
        }
        Ok(())
    }

    #[test]
    fn component_types_and_ambiguous_inputs_are_explicit() -> Result<(), Box<dyn Error>> {
        let field = PathComponent::field("field_0")?;
        assert!(field.is_field());
        assert_eq!(field.ordinal(), None);
        let ordinal = PathComponent::parse("001")?;
        assert_eq!(ordinal.ordinal(), Some(1));
        assert_eq!(ordinal.as_str(), "001");
        assert_eq!(PathComponent::ordinal_value(42).as_str(), "42");
        let current = PathComponent::parse("")?;
        assert!(current.is_current());
        assert!(!current.is_field());
        assert_eq!(current, PathComponent::current());
        assert_eq!(PathComponent::from_str("field_0")?, field);
        assert_eq!(PathComponent::try_from("field_0")?, field);
        assert_eq!(field.to_string(), "field_0");

        assert!(matches!(
            PathComponent::parse("a-b"),
            Err(CesrError::InvalidPathComponent { .. })
        ));
        for input in ["@", "+", "/", "é"] {
            assert!(matches!(
                PathComponent::parse(input),
                Err(CesrError::InvalidBase64Character { .. })
            ));
        }
        assert!(matches!(
            PathComponent::field("123"),
            Err(CesrError::InvalidPathComponent { .. })
        ));
        assert!(matches!(
            PathComponent::field(""),
            Err(CesrError::InvalidPathComponent { .. })
        ));
        assert!(matches!(SadPath::from_text("a-b"), Err(CesrError::InvalidPath { .. })));
        assert!(matches!(
            SadPath::from_text("--a"),
            Err(CesrError::InvalidPathComponent { component: 0, .. })
        ));
        let identity = SadPath::from_text("-a-")?;
        assert!(identity.components().get(1).is_some_and(PathComponent::is_current));
        Ok(())
    }

    #[test]
    fn all_construction_and_formatting_entry_points_are_consistent() -> Result<(), Box<dyn Error>> {
        let path = SadPath::from_components(["e", "credential", "0"])?;
        let text = path.text()?;
        let qb64 = path.qb64()?;
        let qb64_bytes = path.qb64_bytes()?;
        assert_eq!(SadPath::from_str(&text)?, path);
        assert_eq!(SadPath::try_from(text.as_str())?, path);
        assert_eq!(path.to_string(), text);
        assert!(!path.is_root());
        assert_eq!(SadPath::from_raw(path.code(), path.raw())?, path);
        assert_eq!(SadPath::from_qb64_bytes(&qb64_bytes)?, path);
        assert_eq!(SadPath::from_qb64(&qb64)?, path);

        let root = SadPath::from_components(Vec::<&str>::new())?;
        assert!(root.is_root());
        Ok(())
    }

    #[test]
    fn allocation_and_component_count_bounds_are_enforced_before_path_construction() {
        let too_many = std::iter::repeat_n("a", MAX_SAD_PATH_COMPONENTS + 1);
        assert!(matches!(
            SadPath::from_components(too_many),
            Err(CesrError::InputTooLarge {
                context: "SAD path component count",
                maximum: MAX_SAD_PATH_COMPONENTS,
                ..
            })
        ));
    }

    #[test]
    fn root_strip_and_prefix_use_component_boundaries() -> Result<(), Box<dyn Error>> {
        let root = SadPath::from_components(["a", "b"])?;
        let tail = SadPath::from_components(["c", "d"])?;
        let rooted = tail.root(&root)?;
        assert_eq!(rooted.text()?, "-a-b-c-d");
        assert!(rooted.starts_with(&root));
        assert_eq!(rooted.strip(&root)?, tail);

        let non_root = SadPath::from_components(["a", "c"])?;
        assert!(!rooted.starts_with(&non_root));
        assert_eq!(rooted.strip(&non_root)?, rooted);

        let repeated = SadPath::from_components(["a", "b", "a"])?;
        let non_prefix = SadPath::from_components(["a", "a"])?;
        assert_eq!(repeated.strip(&non_prefix)?, repeated);
        Ok(())
    }

    #[test]
    fn resolve_delegates_json_traversal_without_a_production_json_dependency() -> Result<(), Box<dyn Error>> {
        let sad = json!({"a": {"items": [{"value": 1}, {"value": 2}]}});
        let path = SadPath::from_components(["a", "items", "1", "value"])?;
        let resolved = path.resolve(&sad, json_step)?;
        assert_eq!(resolved, &json!(2));
        let root = SadPath::from_components(Vec::<&str>::new())?;
        assert_eq!(root.resolve(&sad, json_step)?, &sad);

        let missing = SadPath::from_components(["a", "missing"])?;
        assert!(matches!(
            missing.resolve(&sad, json_step),
            Err(CesrError::PathResolutionFailed { component: 1 })
        ));
        let identity = SadPath::from_components(["a", "", "items", "0"])?;
        assert_eq!(identity.resolve(&sad, json_step)?, &json!({"value": 1}));
        Ok(())
    }

    #[test]
    fn stream_parsers_report_consumption_and_strict_forms_reject_suffixes() -> Result<(), Box<dyn Error>> {
        let path = SadPath::from_components(["e", "credential"])?;
        let qb64 = path.qb64()?;
        let stream = format!("{qb64}ABCD");
        let parsed = SadPath::parse_qb64(&stream)?;
        assert_eq!(parsed.consumed(), qb64.len());
        assert_eq!(parsed.value(), &path);
        let (owned, consumed) = parsed.into_parts();
        assert_eq!(owned, path);
        assert_eq!(consumed, qb64.len());
        assert!(matches!(
            SadPath::from_qb64(&stream),
            Err(CesrError::TrailingMaterial { length: 4, .. })
        ));

        let qb2 = path.qb2()?;
        let mut binary_stream = qb2.clone();
        binary_stream.extend_from_slice(&[0_u8; 3]);
        let parsed = SadPath::parse_qb2(&binary_stream)?;
        assert_eq!(parsed.consumed(), qb2.len());
        assert_eq!(parsed.value(), &path);
        assert!(matches!(
            SadPath::from_qb2(&binary_stream),
            Err(CesrError::TrailingMaterial { length: 3, .. })
        ));

        let parsed = SadPath::parse_qb64_bytes(stream.as_bytes())?;
        assert_eq!(parsed.consumed(), qb64.len());
        assert!(matches!(
            SadPath::from_qb64_bytes(stream.as_bytes()),
            Err(CesrError::TrailingMaterial { length: 4, .. })
        ));
        Ok(())
    }

    fn json_step<'a>(value: &'a Value, component: &PathComponent) -> Option<&'a Value> {
        match value {
            Value::Object(map) => component
                .ordinal()
                .and_then(|index| map.values().nth(index))
                .or_else(|| map.get(component.as_str())),
            Value::Array(values) => component.ordinal().and_then(|index| values.get(index)),
            _ => None,
        }
    }

    fn hex(bytes: &[u8]) -> Result<String, std::fmt::Error> {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let high = DIGITS.get(usize::from(byte >> 4)).copied().ok_or(std::fmt::Error)?;
            let low = DIGITS.get(usize::from(byte & 0x0f)).copied().ok_or(std::fmt::Error)?;
            output.push(char::from(high));
            output.push(char::from(low));
        }
        Ok(output)
    }
}
