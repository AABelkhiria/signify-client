//! Validated CESR counters and protocol-stack version fields.
//!
//! Counters prefix groups of attached CESR material. Their hard code selects the group meaning and
//! the width of the unsigned count. This module covers the complete table exposed by the pinned
//! `signify-ts` `Counter` and makes prefix consumption explicit for stream callers.

use std::{fmt, str::FromStr};

use crate::{
    CesrError,
    base64::{decode_u64, decode_url_safe_bounded, encode_u64, encode_url_safe},
    bytes::utf8_text,
};

const MAX_COUNTER_QB64_SIZE: usize = 8;
const MAX_COUNTER_QB2_SIZE: usize = 6;
const MAX_SEMANTIC_VERSION_TEXT_SIZE: usize = 32;

/// Sizing information for one CESR counter code.
///
/// All sizes are qualified-Base64 character counts except `lead_size`, which is a byte count.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CounterCodeSize {
    hard: usize,
    soft: usize,
    full: usize,
    lead: usize,
}

impl CounterCodeSize {
    const fn new(hard: usize, soft: usize, full: usize, lead: usize) -> Self {
        Self { hard, soft, full, lead }
    }

    /// Number of characters in the hard counter code.
    #[must_use]
    pub const fn hard_size(self) -> usize {
        self.hard
    }

    /// Number of Base64 digits carrying the count.
    #[must_use]
    pub const fn soft_size(self) -> usize {
        self.soft
    }

    /// Total qualified-Base64 size.
    #[must_use]
    pub const fn full_size(self) -> usize {
        self.full
    }

    /// Number of binary lead bytes; all pinned counter codes use zero.
    #[must_use]
    pub const fn lead_size(self) -> usize {
        self.lead
    }
}

/// A validated CESR counter derivation code.
///
/// The private representation makes unsupported or reserved codes unrepresentable after parsing.
///
/// ```compile_fail
/// use signify_cesr::counter::CounterCode;
///
/// let invalid = CounterCode("-M");
/// ```
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct CounterCode {
    value: &'static str,
    size: CounterCodeSize,
}

impl CounterCode {
    const fn short(value: &'static str) -> Self {
        Self {
            value,
            size: CounterCodeSize::new(2, 2, 4, 0),
        }
    }

    const fn long(value: &'static str, hard: usize, soft: usize) -> Self {
        Self {
            value,
            size: CounterCodeSize::new(hard, soft, 8, 0),
        }
    }

    /// Indexed controller signatures (`-A`).
    pub const CONTROLLER_INDEXED_SIGNATURES: Self = Self::short("-A");
    /// Indexed witness signatures (`-B`).
    pub const WITNESS_INDEXED_SIGNATURES: Self = Self::short("-B");
    /// Non-transferable receipt couples (`-C`).
    pub const NON_TRANSFERABLE_RECEIPT_COUPLES: Self = Self::short("-C");
    /// Transferable receipt quadruples (`-D`).
    pub const TRANSFERABLE_RECEIPT_QUADRUPLES: Self = Self::short("-D");
    /// First-seen replay couples (`-E`).
    pub const FIRST_SEEN_REPLAY_COUPLES: Self = Self::short("-E");
    /// Transferable indexed-signature groups (`-F`).
    pub const TRANSFERABLE_INDEXED_SIGNATURE_GROUPS: Self = Self::short("-F");
    /// Source-seal couples (`-G`).
    pub const SEAL_SOURCE_COUPLES: Self = Self::short("-G");
    /// Transferable last-indexed-signature groups (`-H`).
    pub const TRANSFERABLE_LAST_INDEXED_SIGNATURE_GROUPS: Self = Self::short("-H");
    /// Source-seal triples (`-I`).
    pub const SEAL_SOURCE_TRIPLES: Self = Self::short("-I");
    /// One SAID-path signature group (`-J`).
    pub const SAID_PATH_SIGNATURE: Self = Self::short("-J");
    /// SAID-path signature groups rooted at a path (`-K`).
    pub const SAID_PATH_SIGNATURE_GROUPS: Self = Self::short("-K");
    /// Grouped pathed material measured in quadlets (`-L`).
    pub const PATHED_MATERIAL_QUADLETS: Self = Self::short("-L");
    /// Grouped attached material measured in quadlets (`-V`).
    pub const ATTACHED_MATERIAL_QUADLETS: Self = Self::short("-V");
    /// Big grouped attached material measured in quadlets (`-0V`).
    pub const BIG_ATTACHED_MATERIAL_QUADLETS: Self = Self::long("-0V", 3, 5);
    /// KERI/ACDC protocol-stack CESR semantic version (`--AAA`).
    pub const KERI_PROTOCOL_STACK: Self = Self::long("--AAA", 5, 3);

    /// Complete supported code table in pinned reference order.
    pub const ALL: &'static [Self] = &[
        Self::CONTROLLER_INDEXED_SIGNATURES,
        Self::WITNESS_INDEXED_SIGNATURES,
        Self::NON_TRANSFERABLE_RECEIPT_COUPLES,
        Self::TRANSFERABLE_RECEIPT_QUADRUPLES,
        Self::FIRST_SEEN_REPLAY_COUPLES,
        Self::TRANSFERABLE_INDEXED_SIGNATURE_GROUPS,
        Self::SEAL_SOURCE_COUPLES,
        Self::TRANSFERABLE_LAST_INDEXED_SIGNATURE_GROUPS,
        Self::SEAL_SOURCE_TRIPLES,
        Self::SAID_PATH_SIGNATURE,
        Self::SAID_PATH_SIGNATURE_GROUPS,
        Self::PATHED_MATERIAL_QUADLETS,
        Self::ATTACHED_MATERIAL_QUADLETS,
        Self::BIG_ATTACHED_MATERIAL_QUADLETS,
        Self::KERI_PROTOCOL_STACK,
    ];

    /// Canonical hard-code text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.value
    }

    /// Counter field sizing selected by this code.
    #[must_use]
    pub const fn size(self) -> CounterCodeSize {
        self.size
    }

    /// Largest count representable by this code.
    #[must_use]
    pub const fn maximum_count(self) -> u32 {
        match self.size.soft {
            2 => 4_095,
            3 => 262_143,
            5 => 1_073_741_823,
            _ => 0,
        }
    }
}

impl fmt::Debug for CounterCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("CounterCode").field(&self.value).finish()
    }
}

impl fmt::Display for CounterCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.value)
    }
}

impl FromStr for CounterCode {
    type Err = CesrError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.is_empty() {
            return Err(CesrError::EmptyInput {
                context: "counter code",
            });
        }
        if let Some((index, byte)) = input
            .bytes()
            .enumerate()
            .find(|(_, byte)| !byte.is_ascii_alphanumeric() && *byte != b'-')
        {
            return Err(CesrError::InvalidCodeCharacter { index, byte });
        }
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.value == input)
            .ok_or_else(|| CesrError::UnsupportedCode {
                code: bounded_code(input),
            })
    }
}

/// A three-component semantic version encoded by a protocol-stack counter.
///
/// Each component is one CESR Base64 digit and is therefore limited to `0..=63`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CounterVersion {
    major: u8,
    minor: u8,
    patch: u8,
}

impl CounterVersion {
    /// Version `0.0.0`.
    pub const ZERO: Self = Self {
        major: 0,
        minor: 0,
        patch: 0,
    };

    /// Constructs a bounded three-component version.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError::SemanticVersionOutOfRange`] when a component is greater than 63.
    pub fn new(major: u8, minor: u8, patch: u8) -> Result<Self, CesrError> {
        validate_version_component(0, u64::from(major))?;
        validate_version_component(1, u64::from(minor))?;
        validate_version_component(2, u64::from(patch))?;
        Ok(Self { major, minor, patch })
    }

    /// Parses the reference's one-to-three-component dotted form, filling omitted trailing
    /// components from `fallback` and treating an explicitly empty component as zero.
    ///
    /// An empty input returns `fallback`. Unlike JavaScript `parseInt`, this parser rejects signs,
    /// whitespace, numeric prefixes with trailing text, and more than three components.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] for malformed, oversized, or out-of-range input.
    pub fn parse_with_fallback(input: &str, fallback: Self) -> Result<Self, CesrError> {
        if input.is_empty() {
            return Ok(fallback);
        }
        if input.len() > MAX_SEMANTIC_VERSION_TEXT_SIZE {
            return Err(CesrError::InputTooLarge {
                context: "CESR semantic version",
                length: input.len(),
                maximum: MAX_SEMANTIC_VERSION_TEXT_SIZE,
            });
        }

        let mut components = [
            u64::from(fallback.major),
            u64::from(fallback.minor),
            u64::from(fallback.patch),
        ];
        let mut seen = 0_usize;
        for (component, part) in input.split('.').enumerate() {
            if component >= 3 {
                return Err(CesrError::InvalidSemanticVersion { component: None });
            }
            let value = if part.is_empty() {
                0
            } else {
                parse_decimal_component(part, component)?
            };
            let slot = components
                .get_mut(component)
                .ok_or(CesrError::InvalidSemanticVersion { component: None })?;
            *slot = value;
            seen = seen.checked_add(1).ok_or(CesrError::LengthOverflow {
                context: "CESR semantic version",
            })?;
        }
        if seen == 0 {
            return Err(CesrError::InvalidSemanticVersion { component: None });
        }
        let [major, minor, patch] = components;
        Self::new(
            version_component_u8(0, major)?,
            version_component_u8(1, minor)?,
            version_component_u8(2, patch)?,
        )
    }

    /// Major version component.
    #[must_use]
    pub const fn major(self) -> u8 {
        self.major
    }

    /// Minor version component.
    #[must_use]
    pub const fn minor(self) -> u8 {
        self.minor
    }

    /// Patch version component.
    #[must_use]
    pub const fn patch(self) -> u8 {
        self.patch
    }

    /// Three canonical CESR Base64 version digits.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] only if the shared integer encoder cannot represent a validated
    /// one-digit component.
    pub fn qb64_digits(self) -> Result<String, CesrError> {
        let mut output = String::with_capacity(3);
        output.push_str(&encode_u64(u64::from(self.major), 1)?);
        output.push_str(&encode_u64(u64::from(self.minor), 1)?);
        output.push_str(&encode_u64(u64::from(self.patch), 1)?);
        Ok(output)
    }

    /// Packed 18-bit counter value corresponding to the three Base64 digits.
    #[must_use]
    pub fn packed_count(self) -> u32 {
        u32::from(self.major) * 4_096 + u32::from(self.minor) * 64 + u32::from(self.patch)
    }

    /// Decodes an 18-bit protocol-stack counter value into version components.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError::CounterOutOfRange`] when `count` exceeds three Base64 digits.
    pub fn from_packed_count(count: u32) -> Result<Self, CesrError> {
        let maximum = CounterCode::KERI_PROTOCOL_STACK.maximum_count();
        if count > maximum {
            return Err(CesrError::CounterOutOfRange {
                value: u64::from(count),
                maximum: u64::from(maximum),
            });
        }
        let major = u8::try_from(count / 4_096).map_err(|_| CesrError::IntegerOverflow {
            context: "CESR semantic-version major component",
        })?;
        let minor = u8::try_from((count / 64) % 64).map_err(|_| CesrError::IntegerOverflow {
            context: "CESR semantic-version minor component",
        })?;
        let patch = u8::try_from(count % 64).map_err(|_| CesrError::IntegerOverflow {
            context: "CESR semantic-version patch component",
        })?;
        Self::new(major, minor, patch)
    }
}

impl FromStr for CounterVersion {
    type Err = CesrError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse_with_fallback(input, Self::ZERO)
    }
}

impl fmt::Display for CounterVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// One validated CESR counter.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Counter {
    code: CounterCode,
    count: u32,
}

impl Counter {
    /// Constructs a counter with an explicit count.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError::CounterOutOfRange`] when `count` does not fit the selected code.
    pub fn new(code: CounterCode, count: u32) -> Result<Self, CesrError> {
        if count > code.maximum_count() {
            return Err(CesrError::CounterOutOfRange {
                value: u64::from(count),
                maximum: u64::from(code.maximum_count()),
            });
        }
        Ok(Self { code, count })
    }

    /// Constructs the reference's default count of one.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] if the selected code cannot represent one.
    pub fn one(code: CounterCode) -> Result<Self, CesrError> {
        Self::new(code, 1)
    }

    /// Constructs a counter by decoding Base64 count digits.
    ///
    /// The digits need not be left-padded to the code's field width; canonical counter output is
    /// always padded. This retains the reference constructor capability while validating the full
    /// URL-safe alphabet and selected code range.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] for an invalid Base64 integer or out-of-range count.
    pub fn from_count_b64(code: CounterCode, digits: &str) -> Result<Self, CesrError> {
        let count = u32::try_from(decode_u64(digits)?).map_err(|_| CesrError::IntegerOverflow {
            context: "counter value",
        })?;
        Self::new(code, count)
    }

    /// Constructs a KERI protocol-stack version counter.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] if the packed version cannot be represented by its counter code.
    pub fn protocol_stack(version: CounterVersion) -> Result<Self, CesrError> {
        Self::new(CounterCode::KERI_PROTOCOL_STACK, version.packed_count())
    }

    /// Parses exactly one qualified-Base64 counter.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] for empty, malformed, truncated, unsupported, or trailing material.
    pub fn from_qb64(input: &str) -> Result<Self, CesrError> {
        let parsed = Self::parse_qb64(input)?;
        reject_trailing("counter qualified Base64", input.len(), parsed.consumed)?;
        Ok(parsed.counter)
    }

    /// Parses exactly one UTF-8 qualified-Base64 byte sequence.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] when the bytes are not UTF-8 or the counter is invalid.
    pub fn from_qb64_bytes(input: &[u8]) -> Result<Self, CesrError> {
        Self::from_qb64(utf8_text(input)?)
    }

    /// Parses one qualified-Base64 counter from the front of a stream.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] for empty, malformed, truncated, or unsupported material.
    pub fn parse_qb64(input: &str) -> Result<ParsedCounter, CesrError> {
        let code = parse_code_prefix(input)?;
        let size = code.size();
        if size.full_size() > MAX_COUNTER_QB64_SIZE {
            return Err(CesrError::InputTooLarge {
                context: "counter qualified Base64",
                length: size.full_size(),
                maximum: MAX_COUNTER_QB64_SIZE,
            });
        }
        let qualified = input.get(..size.full_size()).ok_or(CesrError::Truncated {
            context: "counter qualified Base64",
            needed: size.full_size(),
            available: input.len(),
        })?;
        let digits = qualified
            .get(size.hard_size()..size.full_size())
            .ok_or(CesrError::Truncated {
                context: "counter count",
                needed: size.full_size(),
                available: qualified.len(),
            })?;
        let counter = Self::from_count_b64(code, digits)?;
        Ok(ParsedCounter {
            counter,
            consumed: size.full_size(),
        })
    }

    /// Parses exactly one qualified-binary counter.
    ///
    /// Qualified-binary support is derived from the reference's exact qb64 bytes because its qb2
    /// constructor is empty at the pinned revision.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] for empty, malformed, truncated, unsupported, or trailing material.
    pub fn from_qb2(input: &[u8]) -> Result<Self, CesrError> {
        let parsed = Self::parse_qb2(input)?;
        reject_trailing("counter qualified binary", input.len(), parsed.consumed)?;
        Ok(parsed.counter)
    }

    /// Parses one qualified-binary counter from the front of a stream.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] for empty, malformed, truncated, or unsupported material.
    pub fn parse_qb2(input: &[u8]) -> Result<ParsedCounter, CesrError> {
        if input.is_empty() {
            return Err(CesrError::EmptyInput {
                context: "counter qualified binary",
            });
        }
        let header_bytes = input.get(..3).ok_or(CesrError::Truncated {
            context: "counter qualified binary header",
            needed: 3,
            available: input.len(),
        })?;
        let header = encode_url_safe(header_bytes);
        let consumed = if header.starts_with("--") {
            MAX_COUNTER_QB2_SIZE
        } else {
            parse_code_prefix(&header)?
                .size()
                .full_size()
                .checked_mul(3)
                .and_then(|length| length.checked_div(4))
                .ok_or(CesrError::LengthOverflow {
                    context: "counter qualified binary",
                })?
        };
        let qualified = input.get(..consumed).ok_or(CesrError::Truncated {
            context: "counter qualified binary",
            needed: consumed,
            available: input.len(),
        })?;
        let qb64 = encode_url_safe(qualified);
        let mut parsed = Self::parse_qb64(&qb64)?;
        parsed.consumed = consumed;
        Ok(parsed)
    }

    /// Counter derivation code.
    #[must_use]
    pub const fn code(self) -> CounterCode {
        self.code
    }

    /// Unsigned group count or packed protocol-stack version.
    #[must_use]
    pub const fn count(self) -> u32 {
        self.count
    }

    /// Decodes this counter as a protocol-stack semantic version.
    ///
    /// Returns `None` for ordinary group counters.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] if an internally validated protocol-stack count cannot be decoded.
    pub fn protocol_version(self) -> Result<Option<CounterVersion>, CesrError> {
        if self.code == CounterCode::KERI_PROTOCOL_STACK {
            Ok(Some(CounterVersion::from_packed_count(self.count)?))
        } else {
            Ok(None)
        }
    }

    /// Encodes the count using its selected soft-field width.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] if the shared integer encoder cannot represent the validated count.
    pub fn count_b64(self) -> Result<String, CesrError> {
        let width = u8::try_from(self.code.size().soft_size()).map_err(|_| CesrError::IntegerOverflow {
            context: "counter soft width",
        })?;
        encode_u64(u64::from(self.count), width)
    }

    /// Encodes the count with an explicit minimum width.
    ///
    /// This is the typed equivalent of the reference's `countToB64(length)` helper.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] for an unsupported width or a value that cannot fit a zero width.
    pub fn count_b64_with_width(self, minimum_width: u8) -> Result<String, CesrError> {
        encode_u64(u64::from(self.count), minimum_width)
    }

    /// Canonical qualified-Base64 text.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] if internal length arithmetic or count encoding fails.
    pub fn qb64(self) -> Result<String, CesrError> {
        let size = self.code.size();
        let code_size = size
            .hard_size()
            .checked_add(size.soft_size())
            .ok_or(CesrError::LengthOverflow {
                context: "counter code",
            })?;
        if code_size != size.full_size() || code_size % 4 != 0 {
            return Err(CesrError::InvalidLength {
                context: "counter code table",
                length: code_size,
            });
        }
        let mut output = String::with_capacity(size.full_size());
        output.push_str(self.code.as_str());
        output.push_str(&self.count_b64()?);
        if output.len() != size.full_size() {
            return Err(CesrError::InvalidLength {
                context: "counter qualified Base64",
                length: output.len(),
            });
        }
        Ok(output)
    }

    /// Canonical qualified-Base64 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] if canonical encoding fails.
    pub fn qb64_bytes(self) -> Result<Vec<u8>, CesrError> {
        Ok(self.qb64()?.into_bytes())
    }

    /// Canonical qualified-binary bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] if canonical encoding or bounded decoding fails.
    pub fn qb2(self) -> Result<Vec<u8>, CesrError> {
        decode_url_safe_bounded(&self.qb64()?, MAX_COUNTER_QB2_SIZE)
    }
}

/// One parsed counter and the amount consumed from its input stream.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ParsedCounter {
    counter: Counter,
    consumed: usize,
}

impl ParsedCounter {
    /// Parsed counter value.
    #[must_use]
    pub const fn counter(self) -> Counter {
        self.counter
    }

    /// Number of input characters or bytes consumed.
    #[must_use]
    pub const fn consumed(self) -> usize {
        self.consumed
    }
}

fn parse_code_prefix(input: &str) -> Result<CounterCode, CesrError> {
    if input.is_empty() {
        return Err(CesrError::EmptyInput {
            context: "counter qualified Base64",
        });
    }
    let bytes = input.as_bytes();
    let first = bytes.first().copied().ok_or(CesrError::EmptyInput {
        context: "counter qualified Base64",
    })?;
    if first != b'-' {
        return if first.is_ascii_alphanumeric() {
            Err(CesrError::UnsupportedCode {
                code: char::from(first).to_string(),
            })
        } else {
            Err(CesrError::InvalidCodeCharacter { index: 0, byte: first })
        };
    }
    let second = bytes.get(1).copied().ok_or(CesrError::Truncated {
        context: "counter hard code",
        needed: 2,
        available: input.len(),
    })?;
    let hard_size = match second {
        b'A'..=b'Z' | b'a'..=b'z' => 2,
        b'0' => 3,
        b'-' => 5,
        byte if byte.is_ascii_alphanumeric() => {
            let candidate = input.get(..2).unwrap_or(input);
            return Err(CesrError::UnsupportedCode {
                code: bounded_code(candidate),
            });
        }
        byte => {
            return Err(CesrError::InvalidCodeCharacter { index: 1, byte });
        }
    };
    let hard = input.get(..hard_size).ok_or(CesrError::Truncated {
        context: "counter hard code",
        needed: hard_size,
        available: input.len(),
    })?;
    hard.parse()
}

fn parse_decimal_component(input: &str, component: usize) -> Result<u64, CesrError> {
    if !input.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CesrError::InvalidSemanticVersion {
            component: Some(component),
        });
    }
    let value = input.parse::<u64>().map_err(|_| CesrError::InvalidSemanticVersion {
        component: Some(component),
    })?;
    validate_version_component(component, value)?;
    Ok(value)
}

fn validate_version_component(component: usize, value: u64) -> Result<(), CesrError> {
    if value > 63 {
        return Err(CesrError::SemanticVersionOutOfRange { component, value });
    }
    Ok(())
}

fn version_component_u8(component: usize, value: u64) -> Result<u8, CesrError> {
    validate_version_component(component, value)?;
    u8::try_from(value).map_err(|_| CesrError::IntegerOverflow {
        context: "CESR semantic-version component",
    })
}

fn reject_trailing(context: &'static str, input_length: usize, consumed: usize) -> Result<(), CesrError> {
    let trailing = input_length
        .checked_sub(consumed)
        .ok_or(CesrError::LengthOverflow { context })?;
    if trailing != 0 {
        return Err(CesrError::TrailingMaterial {
            context,
            length: trailing,
        });
    }
    Ok(())
}

fn bounded_code(input: &str) -> String {
    input.chars().take(5).collect()
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn table_matches_reference_shape() -> Result<(), CesrError> {
        assert_eq!(CounterCode::ALL.len(), 15);
        for code in CounterCode::ALL {
            assert_eq!(code.as_str().parse::<CounterCode>()?, *code);
            let size = code.size();
            assert!(size.hard_size() > 0);
            assert!(size.soft_size() > 0);
            assert_eq!(size.hard_size() + size.soft_size(), size.full_size());
            assert_eq!(size.full_size() % 4, 0);
            assert_eq!(size.lead_size(), 0);
        }
        assert_eq!(CounterCode::CONTROLLER_INDEXED_SIGNATURES.maximum_count(), 4_095);
        assert_eq!(CounterCode::KERI_PROTOCOL_STACK.maximum_count(), 262_143);
        assert_eq!(
            CounterCode::BIG_ATTACHED_MATERIAL_QUADLETS.maximum_count(),
            1_073_741_823
        );
        assert!(matches!("".parse::<CounterCode>(), Err(CesrError::EmptyInput { .. })));
        assert!(matches!(
            "-M".parse::<CounterCode>(),
            Err(CesrError::UnsupportedCode { .. })
        ));
        assert!(matches!(
            "-!".parse::<CounterCode>(),
            Err(CesrError::InvalidCodeCharacter { .. })
        ));
        Ok(())
    }

    #[test]
    fn short_big_and_default_counters_round_trip() -> Result<(), Box<dyn Error>> {
        let default = Counter::one(CounterCode::CONTROLLER_INDEXED_SIGNATURES)?;
        assert_eq!(default.qb64()?, "-AAB");
        assert_eq!(default.qb64_bytes()?, b"-AAB");
        assert_eq!(default.count(), 1);
        assert_eq!(Counter::from_qb64("-AAB")?, default);
        assert_eq!(Counter::from_qb64_bytes(b"-AAB")?, default);
        assert_eq!(Counter::from_qb2(&default.qb2()?)?, default);

        let short = Counter::new(CounterCode::CONTROLLER_INDEXED_SIGNATURES, 5)?;
        assert_eq!(short.qb64()?, "-AAF");
        assert_eq!(Counter::from_count_b64(short.code(), "F")?, short);
        assert_eq!(short.count_b64_with_width(3)?, "AAF");
        assert_eq!(short.protocol_version()?, None);
        assert_eq!(short.code().to_string(), "-A");
        assert_eq!(format!("{:?}", short.code()), "CounterCode(\"-A\")");

        let big = Counter::new(CounterCode::BIG_ATTACHED_MATERIAL_QUADLETS, 1_024)?;
        assert_eq!(big.qb64()?, "-0VAAAQA");
        assert_eq!(Counter::from_qb64("-0VAAAQA")?, big);
        assert_eq!(Counter::from_qb2(&big.qb2()?)?, big);
        Ok(())
    }

    #[test]
    fn protocol_versions_match_reference_forms() -> Result<(), Box<dyn Error>> {
        let zero = CounterVersion::ZERO;
        assert_eq!(zero.qb64_digits()?, "AAA");
        assert_eq!(Counter::protocol_stack(zero)?.qb64()?, "--AAAAAA");
        assert_eq!(Counter::from_qb64("--AAAAAA")?.protocol_version()?, Some(zero));

        let version = CounterVersion::new(1, 2, 3)?;
        assert_eq!(version.to_string(), "1.2.3");
        assert_eq!(version.qb64_digits()?, "BCD");
        assert_eq!("1.2.3".parse::<CounterVersion>()?, version);
        assert_eq!("1.1".parse::<CounterVersion>()?.qb64_digits()?, "BBA");
        assert_eq!("1.".parse::<CounterVersion>()?.qb64_digits()?, "BAA");
        assert_eq!("1.2.".parse::<CounterVersion>()?.qb64_digits()?, "BCA");
        assert_eq!("..".parse::<CounterVersion>()?.qb64_digits()?, "AAA");
        assert_eq!("1..3".parse::<CounterVersion>()?.qb64_digits()?, "BAD");
        let fallback = CounterVersion::new(1, 2, 3)?;
        assert_eq!(
            CounterVersion::parse_with_fallback("4", fallback)?.qb64_digits()?,
            "ECD"
        );
        assert_eq!(CounterVersion::from_packed_count(version.packed_count())?, version);
        Ok(())
    }

    #[test]
    fn explicit_stream_parsers_preserve_suffixes() -> Result<(), Box<dyn Error>> {
        let parsed = Counter::parse_qb64("-AAFABCD")?;
        assert_eq!(parsed.counter().qb64()?, "-AAF");
        assert_eq!(parsed.consumed(), 4);
        assert!(matches!(
            Counter::from_qb64("-AAFABCD"),
            Err(CesrError::TrailingMaterial { length: 4, .. })
        ));

        let counter = Counter::new(CounterCode::BIG_ATTACHED_MATERIAL_QUADLETS, 1_024)?;
        let mut binary = counter.qb2()?;
        binary.extend_from_slice(b"suffix");
        let parsed_binary = Counter::parse_qb2(&binary)?;
        assert_eq!(parsed_binary.counter(), counter);
        assert_eq!(parsed_binary.consumed(), 6);
        assert!(matches!(
            Counter::from_qb2(&binary),
            Err(CesrError::TrailingMaterial { length: 6, .. })
        ));
        Ok(())
    }

    #[test]
    fn malformed_and_out_of_range_input_is_typed() {
        assert!(matches!(Counter::from_qb64(""), Err(CesrError::EmptyInput { .. })));
        assert!(matches!(Counter::from_qb64("-AA"), Err(CesrError::Truncated { .. })));
        assert!(matches!(
            Counter::from_qb64("-MAA"),
            Err(CesrError::UnsupportedCode { .. })
        ));
        assert!(matches!(
            Counter::from_qb64("AAAA"),
            Err(CesrError::UnsupportedCode { .. })
        ));
        assert!(matches!(
            Counter::from_qb64("-A!A"),
            Err(CesrError::InvalidBase64Character { .. })
        ));
        assert!(matches!(
            Counter::new(CounterCode::CONTROLLER_INDEXED_SIGNATURES, 4_096),
            Err(CesrError::CounterOutOfRange { .. })
        ));
        assert!(matches!(Counter::from_qb2(&[]), Err(CesrError::EmptyInput { .. })));
        assert!(matches!(
            Counter::from_qb2(&[0_u8; 2]),
            Err(CesrError::Truncated { .. })
        ));
        assert!(matches!(
            CounterVersion::new(64, 0, 0),
            Err(CesrError::SemanticVersionOutOfRange { component: 0, .. })
        ));
        assert!(matches!(
            "1x.2.3".parse::<CounterVersion>(),
            Err(CesrError::InvalidSemanticVersion { component: Some(0) })
        ));
        assert!(matches!(
            "1.2.3.4".parse::<CounterVersion>(),
            Err(CesrError::InvalidSemanticVersion { component: None })
        ));
        assert!(matches!(
            "64.0.0".parse::<CounterVersion>(),
            Err(CesrError::SemanticVersionOutOfRange { component: 0, .. })
        ));
    }
}
