//! Validated CESR indexed material.
//!
//! This module covers the indexed-signature codes and sizing rules from the pinned
//! `signify-ts` `Indexer`. It preserves exact qualified Base64 and qualified-binary bytes while
//! representing the current-index/prior-index relationship explicitly.

use std::{fmt, str::FromStr};

use crate::{
    CesrError,
    base64::{decode_u64, decode_url_safe_bounded, encode_u64, encode_url_safe},
    bytes::{bytes_to_integer, utf8_text},
};

const MAX_INDEXED_QB64_SIZE: usize = 160;
const MAX_INDEXED_QB2_SIZE: usize = 120;

/// Signature algorithm carried by an indexed-signature code.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum IndexedSignatureAlgorithm {
    /// Ed25519 signature material.
    Ed25519,
    /// ECDSA over secp256k1 signature material.
    EcdsaSecp256k1,
    /// ECDSA over secp256r1 signature material.
    EcdsaSecp256r1,
    /// Ed448 signature material.
    Ed448,
}

/// Lists to which an indexed signature applies.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum IndexedSignatureScope {
    /// The signature applies at the current index only and has no prior-list index.
    CurrentOnly,
    /// The signature applies to both lists and carries or implies a prior-list index.
    BothLists,
}

/// Sizing information for one indexed derivation code.
///
/// Character counts describe qualified Base64 fields. Raw and lead sizes are bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IndexerCodeSize {
    hard: usize,
    soft: usize,
    other: usize,
    full: Option<usize>,
    lead: usize,
    raw: Option<usize>,
}

impl IndexerCodeSize {
    const fn fixed(hard: usize, soft: usize, other: usize, full: usize, lead: usize, raw: usize) -> Self {
        Self {
            hard,
            soft,
            other,
            full: Some(full),
            lead,
            raw: Some(raw),
        }
    }

    const fn variable(hard: usize, soft: usize, other: usize, full: Option<usize>, lead: usize) -> Self {
        Self {
            hard,
            soft,
            other,
            full,
            lead,
            raw: None,
        }
    }

    /// Number of characters in the hard derivation code.
    #[must_use]
    pub const fn hard_size(self) -> usize {
        self.hard
    }

    /// Total number of index characters following the hard code.
    #[must_use]
    pub const fn soft_size(self) -> usize {
        self.soft
    }

    /// Number of soft characters reserved for the prior-list index.
    #[must_use]
    pub const fn other_index_size(self) -> usize {
        self.other
    }

    /// Total qualified Base64 size, when fixed by the table.
    #[must_use]
    pub const fn full_size(self) -> Option<usize> {
        self.full
    }

    /// Number of zero lead bytes used for raw-material alignment.
    #[must_use]
    pub const fn lead_size(self) -> usize {
        self.lead
    }

    /// Required raw-material size for supported fixed codes.
    #[must_use]
    pub const fn raw_size(self) -> Option<usize> {
        self.raw
    }

    /// Number of characters carrying the current index.
    #[must_use]
    pub const fn current_index_size(self) -> usize {
        self.soft - self.other
    }
}

/// A validated CESR indexed-material derivation code.
///
/// All entries in the pinned reference table are representable. The three variable-length entries
/// remain table metadata only because the reference explicitly rejects their construction and
/// parsing.
///
/// ```compile_fail
/// use signify_cesr::indexer::IndexerCode;
///
/// let invalid = IndexerCode("A");
/// ```
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct IndexerCode {
    value: &'static str,
    size: IndexerCodeSize,
    algorithm: Option<IndexedSignatureAlgorithm>,
    scope: Option<IndexedSignatureScope>,
}

impl IndexerCode {
    const fn signature(
        value: &'static str,
        soft: usize,
        other: usize,
        full: usize,
        raw: usize,
        algorithm: IndexedSignatureAlgorithm,
        scope: IndexedSignatureScope,
    ) -> Self {
        Self {
            value,
            size: IndexerCodeSize::fixed(value.len(), soft, other, full, 0, raw),
            algorithm: Some(algorithm),
            scope: Some(scope),
        }
    }

    const fn variable(value: &'static str, soft: usize, other: usize, full: Option<usize>, lead: usize) -> Self {
        Self {
            value,
            size: IndexerCodeSize::variable(value.len(), soft, other, full, lead),
            algorithm: None,
            scope: None,
        }
    }

    /// Small Ed25519 signature applying to both lists (`A`).
    pub const ED25519: Self = Self::signature(
        "A",
        1,
        0,
        88,
        64,
        IndexedSignatureAlgorithm::Ed25519,
        IndexedSignatureScope::BothLists,
    );
    /// Small current-only Ed25519 signature (`B`).
    pub const ED25519_CURRENT: Self = Self::signature(
        "B",
        1,
        0,
        88,
        64,
        IndexedSignatureAlgorithm::Ed25519,
        IndexedSignatureScope::CurrentOnly,
    );
    /// Small secp256k1 signature applying to both lists (`C`).
    pub const ECDSA_256K1: Self = Self::signature(
        "C",
        1,
        0,
        88,
        64,
        IndexedSignatureAlgorithm::EcdsaSecp256k1,
        IndexedSignatureScope::BothLists,
    );
    /// Small current-only secp256k1 signature (`D`).
    pub const ECDSA_256K1_CURRENT: Self = Self::signature(
        "D",
        1,
        0,
        88,
        64,
        IndexedSignatureAlgorithm::EcdsaSecp256k1,
        IndexedSignatureScope::CurrentOnly,
    );
    /// Small secp256r1 signature applying to both lists (`E`).
    pub const ECDSA_256R1: Self = Self::signature(
        "E",
        1,
        0,
        88,
        64,
        IndexedSignatureAlgorithm::EcdsaSecp256r1,
        IndexedSignatureScope::BothLists,
    );
    /// Small current-only secp256r1 signature (`F`).
    pub const ECDSA_256R1_CURRENT: Self = Self::signature(
        "F",
        1,
        0,
        88,
        64,
        IndexedSignatureAlgorithm::EcdsaSecp256r1,
        IndexedSignatureScope::CurrentOnly,
    );
    /// Small Ed448 signature applying to both lists (`0A`).
    pub const ED448: Self = Self::signature(
        "0A",
        2,
        1,
        156,
        114,
        IndexedSignatureAlgorithm::Ed448,
        IndexedSignatureScope::BothLists,
    );
    /// Small current-only Ed448 signature (`0B`).
    pub const ED448_CURRENT: Self = Self::signature(
        "0B",
        2,
        1,
        156,
        114,
        IndexedSignatureAlgorithm::Ed448,
        IndexedSignatureScope::CurrentOnly,
    );
    /// Big Ed25519 signature applying to both lists (`2A`).
    pub const ED25519_BIG: Self = Self::signature(
        "2A",
        4,
        2,
        92,
        64,
        IndexedSignatureAlgorithm::Ed25519,
        IndexedSignatureScope::BothLists,
    );
    /// Big current-only Ed25519 signature (`2B`).
    pub const ED25519_BIG_CURRENT: Self = Self::signature(
        "2B",
        4,
        2,
        92,
        64,
        IndexedSignatureAlgorithm::Ed25519,
        IndexedSignatureScope::CurrentOnly,
    );
    /// Big secp256k1 signature applying to both lists (`2C`).
    pub const ECDSA_256K1_BIG: Self = Self::signature(
        "2C",
        4,
        2,
        92,
        64,
        IndexedSignatureAlgorithm::EcdsaSecp256k1,
        IndexedSignatureScope::BothLists,
    );
    /// Big current-only secp256k1 signature (`2D`).
    pub const ECDSA_256K1_BIG_CURRENT: Self = Self::signature(
        "2D",
        4,
        2,
        92,
        64,
        IndexedSignatureAlgorithm::EcdsaSecp256k1,
        IndexedSignatureScope::CurrentOnly,
    );
    /// Big secp256r1 signature applying to both lists (`2E`).
    pub const ECDSA_256R1_BIG: Self = Self::signature(
        "2E",
        4,
        2,
        92,
        64,
        IndexedSignatureAlgorithm::EcdsaSecp256r1,
        IndexedSignatureScope::BothLists,
    );
    /// Big current-only secp256r1 signature (`2F`).
    pub const ECDSA_256R1_BIG_CURRENT: Self = Self::signature(
        "2F",
        4,
        2,
        92,
        64,
        IndexedSignatureAlgorithm::EcdsaSecp256r1,
        IndexedSignatureScope::CurrentOnly,
    );
    /// Big Ed448 signature applying to both lists (`3A`).
    pub const ED448_BIG: Self = Self::signature(
        "3A",
        6,
        3,
        160,
        114,
        IndexedSignatureAlgorithm::Ed448,
        IndexedSignatureScope::BothLists,
    );
    /// Big current-only Ed448 signature (`3B`).
    pub const ED448_BIG_CURRENT: Self = Self::signature(
        "3B",
        6,
        3,
        160,
        114,
        IndexedSignatureAlgorithm::Ed448,
        IndexedSignatureScope::CurrentOnly,
    );

    /// Every code in the pinned reference's `Indexer.Sizes` table, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::ED25519,
        Self::ED25519_CURRENT,
        Self::ECDSA_256K1,
        Self::ECDSA_256K1_CURRENT,
        Self::ECDSA_256R1,
        Self::ECDSA_256R1_CURRENT,
        Self::ED448,
        Self::ED448_CURRENT,
        Self::ED25519_BIG,
        Self::ED25519_BIG_CURRENT,
        Self::ECDSA_256K1_BIG,
        Self::ECDSA_256K1_BIG_CURRENT,
        Self::ECDSA_256R1_BIG,
        Self::ECDSA_256R1_BIG_CURRENT,
        Self::ED448_BIG,
        Self::ED448_BIG_CURRENT,
        Self::variable("0z", 2, 0, None, 0),
        Self::variable("1z", 2, 1, Some(76), 1),
        Self::variable("4z", 6, 3, Some(80), 1),
    ];

    /// Canonical hard-code text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.value
    }

    /// Raw, hard, soft, full, lead, and other-index size metadata.
    #[must_use]
    pub const fn size(self) -> IndexerCodeSize {
        self.size
    }

    /// Signature algorithm, or `None` for a variable table-only entry.
    #[must_use]
    pub const fn signature_algorithm(self) -> Option<IndexedSignatureAlgorithm> {
        self.algorithm
    }

    /// Index scope, or `None` for a variable table-only entry.
    #[must_use]
    pub const fn signature_scope(self) -> Option<IndexedSignatureScope> {
        self.scope
    }
}

impl fmt::Debug for IndexerCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("IndexerCode").field(&self.value).finish()
    }
}

impl fmt::Display for IndexerCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.value)
    }
}

impl FromStr for IndexerCode {
    type Err = CesrError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let Some(&selector) = input.as_bytes().first() else {
            return Err(CesrError::EmptyInput {
                context: "indexed derivation code",
            });
        };
        if let Some((index, byte)) = input
            .bytes()
            .enumerate()
            .find(|(_, byte)| !byte.is_ascii_alphanumeric())
        {
            return Err(CesrError::InvalidCodeCharacter { index, byte });
        }
        let expected = indexer_hard_size(selector)?;
        if input.len() != expected {
            return Err(CesrError::InvalidLength {
                context: "indexed derivation code",
                length: input.len(),
            });
        }
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.value == input)
            .ok_or_else(|| CesrError::UnsupportedCode { code: input.to_owned() })
    }
}

/// A validated indexed CESR material value.
///
/// `index` identifies the current key list position. `other_index` is present only for codes that
/// apply to both current and prior key lists. Small both-list codes imply equality; big and Ed448
/// both-list codes can carry a distinct prior-list index.
#[derive(Clone, Eq, PartialEq)]
pub struct IndexedMaterial {
    code: IndexerCode,
    index: u32,
    other_index: Option<u32>,
    raw: Vec<u8>,
}

impl IndexedMaterial {
    /// Constructs fixed indexed material from exact raw bytes and validated indices.
    ///
    /// Passing `None` for a both-list code defaults the prior-list index to `index`. Current-only
    /// codes require `None`. Raw material must have exactly the size selected by `code`.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] for a table-only variable code, invalid index relationship, out-of-
    /// range index, or raw-size mismatch.
    pub fn new(code: IndexerCode, index: u32, other_index: Option<u32>, raw: &[u8]) -> Result<Self, CesrError> {
        let size = code.size();
        let raw_size = size.raw_size().ok_or(CesrError::UnsupportedVariableLength {
            context: "indexed material",
        })?;
        validate_indices(code, index, other_index)?;
        if raw.len() != raw_size {
            return Err(CesrError::RawSizeMismatch {
                context: "indexed raw material",
                expected: raw_size,
                actual: raw.len(),
            });
        }
        let other_index = normalized_other_index(code, index, other_index)?;
        Ok(Self {
            code,
            index,
            other_index,
            raw: raw.to_vec(),
        })
    }

    /// Parses the fixed raw prefix selected by `code` while retaining an unconsumed suffix.
    ///
    /// This makes the reference constructor's observable prefix consumption explicit while
    /// keeping [`Self::new`] strict about exact input size.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] for a table-only variable code, invalid indices, or truncated input.
    pub fn parse_raw_prefix(
        code: IndexerCode,
        index: u32,
        other_index: Option<u32>,
        input: &[u8],
    ) -> Result<ParsedIndexer, CesrError> {
        let raw_size = code.size().raw_size().ok_or(CesrError::UnsupportedVariableLength {
            context: "indexed material",
        })?;
        let raw = input.get(..raw_size).ok_or(CesrError::Truncated {
            context: "indexed raw material",
            needed: raw_size,
            available: input.len(),
        })?;
        Ok(ParsedIndexer {
            material: Self::new(code, index, other_index, raw)?,
            consumed: raw_size,
        })
    }

    /// Parses exactly one qualified Base64 indexed value.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] for malformed, truncated, unsupported, non-canonical, or trailing
    /// material.
    pub fn from_qb64(input: &str) -> Result<Self, CesrError> {
        let parsed = Self::parse_qb64(input)?;
        reject_trailing("indexed qualified Base64", input.len(), parsed.consumed)?;
        Ok(parsed.material)
    }

    /// Parses exactly one UTF-8 qualified Base64 byte sequence.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] when the bytes are not UTF-8 or indexed material is invalid.
    pub fn from_qb64_bytes(input: &[u8]) -> Result<Self, CesrError> {
        Self::from_qb64(utf8_text(input)?)
    }

    /// Parses one qualified Base64 value from the front of a stream.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] for malformed, truncated, unsupported, or non-canonical material.
    pub fn parse_qb64(input: &str) -> Result<ParsedIndexer, CesrError> {
        let layout = parse_layout(input, true)?;
        let qualified = input.get(..layout.full_size).ok_or(CesrError::Truncated {
            context: "indexed qualified Base64",
            needed: layout.full_size,
            available: input.len(),
        })?;
        let index_text = qualified
            .get(layout.hard_size..layout.hard_size + layout.current_size)
            .ok_or(CesrError::Truncated {
                context: "current index",
                needed: layout.code_size,
                available: qualified.len(),
            })?;
        let index = index_to_u32(decode_u64(index_text)?, "current index")?;
        let other_start = layout.hard_size + layout.current_size;
        let other_text = qualified
            .get(other_start..layout.code_size)
            .ok_or(CesrError::Truncated {
                context: "other index",
                needed: layout.code_size,
                available: qualified.len(),
            })?;
        let encoded_other = if other_text.is_empty() {
            None
        } else {
            Some(index_to_u32(decode_u64(other_text)?, "other index")?)
        };
        let other_index = match layout.code.signature_scope() {
            Some(IndexedSignatureScope::CurrentOnly) => {
                if encoded_other.is_some_and(|value| value != 0) {
                    return Err(CesrError::InvalidIndexRelation {
                        context: "current-only indexed material must encode a zero reserved other index",
                    });
                }
                None
            }
            Some(IndexedSignatureScope::BothLists) => Some(encoded_other.unwrap_or(index)),
            None => {
                return Err(CesrError::UnsupportedVariableLength {
                    context: "indexed material",
                });
            }
        };
        validate_indices(layout.code, index, other_index)?;

        let raw = decode_raw(qualified, &layout)?;
        let material = Self {
            code: layout.code,
            index,
            other_index,
            raw,
        };
        Ok(ParsedIndexer {
            material,
            consumed: layout.full_size,
        })
    }

    /// Parses exactly one qualified-binary indexed value.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] for malformed, truncated, unsupported, or trailing material.
    pub fn from_qb2(input: &[u8]) -> Result<Self, CesrError> {
        let parsed = Self::parse_qb2(input)?;
        reject_trailing("indexed qualified binary", input.len(), parsed.consumed)?;
        Ok(parsed.material)
    }

    /// Parses one qualified-binary indexed value from the front of a stream.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] for malformed, truncated, unsupported, or non-canonical material.
    pub fn parse_qb2(input: &[u8]) -> Result<ParsedIndexer, CesrError> {
        if input.is_empty() {
            return Err(CesrError::EmptyInput {
                context: "indexed qualified binary",
            });
        }
        let header_bytes = input.get(..3).ok_or(CesrError::Truncated {
            context: "indexed qualified binary header",
            needed: 3,
            available: input.len(),
        })?;
        let header = encode_url_safe(header_bytes);
        let layout = parse_layout(&header, false)?;
        let consumed = layout
            .full_size
            .checked_mul(3)
            .and_then(|size| size.checked_div(4))
            .ok_or(CesrError::LengthOverflow {
                context: "indexed qualified binary",
            })?;
        if consumed > MAX_INDEXED_QB2_SIZE {
            return Err(CesrError::InputTooLarge {
                context: "indexed qualified binary",
                length: consumed,
                maximum: MAX_INDEXED_QB2_SIZE,
            });
        }
        let qualified = input.get(..consumed).ok_or(CesrError::Truncated {
            context: "indexed qualified binary",
            needed: consumed,
            available: input.len(),
        })?;
        let qb64 = encode_url_safe(qualified);
        let mut parsed = Self::parse_qb64(&qb64)?;
        parsed.consumed = consumed;
        Ok(parsed)
    }

    /// Derivation code selecting signature kind and index widths.
    #[must_use]
    pub const fn code(&self) -> IndexerCode {
        self.code
    }

    /// Current-list index.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// Prior-list index for both-list codes; `None` for current-only codes.
    #[must_use]
    pub const fn other_index(&self) -> Option<u32> {
        self.other_index
    }

    /// Borrowed raw signature bytes.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Canonical qualified Base64 text.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] if internal length arithmetic or Base64 field encoding fails.
    pub fn qb64(&self) -> Result<String, CesrError> {
        let size = self.code.size();
        let full_size = size.full_size().ok_or(CesrError::UnsupportedVariableLength {
            context: "indexed material",
        })?;
        validate_indices(self.code, self.index, self.other_index)?;
        let current_width = width_u8(size.current_index_size(), "current index width")?;
        let other_width = width_u8(size.other_index_size(), "other index width")?;
        let mut both = String::with_capacity(size.hard_size() + size.soft_size());
        both.push_str(self.code.as_str());
        both.push_str(&encode_u64(u64::from(self.index), current_width)?);
        let encoded_other = if size.other_index_size() == 0 {
            0
        } else {
            self.other_index.unwrap_or(0)
        };
        both.push_str(&encode_u64(u64::from(encoded_other), other_width)?);
        let code_size = size
            .hard_size()
            .checked_add(size.soft_size())
            .ok_or(CesrError::LengthOverflow {
                context: "indexed code",
            })?;
        if both.len() != code_size {
            return Err(CesrError::InvalidLength {
                context: "indexed code",
                length: both.len(),
            });
        }

        let pad_size = (3 - (self.raw.len() % 3)) % 3;
        let expected_alignment = pad_size
            .checked_sub(size.lead_size())
            .ok_or(CesrError::NonZeroPadding {
                context: "indexed lead alignment",
            })?;
        if code_size % 4 != expected_alignment {
            return Err(CesrError::NonZeroPadding {
                context: "indexed code alignment",
            });
        }
        let padded_size = pad_size.checked_add(self.raw.len()).ok_or(CesrError::LengthOverflow {
            context: "indexed raw material",
        })?;
        let mut padded = Vec::with_capacity(padded_size);
        padded.resize(pad_size, 0);
        padded.extend_from_slice(&self.raw);
        let encoded = encode_url_safe(&padded);
        let payload = encoded.get(expected_alignment..).ok_or(CesrError::InvalidLength {
            context: "indexed Base64 payload",
            length: encoded.len(),
        })?;
        let mut qualified = String::with_capacity(full_size);
        qualified.push_str(&both);
        qualified.push_str(payload);
        if qualified.len() != full_size {
            return Err(CesrError::InvalidLength {
                context: "indexed qualified Base64",
                length: qualified.len(),
            });
        }
        Ok(qualified)
    }

    /// Canonical qualified Base64 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] if canonical encoding fails.
    pub fn qb64_bytes(&self) -> Result<Vec<u8>, CesrError> {
        Ok(self.qb64()?.into_bytes())
    }

    /// Canonical qualified-binary bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError`] if canonical encoding or bounded decoding fails.
    pub fn qb2(&self) -> Result<Vec<u8>, CesrError> {
        decode_url_safe_bounded(&self.qb64()?, MAX_INDEXED_QB2_SIZE)
    }
}

impl fmt::Debug for IndexedMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IndexedMaterial")
            .field("code", &self.code)
            .field("index", &self.index)
            .field("other_index", &self.other_index)
            .field("raw_length", &self.raw.len())
            .finish()
    }
}

/// One parsed indexed value and the amount consumed from its input stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedIndexer {
    material: IndexedMaterial,
    consumed: usize,
}

impl ParsedIndexer {
    /// Borrowed parsed material.
    #[must_use]
    pub const fn material(&self) -> &IndexedMaterial {
        &self.material
    }

    /// Number of input characters or bytes consumed.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Moves the parsed material out of this result.
    #[must_use]
    pub fn into_material(self) -> IndexedMaterial {
        self.material
    }
}

#[derive(Clone, Copy, Debug)]
struct IndexerLayout {
    code: IndexerCode,
    hard_size: usize,
    current_size: usize,
    code_size: usize,
    full_size: usize,
    lead_size: usize,
    raw_size: usize,
}

fn parse_layout(input: &str, require_full_input: bool) -> Result<IndexerLayout, CesrError> {
    let Some(&selector) = input.as_bytes().first() else {
        return Err(CesrError::EmptyInput {
            context: "indexed qualified Base64",
        });
    };
    let hard_size = indexer_hard_size(selector)?;
    let hard = input.get(..hard_size).ok_or(CesrError::Truncated {
        context: "indexed hard code",
        needed: hard_size,
        available: input.len(),
    })?;
    let code = hard.parse::<IndexerCode>()?;
    let size = code.size();
    let full_size = size.full_size().ok_or(CesrError::UnsupportedVariableLength {
        context: "indexed material",
    })?;
    if full_size > MAX_INDEXED_QB64_SIZE {
        return Err(CesrError::InputTooLarge {
            context: "indexed qualified Base64",
            length: full_size,
            maximum: MAX_INDEXED_QB64_SIZE,
        });
    }
    let code_size = hard_size
        .checked_add(size.soft_size())
        .ok_or(CesrError::LengthOverflow {
            context: "indexed code",
        })?;
    if require_full_input && input.len() < full_size {
        return Err(CesrError::Truncated {
            context: "indexed qualified Base64",
            needed: full_size,
            available: input.len(),
        });
    }
    let raw_size = size.raw_size().ok_or(CesrError::UnsupportedVariableLength {
        context: "indexed material",
    })?;
    Ok(IndexerLayout {
        code,
        hard_size,
        current_size: size.current_index_size(),
        code_size,
        full_size,
        lead_size: size.lead_size(),
        raw_size,
    })
}

fn decode_raw(qualified: &str, layout: &IndexerLayout) -> Result<Vec<u8>, CesrError> {
    let payload = qualified.get(layout.code_size..).ok_or(CesrError::Truncated {
        context: "indexed Base64 payload",
        needed: layout.full_size,
        available: qualified.len(),
    })?;
    let code_pad = layout.code_size % 4;
    let mut base = String::with_capacity(code_pad + payload.len());
    base.extend(std::iter::repeat_n('A', code_pad));
    base.push_str(payload);
    let maximum = layout
        .raw_size
        .checked_add(code_pad.max(layout.lead_size))
        .ok_or(CesrError::LengthOverflow {
            context: "indexed raw material",
        })?;
    let padded = decode_url_safe_bounded(&base, maximum)?;
    let strip = if code_pad == 0 {
        let lead = padded.get(..layout.lead_size).ok_or(CesrError::Truncated {
            context: "indexed lead bytes",
            needed: layout.lead_size,
            available: padded.len(),
        })?;
        if lead.iter().any(|byte| *byte != 0) {
            return Err(CesrError::NonZeroPadding {
                context: "indexed lead bytes",
            });
        }
        layout.lead_size
    } else {
        let prefix = padded.get(..code_pad).ok_or(CesrError::Truncated {
            context: "indexed alignment bytes",
            needed: code_pad,
            available: padded.len(),
        })?;
        let value = bytes_to_integer(prefix)?;
        let padding_bits = code_pad.checked_mul(2).ok_or(CesrError::LengthOverflow {
            context: "indexed alignment bits",
        })?;
        let mask = 1_u128
            .checked_shl(u32::try_from(padding_bits).map_err(|_| CesrError::IntegerOverflow {
                context: "indexed alignment bits",
            })?)
            .and_then(|value| value.checked_sub(1))
            .ok_or(CesrError::IntegerOverflow {
                context: "indexed alignment mask",
            })?;
        if value & mask != 0 {
            return Err(CesrError::NonZeroPadding {
                context: "indexed code alignment bits",
            });
        }
        code_pad
    };
    let raw = padded.get(strip..).ok_or(CesrError::Truncated {
        context: "indexed raw material",
        needed: strip,
        available: padded.len(),
    })?;
    if raw.len() != layout.raw_size {
        return Err(CesrError::RawSizeMismatch {
            context: "indexed raw material",
            expected: layout.raw_size,
            actual: raw.len(),
        });
    }
    Ok(raw.to_vec())
}

fn validate_indices(code: IndexerCode, index: u32, other_index: Option<u32>) -> Result<(), CesrError> {
    let size = code.size();
    let current_maximum = maximum_index(size.current_index_size())?;
    if index > current_maximum {
        return Err(CesrError::IndexOutOfRange {
            context: "current index",
            value: index,
            maximum: current_maximum,
        });
    }
    match code.signature_scope() {
        Some(IndexedSignatureScope::CurrentOnly) => {
            if other_index.is_some() {
                return Err(CesrError::InvalidIndexRelation {
                    context: "current-only indexed material must not have an other index",
                });
            }
        }
        Some(IndexedSignatureScope::BothLists) => {
            if size.other_index_size() == 0 {
                if other_index.is_some_and(|value| value != index) {
                    return Err(CesrError::InvalidIndexRelation {
                        context: "implicit other index must equal the current index",
                    });
                }
            } else if let Some(value) = other_index {
                let maximum = maximum_index(size.other_index_size())?;
                if value > maximum {
                    return Err(CesrError::IndexOutOfRange {
                        context: "other index",
                        value,
                        maximum,
                    });
                }
            }
        }
        None => {
            return Err(CesrError::UnsupportedVariableLength {
                context: "indexed material",
            });
        }
    }
    Ok(())
}

fn normalized_other_index(code: IndexerCode, index: u32, other_index: Option<u32>) -> Result<Option<u32>, CesrError> {
    match code.signature_scope() {
        Some(IndexedSignatureScope::CurrentOnly) => Ok(None),
        Some(IndexedSignatureScope::BothLists) => Ok(Some(other_index.unwrap_or(index))),
        None => Err(CesrError::UnsupportedVariableLength {
            context: "indexed material",
        }),
    }
}

fn maximum_index(width: usize) -> Result<u32, CesrError> {
    let exponent = u32::try_from(width).map_err(|_| CesrError::IntegerOverflow {
        context: "indexed field width",
    })?;
    let maximum = 64_u32
        .checked_pow(exponent)
        .and_then(|value| value.checked_sub(1))
        .ok_or(CesrError::IntegerOverflow {
            context: "indexed field maximum",
        })?;
    Ok(maximum)
}

fn indexer_hard_size(selector: u8) -> Result<usize, CesrError> {
    match selector {
        b'A'..=b'Z' | b'a'..=b'z' => Ok(1),
        b'0'..=b'4' => Ok(2),
        b'5'..=b'9' | b'-' | b'_' => Err(CesrError::UnsupportedCode {
            code: char::from(selector).to_string(),
        }),
        _ => Err(CesrError::InvalidCodeCharacter {
            index: 0,
            byte: selector,
        }),
    }
}

fn index_to_u32(value: u64, context: &'static str) -> Result<u32, CesrError> {
    u32::try_from(value).map_err(|_| CesrError::IntegerOverflow { context })
}

fn width_u8(width: usize, context: &'static str) -> Result<u8, CesrError> {
    u8::try_from(width).map_err(|_| CesrError::IntegerOverflow { context })
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

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    const SIG: [u8; 64] = [
        153, 210, 60, 57, 36, 36, 48, 159, 107, 251, 24, 160, 140, 64, 114, 18, 50, 46, 107, 178, 199, 31, 112, 14, 39,
        109, 143, 64, 170, 165, 140, 200, 110, 133, 200, 33, 246, 113, 145, 112, 169, 236, 207, 146, 175, 41, 222, 202,
        252, 127, 126, 215, 111, 124, 23, 130, 29, 212, 60, 111, 34, 129, 38, 9,
    ];

    #[test]
    fn table_matches_reference_shape() -> Result<(), CesrError> {
        assert_eq!(IndexerCode::ALL.len(), 19);
        assert_eq!(IndexerCode::ED25519.size().hard_size(), 1);
        assert_eq!(IndexerCode::ED25519.size().soft_size(), 1);
        assert_eq!(IndexerCode::ED25519.size().other_index_size(), 0);
        assert_eq!(IndexerCode::ED25519.size().full_size(), Some(88));
        assert_eq!(IndexerCode::ED25519.size().lead_size(), 0);
        assert_eq!(
            IndexerCode::ED25519.signature_algorithm(),
            Some(IndexedSignatureAlgorithm::Ed25519)
        );
        assert_eq!(
            IndexerCode::ED25519.signature_scope(),
            Some(IndexedSignatureScope::BothLists)
        );
        assert_eq!(
            IndexerCode::ED25519_CURRENT.signature_scope(),
            Some(IndexedSignatureScope::CurrentOnly)
        );
        for code in IndexerCode::ALL {
            assert_eq!(code.as_str().parse::<IndexerCode>()?, *code);
            let size = code.size();
            assert!(size.hard_size() > 0);
            assert!(size.soft_size() > 0);
            if size.other_index_size() > 0 {
                assert_eq!(size.other_index_size(), size.soft_size() / 2);
            }
            if let Some(full) = size.full_size() {
                assert!(full >= size.hard_size() + size.soft_size());
                assert_eq!(full % 4, 0);
            }
        }
        assert!(matches!("".parse::<IndexerCode>(), Err(CesrError::EmptyInput { .. })));
        assert!(matches!(
            "2".parse::<IndexerCode>(),
            Err(CesrError::InvalidLength { .. })
        ));
        assert!(matches!(
            "G".parse::<IndexerCode>(),
            Err(CesrError::UnsupportedCode { .. })
        ));
        assert!(matches!(
            "-".parse::<IndexerCode>(),
            Err(CesrError::InvalidCodeCharacter { .. })
        ));
        Ok(())
    }

    #[test]
    fn reference_small_and_big_signatures_round_trip() -> Result<(), Box<dyn Error>> {
        let small = IndexedMaterial::new(IndexerCode::ED25519, 5, None, &SIG)?;
        assert_eq!(
            small.qb64()?,
            "AFCZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ"
        );
        assert_eq!(small.other_index(), Some(5));
        assert_same(&IndexedMaterial::from_qb64(&small.qb64()?)?, &small);
        assert_same(&IndexedMaterial::from_qb64_bytes(&small.qb64_bytes()?)?, &small);
        assert_same(&IndexedMaterial::from_qb2(&small.qb2()?)?, &small);
        assert_eq!(IndexedMaterial::parse_qb64(&small.qb64()?)?.into_material(), small);

        let big = IndexedMaterial::new(IndexerCode::ED25519_BIG, 90, Some(65), &SIG)?;
        assert_eq!(
            big.qb64()?,
            "2ABaBBCZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ"
        );
        assert_same(&IndexedMaterial::from_qb64(&big.qb64()?)?, &big);
        assert_same(&IndexedMaterial::from_qb2(&big.qb2()?)?, &big);
        Ok(())
    }

    #[test]
    fn current_only_codes_exclude_other_index() -> Result<(), Box<dyn Error>> {
        let material = IndexedMaterial::new(IndexerCode::ED25519_CURRENT, 3, None, &SIG)?;
        assert_eq!(material.other_index(), None);
        assert_eq!(
            material.qb64()?,
            "BDCZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ"
        );
        assert!(matches!(
            IndexedMaterial::new(IndexerCode::ED25519_CURRENT, 3, Some(3), &SIG),
            Err(CesrError::InvalidIndexRelation { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_invalid_indices_sizes_codes_and_padding() {
        assert!(matches!(
            IndexedMaterial::new(IndexerCode::ED25519, 64, None, &SIG),
            Err(CesrError::IndexOutOfRange { .. })
        ));
        assert!(matches!(
            IndexedMaterial::new(IndexerCode::ED25519, 5, Some(4), &SIG),
            Err(CesrError::InvalidIndexRelation { .. })
        ));
        let short = SIG.get(..63).ok_or(CesrError::Truncated {
            context: "short signature test fixture",
            needed: 63,
            available: SIG.len(),
        });
        assert!(matches!(
            short.and_then(|raw| IndexedMaterial::new(IndexerCode::ED25519, 0, None, raw)),
            Err(CesrError::RawSizeMismatch { .. })
        ));
        assert!(matches!(
            "0z".parse::<IndexerCode>()
                .and_then(|code| IndexedMaterial::new(code, 0, None, &[])),
            Err(CesrError::UnsupportedVariableLength { .. })
        ));
        assert!(matches!(
            IndexedMaterial::from_qb64(""),
            Err(CesrError::EmptyInput { .. })
        ));
        assert!(matches!(
            IndexedMaterial::from_qb64(
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            ),
            Err(CesrError::UnsupportedCode { .. })
        ));
        assert!(matches!(
            IndexedMaterial::from_qb64("AA"),
            Err(CesrError::Truncated { .. })
        ));
        assert!(matches!(
            IndexedMaterial::from_qb64_bytes(&[0xff]),
            Err(CesrError::InvalidUtf8 { .. })
        ));
        assert!(matches!(
            IndexedMaterial::from_qb2(&[]),
            Err(CesrError::EmptyInput { .. })
        ));
        assert!(matches!(
            IndexedMaterial::from_qb2(&[0]),
            Err(CesrError::Truncated { .. })
        ));
        assert!(matches!(
            IndexedMaterial::from_qb64(
                "AA_Z0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ"
            ),
            Err(CesrError::NonZeroPadding { .. })
        ));
    }

    #[test]
    fn stream_parsers_report_consumption_and_strict_parsers_reject_suffix() -> Result<(), Box<dyn Error>> {
        let material = IndexedMaterial::new(IndexerCode::ED25519_BIG, 67, None, &SIG)?;
        let qb64 = material.qb64()?;
        let text_stream = format!("{qb64}ABCD");
        let parsed_text = IndexedMaterial::parse_qb64(&text_stream)?;
        assert_eq!(parsed_text.consumed(), qb64.len());
        assert_same(parsed_text.material(), &material);
        assert!(matches!(
            IndexedMaterial::from_qb64(&text_stream),
            Err(CesrError::TrailingMaterial { length: 4, .. })
        ));

        let qb2 = material.qb2()?;
        let mut binary_stream = qb2.clone();
        binary_stream.extend_from_slice(&[1, 2, 3]);
        let parsed_binary = IndexedMaterial::parse_qb2(&binary_stream)?;
        assert_eq!(parsed_binary.consumed(), qb2.len());
        assert_same(parsed_binary.material(), &material);
        assert!(matches!(
            IndexedMaterial::from_qb2(&binary_stream),
            Err(CesrError::TrailingMaterial { length: 3, .. })
        ));
        Ok(())
    }

    #[test]
    fn raw_prefix_parsing_is_explicit() -> Result<(), Box<dyn Error>> {
        let mut input = SIG.to_vec();
        input.extend_from_slice(&[10, 11, 12]);
        let parsed = IndexedMaterial::parse_raw_prefix(IndexerCode::ED25519, 5, None, &input)?;
        assert_eq!(parsed.consumed(), SIG.len());
        assert_eq!(parsed.material().raw(), SIG);
        assert!(matches!(
            IndexedMaterial::new(IndexerCode::ED25519, 5, None, &input),
            Err(CesrError::RawSizeMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn debug_omits_signature_bytes() -> Result<(), CesrError> {
        let material = IndexedMaterial::new(IndexerCode::ED25519, 0, None, &SIG)?;
        let debug = format!("{material:?}");
        assert!(debug.contains("raw_length: 64"));
        assert!(!debug.contains("153, 210"));
        Ok(())
    }

    fn assert_same(left: &IndexedMaterial, right: &IndexedMaterial) {
        assert_eq!(left.code(), right.code());
        assert_eq!(left.index(), right.index());
        assert_eq!(left.other_index(), right.other_index());
        assert_eq!(left.raw(), right.raw());
    }
}
