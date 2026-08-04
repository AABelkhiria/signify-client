//! Validated CESR qualified material.
//!
//! This module is the Rust engine corresponding to the reference `Matter` base class. It owns only
//! qualification, canonical encoding, and bounded parsing. Crypto and protocol crates wrap
//! [`QualifiedMaterial`] in semantic types such as digests, verification keys, and sequence
//! numbers instead of exposing inheritance.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

use crate::{
    CesrError,
    base64::{MAX_DECODED_BYTES, decode_u64, decode_url_safe_bounded, encode_u64, encode_url_safe},
    code::{CodeFamily, DerivationCode, hard_code_size},
};

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const SMALL_VARIABLE_MAX_TRIPLETS: u64 = 64_u64.pow(2) - 1;
const LARGE_VARIABLE_MAX_TRIPLETS: u64 = 64_u64.pow(4) - 1;

/// Maximum raw byte length accepted by the generic material engine.
///
/// CESR's four-character variable-size field can describe almost 48 MiB. This implementation uses
/// a smaller explicit ceiling just below 16 MiB, reserving eight bytes for the largest qualified
/// code and lead prefix within the generic Base64 decoder's bound. Applications should apply
/// tighter semantic limits where their material kind has one.
pub const MAX_RAW_MATERIAL_BYTES: usize = MAX_DECODED_BYTES - 8;

/// One validated, fully qualified CESR material primitive.
///
/// This type is the narrow encoding core for later semantic wrappers. Its fields are private, and
/// construction always validates the derivation code, raw length, variable-size selector, and
/// canonical padding. It is intentionally not cloneable because supported codes include secret
/// seed and private-key material; debug output redacts raw bytes, and owned bytes are zeroized on
/// drop.
///
/// ```compile_fail
/// use signify_cesr::{CesrError, code::DerivationCode, matter::QualifiedMaterial};
///
/// fn main() -> Result<(), CesrError> {
///     let material = QualifiedMaterial::new(DerivationCode::ED25519_SEED, &[0_u8; 32])?;
///     let copied = material.clone();
///     Ok(())
/// }
/// ```
pub struct QualifiedMaterial {
    code: DerivationCode,
    size: Option<u32>,
    raw: Box<[u8]>,
}

/// The result of parsing one material primitive from the front of a stream.
#[derive(Debug)]
pub struct ParsedMaterial {
    material: QualifiedMaterial,
    consumed: usize,
}

impl fmt::Debug for QualifiedMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualifiedMaterial")
            .field("code", &self.code)
            .field("size", &self.size)
            .field("raw_length", &self.raw.len())
            .finish_non_exhaustive()
    }
}

impl Drop for QualifiedMaterial {
    fn drop(&mut self) {
        self.raw.as_mut().zeroize();
    }
}

impl ParsedMaterial {
    /// Returns the validated primitive parsed from the stream.
    #[must_use]
    pub const fn material(&self) -> &QualifiedMaterial {
        &self.material
    }

    /// Returns the number of input bytes or characters consumed.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Separates the parsed primitive from its consumed input length.
    #[must_use]
    pub fn into_parts(self) -> (QualifiedMaterial, usize) {
        (self.material, self.consumed)
    }
}

impl QualifiedMaterial {
    /// Constructs qualified material from an exact raw byte slice.
    ///
    /// Variable-size codes are normalized to the selector matching the actual lead size and are
    /// upgraded from their two-character to four-character form when necessary. A four-character
    /// input code remains in the large form.
    ///
    /// # Errors
    ///
    /// Returns a typed error when `raw` exceeds [`MAX_RAW_MATERIAL_BYTES`], has the wrong fixed
    /// size, or cannot be represented by the selected variable code family.
    ///
    /// ```
    /// use signify_cesr::{
    ///     CesrError,
    ///     code::DerivationCode,
    ///     matter::QualifiedMaterial,
    /// };
    ///
    /// # fn main() -> Result<(), CesrError> {
    /// let material = QualifiedMaterial::new(DerivationCode::BLAKE3_256, &[0_u8; 32])?;
    /// assert_eq!(material.qb64()?, "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(code: DerivationCode, raw: &[u8]) -> Result<Self, CesrError> {
        validate_raw_bound(raw.len())?;
        let metadata = code.size();
        if let Some(expected) = metadata.raw_size() {
            if raw.len() != expected {
                return Err(CesrError::RawSizeMismatch {
                    context: "qualified raw material",
                    expected,
                    actual: raw.len(),
                });
            }
            return Ok(Self {
                code,
                size: None,
                raw: raw.into(),
            });
        }

        let lead = (3 - (raw.len() % 3)) % 3;
        let padded = raw.len().checked_add(lead).ok_or(CesrError::LengthOverflow {
            context: "variable raw material",
        })?;
        let size = padded / 3;
        let size_u64 = u64::try_from(size).map_err(|_| CesrError::IntegerOverflow {
            context: "variable material size",
        })?;
        let normalized = normalize_variable_code(code, lead, size_u64)?;
        let size = u32::try_from(size_u64).map_err(|_| CesrError::IntegerOverflow {
            context: "variable material size",
        })?;
        Ok(Self {
            code: normalized,
            size: Some(size),
            raw: raw.into(),
        })
    }

    /// Parses a caller-sized raw prefix while retaining the unconsumed stream suffix.
    ///
    /// For fixed-size codes, `raw_size` must equal the code table's raw size. For variable-size
    /// codes it supplies the boundary that raw bytes do not carry themselves.
    ///
    /// # Errors
    ///
    /// Returns a typed error for a size mismatch, an oversized request, or truncated input.
    pub fn parse_raw_prefix(code: DerivationCode, input: &[u8], raw_size: usize) -> Result<ParsedMaterial, CesrError> {
        validate_raw_bound(raw_size)?;
        if let Some(expected) = code.size().raw_size()
            && raw_size != expected
        {
            return Err(CesrError::RawSizeMismatch {
                context: "qualified raw prefix",
                expected,
                actual: raw_size,
            });
        }
        let raw = prefix_bytes(input, raw_size, "qualified raw prefix")?;
        Ok(ParsedMaterial {
            material: Self::new(code, raw)?,
            consumed: raw_size,
        })
    }

    /// Parses one qualified Base64 primitive from the beginning of `input`.
    ///
    /// Extra characters are retained and reported through [`ParsedMaterial::consumed`]. Use
    /// [`Self::from_qb64`] when the input must contain exactly one primitive.
    ///
    /// # Errors
    ///
    /// Returns a typed error for empty, malformed, unsupported, truncated, oversized, or
    /// non-canonical material.
    pub fn parse_qb64(input: &str) -> Result<ParsedMaterial, CesrError> {
        let layout = inspect_qb64_layout(input)?;
        if input.len() < layout.full_size {
            return Err(CesrError::Truncated {
                context: "qualified Base64 material",
                needed: layout.full_size,
                available: input.len(),
            });
        }
        let qualified = input.get(..layout.full_size).ok_or(CesrError::Truncated {
            context: "qualified Base64 material",
            needed: layout.full_size,
            available: input.len(),
        })?;
        let payload = qualified.get(layout.code_size..).ok_or(CesrError::InvalidLength {
            context: "qualified Base64 payload",
            length: qualified.len(),
        })?;
        let pad = layout.code_size % 4;
        let decoded_bound = pad
            .checked_add(layout.lead_size)
            .and_then(|value| value.checked_add(layout.raw_size))
            .ok_or(CesrError::LengthOverflow {
                context: "qualified Base64 decoded material",
            })?;
        let mut base = Zeroizing::new(String::with_capacity(pad.checked_add(payload.len()).ok_or(
            CesrError::LengthOverflow {
                context: "qualified Base64 decoding",
            },
        )?));
        base.extend(std::iter::repeat_n('A', pad));
        base.push_str(payload);
        let decoded = Zeroizing::new(decode_url_safe_bounded(&base, decoded_bound)?);
        if decoded.len() != decoded_bound {
            return Err(CesrError::RawSizeMismatch {
                context: "decoded qualified material",
                expected: decoded_bound,
                actual: decoded.len(),
            });
        }
        let zero_prefix = pad.checked_add(layout.lead_size).ok_or(CesrError::LengthOverflow {
            context: "qualified material padding",
        })?;
        let padding = decoded.get(..zero_prefix).ok_or(CesrError::InvalidLength {
            context: "qualified material padding",
            length: decoded.len(),
        })?;
        if padding.iter().any(|byte| *byte != 0) {
            return Err(CesrError::NonZeroPadding {
                context: "alignment bits or lead bytes",
            });
        }
        let raw = decoded.get(zero_prefix..).ok_or(CesrError::InvalidLength {
            context: "qualified raw material",
            length: decoded.len(),
        })?;
        if raw.len() != layout.raw_size {
            return Err(CesrError::RawSizeMismatch {
                context: "qualified raw material",
                expected: layout.raw_size,
                actual: raw.len(),
            });
        }
        let material = Self {
            code: layout.code,
            size: layout.size,
            raw: raw.into(),
        };
        let canonical = Zeroizing::new(material.qb64()?);
        if canonical.as_str() != qualified {
            return Err(CesrError::NonCanonicalBase64);
        }
        Ok(ParsedMaterial {
            material,
            consumed: layout.full_size,
        })
    }

    /// Parses exactly one qualified Base64 primitive.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64`] and rejects trailing characters.
    pub fn from_qb64(input: &str) -> Result<Self, CesrError> {
        let parsed = Self::parse_qb64(input)?;
        reject_trailing("qualified Base64 material", input.len(), parsed.consumed)?;
        Ok(parsed.material)
    }

    /// Parses one UTF-8 qualified Base64 primitive from a byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed UTF-8 or qualified-material error.
    pub fn parse_qb64_bytes(input: &[u8]) -> Result<ParsedMaterial, CesrError> {
        let text = std::str::from_utf8(input).map_err(|source| CesrError::InvalidUtf8 { source })?;
        Self::parse_qb64(text)
    }

    /// Parses exactly one UTF-8 qualified Base64 primitive from bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed UTF-8 or qualified-material error and rejects trailing bytes.
    pub fn from_qb64_bytes(input: &[u8]) -> Result<Self, CesrError> {
        let parsed = Self::parse_qb64_bytes(input)?;
        reject_trailing("qualified Base64 bytes", input.len(), parsed.consumed)?;
        Ok(parsed.material)
    }

    /// Parses one qualified-binary (`qb2`) primitive from the beginning of `input`.
    ///
    /// # Errors
    ///
    /// Returns a typed error for an unsupported selector, truncation, excessive declared size, or
    /// non-zero code/lead padding.
    pub fn parse_qb2(input: &[u8]) -> Result<ParsedMaterial, CesrError> {
        let Some(&first) = input.first() else {
            return Err(CesrError::EmptyInput {
                context: "qualified binary material",
            });
        };
        let selector_index = usize::from(first >> 2);
        let selector = B64_ALPHABET
            .get(selector_index)
            .copied()
            .ok_or(CesrError::InvalidCodeCharacter { index: 0, byte: first })?;
        let hard_size = hard_code_size(selector)?;
        let binary_hard_size = sextets_to_bytes(hard_size)?;
        let hard_bytes = prefix_bytes(input, binary_hard_size, "qualified binary hard code")?;
        let encoded_hard = Zeroizing::new(encode_url_safe(hard_bytes));
        let hard = encoded_hard.get(..hard_size).ok_or(CesrError::Truncated {
            context: "qualified binary hard code",
            needed: hard_size,
            available: encoded_hard.len(),
        })?;
        let code = hard.parse::<DerivationCode>()?;
        let code_size =
            code.size()
                .hard_size()
                .checked_add(code.size().soft_size())
                .ok_or(CesrError::LengthOverflow {
                    context: "qualified binary code",
                })?;
        let binary_code_size = sextets_to_bytes(code_size)?;
        let code_bytes = prefix_bytes(input, binary_code_size, "qualified binary code")?;
        let encoded_code = Zeroizing::new(encode_url_safe(code_bytes));
        let code_text = encoded_code.get(..code_size).ok_or(CesrError::Truncated {
            context: "qualified binary code",
            needed: code_size,
            available: encoded_code.len(),
        })?;
        let layout = inspect_qb64_layout(code_text)?;
        let binary_full_size = layout.full_size.checked_mul(3).ok_or(CesrError::LengthOverflow {
            context: "qualified binary material",
        })? / 4;
        let qualified = prefix_bytes(input, binary_full_size, "qualified binary material")?;
        let qb64 = Zeroizing::new(encode_url_safe(qualified));
        let material = Self::from_qb64(&qb64)?;
        Ok(ParsedMaterial {
            material,
            consumed: binary_full_size,
        })
    }

    /// Parses exactly one qualified-binary (`qb2`) primitive.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb2`] and rejects trailing bytes.
    pub fn from_qb2(input: &[u8]) -> Result<Self, CesrError> {
        let parsed = Self::parse_qb2(input)?;
        reject_trailing("qualified binary material", input.len(), parsed.consumed)?;
        Ok(parsed.material)
    }

    /// Returns the hard derivation code.
    #[must_use]
    pub const fn code(&self) -> DerivationCode {
        self.code
    }

    /// Returns the raw, unqualified material bytes.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Returns the variable size in three-byte triplets, or `None` for fixed-size material.
    #[must_use]
    pub const fn variable_size(&self) -> Option<u32> {
        self.size
    }

    /// Returns the hard and soft derivation code text.
    ///
    /// # Errors
    ///
    /// Returns a typed conversion error only if the private invariant is violated.
    pub fn both(&self) -> Result<String, CesrError> {
        let mut both = String::from(self.code.as_str());
        if let Some(size) = self.size {
            let width = u8::try_from(self.code.size().soft_size()).map_err(|_| CesrError::IntegerOverflow {
                context: "variable material soft size",
            })?;
            let soft = encode_u64(u64::from(size), width)?;
            if soft.len() != usize::from(width) {
                return Err(CesrError::InvalidVariableSize {
                    context: "soft value exceeds its derivation-code width",
                    size: u64::from(size),
                });
            }
            both.push_str(&soft);
        }
        Ok(both)
    }

    /// Returns the complete qualified Base64 size in characters.
    ///
    /// # Errors
    ///
    /// Returns an overflow error only if the private size invariant is violated.
    pub fn full_size(&self) -> Result<usize, CesrError> {
        if let Some(fixed) = self.code.size().full_size() {
            return Ok(fixed);
        }
        let size = self.size.ok_or(CesrError::InvalidVariableSize {
            context: "variable code has no soft size",
            size: 0,
        })?;
        self.code
            .size()
            .hard_size()
            .checked_add(self.code.size().soft_size())
            .and_then(|code_size| {
                usize::try_from(size)
                    .ok()
                    .and_then(|size| size.checked_mul(4))
                    .and_then(|payload| code_size.checked_add(payload))
            })
            .ok_or(CesrError::LengthOverflow {
                context: "qualified material full size",
            })
    }

    /// Encodes this primitive as canonical qualified Base64 (`qb64`).
    ///
    /// # Errors
    ///
    /// Returns a typed error only if a private length or code-alignment invariant is violated.
    pub fn qb64(&self) -> Result<String, CesrError> {
        let both = self.both()?;
        let code_size = both.len();
        let lead = self.code.size().lead_size();
        let pad = code_size % 4;
        let zero_prefix = pad.checked_add(lead).ok_or(CesrError::LengthOverflow {
            context: "qualified material padding",
        })?;
        let mut padded = Zeroizing::new(Vec::with_capacity(zero_prefix.checked_add(self.raw.len()).ok_or(
            CesrError::LengthOverflow {
                context: "qualified raw material",
            },
        )?));
        padded.resize(zero_prefix, 0);
        padded.extend_from_slice(&self.raw);
        if padded.len() % 3 != 0 {
            return Err(CesrError::InvalidLength {
                context: "padded qualified raw material",
                length: padded.len(),
            });
        }
        let encoded = Zeroizing::new(encode_url_safe(&padded));
        let payload = encoded.get(pad..).ok_or(CesrError::InvalidLength {
            context: "qualified Base64 payload",
            length: encoded.len(),
        })?;
        let mut qualified =
            String::with_capacity(both.len().checked_add(payload.len()).ok_or(CesrError::LengthOverflow {
                context: "qualified Base64 material",
            })?);
        qualified.push_str(&both);
        qualified.push_str(payload);
        let expected = self.full_size()?;
        if qualified.len() != expected {
            return Err(CesrError::RawSizeMismatch {
                context: "qualified Base64 material",
                expected,
                actual: qualified.len(),
            });
        }
        Ok(qualified)
    }

    /// Encodes this primitive as UTF-8 qualified Base64 bytes.
    ///
    /// # Errors
    ///
    /// Returns any invariant error produced by [`Self::qb64`].
    pub fn qb64_bytes(&self) -> Result<Vec<u8>, CesrError> {
        Ok(self.qb64()?.into_bytes())
    }

    /// Encodes this primitive in the qualified-binary (`qb2`) domain.
    ///
    /// # Errors
    ///
    /// Returns any invariant or canonical decoding error from the qualified Base64 form.
    pub fn qb2(&self) -> Result<Vec<u8>, CesrError> {
        let qb64 = Zeroizing::new(self.qb64()?);
        let expected = qb64.len().checked_mul(3).ok_or(CesrError::LengthOverflow {
            context: "qualified binary material",
        })? / 4;
        decode_url_safe_bounded(&qb64, expected)
    }

    /// Whether this material may be used as a transferable identifier prefix.
    #[must_use]
    pub fn is_transferable(&self) -> bool {
        !self.code.belongs_to(CodeFamily::NonTransferable)
    }

    /// Whether this material uses a self-addressing digest derivation code.
    #[must_use]
    pub fn is_digest(&self) -> bool {
        self.code.belongs_to(CodeFamily::Digest)
    }
}

#[derive(Clone, Copy, Debug)]
struct MaterialLayout {
    code: DerivationCode,
    size: Option<u32>,
    code_size: usize,
    full_size: usize,
    lead_size: usize,
    raw_size: usize,
}

fn inspect_qb64_layout(input: &str) -> Result<MaterialLayout, CesrError> {
    let Some(&selector) = input.as_bytes().first() else {
        return Err(CesrError::EmptyInput {
            context: "qualified Base64 material",
        });
    };
    let hard_size = hard_code_size(selector)?;
    let hard = input.get(..hard_size).ok_or(CesrError::Truncated {
        context: "qualified Base64 hard code",
        needed: hard_size,
        available: input.len(),
    })?;
    let code = hard.parse::<DerivationCode>()?;
    let metadata = code.size();
    let code_size = metadata
        .hard_size()
        .checked_add(metadata.soft_size())
        .ok_or(CesrError::LengthOverflow {
            context: "qualified Base64 code",
        })?;
    if input.len() < code_size {
        return Err(CesrError::Truncated {
            context: "qualified Base64 code",
            needed: code_size,
            available: input.len(),
        });
    }
    if let (Some(full_size), Some(raw_size)) = (metadata.full_size(), metadata.raw_size()) {
        validate_raw_bound(raw_size)?;
        return Ok(MaterialLayout {
            code,
            size: None,
            code_size,
            full_size,
            lead_size: metadata.lead_size(),
            raw_size,
        });
    }

    let soft = input.get(metadata.hard_size()..code_size).ok_or(CesrError::Truncated {
        context: "qualified Base64 soft size",
        needed: code_size,
        available: input.len(),
    })?;
    let size_u64 = decode_u64(soft)?;
    let maximum = if metadata.soft_size() == 2 {
        SMALL_VARIABLE_MAX_TRIPLETS
    } else {
        LARGE_VARIABLE_MAX_TRIPLETS
    };
    if size_u64 > maximum {
        return Err(CesrError::InvalidVariableSize {
            context: "soft size exceeds the selected derivation code",
            size: size_u64,
        });
    }
    let payload_size = usize::try_from(size_u64)
        .map_err(|_| CesrError::IntegerOverflow {
            context: "variable material size",
        })?
        .checked_mul(4)
        .ok_or(CesrError::LengthOverflow {
            context: "variable qualified material",
        })?;
    let full_size = code_size.checked_add(payload_size).ok_or(CesrError::LengthOverflow {
        context: "variable qualified material",
    })?;
    let decoded_size = usize::try_from(size_u64)
        .map_err(|_| CesrError::IntegerOverflow {
            context: "variable material size",
        })?
        .checked_mul(3)
        .ok_or(CesrError::LengthOverflow {
            context: "variable raw material",
        })?;
    let raw_size = decoded_size
        .checked_sub(metadata.lead_size())
        .ok_or(CesrError::InvalidVariableSize {
            context: "declared triplets cannot contain the code's lead bytes",
            size: size_u64,
        })?;
    validate_raw_bound(raw_size)?;
    let size = u32::try_from(size_u64).map_err(|_| CesrError::IntegerOverflow {
        context: "variable material size",
    })?;
    Ok(MaterialLayout {
        code,
        size: Some(size),
        code_size,
        full_size,
        lead_size: metadata.lead_size(),
        raw_size,
    })
}

fn normalize_variable_code(code: DerivationCode, lead: usize, size: u64) -> Result<DerivationCode, CesrError> {
    let value = code.as_str();
    let Some(&selector) = value.as_bytes().first() else {
        return Err(CesrError::EmptyInput {
            context: "variable derivation code",
        });
    };
    let small = matches!(selector, b'4' | b'5' | b'6');
    let large = matches!(selector, b'7' | b'8' | b'9');
    if !small && !large {
        return Err(CesrError::InvalidVariableSize {
            context: "fixed derivation code used as variable material",
            size,
        });
    }
    if size > LARGE_VARIABLE_MAX_TRIPLETS {
        return Err(CesrError::InvalidVariableSize {
            context: "size exceeds the four-character soft field",
            size,
        });
    }
    let use_large = large || size > SMALL_VARIABLE_MAX_TRIPLETS;
    let lead_selector = match (use_large, lead) {
        (false, 0) => '4',
        (false, 1) => '5',
        (false, 2) => '6',
        (true, 0) => '7',
        (true, 1) => '8',
        (true, 2) => '9',
        _ => {
            return Err(CesrError::InvalidVariableSize {
                context: "lead size must be zero, one, or two",
                size,
            });
        }
    };
    let suffix = value.get(1..).ok_or(CesrError::InvalidLength {
        context: "variable derivation code",
        length: value.len(),
    })?;
    let candidate = if use_large && small {
        let family = suffix.get(..1).ok_or(CesrError::InvalidLength {
            context: "small variable derivation code",
            length: value.len(),
        })?;
        format!("{lead_selector}AA{family}")
    } else {
        format!("{lead_selector}{suffix}")
    };
    candidate.parse()
}

fn validate_raw_bound(length: usize) -> Result<(), CesrError> {
    if length > MAX_RAW_MATERIAL_BYTES {
        return Err(CesrError::InputTooLarge {
            context: "qualified raw material",
            length,
            maximum: MAX_RAW_MATERIAL_BYTES,
        });
    }
    Ok(())
}

fn prefix_bytes<'a>(input: &'a [u8], needed: usize, context: &'static str) -> Result<&'a [u8], CesrError> {
    input.get(..needed).ok_or(CesrError::Truncated {
        context,
        needed,
        available: input.len(),
    })
}

fn sextets_to_bytes(sextets: usize) -> Result<usize, CesrError> {
    sextets
        .checked_mul(6)
        .map(|bits| bits.div_ceil(8))
        .ok_or(CesrError::LengthOverflow {
            context: "qualified binary code",
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

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::{MAX_RAW_MATERIAL_BYTES, QualifiedMaterial};
    use crate::{CesrError, code::DerivationCode};

    #[test]
    fn fixed_material_encodes_and_round_trips_in_both_domains() -> Result<(), Box<dyn Error>> {
        let raw: Vec<u8> = (0_u8..32).collect();
        let material = QualifiedMaterial::new(DerivationCode::ED25519_SEED, &raw)?;
        let qb64 = material.qb64()?;
        assert_eq!(qb64, "AAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f");
        assert_eq!(qb64.len(), 44);
        assert_eq!(material.full_size()?, 44);
        assert_eq!(material.variable_size(), None);
        assert!(material.is_transferable());
        assert!(!material.is_digest());

        let from_text = QualifiedMaterial::from_qb64(&qb64)?;
        let from_text_bytes = QualifiedMaterial::from_qb64_bytes(qb64.as_bytes())?;
        let qb2 = material.qb2()?;
        let from_binary = QualifiedMaterial::from_qb2(&qb2)?;
        assert_same_material(&from_text, &material);
        assert_same_material(&from_text_bytes, &material);
        assert_same_material(&from_binary, &material);
        assert_eq!(material.qb64_bytes()?, qb64.as_bytes());
        let debug = format!("{material:?}");
        assert!(debug.contains("raw_length: 32"));
        assert!(!debug.contains("0, 1, 2, 3"));
        Ok(())
    }

    #[test]
    fn fixed_lead_bytes_are_encoded_and_validated() -> Result<(), Box<dyn Error>> {
        let material = QualifiedMaterial::new("2AAA".parse()?, &[0x12, 0x34])?;
        assert_eq!(material.qb64()?, "2AAAABI0");
        assert_eq!(material.qb2()?, vec![216, 0, 0, 0, 18, 52]);
        assert!(matches!(
            QualifiedMaterial::from_qb64("2AAABBI0"),
            Err(CesrError::NonZeroPadding { .. })
        ));
        Ok(())
    }

    #[test]
    fn variable_material_selects_lead_and_upgrades_code() -> Result<(), Box<dyn Error>> {
        for (length, expected_code, expected_both) in [
            (0, "4A", "4AAA"),
            (1, "6A", "6AAB"),
            (2, "5A", "5AAB"),
            (3, "4A", "4AAB"),
        ] {
            let raw = vec![0xabu8; length];
            let material = QualifiedMaterial::new(DerivationCode::BASE64_TEXT_LEAD_0, &raw)?;
            assert_eq!(material.code().as_str(), expected_code);
            assert_eq!(material.both()?, expected_both);
            let parsed = QualifiedMaterial::from_qb64(&material.qb64()?)?;
            assert_same_material(&parsed, &material);
        }

        let raw = vec![7_u8; 12_288];
        let upgraded = QualifiedMaterial::new(DerivationCode::BASE64_TEXT_LEAD_0, &raw)?;
        assert_eq!(upgraded.code(), DerivationCode::BASE64_TEXT_BIG_LEAD_0);
        assert_eq!(upgraded.variable_size(), Some(4_096));
        let parsed = QualifiedMaterial::from_qb2(&upgraded.qb2()?)?;
        assert_same_material(&parsed, &upgraded);
        Ok(())
    }

    #[test]
    fn stream_parsers_report_consumed_input() -> Result<(), Box<dyn Error>> {
        let raw = [42_u8; 32];
        let material = QualifiedMaterial::new(DerivationCode::BLAKE3_256, &raw)?;
        let qb64 = material.qb64()?;
        let mut text_stream = qb64.clone();
        text_stream.push_str("tail");
        let parsed = QualifiedMaterial::parse_qb64(&text_stream)?;
        assert_same_material(parsed.material(), &material);
        assert_eq!(parsed.consumed(), qb64.len());
        assert!(matches!(
            QualifiedMaterial::from_qb64(&text_stream),
            Err(CesrError::TrailingMaterial { length: 4, .. })
        ));

        let qb2 = material.qb2()?;
        let mut binary_stream = qb2.clone();
        binary_stream.extend_from_slice(&[1, 2, 3]);
        let parsed = QualifiedMaterial::parse_qb2(&binary_stream)?;
        let (parsed_material, consumed) = parsed.into_parts();
        assert_same_material(&parsed_material, &material);
        assert_eq!(consumed, qb2.len());
        assert!(matches!(
            QualifiedMaterial::from_qb2(&binary_stream),
            Err(CesrError::TrailingMaterial { length: 3, .. })
        ));
        Ok(())
    }

    #[test]
    fn raw_prefix_parsing_is_explicit_and_bounded() -> Result<(), Box<dyn Error>> {
        let input = [9_u8; 40];
        let parsed = QualifiedMaterial::parse_raw_prefix(DerivationCode::ED25519_NONTRANSFERABLE, &input, 32)?;
        assert_eq!(parsed.consumed(), 32);
        assert_eq!(parsed.material().raw(), &[9_u8; 32]);
        assert!(!parsed.material().is_transferable());
        assert!(matches!(
            QualifiedMaterial::parse_raw_prefix(DerivationCode::ED25519_NONTRANSFERABLE, &input, 31),
            Err(CesrError::RawSizeMismatch { .. })
        ));
        assert!(matches!(
            QualifiedMaterial::parse_raw_prefix(DerivationCode::ED25519_NONTRANSFERABLE, &[0; 31], 32),
            Err(CesrError::Truncated { .. })
        ));
        let variable = QualifiedMaterial::parse_raw_prefix(DerivationCode::BASE64_TEXT_LEAD_0, &[1, 2, 3, 4], 3)?;
        assert_eq!(variable.consumed(), 3);
        assert_eq!(variable.material().raw(), &[1, 2, 3]);
        Ok(())
    }

    #[test]
    fn malformed_material_returns_typed_errors() {
        assert!(matches!(
            QualifiedMaterial::from_qb64(""),
            Err(CesrError::EmptyInput { .. })
        ));
        assert!(matches!(
            QualifiedMaterial::from_qb64("0"),
            Err(CesrError::Truncated { .. })
        ));
        assert!(matches!(
            QualifiedMaterial::from_qb64("RAAA"),
            Err(CesrError::UnsupportedCode { .. })
        ));
        assert!(matches!(
            QualifiedMaterial::from_qb64("A"),
            Err(CesrError::Truncated { .. })
        ));
        assert!(matches!(
            QualifiedMaterial::from_qb64("5AAA"),
            Err(CesrError::InvalidVariableSize { .. })
        ));
        assert!(matches!(
            QualifiedMaterial::from_qb64("7AAA____"),
            Err(CesrError::InputTooLarge { .. })
        ));
        assert!(matches!(
            QualifiedMaterial::from_qb64(&format!("A+{}", "A".repeat(42))),
            Err(CesrError::InvalidBase64Character { .. })
        ));
        assert!(matches!(
            QualifiedMaterial::from_qb64_bytes(&[0xff]),
            Err(CesrError::InvalidUtf8 { .. })
        ));
        assert!(matches!(
            QualifiedMaterial::from_qb2(&[]),
            Err(CesrError::EmptyInput { .. })
        ));
        assert!(matches!(
            QualifiedMaterial::from_qb2(&[0]),
            Err(CesrError::Truncated { .. })
        ));
        assert!(matches!(
            QualifiedMaterial::from_qb2(&[0xf8]),
            Err(CesrError::InvalidCodeCharacter { .. })
        ));
        assert!(matches!(
            QualifiedMaterial::from_qb2(&[216, 0, 0, 1, 18, 52]),
            Err(CesrError::NonZeroPadding { .. })
        ));
        assert!(matches!(
            QualifiedMaterial::new(DerivationCode::ED25519, &[0; 31]),
            Err(CesrError::RawSizeMismatch { .. })
        ));
        assert!(matches!(
            QualifiedMaterial::parse_raw_prefix(DerivationCode::BASE64_TEXT_LEAD_0, &[], MAX_RAW_MATERIAL_BYTES + 1),
            Err(CesrError::InputTooLarge { .. })
        ));
    }

    fn assert_same_material(left: &QualifiedMaterial, right: &QualifiedMaterial) {
        assert_eq!(left.code(), right.code());
        assert_eq!(left.variable_size(), right.variable_size());
        assert_eq!(left.raw(), right.raw());
    }
}
