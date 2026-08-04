//! Strict URL-safe Base64 and CESR six-bit integer conversion.

use base64::{Engine as _, engine::general_purpose};

use crate::CesrError;

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Maximum decoded byte length accepted by [`decode_url_safe`].
///
/// This prevents a generic decoder call from allocating an unbounded amount of
/// memory. Protocol parsers remain responsible for applying their smaller,
/// material-specific limits before calling the decoder.
pub const MAX_DECODED_BYTES: usize = 16 * 1024 * 1024;

/// Maximum number of Base64 digits needed to represent a `u64`.
pub const MAX_U64_B64_DIGITS: usize = 11;

/// Encodes bytes as canonical, unpadded URL-safe Base64.
///
/// Empty input is encoded as an empty string, matching the upstream helper and
/// RFC 4648.
///
/// ```
/// use signify_cesr::base64::encode_url_safe;
///
/// assert_eq!(encode_url_safe(b"fish"), "ZmlzaA");
/// ```
#[must_use]
pub fn encode_url_safe(input: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(input)
}

/// Decodes canonical padded or unpadded URL-safe Base64.
///
/// The decoder rejects the standard `+` and `/` alphabet, partial or excess
/// padding, non-zero trailing bits, and decoded output larger than
/// [`MAX_DECODED_BYTES`]. Empty text decodes to empty bytes.
///
/// # Errors
///
/// Returns [`CesrError`] for malformed, non-canonical, or oversized input.
///
/// ```
/// use signify_cesr::{CesrError, base64::decode_url_safe};
///
/// # fn main() -> Result<(), CesrError> {
/// assert_eq!(decode_url_safe("Zg==")?, b"f");
/// # Ok(())
/// # }
/// ```
pub fn decode_url_safe(input: &str) -> Result<Vec<u8>, CesrError> {
    decode_url_safe_bounded(input, MAX_DECODED_BYTES)
}

/// Decodes canonical URL-safe Base64 with a caller-selected output limit.
///
/// `maximum_decoded_length` is capped at [`MAX_DECODED_BYTES`]. This lets a
/// protocol parser apply a smaller material-specific bound before allocation.
///
/// # Errors
///
/// Returns [`CesrError`] for malformed, non-canonical, or oversized input.
pub fn decode_url_safe_bounded(input: &str, maximum_decoded_length: usize) -> Result<Vec<u8>, CesrError> {
    let maximum_decoded_length = maximum_decoded_length.min(MAX_DECODED_BYTES);
    let maximum_encoded_length =
        maximum_decoded_length
            .div_ceil(3)
            .checked_mul(4)
            .ok_or(CesrError::LengthOverflow {
                context: "URL-safe Base64 text",
            })?;
    if input.len() > maximum_encoded_length {
        return Err(CesrError::InputTooLarge {
            context: "URL-safe Base64 text",
            length: input.len(),
            maximum: maximum_encoded_length,
        });
    }

    let padding = validate_base64_shape(input)?;
    let decoded_length = decoded_length(input.len(), padding)?;
    if decoded_length > maximum_decoded_length {
        return Err(CesrError::InputTooLarge {
            context: "decoded URL-safe Base64 material",
            length: decoded_length,
            maximum: maximum_decoded_length,
        });
    }

    let engine = if padding == 0 {
        &general_purpose::URL_SAFE_NO_PAD
    } else {
        &general_purpose::URL_SAFE
    };
    engine.decode(input).map_err(|_| CesrError::NonCanonicalBase64)
}

/// Encodes a `u64` using the CESR URL-safe Base64 digit alphabet.
///
/// `minimum_width` left-pads the result with `A` digits. A zero width returns
/// an empty string only for value zero, retaining the useful upstream edge
/// case without silently discarding a non-zero value.
///
/// # Errors
///
/// Returns [`CesrError::InvalidLength`] when `minimum_width` is greater than
/// [`MAX_U64_B64_DIGITS`], or [`CesrError::ValueDoesNotFit`] when a non-zero
/// value is requested with zero width.
///
/// ```
/// use signify_cesr::{CesrError, base64::{decode_u64, encode_u64}};
///
/// # fn main() -> Result<(), CesrError> {
/// let encoded = encode_u64(6_011, 1)?;
/// assert_eq!(encoded, "Bd7");
/// assert_eq!(decode_u64(&encoded)?, 6_011);
/// # Ok(())
/// # }
/// ```
pub fn encode_u64(value: u64, minimum_width: u8) -> Result<String, CesrError> {
    let width = usize::from(minimum_width);
    if width > MAX_U64_B64_DIGITS {
        return Err(CesrError::InvalidLength {
            context: "Base64 integer width",
            length: width,
        });
    }
    if width == 0 {
        return if value == 0 {
            Ok(String::new())
        } else {
            Err(CesrError::ValueDoesNotFit {
                context: "Base64 digits",
                length: 0,
            })
        };
    }

    let mut remaining = value;
    let mut reversed = Vec::with_capacity(MAX_U64_B64_DIGITS);
    loop {
        let index = usize::try_from(remaining % 64).map_err(|_| CesrError::IntegerOverflow {
            context: "Base64 integer digit",
        })?;
        let byte = B64_ALPHABET.get(index).copied().ok_or(CesrError::IntegerOverflow {
            context: "Base64 integer digit",
        })?;
        reversed.push(char::from(byte));
        remaining /= 64;
        if remaining == 0 {
            break;
        }
    }

    let output_width = width.max(reversed.len());
    let mut output = String::with_capacity(output_width);
    for _ in reversed.len()..output_width {
        output.push('A');
    }
    output.extend(reversed.into_iter().rev());
    Ok(output)
}

/// Decodes CESR URL-safe Base64 digits into a `u64`.
///
/// Leading `A` digits are accepted because fixed-width CESR fields use them as
/// zero padding.
///
/// # Errors
///
/// Returns [`CesrError`] for empty input, invalid alphabet bytes, more than 11
/// digits, or arithmetic overflow.
pub fn decode_u64(input: &str) -> Result<u64, CesrError> {
    if input.is_empty() {
        return Err(CesrError::EmptyInput {
            context: "Base64 integer",
        });
    }
    if input.len() > MAX_U64_B64_DIGITS {
        return Err(CesrError::InputTooLarge {
            context: "Base64 integer",
            length: input.len(),
            maximum: MAX_U64_B64_DIGITS,
        });
    }

    input.bytes().enumerate().try_fold(0_u64, |value, (index, byte)| {
        let digit = digit_value(byte).ok_or(CesrError::InvalidBase64Character { index, byte })?;
        value
            .checked_mul(64)
            .and_then(|shifted| shifted.checked_add(u64::from(digit)))
            .ok_or(CesrError::IntegerOverflow {
                context: "Base64 integer",
            })
    })
}

fn digit_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

fn validate_base64_shape(input: &str) -> Result<usize, CesrError> {
    let mut first_padding = None;
    for (index, byte) in input.bytes().enumerate() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => {
                if first_padding.is_some() {
                    return Err(CesrError::InvalidBase64Padding { index });
                }
            }
            b'=' => {
                if first_padding.is_none() {
                    first_padding = Some(index);
                }
            }
            _ => return Err(CesrError::InvalidBase64Character { index, byte }),
        }
    }

    let non_padding_length = first_padding.unwrap_or(input.len());
    let padding = input
        .len()
        .checked_sub(non_padding_length)
        .ok_or(CesrError::LengthOverflow {
            context: "URL-safe Base64 padding",
        })?;
    let remainder = non_padding_length % 4;

    if remainder == 1 {
        return Err(CesrError::InvalidLength {
            context: "URL-safe Base64 text",
            length: input.len(),
        });
    }
    if padding == 0 {
        return Ok(0);
    }

    let required_padding = match remainder {
        2 => 2,
        3 => 1,
        _ => 0,
    };
    if padding != required_padding || !input.len().is_multiple_of(4) {
        return Err(CesrError::InvalidBase64Padding {
            index: non_padding_length,
        });
    }
    Ok(padding)
}

fn decoded_length(encoded_length: usize, padding: usize) -> Result<usize, CesrError> {
    let non_padding = encoded_length.checked_sub(padding).ok_or(CesrError::LengthOverflow {
        context: "decoded URL-safe Base64 material",
    })?;
    let complete = non_padding / 4;
    let trailing = match non_padding % 4 {
        0 => 0,
        2 => 1,
        3 => 2,
        _ => {
            return Err(CesrError::InvalidLength {
                context: "URL-safe Base64 text",
                length: encoded_length,
            });
        }
    };
    complete
        .checked_mul(3)
        .and_then(|length| length.checked_add(trailing))
        .ok_or(CesrError::LengthOverflow {
            context: "decoded URL-safe Base64 material",
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_reference_examples() {
        assert_eq!(encode_url_safe(b"f"), "Zg");
        assert_eq!(encode_url_safe(b"fi"), "Zmk");
        assert_eq!(encode_url_safe(b"fis"), "Zmlz");
        assert_eq!(encode_url_safe(b"fish"), "ZmlzaA");
        assert_eq!(encode_url_safe(&[248]), "-A");
        assert_eq!(encode_url_safe(&[252]), "_A");
    }

    #[test]
    fn decodes_padded_and_unpadded_reference_examples() -> Result<(), CesrError> {
        assert_eq!(decode_url_safe("Zg")?, b"f");
        assert_eq!(decode_url_safe("Zg==")?, b"f");
        assert_eq!(decode_url_safe("Zmk")?, b"fi");
        assert_eq!(decode_url_safe("Zmk=")?, b"fi");
        assert_eq!(decode_url_safe("Zmlz")?, b"fis");
        assert_eq!(decode_url_safe("ZmlzaA")?, b"fish");
        Ok(())
    }

    #[test]
    fn rejects_invalid_alphabet_padding_lengths_and_trailing_bits() {
        assert!(matches!(
            decode_url_safe("+A"),
            Err(CesrError::InvalidBase64Character { index: 0, byte: b'+' })
        ));
        assert!(matches!(
            decode_url_safe("Zg="),
            Err(CesrError::InvalidBase64Padding { .. })
        ));
        assert!(matches!(
            decode_url_safe("Z=g="),
            Err(CesrError::InvalidBase64Padding { .. })
        ));
        assert!(matches!(decode_url_safe("A"), Err(CesrError::InvalidLength { .. })));
        assert_eq!(decode_url_safe("Zh"), Err(CesrError::NonCanonicalBase64));
        assert!(matches!(
            decode_url_safe_bounded("Zm9v", 2),
            Err(CesrError::InputTooLarge { .. })
        ));
    }

    #[test]
    fn integer_examples_match_reference() -> Result<(), CesrError> {
        for (value, width, encoded) in [
            (0, 1, "A"),
            (27, 1, "b"),
            (27, 2, "Ab"),
            (80, 1, "BQ"),
            (4095, 1, "__"),
            (4096, 1, "BAA"),
            (6011, 1, "Bd7"),
        ] {
            assert_eq!(encode_u64(value, width)?, encoded);
            assert_eq!(decode_u64(encoded)?, value);
        }
        assert_eq!(encode_u64(0, 0)?, "");
        Ok(())
    }

    #[test]
    fn integer_conversion_rejects_invalid_and_overflowing_inputs() {
        assert!(matches!(decode_u64(""), Err(CesrError::EmptyInput { .. })));
        assert!(matches!(
            decode_u64("A+"),
            Err(CesrError::InvalidBase64Character { index: 1, byte: b'+' })
        ));
        assert!(matches!(
            decode_u64("________________"),
            Err(CesrError::InputTooLarge { .. })
        ));
        assert!(matches!(decode_u64("P__________"), Ok(u64::MAX)));
        assert!(matches!(
            decode_u64("QAAAAAAAAAA"),
            Err(CesrError::IntegerOverflow { .. })
        ));
        assert!(matches!(encode_u64(1, 0), Err(CesrError::ValueDoesNotFit { .. })));
        assert!(matches!(encode_u64(0, 12), Err(CesrError::InvalidLength { .. })));
    }
}
