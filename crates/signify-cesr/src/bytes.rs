//! Checked UTF-8, byte concatenation, and big-endian integer helpers.

use crate::CesrError;

/// Maximum byte sequence accepted or created by generic byte helpers.
pub const MAX_BYTE_SEQUENCE_LEN: usize = 16 * 1024 * 1024;

/// Maximum byte width supported by the exact integer conversion helpers.
pub const MAX_INTEGER_BYTES: usize = size_of::<u128>();

/// Returns the UTF-8 bytes of a string without allocating.
#[must_use]
pub const fn utf8_bytes(input: &str) -> &[u8] {
    input.as_bytes()
}

/// Validates bytes as UTF-8 and borrows the resulting text.
///
/// # Errors
///
/// Returns [`CesrError::InvalidUtf8`] when `input` is not valid UTF-8.
pub fn utf8_text(input: &[u8]) -> Result<&str, CesrError> {
    std::str::from_utf8(input).map_err(|source| CesrError::InvalidUtf8 { source })
}

/// Concatenates byte slices with checked length arithmetic and allocation bounds.
///
/// # Errors
///
/// Returns [`CesrError::LengthOverflow`] if the total length cannot be represented,
/// or [`CesrError::InputTooLarge`] if it exceeds [`MAX_BYTE_SEQUENCE_LEN`].
pub fn concatenate(parts: &[&[u8]]) -> Result<Vec<u8>, CesrError> {
    let total = parts.iter().try_fold(0_usize, |total, part| {
        total.checked_add(part.len()).ok_or(CesrError::LengthOverflow {
            context: "concatenated byte material",
        })
    })?;
    if total > MAX_BYTE_SEQUENCE_LEN {
        return Err(CesrError::InputTooLarge {
            context: "concatenated byte material",
            length: total,
            maximum: MAX_BYTE_SEQUENCE_LEN,
        });
    }

    let mut output = Vec::with_capacity(total);
    for part in parts {
        output.extend_from_slice(part);
    }
    Ok(output)
}

/// Encodes an integer as exactly `length` big-endian bytes.
///
/// Widths up to 16 bytes are supported so later CESR numeric material can avoid
/// JavaScript's imprecise `number` representation. Zero encoded at width zero is
/// the empty byte string; a non-zero value at width zero is rejected.
///
/// # Errors
///
/// Returns [`CesrError`] when `length` is greater than 16 or the value does not
/// fit in the requested width.
///
/// ```
/// use signify_cesr::{CesrError, bytes::{bytes_to_integer, integer_to_bytes}};
///
/// # fn main() -> Result<(), CesrError> {
/// let encoded = integer_to_bytes(66_051, 3)?;
/// assert_eq!(encoded, [1, 2, 3]);
/// assert_eq!(bytes_to_integer(&encoded)?, 66_051);
/// # Ok(())
/// # }
/// ```
pub fn integer_to_bytes(value: u128, length: u8) -> Result<Vec<u8>, CesrError> {
    let length = usize::from(length);
    if length > MAX_INTEGER_BYTES {
        return Err(CesrError::InvalidLength {
            context: "big-endian integer bytes",
            length,
        });
    }
    if length == 0 {
        return if value == 0 {
            Ok(Vec::new())
        } else {
            Err(CesrError::ValueDoesNotFit {
                context: "big-endian bytes",
                length,
            })
        };
    }

    let bytes = value.to_be_bytes();
    let start = MAX_INTEGER_BYTES.checked_sub(length).ok_or(CesrError::LengthOverflow {
        context: "big-endian integer bytes",
    })?;
    let prefix = bytes.get(..start).ok_or(CesrError::InvalidLength {
        context: "big-endian integer bytes",
        length,
    })?;
    if prefix.iter().any(|byte| *byte != 0) {
        return Err(CesrError::ValueDoesNotFit {
            context: "big-endian bytes",
            length,
        });
    }
    let selected = bytes.get(start..).ok_or(CesrError::InvalidLength {
        context: "big-endian integer bytes",
        length,
    })?;
    Ok(selected.to_vec())
}

/// Decodes one to 16 big-endian bytes into an exact `u128`.
///
/// # Errors
///
/// Returns [`CesrError::EmptyInput`] for empty input and
/// [`CesrError::InputTooLarge`] for more than 16 bytes.
pub fn bytes_to_integer(input: &[u8]) -> Result<u128, CesrError> {
    if input.is_empty() {
        return Err(CesrError::EmptyInput {
            context: "big-endian integer bytes",
        });
    }
    if input.len() > MAX_INTEGER_BYTES {
        return Err(CesrError::InputTooLarge {
            context: "big-endian integer bytes",
            length: input.len(),
            maximum: MAX_INTEGER_BYTES,
        });
    }

    input.iter().try_fold(0_u128, |value, byte| {
        value
            .checked_mul(256)
            .and_then(|shifted| shifted.checked_add(u128::from(*byte)))
            .ok_or(CesrError::IntegerOverflow {
                context: "big-endian integer bytes",
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_helpers_borrow_and_validate() -> Result<(), CesrError> {
        let text = "🏳️";
        assert_eq!(utf8_text(utf8_bytes(text))?, text);
        assert!(matches!(utf8_text(&[0xff]), Err(CesrError::InvalidUtf8 { .. })));
        Ok(())
    }

    #[test]
    fn concatenation_preserves_order() -> Result<(), CesrError> {
        assert_eq!(concatenate(&[b"ab", b"", b"cd"])?, b"abcd");
        assert_eq!(concatenate(&[])?, Vec::<u8>::new());
        Ok(())
    }

    #[test]
    fn concatenation_rejects_oversized_output_before_allocating_it() {
        let part = vec![0_u8; (MAX_BYTE_SEQUENCE_LEN / 2) + 1];
        assert!(matches!(
            concatenate(&[&part, &part]),
            Err(CesrError::InputTooLarge { .. })
        ));
    }

    #[test]
    fn integer_examples_match_reference() -> Result<(), CesrError> {
        for length in [2, 8, 16] {
            assert_eq!(bytes_to_integer(&integer_to_bytes(0, length)?)?, 0);
            assert_eq!(bytes_to_integer(&integer_to_bytes(1, length)?)?, 1);
        }
        assert_eq!(integer_to_bytes(0x01_02_03, 3)?, [1, 2, 3]);
        assert_eq!(bytes_to_integer(&[1, 2, 3])?, 66_051);
        Ok(())
    }

    #[test]
    fn integer_conversion_rejects_boundaries() {
        assert!(matches!(bytes_to_integer(&[]), Err(CesrError::EmptyInput { .. })));
        assert!(matches!(
            bytes_to_integer(&[0; 17]),
            Err(CesrError::InputTooLarge { .. })
        ));
        assert!(matches!(
            integer_to_bytes(256, 1),
            Err(CesrError::ValueDoesNotFit { .. })
        ));
        assert!(matches!(integer_to_bytes(1, 0), Err(CesrError::ValueDoesNotFit { .. })));
        assert!(matches!(integer_to_bytes(0, 17), Err(CesrError::InvalidLength { .. })));
    }
}
