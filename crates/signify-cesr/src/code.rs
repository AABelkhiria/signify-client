//! CESR qualified-material derivation codes and their size metadata.
//!
//! The table is pinned to `Matter.Sizes` and the codices in
//! `signify-ts/src/keri/core/matter.ts` at reference commit
//! `ae92eceb8e776ad57669707bff7f84db9390b711`.

use std::{fmt, str::FromStr};

use crate::CesrError;

/// A semantic subset of the derivation-code table.
///
/// Membership mirrors the named codices exported by the pinned TypeScript reference. Codes may
/// belong to more than one family; for example, `E` is both a general matter and a digest code.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum CodeFamily {
    /// Codes exported by the reference's general `MatterCodex` (`MtrDex`).
    GeneralMatter,
    /// Basic, non-transferable identifier prefix codes (`NonTransDex`).
    NonTransferable,
    /// Self-addressing digest codes (`DigiDex`).
    Digest,
    /// Exact unsigned-number encodings (`NumDex`).
    Numeric,
    /// Variable-size Base64 text encodings (`BexDex`).
    Base64Text,
}

/// Fixed and variable sizing information for one derivation code.
///
/// Values are expressed in bytes for raw/lead sizes and characters for hard, soft, and full
/// qualified sizes. Variable-size codes have no fixed full or raw size.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CodeSize {
    hard: usize,
    soft: usize,
    full: Option<usize>,
    lead: usize,
    raw: Option<usize>,
}

impl CodeSize {
    const fn fixed(hard_size: usize, full_size: usize, lead_size: usize, raw_size: usize) -> Self {
        Self {
            hard: hard_size,
            soft: 0,
            full: Some(full_size),
            lead: lead_size,
            raw: Some(raw_size),
        }
    }

    const fn variable(hard_size: usize, soft_size: usize, lead_size: usize) -> Self {
        Self {
            hard: hard_size,
            soft: soft_size,
            full: None,
            lead: lead_size,
            raw: None,
        }
    }

    /// Number of characters in the hard derivation code.
    #[must_use]
    pub const fn hard_size(self) -> usize {
        self.hard
    }

    /// Number of Base64 characters encoding a variable material's size.
    #[must_use]
    pub const fn soft_size(self) -> usize {
        self.soft
    }

    /// Total qualified size in characters, or `None` for variable-size material.
    #[must_use]
    pub const fn full_size(self) -> Option<usize> {
        self.full
    }

    /// Number of zero lead bytes used to align the raw material.
    #[must_use]
    pub const fn lead_size(self) -> usize {
        self.lead
    }

    /// Fixed raw-material size in bytes, or `None` for variable-size material.
    #[must_use]
    pub const fn raw_size(self) -> Option<usize> {
        self.raw
    }

    /// Whether the code carries a soft size instead of a fixed full size.
    #[must_use]
    pub const fn is_variable(self) -> bool {
        self.full.is_none()
    }
}

/// A validated CESR qualified-material derivation code.
///
/// Construction is limited to [`FromStr`] and the named constants, so unsupported codes cannot be
/// represented. All 50 codes accepted by the pinned reference table are available through
/// [`DerivationCode::ALL`], including reserved codes without an upstream semantic name.
///
/// ```compile_fail
/// use signify_cesr::code::DerivationCode;
///
/// let invalid = DerivationCode("R");
/// ```
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct DerivationCode {
    value: &'static str,
    size: CodeSize,
}

impl DerivationCode {
    const fn fixed(value: &'static str, full_size: usize, lead_size: usize, raw_size: usize) -> Self {
        Self {
            value,
            size: CodeSize::fixed(value.len(), full_size, lead_size, raw_size),
        }
    }

    const fn variable(value: &'static str, soft_size: usize, lead_size: usize) -> Self {
        Self {
            value,
            size: CodeSize::variable(value.len(), soft_size, lead_size),
        }
    }

    /// Ed25519 256-bit private signing seed (`A`).
    pub const ED25519_SEED: Self = Self::fixed("A", 44, 0, 32);
    /// Non-transferable Ed25519 verification key (`B`).
    pub const ED25519_NONTRANSFERABLE: Self = Self::fixed("B", 44, 0, 32);
    /// X25519 public encryption key (`C`).
    pub const X25519_PUBLIC: Self = Self::fixed("C", 44, 0, 32);
    /// Transferable Ed25519 verification key (`D`).
    pub const ED25519: Self = Self::fixed("D", 44, 0, 32);
    /// 256-bit BLAKE3 digest (`E`).
    pub const BLAKE3_256: Self = Self::fixed("E", 44, 0, 32);
    /// 256-bit `BLAKE2b` digest (`F`).
    pub const BLAKE2B_256: Self = Self::fixed("F", 44, 0, 32);
    /// 256-bit BLAKE2s digest (`G`).
    pub const BLAKE2S_256: Self = Self::fixed("G", 44, 0, 32);
    /// 256-bit SHA-3 digest (`H`).
    pub const SHA3_256: Self = Self::fixed("H", 44, 0, 32);
    /// 256-bit SHA-2 digest (`I`).
    pub const SHA2_256: Self = Self::fixed("I", 44, 0, 32);
    /// ECDSA secp256k1 256-bit private signing seed (`J`).
    pub const ECDSA_256K1_SEED: Self = Self::fixed("J", 44, 0, 32);
    /// X25519 private decryption key (`O`).
    pub const X25519_PRIVATE: Self = Self::fixed("O", 44, 0, 32);
    /// Ciphertext containing qualified seed material (`P`).
    pub const X25519_CIPHER_SEED: Self = Self::fixed("P", 124, 0, 92);
    /// ECDSA secp256r1 256-bit private signing seed (`Q`).
    pub const ECDSA_256R1_SEED: Self = Self::fixed("Q", 44, 0, 32);
    /// 128-bit salt, also used for the largest exact number (`0A`).
    pub const SALT_128: Self = Self::fixed("0A", 24, 0, 16);
    /// Sixteen-byte exact unsigned number (`0A`), an alias of [`Self::SALT_128`].
    pub const HUGE_NUMBER: Self = Self::SALT_128;
    /// Unindexed Ed25519 signature (`0B`).
    pub const ED25519_SIGNATURE: Self = Self::fixed("0B", 88, 0, 64);
    /// Unindexed ECDSA secp256k1 signature (`0C`).
    pub const ECDSA_256K1_SIGNATURE: Self = Self::fixed("0C", 88, 0, 64);
    /// 512-bit BLAKE3 digest (`0D`).
    pub const BLAKE3_512: Self = Self::fixed("0D", 88, 0, 64);
    /// 512-bit `BLAKE2b` digest (`0E`).
    pub const BLAKE2B_512: Self = Self::fixed("0E", 88, 0, 64);
    /// 512-bit SHA-3 digest (`0F`).
    pub const SHA3_512: Self = Self::fixed("0F", 88, 0, 64);
    /// 512-bit SHA-2 digest (`0G`).
    pub const SHA2_512: Self = Self::fixed("0G", 88, 0, 64);
    /// Four-byte exact unsigned number (`0H`).
    pub const LONG_NUMBER: Self = Self::fixed("0H", 8, 0, 4);
    /// Unindexed ECDSA secp256r1 signature (`0I`).
    pub const ECDSA_256R1_SIGNATURE: Self = Self::fixed("0I", 88, 0, 64);
    /// Non-transferable ECDSA secp256k1 verification key (`1AAA`).
    pub const ECDSA_256K1_NONTRANSFERABLE: Self = Self::fixed("1AAA", 48, 0, 33);
    /// Transferable ECDSA secp256k1 verification key (`1AAB`).
    pub const ECDSA_256K1: Self = Self::fixed("1AAB", 48, 0, 33);
    /// Non-transferable Ed448 verification key (`1AAC`).
    pub const ED448_NONTRANSFERABLE: Self = Self::fixed("1AAC", 80, 0, 57);
    /// Ciphertext containing qualified salt material (`1AAH`).
    pub const X25519_CIPHER_SALT: Self = Self::fixed("1AAH", 100, 0, 72);
    /// Non-transferable ECDSA secp256r1 verification key (`1AAI`).
    pub const ECDSA_256R1_NONTRANSFERABLE: Self = Self::fixed("1AAI", 48, 0, 33);
    /// Transferable ECDSA secp256r1 verification key (`1AAJ`).
    pub const ECDSA_256R1: Self = Self::fixed("1AAJ", 48, 0, 33);
    /// Two-byte exact unsigned number (`M`).
    pub const SHORT_NUMBER: Self = Self::fixed("M", 4, 0, 2);
    /// Eight-byte exact unsigned number (`N`).
    pub const BIG_NUMBER: Self = Self::fixed("N", 12, 0, 8);
    /// Small variable Base64 text code with no lead byte (`4A`).
    pub const BASE64_TEXT_LEAD_0: Self = Self::variable("4A", 2, 0);
    /// Small variable Base64 text code with one lead byte (`5A`).
    pub const BASE64_TEXT_LEAD_1: Self = Self::variable("5A", 2, 1);
    /// Small variable Base64 text code with two lead bytes (`6A`).
    pub const BASE64_TEXT_LEAD_2: Self = Self::variable("6A", 2, 2);
    /// Large variable Base64 text code with no lead byte (`7AAA`).
    pub const BASE64_TEXT_BIG_LEAD_0: Self = Self::variable("7AAA", 4, 0);
    /// Large variable Base64 text code with one lead byte (`8AAA`).
    pub const BASE64_TEXT_BIG_LEAD_1: Self = Self::variable("8AAA", 4, 1);
    /// Large variable Base64 text code with two lead bytes (`9AAA`).
    pub const BASE64_TEXT_BIG_LEAD_2: Self = Self::variable("9AAA", 4, 2);

    /// Every hard code present in the pinned reference's `Matter.Sizes` table.
    ///
    /// Order matches the TypeScript table declaration and the checked-in cross-language fixture.
    pub const ALL: &'static [Self] = &[
        Self::ED25519_SEED,
        Self::ED25519_NONTRANSFERABLE,
        Self::X25519_PUBLIC,
        Self::ED25519,
        Self::BLAKE3_256,
        Self::BLAKE2B_256,
        Self::BLAKE2S_256,
        Self::SHA3_256,
        Self::SHA2_256,
        Self::ECDSA_256K1_SEED,
        Self::fixed("K", 76, 0, 56),
        Self::fixed("L", 76, 0, 56),
        Self::SHORT_NUMBER,
        Self::BIG_NUMBER,
        Self::X25519_PRIVATE,
        Self::X25519_CIPHER_SEED,
        Self::ECDSA_256R1_SEED,
        Self::SALT_128,
        Self::ED25519_SIGNATURE,
        Self::ECDSA_256K1_SIGNATURE,
        Self::BLAKE3_512,
        Self::BLAKE2B_512,
        Self::SHA3_512,
        Self::SHA2_512,
        Self::LONG_NUMBER,
        Self::ECDSA_256R1_SIGNATURE,
        Self::ECDSA_256K1_NONTRANSFERABLE,
        Self::ECDSA_256K1,
        Self::ED448_NONTRANSFERABLE,
        Self::fixed("1AAD", 80, 0, 57),
        Self::fixed("1AAE", 56, 0, 39),
        Self::fixed("1AAF", 8, 0, 3),
        Self::fixed("1AAG", 36, 0, 24),
        Self::X25519_CIPHER_SALT,
        Self::ECDSA_256R1_NONTRANSFERABLE,
        Self::ECDSA_256R1,
        Self::fixed("2AAA", 8, 1, 2),
        Self::fixed("3AAA", 8, 2, 1),
        Self::BASE64_TEXT_LEAD_0,
        Self::BASE64_TEXT_LEAD_1,
        Self::BASE64_TEXT_LEAD_2,
        Self::BASE64_TEXT_BIG_LEAD_0,
        Self::BASE64_TEXT_BIG_LEAD_1,
        Self::BASE64_TEXT_BIG_LEAD_2,
        Self::variable("4B", 2, 0),
        Self::variable("5B", 2, 1),
        Self::variable("6B", 2, 2),
        Self::variable("7AAB", 4, 0),
        Self::variable("8AAB", 4, 1),
        Self::variable("9AAB", 4, 2),
    ];

    /// Canonical hard-code text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.value
    }

    /// Raw, hard, soft, full, and lead size metadata for this code.
    #[must_use]
    pub const fn size(self) -> CodeSize {
        self.size
    }

    /// Whether this code belongs to the requested upstream semantic codex.
    #[must_use]
    pub fn belongs_to(self, family: CodeFamily) -> bool {
        match family {
            CodeFamily::GeneralMatter => matches!(
                self.value,
                "A" | "B"
                    | "C"
                    | "D"
                    | "E"
                    | "H"
                    | "I"
                    | "J"
                    | "O"
                    | "P"
                    | "Q"
                    | "0A"
                    | "0B"
                    | "0C"
                    | "0I"
                    | "4A"
                    | "5A"
                    | "6A"
                    | "1AAA"
                    | "1AAB"
                    | "1AAH"
                    | "1AAI"
                    | "1AAJ"
                    | "7AAA"
                    | "8AAA"
                    | "9AAA"
            ),
            CodeFamily::NonTransferable => {
                matches!(self.value, "B" | "1AAA" | "1AAC" | "1AAI")
            }
            CodeFamily::Digest => matches!(self.value, "E" | "F" | "G" | "H" | "I" | "0D" | "0E" | "0F" | "0G"),
            CodeFamily::Numeric => matches!(self.value, "M" | "0H" | "N" | "0A"),
            CodeFamily::Base64Text => matches!(self.value, "4A" | "5A" | "6A" | "7AAA" | "8AAA" | "9AAA"),
        }
    }
}

impl fmt::Debug for DerivationCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("DerivationCode").field(&self.value).finish()
    }
}

impl fmt::Display for DerivationCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.value)
    }
}

impl FromStr for DerivationCode {
    type Err = CesrError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let Some(&selector) = input.as_bytes().first() else {
            return Err(CesrError::EmptyInput {
                context: "derivation code",
            });
        };
        let expected = hard_code_size(selector)?;
        if input.len() != expected {
            return Err(CesrError::InvalidLength {
                context: "derivation code",
                length: input.len(),
            });
        }
        if let Some((index, byte)) = input
            .bytes()
            .enumerate()
            .find(|(_, byte)| !byte.is_ascii_alphanumeric())
        {
            return Err(CesrError::InvalidCodeCharacter { index, byte });
        }
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.value == input)
            .ok_or_else(|| CesrError::UnsupportedCode { code: input.to_owned() })
    }
}

impl TryFrom<&str> for DerivationCode {
    type Error = CesrError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

/// Returns the hard-code length selected by the first qualified Base64 character.
///
/// This reproduces `Matter.Hards` without allocating a 64-entry map. It does not assert that a
/// complete supported code follows the selector; use [`DerivationCode::from_str`] for that.
///
/// # Errors
///
/// Returns [`CesrError::InvalidCodeCharacter`] when `selector` is not an ASCII alphanumeric CESR
/// hard-code selector.
pub fn hard_code_size(selector: u8) -> Result<usize, CesrError> {
    match selector {
        b'A'..=b'Z' | b'a'..=b'z' => Ok(1),
        b'0' | b'4' | b'5' | b'6' => Ok(2),
        b'1' | b'2' | b'3' | b'7' | b'8' | b'9' => Ok(4),
        _ => Err(CesrError::InvalidCodeCharacter {
            index: 0,
            byte: selector,
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, error::Error};

    use super::{CodeFamily, DerivationCode, hard_code_size};
    use crate::CesrError;

    #[test]
    fn table_codes_are_unique_and_self_consistent() -> Result<(), Box<dyn Error>> {
        let mut values = HashSet::new();
        assert_eq!(DerivationCode::ALL.len(), 50);

        for code in DerivationCode::ALL {
            assert!(values.insert(code.as_str()));
            assert_eq!(code.size().hard_size(), code.as_str().len());
            let selector = code
                .as_str()
                .as_bytes()
                .first()
                .copied()
                .ok_or("table contains an empty code")?;
            assert_eq!(hard_code_size(selector)?, code.size().hard_size());

            if let (Some(full), Some(raw)) = (code.size().full_size(), code.size().raw_size()) {
                assert_eq!(code.size().soft_size(), 0);
                assert_eq!(full % 4, 0);
                let material_chars = full
                    .checked_sub(code.size().hard_size())
                    .ok_or("fixed full size is shorter than its hard code")?;
                let decoded = material_chars
                    .checked_mul(3)
                    .ok_or("fixed size calculation overflowed")?
                    / 4;
                let expected_raw = decoded
                    .checked_sub(code.size().lead_size())
                    .ok_or("fixed lead size exceeds decoded material")?;
                assert_eq!(raw, expected_raw);
                assert!(!code.size().is_variable());
            } else {
                assert_eq!(code.size().full_size(), None);
                assert_eq!(code.size().raw_size(), None);
                assert_eq!((code.size().hard_size() + code.size().soft_size()) % 4, 0);
                assert!(code.size().is_variable());
            }
        }
        Ok(())
    }

    #[test]
    fn parsing_rejects_empty_truncated_excess_invalid_and_unknown_codes() {
        assert!(matches!(
            "".parse::<DerivationCode>(),
            Err(CesrError::EmptyInput { .. })
        ));
        assert!(matches!(
            "0".parse::<DerivationCode>(),
            Err(CesrError::InvalidLength { .. })
        ));
        assert!(matches!(
            "AA".parse::<DerivationCode>(),
            Err(CesrError::InvalidLength { .. })
        ));
        assert!(matches!(
            "0!".parse::<DerivationCode>(),
            Err(CesrError::InvalidCodeCharacter { .. })
        ));
        assert!(matches!(
            "R".parse::<DerivationCode>(),
            Err(CesrError::UnsupportedCode { .. })
        ));
        assert!(matches!(
            "1ZZZ".parse::<DerivationCode>(),
            Err(CesrError::UnsupportedCode { .. })
        ));
    }

    #[test]
    fn named_constants_and_text_round_trip() -> Result<(), Box<dyn Error>> {
        assert_eq!(DerivationCode::ED25519_SEED.to_string(), "A");
        assert_eq!(DerivationCode::try_from("1AAJ")?, DerivationCode::ECDSA_256R1);
        assert_eq!("0A".parse::<DerivationCode>()?, DerivationCode::SALT_128);
        assert_eq!(DerivationCode::HUGE_NUMBER, DerivationCode::SALT_128);
        assert_eq!(
            DerivationCode::try_from("9AAA")?,
            DerivationCode::BASE64_TEXT_BIG_LEAD_2
        );
        assert_eq!(DerivationCode::X25519_CIPHER_SEED.size().raw_size(), Some(92));
        Ok(())
    }

    #[test]
    fn family_membership_matches_reference_codices() -> Result<(), Box<dyn Error>> {
        assert!(DerivationCode::BLAKE3_256.belongs_to(CodeFamily::GeneralMatter));
        assert!(DerivationCode::BLAKE3_256.belongs_to(CodeFamily::Digest));
        assert!(!DerivationCode::BLAKE2B_256.belongs_to(CodeFamily::GeneralMatter));
        assert!(DerivationCode::BLAKE2B_256.belongs_to(CodeFamily::Digest));
        assert!(DerivationCode::ED25519_NONTRANSFERABLE.belongs_to(CodeFamily::NonTransferable));
        assert!(DerivationCode::SALT_128.belongs_to(CodeFamily::Numeric));
        assert!("8AAA".parse::<DerivationCode>()?.belongs_to(CodeFamily::Base64Text));
        assert!(!"8AAB".parse::<DerivationCode>()?.belongs_to(CodeFamily::Base64Text));
        Ok(())
    }

    #[test]
    fn selector_table_covers_exact_ascii_alphanumeric_ranges() -> Result<(), Box<dyn Error>> {
        for selector in b'A'..=b'Z' {
            assert_eq!(hard_code_size(selector)?, 1);
        }
        for selector in b'a'..=b'z' {
            assert_eq!(hard_code_size(selector)?, 1);
        }
        for (selector, expected) in [
            (b'0', 2),
            (b'1', 4),
            (b'2', 4),
            (b'3', 4),
            (b'4', 2),
            (b'5', 2),
            (b'6', 2),
            (b'7', 4),
            (b'8', 4),
            (b'9', 4),
        ] {
            assert_eq!(hard_code_size(selector)?, expected);
        }
        assert!(matches!(
            hard_code_size(b'-'),
            Err(CesrError::InvalidCodeCharacter { .. })
        ));
        Ok(())
    }
}
