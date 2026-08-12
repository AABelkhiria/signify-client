//! Secret Ed25519 signing seeds and CESR signature production.
//!
//! The pinned TypeScript `Signer` supports only the Ed25519 seed derivation code. This module
//! keeps that algorithm boundary explicit, derives a validated public [`VerificationKey`], and
//! returns the existing semantic indexed or unindexed signature types. Secret seed bytes are
//! never exposed by the signer API and are zeroized by the selected primitive on drop.

use std::{error::Error, fmt};

use ed25519_dalek::{Signer as _, SigningKey};
use signify_cesr::{
    CesrError,
    code::DerivationCode,
    indexer::IndexerCode,
    matter::{ParsedMaterial, QualifiedMaterial},
};
use zeroize::Zeroizing;

use crate::{
    CryptoError,
    signature::{IndexedSignature, SignatureAlgorithm, UnindexedSignature},
    verifier::{KeyTransferability, VerificationAlgorithm, VerificationKey},
};

/// Raw byte width of a supported Ed25519 private signing seed.
pub const ED25519_SEED_SIZE: usize = 32;

const SMALL_INDEX_MAXIMUM: u32 = 63;

type SecretSourceError = Box<dyn Error + Send + Sync>;

/// A private signing algorithm supported by the pinned Signify reference.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum SigningAlgorithm {
    /// Ed25519 signing from one 32-byte seed.
    Ed25519,
}

impl SigningAlgorithm {
    /// Returns a stable, non-secret algorithm name for diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
        }
    }

    /// Returns the exact CESR private-seed derivation code.
    #[must_use]
    pub const fn code(self) -> DerivationCode {
        match self {
            Self::Ed25519 => DerivationCode::ED25519_SEED,
        }
    }
}

/// Placement of an indexed signature in current and prior key lists.
///
/// Constructors make the current-only and both-list modes explicit without a boolean argument.
/// The final index widths are validated when a signature is produced because CESR uses different
/// small and big codes for the two modes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SignaturePlacement {
    index: u32,
    prior_index: Option<u32>,
}

impl SignaturePlacement {
    /// Creates a both-lists placement using the same current and prior-list index.
    #[must_use]
    pub const fn both_lists(index: u32) -> Self {
        Self {
            index,
            prior_index: Some(index),
        }
    }

    /// Creates a both-lists placement with distinct current and prior-list indices.
    #[must_use]
    pub const fn both_lists_with_prior(index: u32, prior_index: u32) -> Self {
        Self {
            index,
            prior_index: Some(prior_index),
        }
    }

    /// Creates a current-list-only placement.
    #[must_use]
    pub const fn current_list(index: u32) -> Self {
        Self {
            index,
            prior_index: None,
        }
    }

    /// Returns the current-list index.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.index
    }

    /// Returns the prior-list index, or `None` for a current-only placement.
    #[must_use]
    pub const fn prior_index(self) -> Option<u32> {
        self.prior_index
    }

    /// Returns whether this placement applies only to the current key list.
    #[must_use]
    pub const fn is_current_only(self) -> bool {
        self.prior_index.is_none()
    }
}

/// One private Ed25519 signer with its derived public verification key.
///
/// The signer does not implement `Clone`, equality, `Display`, or serialization. Its `Debug`
/// representation is redacted, and no method exposes the seed. The underlying `ed25519-dalek`
/// signing key is built with zeroization enabled, so its owned seed and expanded signing
/// temporaries are erased on drop. Borrowed input remains the caller's responsibility.
///
/// ```
/// use signify_crypto::{
///     signer::{SignaturePlacement, Signer},
///     verifier::KeyTransferability,
/// };
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let signer = Signer::from_seed(&[7_u8; 32], KeyTransferability::Transferable)?;
/// let signature = signer.sign_indexed(b"example serialization", SignaturePlacement::both_lists(0))?;
/// signer.verifier().verify(signature.raw(), b"example serialization")?;
/// # Ok(())
/// # }
/// ```
///
/// Secret state cannot be assembled or accessed directly:
///
/// ```compile_fail
/// use signify_crypto::signer::Signer;
///
/// let signer = Signer { signing_key: [0_u8; 32], verifier: () };
/// let leaked = signer.signing_key;
/// ```
pub struct Signer {
    signing_key: SigningKey,
    verifier: VerificationKey,
}

/// One private signer parsed from the front of a raw, qb64, or qb2 stream.
pub struct ParsedSigner {
    signer: Signer,
    consumed: usize,
}

impl ParsedSigner {
    /// Returns the parsed signer by reference without exposing its seed.
    #[must_use]
    pub const fn signer(&self) -> &Signer {
        &self.signer
    }

    /// Returns the number of input bytes or characters consumed.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Separates the signer from its consumed input length.
    #[must_use]
    pub fn into_parts(self) -> (Signer, usize) {
        (self.signer, self.consumed)
    }
}

impl Signer {
    /// Generates a signer from 32 bytes supplied by the operating-system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::EntropyUnavailable`] if the operating system cannot fill the seed,
    /// or a typed key-construction error if the derived public key is invalid.
    pub fn generate(transferability: KeyTransferability) -> Result<Self, CryptoError> {
        Self::generate_with(transferability, |seed| {
            getrandom::fill(seed).map_err(|source| Box::new(source) as SecretSourceError)
        })
    }

    /// Constructs a signer from exactly one borrowed 32-byte Ed25519 seed.
    ///
    /// The signer immediately copies the seed into zeroizing owned storage. The caller remains
    /// responsible for clearing the borrowed source buffer when it is no longer needed.
    ///
    /// # Errors
    ///
    /// Returns a typed truncation or trailing-material error unless `input` is exactly 32 bytes,
    /// or a typed key-construction error if public-key derivation fails.
    pub fn from_seed(input: &[u8], transferability: KeyTransferability) -> Result<Self, CryptoError> {
        let parsed = Self::parse_seed_prefix(input, transferability)?;
        reject_trailing("private signing seed", input.len(), parsed.consumed)?;
        Ok(parsed.signer)
    }

    /// Parses one fixed-width Ed25519 seed from the beginning of a raw byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed truncation, CESR size, or key-construction error.
    pub fn parse_seed_prefix(input: &[u8], transferability: KeyTransferability) -> Result<ParsedSigner, CryptoError> {
        Self::from_parsed_material(
            QualifiedMaterial::parse_raw_prefix(DerivationCode::ED25519_SEED, input, ED25519_SEED_SIZE)?,
            transferability,
        )
    }

    /// Parses one canonical qb64 signing seed from the beginning of `input`.
    ///
    /// Transferability is supplied separately because it belongs to the derived verifier and is
    /// not encoded by the private seed code.
    ///
    /// # Errors
    ///
    /// Returns a typed material, signer-code, unsupported-algorithm, or key-construction error.
    pub fn parse_qb64(input: &str, transferability: KeyTransferability) -> Result<ParsedSigner, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb64(input)?, transferability)
    }

    /// Parses exactly one canonical qb64 signing seed.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64`] and rejects trailing characters.
    pub fn from_qb64(input: &str, transferability: KeyTransferability) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb64(input, transferability)?;
        reject_trailing("private signing seed qualified Base64", input.len(), parsed.consumed)?;
        Ok(parsed.signer)
    }

    /// Parses one UTF-8 qb64 signing seed from the beginning of a byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed UTF-8, material, signer-code, or key-construction error.
    pub fn parse_qb64_bytes(input: &[u8], transferability: KeyTransferability) -> Result<ParsedSigner, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb64_bytes(input)?, transferability)
    }

    /// Parses exactly one UTF-8 qb64 signing seed from bytes.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64_bytes`] and rejects trailing bytes.
    pub fn from_qb64_bytes(input: &[u8], transferability: KeyTransferability) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb64_bytes(input, transferability)?;
        reject_trailing(
            "private signing seed qualified Base64 bytes",
            input.len(),
            parsed.consumed,
        )?;
        Ok(parsed.signer)
    }

    /// Parses one canonical qualified-binary (`qb2`) seed from the input prefix.
    ///
    /// # Errors
    ///
    /// Returns a typed material, signer-code, unsupported-algorithm, or key-construction error.
    pub fn parse_qb2(input: &[u8], transferability: KeyTransferability) -> Result<ParsedSigner, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb2(input)?, transferability)
    }

    /// Parses exactly one canonical qualified-binary (`qb2`) signing seed.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb2`] and rejects trailing bytes.
    pub fn from_qb2(input: &[u8], transferability: KeyTransferability) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb2(input, transferability)?;
        reject_trailing("private signing seed qualified binary", input.len(), parsed.consumed)?;
        Ok(parsed.signer)
    }

    /// Returns the signing algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Ed25519
    }

    /// Returns the private seed's CESR derivation code without exposing seed bytes.
    #[must_use]
    pub const fn code(&self) -> DerivationCode {
        DerivationCode::ED25519_SEED
    }

    /// Returns the public verification key derived from this signer's seed.
    #[must_use]
    pub const fn verifier(&self) -> &VerificationKey {
        &self.verifier
    }

    /// Returns the derived public key's transferability classification.
    #[must_use]
    pub const fn transferability(&self) -> KeyTransferability {
        self.verifier.transferability()
    }

    /// Returns whether the derived public key is transferable.
    #[must_use]
    pub const fn is_transferable(&self) -> bool {
        self.verifier.is_transferable()
    }

    /// Produces an unindexed Ed25519 signature associated with this signer's public verifier.
    ///
    /// # Errors
    ///
    /// Returns a typed primitive failure or signature/verifier construction error.
    pub fn sign_unindexed(&self, serialization: &[u8]) -> Result<UnindexedSignature, CryptoError> {
        let raw = self.sign_raw(serialization)?;
        UnindexedSignature::from_raw_with_verifier(SignatureAlgorithm::Ed25519, &raw, self.verifier.clone())
    }

    /// Produces an indexed Ed25519 signature at the requested key-list placement.
    ///
    /// Matching indices up to 63 use the small both-lists code. Other both-list placements use
    /// the big code. Current-only indices up to 63 use the small current code and larger values use
    /// the big current code, exactly matching the pinned reference's selection rules.
    ///
    /// # Errors
    ///
    /// Returns a typed primitive failure, out-of-range index, invalid relationship, or
    /// signature/verifier construction error.
    pub fn sign_indexed(
        &self,
        serialization: &[u8],
        placement: SignaturePlacement,
    ) -> Result<IndexedSignature, CryptoError> {
        let raw = self.sign_raw(serialization)?;
        let (code, prior_index) = match placement.prior_index {
            None if placement.index <= SMALL_INDEX_MAXIMUM => (IndexerCode::ED25519_CURRENT, None),
            None => (IndexerCode::ED25519_BIG_CURRENT, None),
            Some(prior) if placement.index <= SMALL_INDEX_MAXIMUM && prior == placement.index => {
                (IndexerCode::ED25519, Some(prior))
            }
            Some(prior) => (IndexerCode::ED25519_BIG, Some(prior)),
        };
        IndexedSignature::from_raw_with_verifier(code, placement.index, prior_index, &raw, self.verifier.clone())
    }

    fn generate_with<F>(transferability: KeyTransferability, fill: F) -> Result<Self, CryptoError>
    where
        F: FnOnce(&mut [u8]) -> Result<(), SecretSourceError>,
    {
        let mut seed = Zeroizing::new([0_u8; ED25519_SEED_SIZE]);
        fill(seed.as_mut()).map_err(|source| CryptoError::EntropyUnavailable { source })?;
        Self::from_zeroizing_seed(&seed, transferability)
    }

    fn from_parsed_material(
        parsed: ParsedMaterial,
        transferability: KeyTransferability,
    ) -> Result<ParsedSigner, CryptoError> {
        let (material, consumed) = parsed.into_parts();
        validate_signing_code(material.code())?;
        let mut seed = Zeroizing::new([0_u8; ED25519_SEED_SIZE]);
        if material.raw().len() != ED25519_SEED_SIZE {
            return Err(CesrError::RawSizeMismatch {
                context: "private signing seed",
                expected: ED25519_SEED_SIZE,
                actual: material.raw().len(),
            }
            .into());
        }
        for (target, source) in seed.iter_mut().zip(material.raw().iter().copied()) {
            *target = source;
        }
        Ok(ParsedSigner {
            signer: Self::from_zeroizing_seed(&seed, transferability)?,
            consumed,
        })
    }

    fn from_zeroizing_seed(
        seed: &Zeroizing<[u8; ED25519_SEED_SIZE]>,
        transferability: KeyTransferability,
    ) -> Result<Self, CryptoError> {
        let signing_key = SigningKey::from_bytes(seed);
        let verifier = VerificationKey::from_raw(
            VerificationAlgorithm::Ed25519,
            transferability,
            signing_key.verifying_key().as_bytes(),
        )?;
        Ok(Self { signing_key, verifier })
    }

    fn sign_raw(&self, serialization: &[u8]) -> Result<[u8; 64], CryptoError> {
        self.signing_key
            .try_sign(serialization)
            .map(|signature| signature.to_bytes())
            .map_err(|source| CryptoError::SigningFailed {
                algorithm: SigningAlgorithm::Ed25519.name(),
                source: Box::new(source),
            })
    }
}

impl fmt::Debug for Signer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Signer")
            .field("algorithm", &self.algorithm())
            .field("transferability", &self.transferability())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ParsedSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedSigner")
            .field("signer", &self.signer)
            .field("consumed", &self.consumed)
            .finish()
    }
}

fn validate_signing_code(code: DerivationCode) -> Result<(), CryptoError> {
    match code {
        DerivationCode::ED25519_SEED => Ok(()),
        DerivationCode::ECDSA_256K1_SEED | DerivationCode::ECDSA_256R1_SEED => {
            Err(CryptoError::UnsupportedSigningAlgorithm { code: code.as_str() })
        }
        other => Err(CryptoError::InvalidSigningCode { code: other.as_str() }),
    }
}

fn reject_trailing(context: &'static str, total: usize, consumed: usize) -> Result<(), CryptoError> {
    let trailing = total
        .checked_sub(consumed)
        .ok_or(CesrError::LengthOverflow { context })?;
    if trailing == 0 {
        Ok(())
    } else {
        Err(CesrError::TrailingMaterial {
            context,
            length: trailing,
        }
        .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; ED25519_SEED_SIZE] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        30, 31,
    ];
    const MESSAGE: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    const VERIFIER_QB64: &str = "DAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";
    const SIGNATURE_QB64: &str =
        "0BB43fz0GkIj6INCvq732d7FBZxt3Gw08S1mak9TeRgStsrxiUPEKcMAP9SlJrt6sg5h2pEvTshrYz56rM8IIzcO";

    #[test]
    fn reference_seed_derives_verifier_and_unindexed_signature() -> Result<(), CryptoError> {
        let signer = Signer::from_seed(&SEED, KeyTransferability::Transferable)?;
        assert_eq!(signer.algorithm(), SigningAlgorithm::Ed25519);
        assert_eq!(signer.code(), DerivationCode::ED25519_SEED);
        assert_eq!(signer.transferability(), KeyTransferability::Transferable);
        assert!(signer.is_transferable());
        assert_eq!(signer.verifier().qb64()?, VERIFIER_QB64);

        let signature = signer.sign_unindexed(MESSAGE)?;
        assert_eq!(signature.qb64()?, SIGNATURE_QB64);
        assert_eq!(signature.verifier(), Some(signer.verifier()));
        signer.verifier().verify(signature.raw(), MESSAGE)?;
        Ok(())
    }

    #[test]
    fn all_index_selection_branches_match_reference_rules() -> Result<(), CryptoError> {
        let signer = Signer::from_seed(&SEED, KeyTransferability::Transferable)?;
        let cases = [
            (SignaturePlacement::both_lists(63), IndexerCode::ED25519, Some(63)),
            (
                SignaturePlacement::both_lists_with_prior(3, 4),
                IndexerCode::ED25519_BIG,
                Some(4),
            ),
            (SignaturePlacement::both_lists(64), IndexerCode::ED25519_BIG, Some(64)),
            (SignaturePlacement::current_list(63), IndexerCode::ED25519_CURRENT, None),
            (
                SignaturePlacement::current_list(64),
                IndexerCode::ED25519_BIG_CURRENT,
                None,
            ),
        ];
        for (placement, code, prior_index) in cases {
            assert_eq!(placement.prior_index(), prior_index);
            assert_eq!(placement.is_current_only(), prior_index.is_none());
            let signature = signer.sign_indexed(MESSAGE, placement)?;
            assert_eq!(signature.code(), code);
            assert_eq!(signature.index(), placement.index());
            assert_eq!(signature.other_index(), prior_index);
            assert_eq!(signature.verifier(), Some(signer.verifier()));
            signer.verifier().verify(signature.raw(), MESSAGE)?;
        }
        Ok(())
    }

    #[test]
    fn raw_and_encoded_parsers_preserve_boundaries_without_exposing_seed() -> Result<(), CryptoError> {
        let material = QualifiedMaterial::new(DerivationCode::ED25519_SEED, &SEED)?;
        let qb64 = material.qb64()?;
        let qb64_bytes = material.qb64_bytes()?;
        let qb2 = material.qb2()?;

        let raw = Signer::from_seed(&SEED, KeyTransferability::NonTransferable)?;
        let from_text = Signer::from_qb64(&qb64, KeyTransferability::NonTransferable)?;
        let from_bytes = Signer::from_qb64_bytes(&qb64_bytes, KeyTransferability::NonTransferable)?;
        let from_binary = Signer::from_qb2(&qb2, KeyTransferability::NonTransferable)?;
        assert_eq!(raw.verifier(), from_text.verifier());
        assert_eq!(raw.verifier(), from_bytes.verifier());
        assert_eq!(raw.verifier(), from_binary.verifier());
        assert!(!raw.is_transferable());

        let mut raw_stream = SEED.to_vec();
        raw_stream.push(0xff);
        let parsed_raw = Signer::parse_seed_prefix(&raw_stream, KeyTransferability::Transferable)?;
        assert_eq!(parsed_raw.consumed(), ED25519_SEED_SIZE);
        assert_eq!(parsed_raw.signer().verifier().qb64()?, VERIFIER_QB64);
        assert!(Signer::from_seed(&raw_stream, KeyTransferability::Transferable).is_err());

        let text_stream = format!("{qb64}ABCD");
        let parsed_text = Signer::parse_qb64(&text_stream, KeyTransferability::Transferable)?;
        assert_eq!(parsed_text.consumed(), qb64.len());
        let (parsed_signer, consumed) = parsed_text.into_parts();
        assert_eq!(consumed, qb64.len());
        assert_eq!(parsed_signer.verifier().qb64()?, VERIFIER_QB64);
        assert!(Signer::from_qb64(&text_stream, KeyTransferability::Transferable).is_err());

        let mut binary_stream = qb2.clone();
        binary_stream.extend_from_slice(&[1, 2, 3]);
        let parsed_binary = Signer::parse_qb2(&binary_stream, KeyTransferability::Transferable)?;
        assert_eq!(parsed_binary.consumed(), qb2.len());
        assert!(Signer::from_qb2(&binary_stream, KeyTransferability::Transferable).is_err());

        let byte_stream = [qb64_bytes.as_slice(), b"ABCD"].concat();
        let parsed_bytes = Signer::parse_qb64_bytes(&byte_stream, KeyTransferability::Transferable)?;
        assert_eq!(parsed_bytes.consumed(), qb64_bytes.len());
        assert!(Signer::from_qb64_bytes(&byte_stream, KeyTransferability::Transferable).is_err());
        Ok(())
    }

    #[test]
    fn unsupported_and_invalid_seed_codes_are_typed() -> Result<(), CryptoError> {
        for code in [DerivationCode::ECDSA_256K1_SEED, DerivationCode::ECDSA_256R1_SEED] {
            let material = QualifiedMaterial::new(code, &SEED)?;
            assert!(matches!(
                Signer::from_qb64(&material.qb64()?, KeyTransferability::Transferable),
                Err(CryptoError::UnsupportedSigningAlgorithm { code: "J" | "Q" })
            ));
        }
        let digest = QualifiedMaterial::new(DerivationCode::BLAKE3_256, &SEED)?;
        assert!(matches!(
            Signer::from_qb64(&digest.qb64()?, KeyTransferability::Transferable),
            Err(CryptoError::InvalidSigningCode { code: "E" })
        ));
        assert!(Signer::from_seed(&[0_u8; 31], KeyTransferability::Transferable).is_err());
        assert!(Signer::from_seed(&[0_u8; 33], KeyTransferability::Transferable).is_err());
        Ok(())
    }

    #[test]
    fn indexed_signing_rejects_the_first_value_above_big_index_fields() -> Result<(), CryptoError> {
        let signer = Signer::from_seed(&SEED, KeyTransferability::Transferable)?;
        assert!(
            signer
                .sign_indexed(MESSAGE, SignaturePlacement::both_lists(4095))
                .is_ok()
        );
        assert!(
            signer
                .sign_indexed(MESSAGE, SignaturePlacement::current_list(4095))
                .is_ok()
        );
        for placement in [
            SignaturePlacement::both_lists(4096),
            SignaturePlacement::current_list(4096),
        ] {
            assert!(matches!(
                signer.sign_indexed(MESSAGE, placement),
                Err(CryptoError::Cesr { ref source })
                    if matches!(source.as_ref(), CesrError::IndexOutOfRange {
                        context: "current index",
                        value: 4096,
                        maximum: 4095,
                    })
            ));
        }
        Ok(())
    }

    #[test]
    fn generation_signs_and_entropy_failures_preserve_a_source() -> Result<(), CryptoError> {
        let generated = Signer::generate(KeyTransferability::Transferable)?;
        let signature = generated.sign_unindexed(MESSAGE)?;
        generated.verifier().verify(signature.raw(), MESSAGE)?;

        let error = Signer::generate_with(KeyTransferability::Transferable, |_| {
            Err(Box::new(std::io::Error::other("injected entropy failure")))
        })
        .err()
        .ok_or(CryptoError::SigningFailed {
            algorithm: "test",
            source: Box::new(std::io::Error::other("missing injected failure")),
        })?;
        assert!(matches!(error, CryptoError::EntropyUnavailable { .. }));
        assert!(error.source().is_some());
        Ok(())
    }

    #[test]
    fn debug_output_is_redacted() -> Result<(), CryptoError> {
        let material = QualifiedMaterial::new(DerivationCode::ED25519_SEED, &SEED)?;
        let seed_qb64 = material.qb64()?;
        let signer = Signer::from_seed(&SEED, KeyTransferability::Transferable)?;
        let debug = format!("{signer:?}");
        assert!(debug.contains("Ed25519"));
        assert!(debug.contains("Transferable"));
        assert!(!debug.contains(&seed_qb64));
        assert!(!debug.contains("00010203"));
        Ok(())
    }
}
