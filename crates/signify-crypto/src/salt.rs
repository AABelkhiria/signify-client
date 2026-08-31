//! Secret key-derivation salts and deterministic signer derivation.
//!
//! The pinned TypeScript `Salter` uses Argon2id v1.3 with one lane and fixed temporary, low,
//! medium, and high cost profiles. This module preserves those parameters while making the
//! profile explicit, bounding path input, reserving KDF memory fallibly, and zeroizing salt,
//! derived seed, and Argon2 working memory.

use std::{error::Error, fmt};

use argon2id_p1::{Algorithm, Argon2, Block, Params, Version};
use signify_cesr::{
    CesrError,
    code::DerivationCode,
    matter::{ParsedMaterial, QualifiedMaterial},
};
use zeroize::Zeroizing;

use crate::{
    CryptoError,
    signer::{ED25519_SEED_SIZE, Signer},
    verifier::KeyTransferability,
};

/// Raw byte width of the pinned 128-bit key-derivation salt.
pub const SALT_SIZE: usize = 16;

/// Maximum accepted deterministic derivation-path length in UTF-8 bytes.
///
/// Signify paths are short labels and numeric components. The explicit ceiling bounds hashing
/// work on caller-controlled text while remaining far above all pinned reference uses.
pub const MAX_DERIVATION_PATH_BYTES: usize = 4_096;

const ARGON2ID_NAME: &str = "Argon2id v1.3";
const ARGON2_PARALLELISM: u32 = 1;

type SecretSourceError = Box<dyn Error + Send + Sync>;

/// Standard security tiers defined by the pinned Signify reference.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum SecurityTier {
    /// Interactive profile: two iterations and 64 MiB of memory.
    #[default]
    Low,
    /// Moderate profile: three iterations and 256 MiB of memory.
    Medium,
    /// Sensitive profile: four iterations and 1 GiB of memory.
    High,
}

/// Complete Argon2id cost profile used for deterministic signer derivation.
///
/// `Temporary` exists only for deterministic tests and low-cost ephemeral tooling. Production
/// callers should use a standard tier.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum KeyDerivationProfile {
    /// Insecure test profile: one iteration and 8 KiB of memory.
    Temporary,
    /// One of the standard Signify security tiers.
    Standard(SecurityTier),
}

impl KeyDerivationProfile {
    /// Returns the exact Argon2 iteration count used by the pinned reference.
    #[must_use]
    pub const fn iterations(self) -> u32 {
        match self {
            Self::Temporary => 1,
            Self::Standard(SecurityTier::Low) => 2,
            Self::Standard(SecurityTier::Medium) => 3,
            Self::Standard(SecurityTier::High) => 4,
        }
    }

    /// Returns the exact Argon2 memory cost in kibibytes.
    #[must_use]
    pub const fn memory_kibibytes(self) -> u32 {
        match self {
            Self::Temporary => 8,
            Self::Standard(SecurityTier::Low) => 65_536,
            Self::Standard(SecurityTier::Medium) => 262_144,
            Self::Standard(SecurityTier::High) => 1_048_576,
        }
    }
}

impl From<SecurityTier> for KeyDerivationProfile {
    fn from(tier: SecurityTier) -> Self {
        Self::Standard(tier)
    }
}

/// A non-cloneable, redacted 128-bit salt for deterministic private-key derivation.
///
/// The salt is treated as secret because Signify commonly constructs it from a passcode. It does
/// not implement `Clone`, equality, `Display`, or serialization. Explicit CESR export methods
/// return zeroizing buffers so callers can persist or encrypt the value when required. Borrowed
/// constructor input remains the caller's responsibility.
///
/// ```
/// use signify_crypto::{
///     salt::{KeyDerivationProfile, Salt, SecurityTier},
///     verifier::KeyTransferability,
/// };
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let salt = Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)?;
/// let signer = salt.derive_signer_with_profile(
///     "signify:controller00",
///     KeyTransferability::Transferable,
///     KeyDerivationProfile::Temporary,
/// )?;
/// let signature = signer.sign_unindexed(b"example serialization")?;
/// signer.verifier().verify(signature.raw(), b"example serialization")?;
/// # Ok(())
/// # }
/// ```
///
/// Secret state cannot be assembled or accessed directly:
///
/// ```compile_fail
/// use signify_crypto::salt::{Salt, SecurityTier};
///
/// let salt = Salt { raw: [0_u8; 16], tier: SecurityTier::Low };
/// let leaked = salt.raw;
/// ```
///
/// Salt values cannot be cloned accidentally:
///
/// ```compile_fail
/// use signify_crypto::salt::{Salt, SecurityTier};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let salt = Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)?;
/// let copied = salt.clone();
/// # Ok(())
/// # }
/// ```
pub struct Salt {
    raw: Zeroizing<[u8; SALT_SIZE]>,
    tier: SecurityTier,
}

/// One salt parsed from the front of a raw, qb64, or qb2 stream.
pub struct ParsedSalt {
    salt: Salt,
    consumed: usize,
}

impl ParsedSalt {
    /// Returns the parsed salt by reference without exposing its raw bytes.
    #[must_use]
    pub const fn salt(&self) -> &Salt {
        &self.salt
    }

    /// Returns the number of input bytes or characters consumed.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Separates the salt from its consumed input length.
    #[must_use]
    pub fn into_parts(self) -> (Salt, usize) {
        (self.salt, self.consumed)
    }
}

impl Salt {
    /// Generates a 128-bit salt from the operating-system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::EntropyUnavailable`] if the operating system cannot fill the salt.
    pub fn generate(tier: SecurityTier) -> Result<Self, CryptoError> {
        Self::generate_with(tier, |salt| {
            getrandom::fill(salt).map_err(|source| Box::new(source) as SecretSourceError)
        })
    }

    /// Constructs a salt from exactly 16 borrowed bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed truncation or trailing-material error unless `input` is exactly 16 bytes.
    pub fn from_raw(input: &[u8], tier: SecurityTier) -> Result<Self, CryptoError> {
        let parsed = Self::parse_raw_prefix(input, tier)?;
        reject_trailing("key-derivation salt", input.len(), parsed.consumed)?;
        Ok(parsed.salt)
    }

    /// Parses one 16-byte salt from the beginning of a raw byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed truncation or CESR size error.
    pub fn parse_raw_prefix(input: &[u8], tier: SecurityTier) -> Result<ParsedSalt, CryptoError> {
        Self::from_parsed_material(
            QualifiedMaterial::parse_raw_prefix(DerivationCode::SALT_128, input, SALT_SIZE)?,
            tier,
        )
    }

    /// Parses one canonical qb64 salt from the beginning of `input`.
    ///
    /// # Errors
    ///
    /// Returns a typed material or salt-code error.
    pub fn parse_qb64(input: &str, tier: SecurityTier) -> Result<ParsedSalt, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb64(input)?, tier)
    }

    /// Parses exactly one canonical qb64 salt.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64`] and rejects trailing characters.
    pub fn from_qb64(input: &str, tier: SecurityTier) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb64(input, tier)?;
        reject_trailing("key-derivation salt qualified Base64", input.len(), parsed.consumed)?;
        Ok(parsed.salt)
    }

    /// Parses one UTF-8 qb64 salt from the beginning of a byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed UTF-8, material, or salt-code error.
    pub fn parse_qb64_bytes(input: &[u8], tier: SecurityTier) -> Result<ParsedSalt, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb64_bytes(input)?, tier)
    }

    /// Parses exactly one UTF-8 qb64 salt from bytes.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64_bytes`] and rejects trailing bytes.
    pub fn from_qb64_bytes(input: &[u8], tier: SecurityTier) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb64_bytes(input, tier)?;
        reject_trailing(
            "key-derivation salt qualified Base64 bytes",
            input.len(),
            parsed.consumed,
        )?;
        Ok(parsed.salt)
    }

    /// Parses one canonical qualified-binary (`qb2`) salt from the input prefix.
    ///
    /// # Errors
    ///
    /// Returns a typed material or salt-code error.
    pub fn parse_qb2(input: &[u8], tier: SecurityTier) -> Result<ParsedSalt, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb2(input)?, tier)
    }

    /// Parses exactly one canonical qualified-binary (`qb2`) salt.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb2`] and rejects trailing bytes.
    pub fn from_qb2(input: &[u8], tier: SecurityTier) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb2(input, tier)?;
        reject_trailing("key-derivation salt qualified binary", input.len(), parsed.consumed)?;
        Ok(parsed.salt)
    }

    /// Returns the salt's fixed CESR derivation code.
    #[must_use]
    pub const fn code(&self) -> DerivationCode {
        DerivationCode::SALT_128
    }

    /// Returns the default standard derivation tier stored with this salt.
    #[must_use]
    pub const fn tier(&self) -> SecurityTier {
        self.tier
    }

    /// Explicitly exports canonical qb64 salt text in an owned zeroizing buffer.
    ///
    /// The returned text contains secret-equivalent passcode material and must not be logged.
    ///
    /// # Errors
    ///
    /// Returns a typed CESR encoding error.
    pub fn expose_qb64(&self) -> Result<Zeroizing<String>, CryptoError> {
        Ok(Zeroizing::new(self.qualified()?.qb64()?))
    }

    /// Explicitly exports canonical qb64 salt bytes in an owned zeroizing buffer.
    ///
    /// # Errors
    ///
    /// Returns a typed CESR encoding error.
    pub fn expose_qb64_bytes(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        Ok(Zeroizing::new(self.qualified()?.qb64_bytes()?))
    }

    /// Explicitly exports canonical qualified-binary salt bytes in an owned zeroizing buffer.
    ///
    /// # Errors
    ///
    /// Returns a typed CESR encoding error.
    pub fn expose_qb2(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        Ok(Zeroizing::new(self.qualified()?.qb2()?))
    }

    /// Derives an Ed25519 signer using this salt's stored standard tier.
    ///
    /// The path is encoded as UTF-8 exactly as in the pinned reference.
    ///
    /// # Errors
    ///
    /// Returns a typed path-bound, memory-allocation, Argon2, or signer-construction error.
    pub fn derive_signer(&self, path: &str, transferability: KeyTransferability) -> Result<Signer, CryptoError> {
        self.derive_signer_with_profile(path, transferability, self.tier.into())
    }

    /// Derives an Ed25519 signer using an explicit standard or temporary profile.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::DerivationPathTooLong`] above
    /// [`MAX_DERIVATION_PATH_BYTES`], a typed allocation failure when the selected memory cannot
    /// be reserved, a source-preserving Argon2 failure, or a signer-construction error.
    pub fn derive_signer_with_profile(
        &self,
        path: &str,
        transferability: KeyTransferability,
        profile: KeyDerivationProfile,
    ) -> Result<Signer, CryptoError> {
        if path.len() > MAX_DERIVATION_PATH_BYTES {
            return Err(CryptoError::DerivationPathTooLong {
                maximum: MAX_DERIVATION_PATH_BYTES,
                actual: path.len(),
            });
        }

        let params = Params::new(
            profile.memory_kibibytes(),
            profile.iterations(),
            ARGON2_PARALLELISM,
            Some(ED25519_SEED_SIZE),
        )
        .map_err(key_derivation_error)?;
        let block_count = params.block_count();
        let mut memory = allocate_memory(block_count)?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut seed = Zeroizing::new([0_u8; ED25519_SEED_SIZE]);
        argon2
            .hash_password_into_with_memory(path.as_bytes(), self.raw.as_ref(), seed.as_mut(), memory.as_mut_slice())
            .map_err(key_derivation_error)?;
        Signer::from_seed(seed.as_ref(), transferability)
    }

    fn generate_with<F>(tier: SecurityTier, fill: F) -> Result<Self, CryptoError>
    where
        F: FnOnce(&mut [u8]) -> Result<(), SecretSourceError>,
    {
        let mut raw = Zeroizing::new([0_u8; SALT_SIZE]);
        fill(raw.as_mut()).map_err(|source| CryptoError::EntropyUnavailable { source })?;
        Ok(Self { raw, tier })
    }

    fn from_parsed_material(parsed: ParsedMaterial, tier: SecurityTier) -> Result<ParsedSalt, CryptoError> {
        let (material, consumed) = parsed.into_parts();
        if material.code() != DerivationCode::SALT_128 {
            return Err(CryptoError::InvalidSaltCode {
                code: material.code().as_str(),
            });
        }
        if material.raw().len() != SALT_SIZE {
            return Err(CesrError::RawSizeMismatch {
                context: "key-derivation salt",
                expected: SALT_SIZE,
                actual: material.raw().len(),
            }
            .into());
        }
        let mut raw = Zeroizing::new([0_u8; SALT_SIZE]);
        for (target, source) in raw.iter_mut().zip(material.raw().iter().copied()) {
            *target = source;
        }
        Ok(ParsedSalt {
            salt: Self { raw, tier },
            consumed,
        })
    }

    fn qualified(&self) -> Result<QualifiedMaterial, CryptoError> {
        Ok(QualifiedMaterial::new(DerivationCode::SALT_128, self.raw.as_ref())?)
    }
}

impl fmt::Debug for Salt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Salt")
            .field("code", &self.code())
            .field("tier", &self.tier)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ParsedSalt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedSalt")
            .field("salt", &self.salt)
            .field("consumed", &self.consumed)
            .finish()
    }
}

#[derive(Debug)]
struct Argon2Source(argon2id_p1::Error);

impl fmt::Display for Argon2Source {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Error for Argon2Source {}

fn key_derivation_error(source: argon2id_p1::Error) -> CryptoError {
    CryptoError::KeyDerivationFailed {
        algorithm: ARGON2ID_NAME,
        source: Box::new(Argon2Source(source)),
    }
}

fn allocate_memory(block_count: usize) -> Result<Zeroizing<Vec<Block>>, CryptoError> {
    let required = block_count.checked_mul(Block::SIZE).ok_or(CesrError::LengthOverflow {
        context: "Argon2 working memory",
    })?;
    let mut memory = Zeroizing::new(Vec::<Block>::new());
    memory
        .try_reserve_exact(block_count)
        .map_err(|source| CryptoError::KeyDerivationMemoryUnavailable {
            required,
            source: Box::new(source),
        })?;
    memory.resize(block_count, Block::default());
    Ok(memory)
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
    use zeroize::Zeroize;

    const RAW: &[u8; SALT_SIZE] = b"0123456789abcdef";
    const QB64: &str = "0AAwMTIzNDU2Nzg5YWJjZGVm";
    const UPSTREAM_RAW: [u8; SALT_SIZE] = [146, 78, 142, 186, 189, 77, 130, 3, 232, 248, 186, 197, 8, 0, 73, 182];
    const UPSTREAM_QB64: &str = "0ACSTo66vU2CA-j4usUIAEm2";

    #[test]
    fn cost_profiles_match_pinned_libsodium_parameters() {
        let cases = [
            (KeyDerivationProfile::Temporary, 1, 8),
            (KeyDerivationProfile::Standard(SecurityTier::Low), 2, 65_536),
            (KeyDerivationProfile::Standard(SecurityTier::Medium), 3, 262_144),
            (KeyDerivationProfile::Standard(SecurityTier::High), 4, 1_048_576),
        ];
        for (profile, iterations, memory) in cases {
            assert_eq!(profile.iterations(), iterations);
            assert_eq!(profile.memory_kibibytes(), memory);
        }
        assert_eq!(SecurityTier::default(), SecurityTier::Low);
    }

    #[test]
    fn raw_and_encoded_construction_match_reference_without_debug_exposure() -> Result<(), CryptoError> {
        let salt = Salt::from_raw(&UPSTREAM_RAW, SecurityTier::Medium)?;
        assert_eq!(salt.code(), DerivationCode::SALT_128);
        assert_eq!(salt.tier(), SecurityTier::Medium);
        assert_eq!(salt.expose_qb64()?.as_str(), UPSTREAM_QB64);
        let from_qb64 = Salt::from_qb64(UPSTREAM_QB64, SecurityTier::High)?;
        assert_eq!(from_qb64.expose_qb64()?.as_str(), UPSTREAM_QB64);
        let qb64_bytes = salt.expose_qb64_bytes()?;
        let from_bytes = Salt::from_qb64_bytes(qb64_bytes.as_ref(), SecurityTier::Low)?;
        assert_eq!(from_bytes.expose_qb64()?.as_str(), UPSTREAM_QB64);
        let qb2 = salt.expose_qb2()?;
        let from_qb2 = Salt::from_qb2(qb2.as_ref(), SecurityTier::Low)?;
        assert_eq!(from_qb2.expose_qb64()?.as_str(), UPSTREAM_QB64);

        let debug = format!("{salt:?}");
        assert!(debug.contains("Medium"));
        assert!(!debug.contains(UPSTREAM_QB64));
        assert!(!debug.contains("146"));
        Ok(())
    }

    #[test]
    fn prefix_parsers_preserve_boundaries_and_strict_forms_reject_suffixes() -> Result<(), CryptoError> {
        let mut raw_stream = RAW.to_vec();
        raw_stream.push(0xff);
        let parsed_raw = Salt::parse_raw_prefix(&raw_stream, SecurityTier::Low)?;
        assert_eq!(parsed_raw.consumed(), SALT_SIZE);
        assert_eq!(parsed_raw.salt().expose_qb64()?.as_str(), QB64);
        assert!(Salt::from_raw(&raw_stream, SecurityTier::Low).is_err());

        let text_stream = format!("{QB64}ABCD");
        let parsed_text = Salt::parse_qb64(&text_stream, SecurityTier::Low)?;
        assert_eq!(parsed_text.consumed(), QB64.len());
        let (parsed_salt, consumed) = parsed_text.into_parts();
        assert_eq!(consumed, QB64.len());
        assert_eq!(parsed_salt.expose_qb64()?.as_str(), QB64);
        assert!(Salt::from_qb64(&text_stream, SecurityTier::Low).is_err());

        let salt = Salt::from_raw(RAW, SecurityTier::Low)?;
        let mut binary_stream = salt.expose_qb2()?.to_vec();
        binary_stream.extend_from_slice(&[1, 2, 3]);
        let parsed_binary = Salt::parse_qb2(&binary_stream, SecurityTier::Low)?;
        assert_eq!(parsed_binary.consumed(), salt.expose_qb2()?.len());
        assert!(Salt::from_qb2(&binary_stream, SecurityTier::Low).is_err());
        Ok(())
    }

    #[test]
    fn invalid_codes_lengths_and_paths_are_typed() -> Result<(), CryptoError> {
        assert!(Salt::from_raw(&[0_u8; SALT_SIZE - 1], SecurityTier::Low).is_err());
        assert!(Salt::from_raw(&[0_u8; SALT_SIZE + 1], SecurityTier::Low).is_err());
        let numeric_width = QualifiedMaterial::new(DerivationCode::SHORT_NUMBER, &[0_u8; 2])?;
        assert!(matches!(
            Salt::from_qb64(&numeric_width.qb64()?, SecurityTier::Low),
            Err(CryptoError::InvalidSaltCode { code: "M" })
        ));

        let salt = Salt::from_raw(RAW, SecurityTier::Low)?;
        let maximum = "x".repeat(MAX_DERIVATION_PATH_BYTES);
        assert!(
            salt.derive_signer_with_profile(
                &maximum,
                KeyTransferability::Transferable,
                KeyDerivationProfile::Temporary,
            )
            .is_ok()
        );
        let oversized = "x".repeat(MAX_DERIVATION_PATH_BYTES + 1);
        assert!(matches!(
            salt.derive_signer_with_profile(
                &oversized,
                KeyTransferability::Transferable,
                KeyDerivationProfile::Temporary,
            ),
            Err(CryptoError::DerivationPathTooLong {
                maximum: MAX_DERIVATION_PATH_BYTES,
                actual,
            }) if actual == MAX_DERIVATION_PATH_BYTES + 1
        ));
        Ok(())
    }

    #[test]
    fn temporary_derivation_is_deterministic_and_path_sensitive() -> Result<(), CryptoError> {
        let salt = Salt::from_raw(RAW, SecurityTier::Low)?;
        let first = salt.derive_signer_with_profile(
            "signify:controller00",
            KeyTransferability::Transferable,
            KeyDerivationProfile::Temporary,
        )?;
        let repeated = salt.derive_signer_with_profile(
            "signify:controller00",
            KeyTransferability::Transferable,
            KeyDerivationProfile::Temporary,
        )?;
        let next = salt.derive_signer_with_profile(
            "signify:controller01",
            KeyTransferability::Transferable,
            KeyDerivationProfile::Temporary,
        )?;
        assert_eq!(first.verifier(), repeated.verifier());
        assert_ne!(first.verifier(), next.verifier());

        let nontransferable = salt.derive_signer_with_profile(
            "signify:controller00",
            KeyTransferability::NonTransferable,
            KeyDerivationProfile::Temporary,
        )?;
        assert_eq!(first.verifier().raw(), nontransferable.verifier().raw());
        assert_ne!(first.verifier().code(), nontransferable.verifier().code());
        Ok(())
    }

    #[test]
    fn default_low_derivation_matches_upstream_unit_vector() -> Result<(), CryptoError> {
        let salt = Salt::from_qb64(UPSTREAM_QB64, SecurityTier::Low)?;
        let signer = salt.derive_signer("", KeyTransferability::Transferable)?;
        assert_eq!(
            signer.verifier().qb64()?,
            "DD28x2a4KCZ8f6OAcA856jAD1chNOo4pT8ICxyzJUJhj"
        );
        Ok(())
    }

    #[test]
    fn generation_uses_entropy_and_preserves_failure_source() -> Result<(), CryptoError> {
        let generated = Salt::generate(SecurityTier::Low)?;
        assert_eq!(generated.expose_qb64()?.len(), 24);

        let error = Salt::generate_with(SecurityTier::Low, |_| {
            Err(Box::new(std::io::Error::other("injected entropy failure")))
        })
        .err()
        .ok_or(CryptoError::KeyDerivationFailed {
            algorithm: "test",
            source: Box::new(std::io::Error::other("missing injected failure")),
        })?;
        assert!(matches!(error, CryptoError::EntropyUnavailable { .. }));
        assert!(error.source().is_some());
        Ok(())
    }

    #[test]
    fn zeroizing_profile_memory_type_remains_available() {
        let mut block = Block::default();
        block.zeroize();
    }

    #[test]
    fn allocation_and_primitive_failures_retain_typed_sources() -> Result<(), CryptoError> {
        let impossible_blocks = usize::MAX / Block::SIZE;
        let allocation = allocate_memory(impossible_blocks)
            .err()
            .ok_or(CryptoError::KeyDerivationFailed {
                algorithm: "test",
                source: Box::new(std::io::Error::other("impossible allocation succeeded")),
            })?;
        assert!(matches!(allocation, CryptoError::KeyDerivationMemoryUnavailable { .. }));
        assert!(allocation.source().is_some());

        let primitive = key_derivation_error(argon2id_p1::Error::OutputTooShort);
        assert!(matches!(primitive, CryptoError::KeyDerivationFailed { .. }));
        assert!(primitive.source().is_some());
        Ok(())
    }
}
