//! Typed X25519 encrypters and CESR-qualified ciphertext material.
//!
//! The pinned TypeScript `Cipher` supports the two fixed X25519 sealed-box ciphertext codes used
//! to wrap qualified signing seeds and salts. This module models those payload forms explicitly
//! and provides anonymous sealed-box encryption for a validated X25519 recipient key. Decryption
//! belongs to a later roadmap item.

use std::{fmt, str::FromStr};

use nacl_sealed_box::{PublicKey as X25519PublicKey, seal_with_rng};
use rand_core::{TryCryptoRng, TryRng};
use signify_cesr::{
    CesrError,
    code::DerivationCode,
    matter::{ParsedMaterial, QualifiedMaterial},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    CryptoError,
    salt::Salt,
    signer::Signer,
    verifier::{KeyTransferability, VerificationKey},
};

/// Raw byte width of an X25519 public encryption key.
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

const SEALED_BOX_ALGORITHM: &str = "X25519/XSalsa20-Poly1305 sealed box";

/// Raw byte width of ciphertext wrapping a 44-character qualified signing seed.
pub const SEED_CIPHERTEXT_RAW_SIZE: usize = 92;

/// Raw byte width of ciphertext wrapping a 24-character qualified salt.
pub const SALT_CIPHERTEXT_RAW_SIZE: usize = 72;

/// The qualified plaintext form carried by a supported ciphertext.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum CiphertextKind {
    /// An X25519 sealed-box ciphertext wrapping qualified signing-seed material (`P`).
    QualifiedSeed,
    /// An X25519 sealed-box ciphertext wrapping qualified salt material (`1AAH`).
    QualifiedSalt,
}

impl CiphertextKind {
    /// Returns the CESR derivation code for this ciphertext form.
    #[must_use]
    pub const fn code(self) -> DerivationCode {
        match self {
            Self::QualifiedSeed => DerivationCode::X25519_CIPHER_SEED,
            Self::QualifiedSalt => DerivationCode::X25519_CIPHER_SALT,
        }
    }

    /// Returns the exact raw ciphertext width selected by this form.
    #[must_use]
    pub const fn raw_size(self) -> usize {
        match self {
            Self::QualifiedSeed => SEED_CIPHERTEXT_RAW_SIZE,
            Self::QualifiedSalt => SALT_CIPHERTEXT_RAW_SIZE,
        }
    }
}

impl TryFrom<DerivationCode> for CiphertextKind {
    type Error = CryptoError;

    fn try_from(code: DerivationCode) -> Result<Self, Self::Error> {
        match code {
            DerivationCode::X25519_CIPHER_SEED => Ok(Self::QualifiedSeed),
            DerivationCode::X25519_CIPHER_SALT => Ok(Self::QualifiedSalt),
            other => Err(CryptoError::InvalidCiphertextCode { code: other.as_str() }),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
enum CiphertextBytes {
    QualifiedSeed([u8; SEED_CIPHERTEXT_RAW_SIZE]),
    QualifiedSalt([u8; SALT_CIPHERTEXT_RAW_SIZE]),
}

impl CiphertextBytes {
    const fn as_slice(&self) -> &[u8] {
        match self {
            Self::QualifiedSeed(raw) => raw,
            Self::QualifiedSalt(raw) => raw,
        }
    }
}

/// One immutable, CESR-qualified ciphertext.
///
/// Construction validates the ciphertext kind and exact raw width. Encoded constructors enforce
/// canonical CESR spelling and whole-input consumption, while prefix parsers report the boundary
/// of one ciphertext in a stream. Ciphertext is non-secret public transport material and may be
/// cloned, but debug output omits its bytes because it normally carries encrypted secrets.
///
/// ```
/// use signify_crypto::cipher::{Ciphertext, CiphertextKind, SALT_CIPHERTEXT_RAW_SIZE};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let ciphertext = Ciphertext::from_raw(
///     CiphertextKind::QualifiedSalt,
///     &[0_u8; SALT_CIPHERTEXT_RAW_SIZE],
/// )?;
/// assert_eq!(ciphertext.kind(), CiphertextKind::QualifiedSalt);
/// assert_eq!(Ciphertext::from_qb64(&ciphertext.qb64()?)?, ciphertext);
/// # Ok(())
/// # }
/// ```
///
/// Invalid ciphertext state cannot be assembled directly:
///
/// ```compile_fail
/// use signify_crypto::cipher::{Ciphertext, CiphertextKind};
///
/// let invalid = Ciphertext {
///     kind: CiphertextKind::QualifiedSeed,
///     raw: vec![0_u8; 3],
/// };
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct Ciphertext {
    kind: CiphertextKind,
    raw: CiphertextBytes,
}

/// One ciphertext parsed from the front of a raw, qb64, or qb2 stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedCiphertext {
    ciphertext: Ciphertext,
    consumed: usize,
}

/// One immutable X25519 public key for anonymous sealed-box encryption.
///
/// Raw construction rejects non-contributory X25519 points. An Ed25519 verification key can be
/// converted through its Edwards point, matching libsodium and the pinned TypeScript reference.
/// Encryption accepts typed salts or strictly validated qualified Ed25519 seeds and returns a
/// [`Ciphertext`] whose CESR code records the plaintext kind.
///
/// ```
/// use signify_crypto::{
///     cipher::{CiphertextKind, Encrypter},
///     signer::Signer,
///     verifier::KeyTransferability,
/// };
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let signer = Signer::from_seed(&[7_u8; 32], KeyTransferability::Transferable)?;
/// let encrypter = Encrypter::from_verification_key(signer.verifier())?;
/// let seed = b"AAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";
/// let ciphertext = encrypter.encrypt_seed_qb64(seed)?;
/// assert_eq!(ciphertext.kind(), CiphertextKind::QualifiedSeed);
/// # Ok(())
/// # }
/// ```
///
/// Plaintext kind cannot be omitted or selected with a boolean/string mode:
///
/// ```compile_fail
/// use signify_crypto::cipher::Encrypter;
///
/// # fn demo(encrypter: &Encrypter) {
/// let ciphertext = encrypter.encrypt();
/// # }
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct Encrypter {
    raw: [u8; X25519_PUBLIC_KEY_SIZE],
    key: X25519PublicKey,
}

/// One X25519 encrypter parsed from the front of a raw, qb64, or qb2 stream.
#[derive(Clone, Eq, PartialEq)]
pub struct ParsedEncrypter {
    encrypter: Encrypter,
    consumed: usize,
}

impl ParsedEncrypter {
    /// Returns the parsed encrypter.
    #[must_use]
    pub const fn encrypter(&self) -> &Encrypter {
        &self.encrypter
    }

    /// Returns the number of input bytes or characters consumed.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Separates the encrypter from its consumed input length.
    #[must_use]
    pub fn into_parts(self) -> (Encrypter, usize) {
        (self.encrypter, self.consumed)
    }
}

impl Encrypter {
    /// Constructs one encrypter from exactly 32 raw X25519 public-key bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed size error for the wrong width or
    /// [`CryptoError::InvalidEncryptionKey`] for a non-contributory public key.
    pub fn from_raw(input: &[u8]) -> Result<Self, CryptoError> {
        let parsed = Self::parse_raw_prefix(input)?;
        reject_trailing("X25519 public encryption key", input.len(), parsed.consumed)?;
        Ok(parsed.encrypter)
    }

    /// Parses one fixed-width X25519 public key from the beginning of a raw byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed truncation, CESR-size, or invalid-key error.
    pub fn parse_raw_prefix(input: &[u8]) -> Result<ParsedEncrypter, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_raw_prefix(
            DerivationCode::X25519_PUBLIC,
            input,
            X25519_PUBLIC_KEY_SIZE,
        )?)
    }

    /// Converts an Ed25519 public verification key to X25519.
    ///
    /// Transferability does not affect the conversion because both Ed25519 verifier codes carry
    /// the same point format.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::UnsupportedEncryptionKey`] for a P-256 verifier or
    /// [`CryptoError::InvalidEncryptionKey`] if conversion yields a non-contributory point.
    pub fn from_verification_key(verifier: &VerificationKey) -> Result<Self, CryptoError> {
        Self::from_raw(&verifier.x25519_public_bytes()?)
    }

    /// Parses one canonical qb64 X25519 public key from the beginning of `input`.
    ///
    /// # Errors
    ///
    /// Returns a typed CESR, code, or invalid-key error.
    pub fn parse_qb64(input: &str) -> Result<ParsedEncrypter, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb64(input)?)
    }

    /// Parses exactly one canonical qb64 X25519 public key.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64`] and rejects trailing characters.
    pub fn from_qb64(input: &str) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb64(input)?;
        reject_trailing(
            "X25519 public encryption key qualified Base64",
            input.len(),
            parsed.consumed,
        )?;
        Ok(parsed.encrypter)
    }

    /// Parses one UTF-8 qb64 X25519 public key from the beginning of a byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed UTF-8, CESR, code, or invalid-key error.
    pub fn parse_qb64_bytes(input: &[u8]) -> Result<ParsedEncrypter, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb64_bytes(input)?)
    }

    /// Parses exactly one UTF-8 qb64 X25519 public key from bytes.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64_bytes`] and rejects trailing bytes.
    pub fn from_qb64_bytes(input: &[u8]) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb64_bytes(input)?;
        reject_trailing(
            "X25519 public encryption key qualified Base64 bytes",
            input.len(),
            parsed.consumed,
        )?;
        Ok(parsed.encrypter)
    }

    /// Parses one canonical qualified-binary X25519 public key from an input prefix.
    ///
    /// # Errors
    ///
    /// Returns a typed CESR, code, or invalid-key error.
    pub fn parse_qb2(input: &[u8]) -> Result<ParsedEncrypter, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb2(input)?)
    }

    /// Parses exactly one canonical qualified-binary X25519 public key.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb2`] and rejects trailing bytes.
    pub fn from_qb2(input: &[u8]) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb2(input)?;
        reject_trailing(
            "X25519 public encryption key qualified binary",
            input.len(),
            parsed.consumed,
        )?;
        Ok(parsed.encrypter)
    }

    /// Returns the X25519 public-key derivation code (`C`).
    #[must_use]
    pub const fn code(&self) -> DerivationCode {
        DerivationCode::X25519_PUBLIC
    }

    /// Returns the exact public X25519 key bytes.
    #[must_use]
    pub const fn raw(&self) -> &[u8; X25519_PUBLIC_KEY_SIZE] {
        &self.raw
    }

    /// Encodes the public key as canonical qualified Base64.
    ///
    /// # Errors
    ///
    /// Returns a typed error if the shared fixed-code table is internally inconsistent.
    pub fn qb64(&self) -> Result<String, CryptoError> {
        Ok(self.material()?.qb64()?)
    }

    /// Encodes the public key as UTF-8 qualified-Base64 bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed error if the shared fixed-code table is internally inconsistent.
    pub fn qb64_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.material()?.qb64_bytes()?)
    }

    /// Encodes the public key as canonical qualified binary.
    ///
    /// # Errors
    ///
    /// Returns a typed error if the shared fixed-code table is internally inconsistent.
    pub fn qb2(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.material()?.qb2()?)
    }

    /// Checks whether a canonical qualified Ed25519 seed derives this encryption key.
    ///
    /// The public-key comparison is constant-time. The caller retains responsibility for clearing
    /// its seed input after use.
    ///
    /// # Errors
    ///
    /// Returns a typed CESR or signing-seed error for malformed, noncanonical, or wrong-code input.
    pub fn matches_seed_qb64(&self, seed_qb64: &[u8]) -> Result<bool, CryptoError> {
        let signer = Signer::from_qb64_bytes(seed_qb64, KeyTransferability::Transferable)?;
        let candidate = Self::from_verification_key(signer.verifier())?;
        Ok(bool::from(self.raw.ct_eq(&candidate.raw)))
    }

    /// Encrypts one canonical qualified Ed25519 seed in a libsodium-compatible sealed box.
    ///
    /// Each call obtains a fresh ephemeral secret from the operating-system CSPRNG. The caller
    /// retains responsibility for clearing its seed input after use.
    ///
    /// # Errors
    ///
    /// Returns a typed seed-validation, entropy, primitive, or ciphertext-construction error.
    pub fn encrypt_seed_qb64(&self, seed_qb64: &[u8]) -> Result<Ciphertext, CryptoError> {
        let _validated = Signer::from_qb64_bytes(seed_qb64, KeyTransferability::Transferable)?;
        self.encrypt(CiphertextKind::QualifiedSeed, seed_qb64)
    }

    /// Encrypts one validated 128-bit salt in a libsodium-compatible sealed box.
    ///
    /// Each call obtains a fresh ephemeral secret from the operating-system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns a typed CESR-encoding, entropy, primitive, or ciphertext-construction error.
    pub fn encrypt_salt(&self, salt: &Salt) -> Result<Ciphertext, CryptoError> {
        let plaintext = salt.expose_qb64_bytes()?;
        self.encrypt(CiphertextKind::QualifiedSalt, plaintext.as_ref())
    }

    fn encrypt(&self, kind: CiphertextKind, plaintext: &[u8]) -> Result<Ciphertext, CryptoError> {
        let mut entropy = Zeroizing::new([0_u8; X25519_PUBLIC_KEY_SIZE]);
        getrandom::fill(&mut *entropy).map_err(|source| CryptoError::EntropyUnavailable {
            source: Box::new(source),
        })?;
        self.encrypt_with_ephemeral_secret(kind, plaintext, entropy)
    }

    fn encrypt_with_ephemeral_secret(
        &self,
        kind: CiphertextKind,
        plaintext: &[u8],
        ephemeral_secret: Zeroizing<[u8; X25519_PUBLIC_KEY_SIZE]>,
    ) -> Result<Ciphertext, CryptoError> {
        let mut entropy = FixedEntropy::new(ephemeral_secret);
        let raw =
            seal_with_rng(&mut entropy, &self.key, plaintext).map_err(|source| CryptoError::EncryptionFailed {
                algorithm: SEALED_BOX_ALGORITHM,
                source: Box::new(source),
            })?;
        Ciphertext::from_raw(kind, &raw)
    }

    fn material(&self) -> Result<QualifiedMaterial, CryptoError> {
        Ok(QualifiedMaterial::new(self.code(), &self.raw)?)
    }

    fn from_parsed_material(parsed: ParsedMaterial) -> Result<ParsedEncrypter, CryptoError> {
        let (material, consumed) = parsed.into_parts();
        if material.code() != DerivationCode::X25519_PUBLIC {
            return Err(CryptoError::InvalidEncrypterCode {
                code: material.code().as_str(),
            });
        }
        let raw = <[u8; X25519_PUBLIC_KEY_SIZE]>::try_from(material.raw())
            .map_err(|_| CryptoError::InvalidEncryptionKey { algorithm: "X25519" })?;
        // `PublicKey::from_bytes` rejects non-contributory keys, so no separate scalar probe is
        // needed here.
        let key =
            X25519PublicKey::from_bytes(raw).map_err(|_| CryptoError::InvalidEncryptionKey { algorithm: "X25519" })?;
        Ok(ParsedEncrypter {
            encrypter: Self { raw, key },
            consumed,
        })
    }
}

impl fmt::Debug for Encrypter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Encrypter")
            .field("algorithm", &"X25519")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ParsedEncrypter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedEncrypter")
            .field("encrypter", &self.encrypter)
            .field("consumed", &self.consumed)
            .finish()
    }
}

impl TryFrom<&str> for Encrypter {
    type Error = CryptoError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Self::from_qb64(input)
    }
}

impl FromStr for Encrypter {
    type Err = CryptoError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_qb64(input)
    }
}

impl fmt::Display for Encrypter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.qb64()
            .map_err(|_| fmt::Error)
            .and_then(|qb64| formatter.write_str(&qb64))
    }
}

struct FixedEntropy {
    bytes: Zeroizing<[u8; X25519_PUBLIC_KEY_SIZE]>,
}

impl FixedEntropy {
    fn new(bytes: Zeroizing<[u8; X25519_PUBLIC_KEY_SIZE]>) -> Self {
        Self { bytes }
    }

    fn fill(&self, destination: &mut [u8]) {
        for (output, source) in destination.iter_mut().zip(self.bytes.iter().cycle()) {
            *output = *source;
        }
    }
}

impl TryRng for FixedEntropy {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0_u8; 4];
        self.fill(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0_u8; 8];
        self.fill(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.fill(destination);
        Ok(())
    }
}

impl TryCryptoRng for FixedEntropy {}

impl fmt::Debug for Ciphertext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ciphertext")
            .field("kind", &self.kind)
            .field("raw_length", &self.raw().len())
            .finish_non_exhaustive()
    }
}

impl ParsedCiphertext {
    /// Returns the parsed ciphertext.
    #[must_use]
    pub const fn ciphertext(&self) -> &Ciphertext {
        &self.ciphertext
    }

    /// Returns the number of input bytes or characters consumed.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Separates the ciphertext from its consumed input length.
    #[must_use]
    pub fn into_parts(self) -> (Ciphertext, usize) {
        (self.ciphertext, self.consumed)
    }
}

impl Ciphertext {
    /// Constructs a ciphertext from exactly one raw value of the selected kind.
    ///
    /// # Errors
    ///
    /// Returns a typed truncation error for short input and a trailing-material error for long
    /// input.
    pub fn from_raw(kind: CiphertextKind, input: &[u8]) -> Result<Self, CryptoError> {
        let parsed = Self::parse_raw_prefix(kind, input)?;
        reject_trailing("ciphertext raw material", input.len(), parsed.consumed)?;
        Ok(parsed.ciphertext)
    }

    /// Infers the ciphertext kind from an exact supported raw width.
    ///
    /// This safely replaces the pinned constructor's raw-length inference, which accidentally
    /// classifies a 92-byte seed ciphertext as a salt ciphertext and truncates it.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidCiphertextLength`] unless `input` is exactly 72 or 92 bytes.
    pub fn infer_from_raw(input: &[u8]) -> Result<Self, CryptoError> {
        let kind = match input.len() {
            SEED_CIPHERTEXT_RAW_SIZE => CiphertextKind::QualifiedSeed,
            SALT_CIPHERTEXT_RAW_SIZE => CiphertextKind::QualifiedSalt,
            actual => return Err(CryptoError::InvalidCiphertextLength { actual }),
        };
        Self::from_raw(kind, input)
    }

    /// Parses one ciphertext of `kind` from the beginning of a raw byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed truncation or CESR size error.
    pub fn parse_raw_prefix(kind: CiphertextKind, input: &[u8]) -> Result<ParsedCiphertext, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_raw_prefix(
            kind.code(),
            input,
            kind.raw_size(),
        )?)
    }

    /// Parses one canonical qb64 ciphertext from the beginning of `input`.
    ///
    /// # Errors
    ///
    /// Returns a typed material error and rejects every derivation code other than `P` and `1AAH`.
    pub fn parse_qb64(input: &str) -> Result<ParsedCiphertext, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb64(input)?)
    }

    /// Parses exactly one canonical qb64 ciphertext.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64`] and rejects trailing characters.
    pub fn from_qb64(input: &str) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb64(input)?;
        reject_trailing("ciphertext qualified Base64", input.len(), parsed.consumed)?;
        Ok(parsed.ciphertext)
    }

    /// Parses one UTF-8 qb64 ciphertext from the beginning of a byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed UTF-8, CESR, or ciphertext-code error.
    pub fn parse_qb64_bytes(input: &[u8]) -> Result<ParsedCiphertext, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb64_bytes(input)?)
    }

    /// Parses exactly one UTF-8 qb64 ciphertext from bytes.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64_bytes`] and rejects trailing bytes.
    pub fn from_qb64_bytes(input: &[u8]) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb64_bytes(input)?;
        reject_trailing("ciphertext qualified Base64 bytes", input.len(), parsed.consumed)?;
        Ok(parsed.ciphertext)
    }

    /// Parses one canonical qualified-binary (`qb2`) ciphertext from the beginning of `input`.
    ///
    /// # Errors
    ///
    /// Returns a typed material error and rejects every derivation code other than `P` and `1AAH`.
    pub fn parse_qb2(input: &[u8]) -> Result<ParsedCiphertext, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb2(input)?)
    }

    /// Parses exactly one canonical qualified-binary (`qb2`) ciphertext.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb2`] and rejects trailing bytes.
    pub fn from_qb2(input: &[u8]) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb2(input)?;
        reject_trailing("ciphertext qualified binary", input.len(), parsed.consumed)?;
        Ok(parsed.ciphertext)
    }

    /// Returns the qualified plaintext form carried by this ciphertext.
    #[must_use]
    pub const fn kind(&self) -> CiphertextKind {
        self.kind
    }

    /// Returns the ciphertext's CESR derivation code.
    #[must_use]
    pub const fn code(&self) -> DerivationCode {
        self.kind.code()
    }

    /// Returns the exact raw ciphertext bytes.
    #[must_use]
    pub const fn raw(&self) -> &[u8] {
        self.raw.as_slice()
    }

    /// Encodes the ciphertext as canonical qualified Base64 (`qb64`).
    ///
    /// # Errors
    ///
    /// Returns a typed error if the shared fixed-code table is internally inconsistent.
    pub fn qb64(&self) -> Result<String, CryptoError> {
        Ok(self.material()?.qb64()?)
    }

    /// Encodes the ciphertext as UTF-8 qualified-Base64 bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed error if the shared fixed-code table is internally inconsistent.
    pub fn qb64_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.material()?.qb64_bytes()?)
    }

    /// Encodes the ciphertext as canonical qualified binary (`qb2`).
    ///
    /// # Errors
    ///
    /// Returns a typed error if the shared fixed-code table is internally inconsistent.
    pub fn qb2(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.material()?.qb2()?)
    }

    fn material(&self) -> Result<QualifiedMaterial, CryptoError> {
        Ok(QualifiedMaterial::new(self.code(), self.raw())?)
    }

    fn from_parsed_material(parsed: ParsedMaterial) -> Result<ParsedCiphertext, CryptoError> {
        let (material, consumed) = parsed.into_parts();
        let kind = CiphertextKind::try_from(material.code())?;
        let raw = match kind {
            CiphertextKind::QualifiedSeed => CiphertextBytes::QualifiedSeed(
                <[u8; SEED_CIPHERTEXT_RAW_SIZE]>::try_from(material.raw()).map_err(|_| {
                    CryptoError::from(CesrError::RawSizeMismatch {
                        context: "seed ciphertext raw material",
                        expected: SEED_CIPHERTEXT_RAW_SIZE,
                        actual: material.raw().len(),
                    })
                })?,
            ),
            CiphertextKind::QualifiedSalt => CiphertextBytes::QualifiedSalt(
                <[u8; SALT_CIPHERTEXT_RAW_SIZE]>::try_from(material.raw()).map_err(|_| {
                    CryptoError::from(CesrError::RawSizeMismatch {
                        context: "salt ciphertext raw material",
                        expected: SALT_CIPHERTEXT_RAW_SIZE,
                        actual: material.raw().len(),
                    })
                })?,
            ),
        };
        Ok(ParsedCiphertext {
            ciphertext: Self { kind, raw },
            consumed,
        })
    }
}

impl TryFrom<&[u8]> for Ciphertext {
    type Error = CryptoError;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        Self::infer_from_raw(input)
    }
}

impl TryFrom<&str> for Ciphertext {
    type Error = CryptoError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Self::from_qb64(input)
    }
}

impl FromStr for Ciphertext {
    type Err = CryptoError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_qb64(input)
    }
}

impl fmt::Display for Ciphertext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.qb64()
            .map_err(|_| fmt::Error)
            .and_then(|qb64| formatter.write_str(&qb64))
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
    use crate::{salt::SecurityTier, verifier::VerificationKey};

    const SEED_QB64: &str = "PM9jOGWNYfjM_oLXJNaQ8UlFSAV5ACjsUY7J16xfzrlpc9Ve3A5WYrZ4o_NHtP5lhp78Usspl9fyFdnCdItNd5JyqZ6dt8SXOt6TOqOCs-gy0obrwFkPPqBvVkEw";
    const SALT_QB64: &str =
        "1AAHjlR2QR9J5Et67Wy-ZaVdTryN6T6ohg44r73GLRPnHw-5S3ABFkhWyIwLOI6TXUB_5CT13S8JvknxLxBaF8ANPK9FSOPD8tYu";
    const CRYPT_SEED: [u8; 32] = [
        104, 44, 35, 124, 138, 112, 34, 18, 196, 51, 116, 50, 166, 225, 24, 25, 240, 102, 50, 44, 121, 196, 194, 49,
        64, 245, 64, 21, 46, 162, 26, 207,
    ];
    const REFERENCE_ENCRYPTER_QB64: &str = "CAF7Wr3XNq5hArcOuBJzaY6Nd23jgtUVI6KDfb3VngkR";
    const REFERENCE_SEED_QB64: &str = "ABg7MMQPKnZG-uOiRWVlH5ZvzilHheNYhtoE8NzeBsAr";
    const REFERENCE_SALT_RAW: [u8; 16] = [54, 8, 100, 13, 161, 187, 57, 141, 112, 141, 160, 192, 19, 74, 135, 114];
    const P256_QB64: &str = "1AAJA-blKBTkTkEEOX_Yq3i3KxZJvcHarPfu_crKVwcfEwvQ";

    #[test]
    fn reference_verifier_conversion_and_seed_matching_are_exact() -> Result<(), CryptoError> {
        let signer = Signer::from_seed(&CRYPT_SEED, KeyTransferability::Transferable)?;
        let encrypter = Encrypter::from_verification_key(signer.verifier())?;
        assert_eq!(encrypter.code(), DerivationCode::X25519_PUBLIC);
        assert_eq!(encrypter.qb64()?, REFERENCE_ENCRYPTER_QB64);
        assert!(
            encrypter
                .matches_seed_qb64(&QualifiedMaterial::new(DerivationCode::ED25519_SEED, &CRYPT_SEED)?.qb64_bytes()?)?
        );
        assert!(!encrypter.matches_seed_qb64(REFERENCE_SEED_QB64.as_bytes())?);

        let parsed = Encrypter::from_qb64(REFERENCE_ENCRYPTER_QB64)?;
        assert_eq!(parsed, encrypter);
        assert_eq!(Encrypter::from_qb64_bytes(&parsed.qb64_bytes()?)?, parsed);
        assert_eq!(Encrypter::from_qb2(&parsed.qb2()?)?, parsed);
        assert_eq!(parsed.to_string(), REFERENCE_ENCRYPTER_QB64);
        Ok(())
    }

    #[test]
    fn encrypter_stream_parsers_preserve_boundaries() -> Result<(), CryptoError> {
        let encrypter = Encrypter::from_qb64(REFERENCE_ENCRYPTER_QB64)?;
        let text_stream = format!("{REFERENCE_ENCRYPTER_QB64}ABCD");
        let parsed_text = Encrypter::parse_qb64(&text_stream)?;
        assert_eq!(parsed_text.encrypter(), &encrypter);
        assert_eq!(parsed_text.consumed(), REFERENCE_ENCRYPTER_QB64.len());
        assert!(Encrypter::from_qb64(&text_stream).is_err());

        let mut raw_stream = encrypter.raw().to_vec();
        raw_stream.extend_from_slice(&[1, 2, 3]);
        let parsed_raw = Encrypter::parse_raw_prefix(&raw_stream)?;
        assert_eq!(parsed_raw.into_parts(), (encrypter.clone(), X25519_PUBLIC_KEY_SIZE));
        assert!(Encrypter::from_raw(&raw_stream).is_err());

        let mut qb2_stream = encrypter.qb2()?;
        let qb2_length = qb2_stream.len();
        qb2_stream.extend_from_slice(&[1, 2, 3]);
        assert_eq!(Encrypter::parse_qb2(&qb2_stream)?.into_parts(), (encrypter, qb2_length));
        assert!(Encrypter::from_qb2(&qb2_stream).is_err());
        Ok(())
    }

    #[test]
    fn invalid_and_unsupported_encryption_keys_are_rejected() -> Result<(), CryptoError> {
        assert!(matches!(
            Encrypter::from_raw(&[0_u8; X25519_PUBLIC_KEY_SIZE]),
            Err(CryptoError::InvalidEncryptionKey { algorithm: "X25519" })
        ));
        assert!(Encrypter::from_raw(&[1_u8; X25519_PUBLIC_KEY_SIZE - 1]).is_err());
        assert!(matches!(
            Encrypter::from_verification_key(&VerificationKey::from_qb64(P256_QB64)?),
            Err(CryptoError::UnsupportedEncryptionKey {
                algorithm: "P-256 ECDSA/SHA-256"
            })
        ));
        let digest = QualifiedMaterial::new(DerivationCode::BLAKE3_256, &[9_u8; 32])?;
        assert!(matches!(
            Encrypter::from_qb64(&digest.qb64()?),
            Err(CryptoError::InvalidEncrypterCode { code: "E" })
        ));
        let encrypter = Encrypter::from_qb64(REFERENCE_ENCRYPTER_QB64)?;
        assert!(matches!(
            encrypter.matches_seed_qb64(&digest.qb64_bytes()?),
            Err(CryptoError::InvalidSigningCode { code: "E" })
        ));
        Ok(())
    }

    #[test]
    fn fixed_ephemeral_vectors_have_exact_ciphertext() -> Result<(), CryptoError> {
        let encrypter = Encrypter::from_qb64(REFERENCE_ENCRYPTER_QB64)?;
        let seed_ciphertext = encrypter.encrypt_with_ephemeral_secret(
            CiphertextKind::QualifiedSeed,
            REFERENCE_SEED_QB64.as_bytes(),
            Zeroizing::new([7_u8; X25519_PUBLIC_KEY_SIZE]),
        )?;
        assert_eq!(
            seed_ciphertext.qb64()?,
            "PBO-T-rq8gTH_TNY_JwAchiB0XQngSgifsZ0839_6XttzG8cehOC0KYRK_IJh20mnNHMu9QmTEFdMSV-VY13PwMUlyZnoE3_0x-sip0x_7K5J9JfzbLXFBvu7eqQ"
        );

        let salt = Salt::from_raw(&REFERENCE_SALT_RAW, SecurityTier::Low)?;
        let salt_qb64 = salt.expose_qb64_bytes()?;
        let salt_ciphertext = encrypter.encrypt_with_ephemeral_secret(
            CiphertextKind::QualifiedSalt,
            salt_qb64.as_ref(),
            Zeroizing::new([8_u8; X25519_PUBLIC_KEY_SIZE]),
        )?;
        assert_eq!(
            salt_ciphertext.qb64()?,
            "1AAHMdSras7slhE3kXA3k25gcW-sVzr-lNnahKgCBEjfwRKrWrKDCDCEa3V8DhzqI1blWMiIGpY432PbGS__nGpEj-rZ5HMqrVls"
        );
        Ok(())
    }

    #[test]
    fn public_encryption_validates_plaintext_and_selects_exact_codes() -> Result<(), CryptoError> {
        let encrypter = Encrypter::from_qb64(REFERENCE_ENCRYPTER_QB64)?;
        let seed_ciphertext = encrypter.encrypt_seed_qb64(REFERENCE_SEED_QB64.as_bytes())?;
        assert_eq!(seed_ciphertext.kind(), CiphertextKind::QualifiedSeed);
        assert_eq!(seed_ciphertext.raw().len(), SEED_CIPHERTEXT_RAW_SIZE);
        assert!(encrypter.encrypt_seed_qb64(b"").is_err());

        let salt = Salt::from_raw(&REFERENCE_SALT_RAW, SecurityTier::Low)?;
        let salt_ciphertext = encrypter.encrypt_salt(&salt)?;
        assert_eq!(salt_ciphertext.kind(), CiphertextKind::QualifiedSalt);
        assert_eq!(salt_ciphertext.raw().len(), SALT_CIPHERTEXT_RAW_SIZE);
        Ok(())
    }

    #[test]
    fn encrypter_debug_omits_public_key_bytes() -> Result<(), CryptoError> {
        let encrypter = Encrypter::from_qb64(REFERENCE_ENCRYPTER_QB64)?;
        let debug = format!("{encrypter:?}");
        assert!(debug.contains("X25519"));
        assert!(!debug.contains("CAF7Wr3"));
        assert!(!debug.contains("123"));
        Ok(())
    }

    #[test]
    fn reference_ciphertexts_parse_and_display() -> Result<(), CryptoError> {
        let seed = Ciphertext::from_qb64(SEED_QB64)?;
        assert_eq!(seed.kind(), CiphertextKind::QualifiedSeed);
        assert_eq!(seed.code(), DerivationCode::X25519_CIPHER_SEED);
        assert_eq!(seed.raw().len(), SEED_CIPHERTEXT_RAW_SIZE);
        assert_eq!(seed.to_string(), SEED_QB64);

        let salt = Ciphertext::from_qb64(SALT_QB64)?;
        assert_eq!(salt.kind(), CiphertextKind::QualifiedSalt);
        assert_eq!(salt.code(), DerivationCode::X25519_CIPHER_SALT);
        assert_eq!(salt.raw().len(), SALT_CIPHERTEXT_RAW_SIZE);
        assert_eq!(salt.to_string(), SALT_QB64);
        Ok(())
    }

    #[test]
    fn raw_and_encoded_domains_round_trip_with_stream_boundaries() -> Result<(), CryptoError> {
        for qb64 in [SEED_QB64, SALT_QB64] {
            let ciphertext = Ciphertext::from_qb64(qb64)?;
            assert_eq!(Ciphertext::from_raw(ciphertext.kind(), ciphertext.raw())?, ciphertext);
            assert_eq!(Ciphertext::infer_from_raw(ciphertext.raw())?, ciphertext);
            assert_eq!(Ciphertext::try_from(ciphertext.raw())?, ciphertext);
            assert_eq!(Ciphertext::try_from(qb64)?, ciphertext);
            assert_eq!(qb64.parse::<Ciphertext>()?, ciphertext);
            assert_eq!(Ciphertext::from_qb64_bytes(&ciphertext.qb64_bytes()?)?, ciphertext);
            assert_eq!(Ciphertext::from_qb2(&ciphertext.qb2()?)?, ciphertext);

            let text_stream = format!("{qb64}ABCD");
            let parsed_text = Ciphertext::parse_qb64(&text_stream)?;
            assert_eq!(parsed_text.ciphertext(), &ciphertext);
            assert_eq!(parsed_text.consumed(), qb64.len());
            assert!(Ciphertext::from_qb64(&text_stream).is_err());

            let mut raw_stream = ciphertext.raw().to_vec();
            raw_stream.extend_from_slice(&[1, 2, 3]);
            let parsed_raw = Ciphertext::parse_raw_prefix(ciphertext.kind(), &raw_stream)?;
            assert_eq!(parsed_raw.into_parts(), (ciphertext.clone(), ciphertext.raw().len()));
            assert!(Ciphertext::from_raw(ciphertext.kind(), &raw_stream).is_err());

            let mut binary_stream = ciphertext.qb2()?;
            let binary_length = binary_stream.len();
            binary_stream.extend_from_slice(&[1, 2, 3]);
            let parsed_binary = Ciphertext::parse_qb2(&binary_stream)?;
            assert_eq!(parsed_binary.into_parts(), (ciphertext, binary_length));
            assert!(Ciphertext::from_qb2(&binary_stream).is_err());
        }
        Ok(())
    }

    #[test]
    fn raw_widths_are_strict_and_inference_is_safe() {
        for (kind, size) in [
            (CiphertextKind::QualifiedSeed, SEED_CIPHERTEXT_RAW_SIZE),
            (CiphertextKind::QualifiedSalt, SALT_CIPHERTEXT_RAW_SIZE),
        ] {
            assert!(matches!(
                Ciphertext::from_raw(kind, &vec![0_u8; size - 1]),
                Err(CryptoError::Cesr { source })
                    if matches!(source.as_ref(), CesrError::Truncated { .. })
            ));
            assert!(matches!(
                Ciphertext::from_raw(kind, &vec![0_u8; size + 1]),
                Err(CryptoError::Cesr { source })
                    if matches!(source.as_ref(), CesrError::TrailingMaterial { length: 1, .. })
            ));
        }
        assert!(matches!(
            Ciphertext::infer_from_raw(&[0_u8; 80]),
            Err(CryptoError::InvalidCiphertextLength { actual: 80 })
        ));
        assert!(matches!(
            Ciphertext::infer_from_raw(&[0_u8; SEED_CIPHERTEXT_RAW_SIZE]),
            Ok(ciphertext) if ciphertext.kind() == CiphertextKind::QualifiedSeed
        ));
    }

    #[test]
    fn ciphertext_code_validation_rejects_other_material() -> Result<(), CryptoError> {
        assert!(matches!(
            CiphertextKind::try_from(DerivationCode::BLAKE3_256),
            Err(CryptoError::InvalidCiphertextCode { code: "E" })
        ));
        let digest = QualifiedMaterial::new(DerivationCode::BLAKE3_256, &[0_u8; 32])?;
        assert!(matches!(
            Ciphertext::from_qb64(&digest.qb64()?),
            Err(CryptoError::InvalidCiphertextCode { code: "E" })
        ));
        assert!(matches!(
            Ciphertext::from_qb2(&digest.qb2()?),
            Err(CryptoError::InvalidCiphertextCode { code: "E" })
        ));
        Ok(())
    }

    #[test]
    fn debug_output_omits_ciphertext_bytes() -> Result<(), CryptoError> {
        let ciphertext = Ciphertext::from_raw(CiphertextKind::QualifiedSalt, &[0xab_u8; SALT_CIPHERTEXT_RAW_SIZE])?;
        let debug = format!("{ciphertext:?}");
        assert!(debug.contains("QualifiedSalt"));
        assert!(debug.contains("raw_length: 72"));
        assert!(!debug.contains("171"));
        assert!(!debug.contains("abab"));
        Ok(())
    }
}
