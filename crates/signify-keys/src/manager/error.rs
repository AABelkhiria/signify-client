//! Failures raised while creating, storing, rotating, and using managed keys.

use core::fmt;
use std::error::Error;

use keri_cesr::crypto::CryptoError;

use super::algorithm::KeyAlgorithm;

/// Stable key-management failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum ManagerError {
    /// A derivation path exceeds [`MAX_DERIVATION_PATH_BYTES`](super::MAX_DERIVATION_PATH_BYTES).
    DerivationPathTooLong {
        /// Accepted maximum in bytes.
        maximum: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// A derivation stem exceeds [`MAX_STEM_BYTES`](super::MAX_STEM_BYTES).
    StemTooLong {
        /// Accepted maximum in bytes.
        maximum: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// A key count exceeds [`MAX_KEYS_PER_SET`](super::MAX_KEYS_PER_SET).
    ///
    /// Every key in a set costs one Argon2 derivation at the configured memory cost, so an
    /// unbounded count is a denial-of-service lever for whatever chooses it.
    TooManyKeys {
        /// Accepted maximum.
        maximum: usize,
        /// Requested count.
        requested: usize,
    },
    /// A key index would overflow.
    ///
    /// Prefix, rotation, and key indices are written into a derivation path as hexadecimal and
    /// advance on every inception and rotation.
    IndexOverflow {
        /// Which index overflowed.
        index: &'static str,
    },
    /// An algorithm has no key creator.
    ///
    /// The reference's factory throws for the group and external algorithms, whose keys come from
    /// a group member or an external module rather than from a creator.
    UnsupportedAlgorithm {
        /// The algorithm asked for.
        algorithm: KeyAlgorithm,
    },
    /// A passcode is shorter than [`PASSCODE_LENGTH`](super::PASSCODE_LENGTH) characters.
    PasscodeTooShort {
        /// Required length.
        required: usize,
        /// Actual length.
        actual: usize,
    },
    /// A passcode holds a character outside the Base64 URL-safe alphabet.
    ///
    /// The passcode is prefixed with a salt code and parsed as qualified Base64, so a character
    /// outside the alphabet cannot produce a salt at all. The reference discovers this several
    /// calls later, as a parse failure with no mention of the passcode.
    InvalidPasscode {
        /// Offset of the first offending character.
        offset: usize,
    },
    /// An inception named no current keys.
    ///
    /// An identifier's prefix is derived from its first current key, so there has to be one. The
    /// reference reads position zero of an empty list and fails with a `TypeError`.
    NoCurrentKeys,
    /// A salty operation has no salt to derive from.
    MissingSalt,
    /// Randomly generated keys were requested without encryption to store them under.
    ///
    /// A randy key exists only in the store, so without an encrypter it would have to be held in
    /// the clear or lost. The reference refuses this too.
    RandomKeysNeedEncryption,
    /// The supplied seed does not belong to the supplied encryption identifier.
    SeedDoesNotMatchIdentifier,
    /// An identifier prefix already has managed keys.
    AlreadyIncepted {
        /// The prefix in question.
        prefix: String,
    },
    /// An identifier prefix has no managed keys.
    NotIncepted {
        /// The prefix in question.
        prefix: String,
    },
    /// An identifier prefix has no next keys committed, so it cannot rotate again.
    ///
    /// This is the abandoned state a rotation to zero next keys produces.
    Abandoned {
        /// The prefix in question.
        prefix: String,
    },
    /// A managed private key is missing from the store.
    MissingPrivateKey {
        /// Public key whose private half is absent.
        public_key: String,
    },
    /// A salty identifier stores an encrypted salt but the manager has no decrypter.
    SaltDecryptionUnavailable,
    /// A signing request named neither public keys nor verification keys.
    NoSigningKeysRequested,
    /// A signing request supplied a different number of placements than keys.
    PlacementCountMismatch {
        /// Placements supplied.
        placements: usize,
        /// Keys the request resolved to.
        keys: usize,
    },
    /// No external key-manager module is registered under a name.
    UnknownExternalModule {
        /// The module type the record named.
        module_type: String,
    },
    /// A group's local member is not among the group's current signing keys.
    ///
    /// The member cannot sign for the group, because the event it would sign gives its key no
    /// position.
    MemberNotInSigningKeys {
        /// The member's signing key.
        key: String,
    },
    /// A group's local member key was never committed to by the prior next digests.
    ///
    /// A rotation signature has to prove the key it signs with was precommitted; without a
    /// matching digest there is no position to point at.
    MemberNotPrecommitted {
        /// The member's signing key.
        key: String,
    },
    /// An identifier record carries no signing keys.
    NoSigningKeys {
        /// The identifier in question.
        prefix: String,
    },
    /// A keeper derived under the temporary profile cannot be written into a record.
    ///
    /// A KERIA identifier record stores a tier, not a cost profile, so a keeper built under the
    /// deliberately cheap temporary profile would reload under the production one and derive
    /// different keys. Such a keeper is ephemeral by construction.
    ProfileNotStorable,
    /// A derivation tier has no spelling in a KERIA identifier record.
    ///
    /// The record's tier field is a three-value enum; a tier outside it could not be written down
    /// and so could not be reloaded.
    UnsupportedTier,
    /// A digest code names an algorithm this port does not implement.
    UnsupportedDigest {
        /// The code the record carried.
        code: String,
    },
    /// A destination prefix already has managed keys.
    DestinationOccupied {
        /// The prefix in question.
        prefix: String,
    },
    /// A cryptographic operation failed.
    Crypto {
        /// Underlying failure.
        source: Box<CryptoError>,
    },
}

impl fmt::Display for ManagerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DerivationPathTooLong { maximum, actual } => {
                write!(formatter, "derivation path of {actual} bytes exceeds maximum {maximum}")
            }
            Self::StemTooLong { maximum, actual } => {
                write!(formatter, "derivation stem of {actual} bytes exceeds maximum {maximum}")
            }
            Self::TooManyKeys { maximum, requested } => {
                write!(formatter, "{requested} keys requested, more than the maximum {maximum}")
            }
            Self::IndexOverflow { index } => write!(formatter, "the {index} index would overflow"),
            Self::UnsupportedAlgorithm { algorithm } => {
                write!(formatter, "the {algorithm} algorithm has no key creator")
            }
            Self::PasscodeTooShort { required, actual } => {
                write!(
                    formatter,
                    "a passcode of {actual} characters is shorter than the required {required}"
                )
            }
            Self::InvalidPasscode { offset } => {
                write!(formatter, "a passcode holds an unusable character at offset {offset}")
            }
            Self::NoCurrentKeys => formatter.write_str("an inception named no current keys"),
            Self::MissingSalt => formatter.write_str("a salty operation has no salt to derive from"),
            Self::RandomKeysNeedEncryption => {
                formatter.write_str("randomly generated keys need encryption to be stored under")
            }
            Self::SeedDoesNotMatchIdentifier => {
                formatter.write_str("the seed does not belong to the encryption identifier")
            }
            Self::AlreadyIncepted { prefix } => write!(formatter, "{prefix} already has managed keys"),
            Self::NotIncepted { prefix } => write!(formatter, "{prefix} has no managed keys"),
            Self::Abandoned { prefix } => write!(formatter, "{prefix} has no next keys and cannot rotate"),
            Self::MissingPrivateKey { public_key } => {
                write!(formatter, "no private key is stored for {public_key}")
            }
            Self::SaltDecryptionUnavailable => {
                formatter.write_str("an identifier stores an encrypted salt but no seed was supplied")
            }
            Self::NoSigningKeysRequested => formatter.write_str("a signing request named no keys"),
            Self::PlacementCountMismatch { placements, keys } => write!(
                formatter,
                "{placements} signature placements were supplied for {keys} keys"
            ),
            Self::UnknownExternalModule { module_type } => {
                write!(
                    formatter,
                    "no external key-manager module is registered as {module_type}"
                )
            }
            Self::MemberNotInSigningKeys { key } => write!(
                formatter,
                "the group member key {key} is not among the group's current signing keys"
            ),
            Self::MemberNotPrecommitted { key } => write!(
                formatter,
                "the group member key {key} was not committed to by the prior next digests"
            ),
            Self::NoSigningKeys { prefix } => write!(formatter, "{prefix} carries no signing keys"),
            Self::ProfileNotStorable => {
                formatter.write_str("a keeper derived under the temporary profile cannot be stored")
            }
            Self::UnsupportedTier => formatter.write_str("a derivation tier has no spelling in an identifier record"),
            Self::UnsupportedDigest { code } => {
                write!(formatter, "the digest code {code} names an unsupported algorithm")
            }
            Self::DestinationOccupied { prefix } => {
                write!(
                    formatter,
                    "{prefix} already has managed keys and may not be overwritten"
                )
            }
            Self::Crypto { .. } => formatter.write_str("a cryptographic operation failed"),
        }
    }
}

impl Error for ManagerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Crypto { source } => Some(source.as_ref()),
            _ => None,
        }
    }
}

impl From<CryptoError> for ManagerError {
    fn from(source: CryptoError) -> Self {
        Self::Crypto {
            source: Box::new(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_carry_readable_text_and_preserve_their_source() -> Result<(), Box<dyn Error>> {
        let crypto = ManagerError::from(
            keri_cesr::crypto::signer::Signer::from_seed(
                &[],
                keri_cesr::crypto::verifier::KeyTransferability::Transferable,
            )
            .err()
            .ok_or("an empty seed must not build a signer")?,
        );
        assert!(crypto.source().is_some());

        for error in [
            ManagerError::DerivationPathTooLong { maximum: 8, actual: 9 },
            ManagerError::StemTooLong { maximum: 8, actual: 9 },
            ManagerError::TooManyKeys {
                maximum: 8,
                requested: 9,
            },
            ManagerError::IndexOverflow { index: "rotation" },
            ManagerError::UnsupportedAlgorithm {
                algorithm: KeyAlgorithm::Group,
            },
            ManagerError::PasscodeTooShort {
                required: 21,
                actual: 3,
            },
            ManagerError::InvalidPasscode { offset: 2 },
            ManagerError::NoCurrentKeys,
            ManagerError::MissingSalt,
            ManagerError::RandomKeysNeedEncryption,
            ManagerError::SeedDoesNotMatchIdentifier,
            ManagerError::AlreadyIncepted {
                prefix: "EABC".to_owned(),
            },
            ManagerError::NotIncepted {
                prefix: "EABC".to_owned(),
            },
            ManagerError::Abandoned {
                prefix: "EABC".to_owned(),
            },
            ManagerError::MissingPrivateKey {
                public_key: "DABC".to_owned(),
            },
            ManagerError::SaltDecryptionUnavailable,
            ManagerError::NoSigningKeysRequested,
            ManagerError::PlacementCountMismatch { placements: 2, keys: 1 },
            ManagerError::UnknownExternalModule {
                module_type: "hsm".to_owned(),
            },
            ManagerError::MemberNotInSigningKeys { key: "DABC".to_owned() },
            ManagerError::MemberNotPrecommitted { key: "DABC".to_owned() },
            ManagerError::NoSigningKeys {
                prefix: "EABC".to_owned(),
            },
            ManagerError::ProfileNotStorable,
            ManagerError::UnsupportedTier,
            ManagerError::UnsupportedDigest { code: "H".to_owned() },
            ManagerError::DestinationOccupied {
                prefix: "EABC".to_owned(),
            },
            crypto,
        ] {
            assert_ne!(error.to_string(), "");
        }
        Ok(())
    }

    #[test]
    fn non_cryptographic_errors_have_no_source() {
        assert!(ManagerError::NoSigningKeysRequested.source().is_none());
        assert!(ManagerError::RandomKeysNeedEncryption.source().is_none());
    }
}
