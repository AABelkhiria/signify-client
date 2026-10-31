//! The two random values a client generates for itself.
//!
//! This ports `randomPasscode` and `randomNonce` from the pinned `src/keri/app/coring.ts`. Both
//! draw from the operating system's entropy source, which is why they live here rather than in a
//! protocol crate: everything below `signify-client` takes its randomness as an argument so its
//! output is reproducible.

use keri_cesr::code::DerivationCode;
use keri_cesr::crypto::salt::{Salt, SecurityTier};
use keri_cesr::matter::QualifiedMaterial;

use crate::config::{PASSCODE_LENGTH, Passcode};
use crate::error::ClientError;

/// How many random bytes a passcode is drawn from; the reference's `randombytes_buf(16)`.
pub const PASSCODE_ENTROPY_BYTES: usize = 16;

/// How many random bytes a nonce is drawn from; the reference's `crypto_sign_SEEDBYTES`.
pub const NONCE_ENTROPY_BYTES: usize = 32;

/// How many characters of derivation code a qualified salt opens with.
const SALT_CODE_LENGTH: usize = 2;

/// Generates a fresh client passcode.
///
/// The reference builds a salt from sixteen random bytes and slices `qb64.substring(2, 23)` — it
/// drops the two-character derivation code and keeps twenty-one of the twenty-two remaining
/// characters, which is exactly the length its own constructor requires. That is reproduced, so a
/// passcode generated here is one the reference would accept and vice versa.
///
/// The upstream issue the slice cites is that the discarded twenty-second character costs entropy:
/// the result carries 126 bits of the 128 drawn. That is a property of the format both
/// implementations share, not something this port can change without producing passcodes the
/// reference cannot use.
///
/// # Errors
///
/// Returns [`ClientError::Randomness`] when the operating system's entropy source is unavailable,
/// and layered failures if the drawn bytes cannot be qualified.
pub fn random_passcode() -> Result<Passcode, ClientError> {
    let mut raw = [0_u8; PASSCODE_ENTROPY_BYTES];
    getrandom::fill(&mut raw).map_err(|_| ClientError::Randomness)?;
    let salt = Salt::from_raw(&raw, SecurityTier::Low)?;
    let qualified = salt.expose_qb64()?;
    // The reference slices `substring(2, 23)`: two characters of derivation code, then 21 of the
    // 22 that follow.
    // Sized up front: a buffer that grew would leave its earlier copies unwiped.
    let mut text = String::with_capacity(PASSCODE_LENGTH);
    text.extend(qualified.chars().skip(SALT_CODE_LENGTH).take(PASSCODE_LENGTH));
    Passcode::new(text)
}

/// Generates a fresh qualified nonce.
///
/// Thirty-two random bytes under the Ed25519 seed code, which is what a registry inception commits
/// to. The registry builder made the nonce a required input precisely because this generator was
/// not yet ported; it now is.
///
/// # Errors
///
/// Returns [`ClientError::Randomness`] when the operating system's entropy source is unavailable,
/// and layered failures if the drawn bytes cannot be qualified.
pub fn random_nonce() -> Result<String, ClientError> {
    let mut raw = [0_u8; NONCE_ENTROPY_BYTES];
    getrandom::fill(&mut raw).map_err(|_| ClientError::Randomness)?;
    Ok(QualifiedMaterial::new(DerivationCode::ED25519_SEED, &raw)?.qb64()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::error::Error;

    #[test]
    fn a_generated_passcode_is_one_the_reference_would_accept() -> Result<(), Box<dyn Error>> {
        for _ in 0..32 {
            let passcode = random_passcode()?;
            assert_eq!(passcode.expose().chars().count(), PASSCODE_LENGTH);
            // Re-validating is the check the reference's own constructor performs.
            Passcode::new(passcode.expose())?;
        }
        Ok(())
    }

    #[test]
    fn generated_passcodes_differ() -> Result<(), Box<dyn Error>> {
        let mut seen = BTreeSet::new();
        for _ in 0..32 {
            seen.insert(random_passcode()?.expose().to_owned());
        }
        assert_eq!(seen.len(), 32, "a repeated passcode means the entropy source is not");
        Ok(())
    }

    #[test]
    fn a_generated_nonce_is_a_qualified_seed() -> Result<(), Box<dyn Error>> {
        let mut seen = BTreeSet::new();
        for _ in 0..32 {
            let nonce = random_nonce()?;
            assert_eq!(nonce.len(), 44);
            assert!(nonce.starts_with('A'), "{nonce}");
            seen.insert(nonce);
        }
        assert_eq!(seen.len(), 32);
        Ok(())
    }
}
