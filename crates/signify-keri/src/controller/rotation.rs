//! Passcode rotation: the artifact set that moves a controller to a new passcode.
//!
//! # Security note: everything is sealed to the *prior* passcode's encryption key
//!
//! The reference derives its encrypter from the **old** salter (`this.salter.signer(...)`), so the
//! controller salt and every re-encrypted identifier key are sealed to the encryption key the old
//! passcode derives — and the sealed salt is the **old** salt, not the new one. Rotating the
//! signing keys therefore does not rotate the encryption: whoever holds the old passcode can still
//! open everything this payload stores. That is reproduced here exactly, because diverging would
//! change what KERIA stores and 8.9 owns the workflow-level decision; the field names and
//! documentation say it out loud so no caller mistakes it for a completed re-encryption. See
//! `PORTING.md` §9 and §10.

use signify_crypto::cipher::{Ciphertext, Decrypter, Encrypter};
use signify_crypto::digest::{Digest, DigestAlgorithm};
use signify_crypto::signature::IndexedSignature;
use signify_crypto::signer::SignaturePlacement;
use signify_crypto::verifier::KeyTransferability;
use signify_types::api::{AcceptedHab, KeyManagerState, RandyState, SaltyState};

use crate::controller::client::{CONTROLLER_STEM, Controller, single_signer};
use crate::controller::error::ControllerError;
use crate::event::KeyEvent;
use crate::event::rotation::RotationBuilder;
use crate::manager::keeper::security_tier;
use crate::manager::key_manager::salt_from_passcode;
use crate::manager::{KeyIndices, SaltyKeyCreator, Stem};
use crate::threshold::SigningThreshold;

/// One identifier's key material, re-sealed for the rotation payload.
#[derive(Debug)]
pub enum ReEncryptedKeyState {
    /// A salty identifier: its decrypted salt was verified against the recorded signing keys and
    /// sealed again.
    Salty {
        /// The re-sealed salt; the wire's `sxlt`. Sealed to the *prior* passcode's encryption
        /// key, as the module documentation explains.
        sealed_salt: Ciphertext,
    },
    /// A randy identifier: every private key was decrypted, the signing keys verified against the
    /// recorded state, and each sealed again.
    Randy {
        /// The re-sealed current signing keys; the wire's `prxs`, in stored order.
        signing_keys: Vec<Ciphertext>,
        /// The re-sealed next keys; the wire's `nxts`, in stored order. These are re-sealed
        /// without verification, as the reference does — nothing public commits to them here.
        next_keys: Vec<Ciphertext>,
    },
}

/// The complete artifact set one passcode rotation produces; the reference's `rotate` return.
#[derive(Debug)]
pub struct PasscodeRotation {
    /// The rotation event, always at sequence number one — the reference never passes a sequence
    /// number, so a controller that has moved past its inception still emits `s = "1"`.
    pub rotation: KeyEvent,
    /// The two indexed signatures, in the reference's order: the old committed-to key signing at
    /// position one with prior position zero, then the new key signing at position zero.
    pub signatures: Vec<IndexedSignature>,
    /// The controller's **old** salt, sealed to the **prior** passcode's encryption key; the
    /// wire's `sxlt`. See the module documentation.
    pub sealed_salt: Ciphertext,
    /// Each identifier's re-sealed key material, in input order; the wire's `keys` map.
    pub re_encrypted: Vec<(String, ReEncryptedKeyState)>,
}

impl Controller {
    /// Builds the artifact set that rotates this controller to a new passcode; the reference's
    /// `rotate`.
    ///
    /// The new signing key derives from the new passcode at this controller's rotation index, the
    /// old committed-to key co-signs with weight zero, and every supplied identifier's key
    /// material is decrypted, verified against its recorded key state, and sealed again — all to
    /// the *prior* passcode's encryption key, as the module documentation explains.
    ///
    /// On success the controller's signer, next signer, keys, and next digests move to the new
    /// passcode's derivations. The current event, rotation index, and stored salt deliberately do
    /// **not** move, because the reference leaves them untouched; a second rotation therefore
    /// derives its "old" key from the original passcode again, which `PORTING.md` §9 records.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidSaltyIdentifier`] or
    /// [`ControllerError::InvalidRandyIdentifier`] when a record's decrypted keys do not match its
    /// key state, [`ControllerError::UnsupportedKeyManager`] for a group or external record, a
    /// passcode failure via [`ControllerError::Manager`], and layered cipher, derivation, event,
    /// and signing failures.
    pub fn rotate_passcode(
        &mut self,
        new_passcode: &str,
        identifiers: &[AcceptedHab],
    ) -> Result<PasscodeRotation, ControllerError> {
        // The prior passcode's encryption key pair: the decrypter must open material sealed under
        // the old passcode, and the reference derives its encrypter from the same signer.
        let prior_encryption = self.salt.derive_signer_with_profile(
            "",
            KeyTransferability::NonTransferable,
            self.cost.profile(self.tier),
        )?;
        let encrypter = Encrypter::from_verification_key(prior_encryption.verifier())?;
        let decrypter = Decrypter::from_signer(&prior_encryption);

        // The key the old chain committed to, derived from the *stored* salt — which never moves,
        // so this is always the original passcode's derivation.
        let next_index = self
            .rotation_index
            .checked_add(1)
            .ok_or(ControllerError::SequenceNumberOverflow)?;
        let stem = Stem::new(CONTROLLER_STEM)?;
        let profile = self.cost.profile(self.tier);
        let old_committed = {
            let creator = SaltyKeyCreator::new(&self.salt, stem.clone());
            single_signer(&creator, next_index, profile)?
        };

        // The new passcode's chain, at the same indices.
        let new_salt = salt_from_passcode(new_passcode, self.tier)?;
        let (new_signer, new_next_signer) = {
            let creator = SaltyKeyCreator::new(&new_salt, stem);
            (
                single_signer(&creator, self.rotation_index, profile)?,
                single_signer(&creator, next_index, profile)?,
            )
        };

        let keys = vec![new_signer.verifier().qb64()?, old_committed.verifier().qb64()?];
        let next_digest = Digest::derive(DigestAlgorithm::Blake3_256, &new_next_signer.verifier().qb64_bytes()?);

        // The reference's exact event: the new key carries the whole weight, the old committed-to
        // key carries none, and the sequence number is the builder default of one. The threshold
        // is spelled exactly as the reference's `isith: ['1', '0']`.
        let threshold = SigningThreshold::from_sith(r#"["1","0"]"#)?;
        let rotation = RotationBuilder::new(
            self.prefix().clone(),
            self.current_said(),
            1,
            vec![new_signer.verifier().clone(), old_committed.verifier().clone()],
        )
        .signing_threshold(threshold)
        .next_key_digests(vec![next_digest])
        .next_threshold(SigningThreshold::numeric(1))
        .build()?;

        let signatures = vec![
            old_committed.sign_indexed(rotation.raw(), SignaturePlacement::both_lists_with_prior(1, 0))?,
            new_signer.sign_indexed(rotation.raw(), SignaturePlacement::both_lists(0))?,
        ];
        let sealed_salt = encrypter.encrypt_salt(&self.salt)?;

        let mut re_encrypted = Vec::with_capacity(identifiers.len());
        for identifier in identifiers {
            let prefix = identifier.common.prefix.clone();
            let state = match &identifier.common.key_manager {
                KeyManagerState::Salty(salty) => self.re_encrypt_salty(identifier, salty, &encrypter, &decrypter)?,
                KeyManagerState::Randy(randy) => Self::re_encrypt_randy(identifier, randy, &encrypter, &decrypter)?,
                other => {
                    return Err(ControllerError::UnsupportedKeyManager {
                        prefix,
                        algorithm: other.label(),
                    });
                }
            };
            re_encrypted.push((prefix, state));
        }

        // The reference replaces the signers, keys, and digests, and nothing else.
        self.signer = new_signer;
        self.next_signer = new_next_signer;
        self.keys = keys;
        self.next_digests = vec![next_digest.qb64()?];

        Ok(PasscodeRotation {
            rotation,
            signatures,
            sealed_salt,
            re_encrypted,
        })
    }

    /// Verifies and re-seals one salty identifier's salt.
    fn re_encrypt_salty(
        &self,
        identifier: &AcceptedHab,
        salty: &SaltyState,
        encrypter: &Encrypter,
        decrypter: &Decrypter,
    ) -> Result<ReEncryptedKeyState, ControllerError> {
        let tier = security_tier(salty.tier);
        let cipher = Ciphertext::from_qb64(&salty.encrypted_salt)?;
        let salt = decrypter.decrypt_salt(&cipher, tier)?;

        // Re-derive the identifier's current keys exactly as the reference does — rotation index
        // zero with the stored key index, which is the keeper's arrangement from Roadmap 4.3 —
        // and require them to match the recorded key state.
        let transferability = if salty.transferable {
            KeyTransferability::Transferable
        } else {
            KeyTransferability::NonTransferable
        };
        let creator = SaltyKeyCreator::new(&salt, Stem::new(salty.stem.clone())?);
        let created = creator.create(
            salty.inception_codes.len(),
            transferability,
            KeyIndices::new(salty.key_pair_index, 0, salty.key_index),
            self.cost.profile(tier),
        )?;
        if created.public_keys()? != identifier.state.signing_keys {
            return Err(ControllerError::InvalidSaltyIdentifier {
                prefix: identifier.common.prefix.clone(),
            });
        }

        Ok(ReEncryptedKeyState::Salty {
            sealed_salt: encrypter.encrypt_salt(&salt)?,
        })
    }

    /// Verifies and re-seals one randy identifier's private keys.
    fn re_encrypt_randy(
        identifier: &AcceptedHab,
        randy: &RandyState,
        encrypter: &Encrypter,
        decrypter: &Decrypter,
    ) -> Result<ReEncryptedKeyState, ControllerError> {
        let mut signing_keys = Vec::with_capacity(randy.encrypted_signing_keys.len());
        let mut public_keys = Vec::with_capacity(randy.encrypted_signing_keys.len());
        for sealed in &randy.encrypted_signing_keys {
            let signer = decrypter.decrypt_seed(&Ciphertext::from_qb64(sealed)?, KeyTransferability::Transferable)?;
            public_keys.push(signer.verifier().qb64()?);
            signing_keys.push(encrypter.encrypt_signer(&signer)?);
        }
        if public_keys != identifier.state.signing_keys {
            return Err(ControllerError::InvalidRandyIdentifier {
                prefix: identifier.common.prefix.clone(),
            });
        }

        // The next keys are re-sealed without verification, as the reference does; the seed bytes
        // are the same under either transferability.
        let mut next_keys = Vec::with_capacity(randy.encrypted_next_keys.len());
        for sealed in &randy.encrypted_next_keys {
            let signer =
                decrypter.decrypt_seed(&Ciphertext::from_qb64(sealed)?, KeyTransferability::NonTransferable)?;
            next_keys.push(encrypter.encrypt_signer(&signer)?);
        }

        Ok(ReEncryptedKeyState::Randy {
            signing_keys,
            next_keys,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    use signify_crypto::salt::{Salt, SecurityTier};
    use signify_types::api::Hab;

    use crate::controller::{Controller, ControllerOptions};
    use crate::event::kind::EventKind;
    use crate::manager::{DerivationCost, ManagerError};
    use crate::serialization::SadValue;

    const PASSCODE: &str = "0123456789abcdefghijk";
    const NEW_PASSCODE: &str = "abcdefghijk0123456789";

    fn ephemeral() -> Result<Controller, Box<dyn Error>> {
        Ok(Controller::with_options(
            PASSCODE,
            SecurityTier::Low,
            ControllerOptions {
                derivation_cost: DerivationCost::Ephemeral,
                ..ControllerOptions::default()
            },
        )?)
    }

    /// The prior passcode's encryption key pair, at the same ephemeral cost the controller uses.
    fn prior_encryption(controller: &Controller) -> Result<(Encrypter, Decrypter), Box<dyn Error>> {
        let signer = controller.salt().derive_signer_with_profile(
            "",
            KeyTransferability::NonTransferable,
            DerivationCost::Ephemeral.profile(controller.tier()),
        )?;
        Ok((
            Encrypter::from_verification_key(signer.verifier())?,
            Decrypter::from_signer(&signer),
        ))
    }

    fn accepted(value: serde_json::Value) -> Result<AcceptedHab, Box<dyn Error>> {
        match serde_json::from_value::<Hab>(value)? {
            Hab::Accepted(hab) => Ok(hab),
            Hab::Pending(_) => Err("the record parsed as pending".into()),
        }
    }

    /// Builds a salty identifier record whose salt is sealed to the prior encryption key.
    fn salty_record(encrypter: &Encrypter, keys: Option<Vec<String>>) -> Result<AcceptedHab, Box<dyn Error>> {
        let aid_salt = Salt::from_raw(b"fedcba9876543210", SecurityTier::Low)?;
        let creator = SaltyKeyCreator::new(&aid_salt, Stem::new("signify:aid")?);
        let created = creator.create(
            1,
            KeyTransferability::Transferable,
            KeyIndices::new(0, 0, 0),
            DerivationCost::Ephemeral.profile(SecurityTier::Low),
        )?;
        let derived = created.public_keys()?;
        let sealed = encrypter.encrypt_salt(&aid_salt)?.qb64()?;
        let keys = keys.unwrap_or(derived);
        let first = keys.first().cloned().unwrap_or_default();
        accepted(serde_json::json!({
            "name": "aid0",
            "prefix": first,
            "icp_dt": "2023-12-01T10:05:25.062609+00:00",
            "salty": {
                "tier": "low",
                "sxlt": sealed,
                "pidx": 0,
                "kidx": 0,
                "stem": "signify:aid",
                "dcode": "E",
                "icodes": ["A"],
                "ncodes": ["A"],
                "transferable": true
            },
            "state": state_with_keys(&keys)
        }))
    }

    /// Builds a randy identifier record whose keys are sealed to the prior encryption key.
    fn randy_record(
        encrypter: &Encrypter,
        keys_override: Option<Vec<String>>,
    ) -> Result<(AcceptedHab, Vec<String>), Box<dyn Error>> {
        let seeds: [[u8; 32]; 2] = [[7; 32], [11; 32]];
        let mut sealed = Vec::new();
        let mut public = Vec::new();
        for seed in &seeds {
            let signer = signify_crypto::signer::Signer::from_seed(seed, KeyTransferability::Transferable)?;
            public.push(signer.verifier().qb64()?);
            sealed.push(encrypter.encrypt_signer(&signer)?.qb64()?);
        }
        let next_signer = signify_crypto::signer::Signer::from_seed(&[13; 32], KeyTransferability::Transferable)?;
        let next_sealed = encrypter.encrypt_signer(&next_signer)?.qb64()?;
        let keys = keys_override.unwrap_or_else(|| public.clone());
        let first = keys.first().cloned().unwrap_or_default();
        let record = accepted(serde_json::json!({
            "name": "aid1",
            "prefix": first,
            "icp_dt": "2023-12-01T10:05:25.062609+00:00",
            "randy": {
                "prxs": sealed,
                "nxts": [next_sealed]
            },
            "state": state_with_keys(&keys)
        }))?;
        Ok((record, public))
    }

    fn state_with_keys(keys: &[String]) -> serde_json::Value {
        serde_json::json!({
            "i": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
            "s": "0",
            "p": "",
            "d": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
            "f": "0",
            "dt": "2023-12-01T10:05:25.062609+00:00",
            "et": "icp",
            "kt": "1",
            "k": keys,
            "nt": "1",
            "n": ["ENBWnU8wNHqq9oqJIimWhxUtNDHReUXtiCwwtjg9zKY0"],
            "bt": "0",
            "b": [],
            "c": [],
            "ee": {"s": "0", "d": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY", "br": [], "ba": []},
            "di": ""
        })
    }

    #[test]
    fn the_rotation_event_matches_the_reference_shape() -> Result<(), Box<dyn Error>> {
        let mut controller = ephemeral()?;
        let inception_said = controller.current_said();
        let old_next_digest = controller.next_digests().first().cloned().unwrap_or_default();

        let rotation = controller.rotate_passcode(NEW_PASSCODE, &[])?;
        let sad = rotation.rotation.sad();
        assert_eq!(rotation.rotation.kind(), EventKind::Rotation);
        // The reference never passes a sequence number, so the event always claims one.
        assert_eq!(sad.get_text("s"), Some("1"));
        assert_eq!(sad.get_text("p"), Some(inception_said.qb64()?.as_str()));
        assert_eq!(
            sad.get("kt"),
            Some(&SadValue::Array(vec![SadValue::text("1"), SadValue::text("0")]))
        );
        assert_eq!(sad.get_text("nt"), Some("1"));

        // The second key is the one the old chain committed to.
        let Some(SadValue::Array(keys)) = sad.get("k") else {
            return Err("the rotation carries no keys".into());
        };
        assert_eq!(keys.len(), 2);
        let Some(SadValue::Text(old_key)) = keys.get(1) else {
            return Err("the second key is not text".into());
        };
        let digest = Digest::derive(DigestAlgorithm::Blake3_256, old_key.as_bytes());
        assert_eq!(digest.qb64()?, old_next_digest);

        // Both signatures verify over the rotation bytes against the keys they index.
        let placements: Vec<(u32, Option<u32>)> = rotation
            .signatures
            .iter()
            .map(|signature| (signature.index(), signature.other_index()))
            .collect();
        assert_eq!(placements, [(1, Some(0)), (0, Some(0))]);
        for signature in &rotation.signatures {
            let position = usize::try_from(signature.index())?;
            let Some(SadValue::Text(key)) = keys.get(position) else {
                return Err("a signature indexes a missing key".into());
            };
            let verifier = signify_crypto::verifier::VerificationKey::from_qb64(key)?;
            assert!(verifier.verify(signature.raw(), rotation.rotation.raw()).is_ok());
        }
        Ok(())
    }

    #[test]
    fn everything_is_sealed_to_the_prior_passcode_key() -> Result<(), Box<dyn Error>> {
        let mut controller = ephemeral()?;
        let (_, prior_decrypter) = prior_encryption(&controller)?;
        let old_salt_qb64 = controller.salt().expose_qb64()?.as_str().to_owned();

        let rotation = controller.rotate_passcode(NEW_PASSCODE, &[])?;

        // The sealed salt is the OLD salt, and the OLD passcode's key still opens it: rotating
        // the signing keys did not rotate the encryption. This is the reference's arrangement,
        // recorded in `PORTING.md` §9.
        let opened = prior_decrypter.decrypt_salt(&rotation.sealed_salt, SecurityTier::Low)?;
        assert_eq!(opened.expose_qb64()?.as_str(), old_salt_qb64);
        Ok(())
    }

    #[test]
    fn the_controller_state_moves_exactly_as_the_reference_mutates() -> Result<(), Box<dyn Error>> {
        let mut controller = ephemeral()?;
        let inception_raw = controller.current_event().raw().to_vec();
        let old_keys = controller.current_keys().to_vec();
        let old_digests = controller.next_digests().to_vec();

        let rotation = controller.rotate_passcode(NEW_PASSCODE, &[])?;

        // Keys and digests move to the new passcode's chain; the event and index do not.
        assert_eq!(controller.current_keys().len(), 2);
        assert_ne!(controller.current_keys(), old_keys.as_slice());
        assert_ne!(controller.next_digests(), old_digests.as_slice());
        assert_eq!(controller.current_event().raw(), inception_raw.as_slice());
        assert_eq!(controller.rotation_index(), 0);

        // The signer is now the new key: a signed event verifies against the rotation's first key.
        let Some(SadValue::Array(keys)) = rotation.rotation.sad().get("k") else {
            return Err("the rotation carries no keys".into());
        };
        let Some(SadValue::Text(new_key)) = keys.first() else {
            return Err("the first key is not text".into());
        };
        let (event, signature) = controller.signed_event()?;
        let verifier = signify_crypto::verifier::VerificationKey::from_qb64(new_key)?;
        assert!(verifier.verify(signature.raw(), event.raw()).is_ok());
        Ok(())
    }

    #[test]
    fn a_salty_identifier_is_verified_and_resealed() -> Result<(), Box<dyn Error>> {
        let mut controller = ephemeral()?;
        let (encrypter, decrypter) = prior_encryption(&controller)?;
        let record = salty_record(&encrypter, None)?;

        let rotation = controller.rotate_passcode(NEW_PASSCODE, std::slice::from_ref(&record))?;
        assert_eq!(rotation.re_encrypted.len(), 1);
        let Some((prefix, ReEncryptedKeyState::Salty { sealed_salt })) = rotation.re_encrypted.first() else {
            return Err("the salty record was not re-encrypted".into());
        };
        assert_eq!(prefix, &record.common.prefix);
        // The re-sealed salt opens — with the PRIOR key — to the identifier's own salt.
        let opened = decrypter.decrypt_salt(sealed_salt, SecurityTier::Low)?;
        assert_eq!(opened.expose_qb64()?.as_str(), "0ABmZWRjYmE5ODc2NTQzMjEw");
        Ok(())
    }

    #[test]
    fn a_randy_identifier_is_verified_and_resealed() -> Result<(), Box<dyn Error>> {
        let mut controller = ephemeral()?;
        let (encrypter, decrypter) = prior_encryption(&controller)?;
        let (record, public) = randy_record(&encrypter, None)?;

        let rotation = controller.rotate_passcode(NEW_PASSCODE, std::slice::from_ref(&record))?;
        let Some((
            _,
            ReEncryptedKeyState::Randy {
                signing_keys,
                next_keys,
            },
        )) = rotation.re_encrypted.first()
        else {
            return Err("the randy record was not re-encrypted".into());
        };
        assert_eq!(signing_keys.len(), 2);
        assert_eq!(next_keys.len(), 1);
        // Each re-sealed key opens to the same public key it was stored under.
        for (sealed, expected) in signing_keys.iter().zip(&public) {
            let signer = decrypter.decrypt_seed(sealed, KeyTransferability::Transferable)?;
            assert_eq!(signer.verifier().qb64()?, *expected);
        }
        Ok(())
    }

    #[test]
    fn a_mismatched_identifier_is_refused() -> Result<(), Box<dyn Error>> {
        let mut controller = ephemeral()?;
        let (encrypter, _) = prior_encryption(&controller)?;
        let wrong = vec!["DAQVURvW74OJH1Q0C6YLim_tdBYoXABwg6GsAlPaUJXE".to_owned()];

        let salty = salty_record(&encrypter, Some(wrong.clone()))?;
        assert!(matches!(
            controller.rotate_passcode(NEW_PASSCODE, std::slice::from_ref(&salty)),
            Err(ControllerError::InvalidSaltyIdentifier { .. })
        ));

        let (randy, _) = randy_record(&encrypter, Some(wrong))?;
        assert!(matches!(
            controller.rotate_passcode(NEW_PASSCODE, std::slice::from_ref(&randy)),
            Err(ControllerError::InvalidRandyIdentifier { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_group_identifier_cannot_be_re_encrypted() -> Result<(), Box<dyn Error>> {
        let mut controller = ephemeral()?;
        let (encrypter, _) = prior_encryption(&controller)?;
        let member = salty_record(&encrypter, None)?;
        let member_value = serde_json::to_value(&member)?;
        let group = accepted(serde_json::json!({
            "name": "group0",
            "prefix": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
            "icp_dt": "2023-12-01T10:05:25.062609+00:00",
            "group": {
                "mhab": member_value,
                "keys": ["DAQVURvW74OJH1Q0C6YLim_tdBYoXABwg6GsAlPaUJXE"],
                "ndigs": ["ENBWnU8wNHqq9oqJIimWhxUtNDHReUXtiCwwtjg9zKY0"]
            },
            "state": state_with_keys(&["DAQVURvW74OJH1Q0C6YLim_tdBYoXABwg6GsAlPaUJXE".to_owned()])
        }))?;
        assert!(matches!(
            controller.rotate_passcode(NEW_PASSCODE, std::slice::from_ref(&group)),
            Err(ControllerError::UnsupportedKeyManager { algorithm: "group", .. })
        ));
        Ok(())
    }

    #[test]
    fn an_unusable_new_passcode_is_refused() -> Result<(), Box<dyn Error>> {
        let mut controller = ephemeral()?;
        assert!(matches!(
            controller.rotate_passcode("short", &[]),
            Err(ControllerError::Manager { source })
                if matches!(*source, ManagerError::PasscodeTooShort { .. })
        ));
        Ok(())
    }
}
