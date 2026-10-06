//! Passcode rotation: the artifact set that moves a controller to a new passcode.
//!
//! # The seal follows the new passcode, as keripy does
//!
//! Rotating a passcode has to move two things: the signing keys, and the encryption that protects
//! the stored key material. keripy's `Manager.updateAeid` moves both — it builds its encrypter from
//! the **new** key, opens each secret with the old decrypter, and seals it again with the new one,
//! having first checked that the new seed belongs to the new key.
//!
//! **The reference moves only the first.** `Controller.rotate` derives one signer from
//! `this.salter` — the *old* salt — and uses it for the decrypter (correct) and the encrypter
//! (which therefore never rotates); the salt it seals is the old one too, and the controller's own
//! salt is left behind while its keys move. Driven, the payload that rotation produces **cannot be
//! opened by the new passcode at all**, so a client that rotated and reconnected could not read its
//! own identifiers — and the old passcode still opens everything. Nothing upstream exercises it:
//! the one test that calls `rotate` passes an empty identifier list, so the whole re-encryption
//! path is dead in its suite.
//!
//! This module follows keripy. The encrypter derives from the new salt, `sealed_salt` carries the
//! **new** salt, and the controller's stored salt moves with its keys — which the fix requires,
//! since material sealed to the new passcode cannot be opened by the old one a second time round.
//! See ADR `0033`, which supersedes ADR `0016`'s decision to reproduce this, and `PORTING.md` §9.
//!
//! # The rotation follows the log, as keripy requires
//!
//! **The reference always claims sequence number one.** `Controller.rotate` calls `rotate()`
//! without an `sn`, so the builder's default of `1` is written whatever the log holds, while the
//! prior digest is the controller's *current* event. Connecting a client approves its agent's
//! delegation with an interaction at sequence one, so every connected client's rotation is a `rot`
//! at sequence one whose prior is that interaction. keripy's `Kever.rotate` reads a rotation at the
//! log's current sequence number as a **recovery** that supersedes the interaction, requires its
//! prior to be the event *before* it — the inception — and refuses it: `Invalid recovery attempt:
//! Mismatch recovery event prior dig`. A live KERIA answers `500`. Nothing upstream notices,
//! because the one test that rotates mocks the agent.
//!
//! Here the rotation is built at the **current sequence number plus one**, with the current event's
//! digest as its prior — keripy's ordinary rotation — and a rotation the agent accepts becomes the
//! controller's current event, so a second rotation chains on the first. Everything else is the
//! reference's byte for byte: the `["1","0"]` weighted threshold, the key order, the signature
//! placements, and the payload's field names. See ADR `0034`.

use keri_cesr::crypto::cipher::{Ciphertext, Decrypter, Encrypter};
use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_cesr::crypto::salt::{Salt, SecurityTier};
use keri_cesr::crypto::signature::IndexedSignature;
use keri_cesr::crypto::signer::SignaturePlacement;
use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;
use keria_types::api::{AcceptedHab, KeyManagerState, RandyState, SaltyState};

use crate::controller::client::{CONTROLLER_STEM, Controller, CurrentEvent, single_signer};
use crate::controller::error::ControllerError;
use crate::event::KeyEvent;
use crate::event::rotation::RotationBuilder;
use crate::manager::keeper::security_tier;
use crate::manager::key_manager::salt_from_passcode;
use crate::manager::{DerivationCost, KeyIndices, SaltyKeyCreator, Stem};
use crate::threshold::SigningThreshold;

/// One identifier's key material, re-sealed for the rotation payload.
#[derive(Debug)]
pub enum ReEncryptedKeyState {
    /// A salty identifier: its decrypted salt was verified against the recorded signing keys and
    /// sealed again.
    Salty {
        /// The re-sealed salt; the wire's `sxlt`. Sealed to the **new** passcode's encryption
        /// key, so only the new passcode opens it.
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
    /// The rotation event, at the sequence number after the controller's current event and with
    /// that event's digest as its prior. The reference always writes `s = "1"`, which a KERI log
    /// that has moved past its inception refuses; see the module documentation and ADR `0034`.
    pub rotation: KeyEvent,
    /// The two indexed signatures, in the reference's order: the old committed-to key signing at
    /// position one with prior position zero, then the new key signing at position zero.
    pub signatures: Vec<IndexedSignature>,
    /// The controller's **new** salt, sealed to the **new** passcode's encryption key; the wire's
    /// `sxlt`. The reference seals the old salt under the old key. See the module documentation.
    pub sealed_salt: Ciphertext,
    /// Each identifier's re-sealed key material, in input order; the wire's `keys` map.
    pub re_encrypted: Vec<(String, ReEncryptedKeyState)>,
}

/// A passcode rotation that has been computed but not yet adopted.
///
/// Holds the artifacts to send and the secrets the controller moves to when they are accepted.
/// Produced by [`Controller::plan_passcode_rotation`] and consumed by
/// [`Controller::apply_passcode_rotation`]; dropping it instead leaves the controller untouched.
#[derive(Debug)]
pub struct PlannedPasscodeRotation {
    artifacts: PasscodeRotation,
    salt: Salt,
    signer: Signer,
    next_signer: Signer,
    keys: Vec<String>,
    next_digests: Vec<String>,
    current: CurrentEvent,
    rotation_index: u32,
    tier: SecurityTier,
    cost: DerivationCost,
}

impl PlannedPasscodeRotation {
    /// Borrows the artifacts this rotation would send.
    #[must_use]
    pub const fn artifacts(&self) -> &PasscodeRotation {
        &self.artifacts
    }

    /// Derives a second copy of the signing key this rotation moves the controller to.
    ///
    /// The key at the rotation's first position, from the new passcode at the controller's rotation
    /// index. An agent checks a request's signature against the controller's keys **after** it has
    /// applied the rotation the request carries, so the request that submits a rotation has to be
    /// signed with the key it introduces — which the client needs owned, and which
    /// [`Signer`] deliberately cannot be cloned into. Re-deriving goes through the same salt, stem,
    /// and index as the planned signer, so the two always agree.
    ///
    /// This costs one key derivation, at the controller's profile.
    ///
    /// # Errors
    ///
    /// Returns layered [`ControllerError::Crypto`] or [`ControllerError::Manager`] failures when
    /// the key cannot be derived.
    pub fn derive_signing_key(&self) -> Result<Signer, ControllerError> {
        let stem = Stem::new(CONTROLLER_STEM)?;
        let creator = SaltyKeyCreator::new(&self.salt, stem);
        single_signer(&creator, self.rotation_index, self.cost.profile(self.tier))
    }
}

impl Controller {
    /// Builds the artifact set that rotates this controller to a new passcode; the reference's
    /// `rotate`.
    ///
    /// The new signing key derives from the new passcode at this controller's rotation index, the
    /// old committed-to key co-signs with weight zero, and every supplied identifier's key material
    /// is opened with the **old** passcode's key and sealed again with the **new** one — as
    /// keripy's `updateAeid` does, and as the module documentation explains the reference does not.
    ///
    /// On success the controller's signer, next signer, keys, next digests, **and stored salt**
    /// move to the new passcode. Moving the salt is what the sealing fix requires: material sealed
    /// to the new passcode cannot be opened by the old one, so a controller that kept its old salt
    /// could rotate exactly once. The rotation also becomes the controller's **current event**, so
    /// a second rotation is built after it; the reference leaves its event behind and would rebuild
    /// the same sequence number again. The rotation index does not move: an agent reports none,
    /// so a reconnecting client derives at index zero from the new passcode, which is exactly the
    /// key the rotation put first.
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
        let planned = self.plan_passcode_rotation(new_passcode, identifiers)?;
        Ok(self.apply_passcode_rotation(planned))
    }

    /// Computes a passcode rotation **without moving this controller to it**.
    ///
    /// The artifacts are ready to send; the controller only advances when the result is handed to
    /// [`Self::apply_passcode_rotation`]. That split exists because the agent has to accept the
    /// rotation before the client may act as though it happened: a controller that advanced on a
    /// request that failed would sign with a key the agent has never seen, and its stored material
    /// would be sealed to a passcode the agent never recorded.
    ///
    /// # Errors
    ///
    /// The failures [`Self::rotate_passcode`] returns.
    pub fn plan_passcode_rotation(
        &self,
        new_passcode: &str,
        identifiers: &[AcceptedHab],
    ) -> Result<PlannedPasscodeRotation, ControllerError> {
        // The prior passcode's encryption key pair opens what is already stored.
        let prior_encryption = self.salt.derive_signer_with_profile(
            "",
            KeyTransferability::NonTransferable,
            self.cost.profile(self.tier),
        )?;
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

        // And the new passcode's encryption key seals what is stored next, so the rotation moves
        // the encryption as well as the signing keys. The reference re-uses `prior_encryption`
        // here; keripy builds its encrypter from the new key, and so does this.
        let new_encryption = new_salt.derive_signer_with_profile(
            "",
            KeyTransferability::NonTransferable,
            self.cost.profile(self.tier),
        )?;
        let encrypter = Encrypter::from_verification_key(new_encryption.verifier())?;

        let (new_signer, new_next_signer) = {
            let creator = SaltyKeyCreator::new(&new_salt, stem);
            (
                single_signer(&creator, self.rotation_index, profile)?,
                single_signer(&creator, next_index, profile)?,
            )
        };

        let keys = vec![new_signer.verifier().qb64()?, old_committed.verifier().qb64()?];
        let next_digest = Digest::derive(DigestAlgorithm::Blake3_256, &new_next_signer.verifier().qb64_bytes()?);

        // The reference's event but for its sequence number: the new key carries the whole weight,
        // the old committed-to key carries none, and the threshold is spelled exactly as the
        // reference's `isith: ['1', '0']`. The reference writes the builder's default `s` of one
        // whatever the log holds; keripy reads a rotation at the current sequence number as a
        // recovery and refuses it unless its prior is the event before, so this one follows the
        // log — the next sequence number, after the event its prior names. ADR `0034`.
        let sequence_number = self
            .current_sequence_number()
            .checked_add(1)
            .ok_or(ControllerError::SequenceNumberOverflow)?;
        let threshold = SigningThreshold::from_sith(r#"["1","0"]"#)?;
        let rotation = RotationBuilder::new(
            self.prefix().clone(),
            self.current_said(),
            sequence_number,
            vec![new_signer.verifier().clone(), old_committed.verifier().clone()],
        )
        .signing_threshold(threshold)
        .next_key_digests(vec![next_digest])
        .next_threshold(SigningThreshold::numeric(1))
        .build()?;
        // Validated now, so adopting it cannot fail once the agent has accepted it.
        let current = CurrentEvent::from_serialized(rotation.clone().into_serialized())?;

        let signatures = vec![
            old_committed.sign_indexed(rotation.raw(), SignaturePlacement::both_lists_with_prior(1, 0))?,
            new_signer.sign_indexed(rotation.raw(), SignaturePlacement::both_lists(0))?,
        ];
        let sealed_salt = encrypter.encrypt_salt(&new_salt)?;

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

        Ok(PlannedPasscodeRotation {
            artifacts: PasscodeRotation {
                rotation,
                signatures,
                sealed_salt,
                re_encrypted,
            },
            salt: new_salt,
            signer: new_signer,
            next_signer: new_next_signer,
            keys,
            next_digests: vec![next_digest.qb64()?],
            current,
            rotation_index: self.rotation_index,
            tier: self.tier,
            cost: self.cost,
        })
    }

    /// Moves this controller onto a planned rotation and returns the artifacts to send.
    ///
    /// The reference replaces the signers, keys, and digests and leaves its salt and its event
    /// behind, so its controller's salt and its keys disagree from there on, and its next rotation
    /// is built at the same place in the log. Here all of them move together: the salt because the
    /// sealing fix requires it, and the rotation becomes the current event so the log goes on.
    pub fn apply_passcode_rotation(&mut self, planned: PlannedPasscodeRotation) -> PasscodeRotation {
        let PlannedPasscodeRotation {
            artifacts,
            salt,
            signer,
            next_signer,
            keys,
            next_digests,
            current,
            rotation_index: _,
            tier: _,
            cost: _,
        } = planned;
        self.salt = salt;
        self.signer = signer;
        self.next_signer = next_signer;
        self.keys = keys;
        self.next_digests = next_digests;
        self.current = current;
        artifacts
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

    use keri_cesr::crypto::salt::{Salt, SecurityTier};
    use keria_types::api::Hab;

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
            let signer = keri_cesr::crypto::signer::Signer::from_seed(seed, KeyTransferability::Transferable)?;
            public.push(signer.verifier().qb64()?);
            sealed.push(encrypter.encrypt_signer(&signer)?.qb64()?);
        }
        let next_signer = keri_cesr::crypto::signer::Signer::from_seed(&[13; 32], KeyTransferability::Transferable)?;
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
        // A fresh controller sits at its inception, so the next sequence number is one — the same
        // value the reference always writes, which is why its one mocked test never noticed.
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
            let verifier = keri_cesr::crypto::verifier::VerificationKey::from_qb64(key)?;
            assert!(verifier.verify(signature.raw(), rotation.rotation.raw()).is_ok());
        }
        Ok(())
    }

    #[test]
    fn everything_is_sealed_to_the_new_passcode_key() -> Result<(), Box<dyn Error>> {
        let mut controller = ephemeral()?;
        let (_, prior_decrypter) = prior_encryption(&controller)?;
        let old_salt_qb64 = controller.salt().expose_qb64()?.as_str().to_owned();

        let rotation = controller.rotate_passcode(NEW_PASSCODE, &[])?;

        // The sealed salt is the NEW salt under the NEW passcode's key, as keripy's `updateAeid`
        // does: rotating the signing keys rotates the encryption with them.
        let new_salt_qb64 = controller.salt().expose_qb64()?.as_str().to_owned();
        assert_ne!(new_salt_qb64, old_salt_qb64, "the controller's salt did not move");
        let (_, new_decrypter) = prior_encryption(&controller)?;
        let opened = new_decrypter.decrypt_salt(&rotation.sealed_salt, SecurityTier::Low)?;
        assert_eq!(opened.expose_qb64()?.as_str(), new_salt_qb64);

        // And the passcode being left behind opens nothing. The reference seals the old salt under
        // this same key, producing a payload the new passcode cannot open at all.
        assert!(
            prior_decrypter
                .decrypt_salt(&rotation.sealed_salt, SecurityTier::Low)
                .is_err(),
            "the old passcode still opens the rotated payload"
        );
        Ok(())
    }

    #[test]
    fn the_controller_moves_onto_the_rotation_it_applied() -> Result<(), Box<dyn Error>> {
        let mut controller = ephemeral()?;
        let old_keys = controller.current_keys().to_vec();
        let old_digests = controller.next_digests().to_vec();

        let rotation = controller.rotate_passcode(NEW_PASSCODE, &[])?;

        // Keys and digests move to the new passcode's chain, and the rotation becomes the current
        // event — the reference leaves its event behind. The rotation index does not move.
        assert_eq!(controller.current_keys().len(), 2);
        assert_ne!(controller.current_keys(), old_keys.as_slice());
        assert_ne!(controller.next_digests(), old_digests.as_slice());
        assert_eq!(controller.current_event().raw(), rotation.rotation.raw());
        assert_eq!(controller.current_sequence_number(), 1);
        assert_eq!(
            controller.current_said().qb64()?,
            rotation.rotation.sad().get_text("d").unwrap_or_default()
        );
        assert_eq!(controller.rotation_index(), 0);

        // The signer is now the new key: a signed event verifies against the rotation's first key.
        let Some(SadValue::Array(keys)) = rotation.rotation.sad().get("k") else {
            return Err("the rotation carries no keys".into());
        };
        let Some(SadValue::Text(new_key)) = keys.first() else {
            return Err("the first key is not text".into());
        };
        let (event, signature) = controller.signed_event()?;
        let verifier = keri_cesr::crypto::verifier::VerificationKey::from_qb64(new_key)?;
        assert!(verifier.verify(signature.raw(), event.raw()).is_ok());
        Ok(())
    }

    /// An agent whose inception a controller can anchor.
    fn agent() -> Result<crate::controller::Agent, Box<dyn Error>> {
        let state: keria_types::api::KeyState = serde_json::from_value(serde_json::json!({
            "i": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
            "s": "0",
            "p": "",
            "d": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
            "f": "0",
            "dt": "2023-12-01T10:05:25.062609+00:00",
            "et": "dip",
            "kt": "1",
            "k": ["DAQVURvW74OJH1Q0C6YLim_tdBYoXABwg6GsAlPaUJXE"],
            "nt": "1",
            "n": ["ENBWnU8wNHqq9oqJIimWhxUtNDHReUXtiCwwtjg9zKY0"],
            "bt": "0",
            "b": [],
            "c": [],
            "ee": {"s": "0", "d": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY", "br": [], "ba": []},
            "di": "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"
        }))?;
        Ok(crate::controller::Agent::from_key_state(state)?)
    }

    fn text(event: &KeyEvent, label: &str) -> String {
        event.sad().get_text(label).map(ToOwned::to_owned).unwrap_or_default()
    }

    #[test]
    fn a_rotation_follows_the_log_after_a_delegation_approval() -> Result<(), Box<dyn Error>> {
        // Connecting a client approves its agent with an interaction at sequence one. The
        // reference's rotation then claims sequence one with that interaction as its prior, which
        // keripy reads as a recovery and refuses. This one is the next event instead.
        let mut controller = ephemeral()?;
        controller.approve_delegation(&agent()?)?;
        let interaction = controller.current_said().qb64()?;
        assert_eq!(controller.current_sequence_number(), 1);

        let first = controller.rotate_passcode(NEW_PASSCODE, &[])?;
        assert_eq!(text(&first.rotation, "s"), "2");
        assert_eq!(text(&first.rotation, "p"), interaction);

        // And a second rotation chains on the first, revealing the key the first committed to.
        let second = controller.rotate_passcode(PASSCODE, &[])?;
        assert_eq!(text(&second.rotation, "s"), "3");
        assert_eq!(text(&second.rotation, "p"), text(&first.rotation, "d"));
        let Some(SadValue::Array(keys)) = second.rotation.sad().get("k") else {
            return Err("the second rotation carries no keys".into());
        };
        let Some(SadValue::Text(revealed)) = keys.get(1) else {
            return Err("the second rotation reveals no committed key".into());
        };
        let Some(SadValue::Array(committed)) = first.rotation.sad().get("n") else {
            return Err("the first rotation commits to nothing".into());
        };
        let digest = Digest::derive(DigestAlgorithm::Blake3_256, revealed.as_bytes());
        assert_eq!(committed.first(), Some(&SadValue::Text(digest.qb64()?)));
        Ok(())
    }

    #[test]
    fn sequence_numbers_past_nine_are_written_in_hexadecimal() -> Result<(), Box<dyn Error>> {
        let mut controller = ephemeral()?;
        for _ in 0..10 {
            controller.approve_delegation(&agent()?)?;
        }
        let rotation = controller.rotate_passcode(NEW_PASSCODE, &[])?;
        assert_eq!(text(&rotation.rotation, "s"), "b");
        Ok(())
    }

    #[test]
    fn a_planned_rotation_left_unapplied_leaves_the_log_where_it_was() -> Result<(), Box<dyn Error>> {
        let mut controller = ephemeral()?;
        controller.approve_delegation(&agent()?)?;
        let said = controller.current_said();
        let raw = controller.current_event().raw().to_vec();

        let planned = controller.plan_passcode_rotation(NEW_PASSCODE, &[])?;
        assert_eq!(text(&planned.artifacts().rotation, "s"), "2");
        drop(planned);

        assert_eq!(controller.current_said(), said);
        assert_eq!(controller.current_sequence_number(), 1);
        assert_eq!(controller.current_event().raw(), raw.as_slice());
        // Planned again, it is the same event: nothing moved.
        let again = controller.plan_passcode_rotation(NEW_PASSCODE, &[])?;
        assert_eq!(text(&again.artifacts().rotation, "p"), said.qb64()?);
        Ok(())
    }

    #[test]
    fn a_log_at_the_last_sequence_number_cannot_rotate() -> Result<(), Box<dyn Error>> {
        let fresh = ephemeral()?;
        let last =
            crate::event::interaction::InteractionBuilder::new(fresh.prefix().clone(), fresh.current_said(), u128::MAX)
                .build()?;
        let options = ControllerOptions {
            derivation_cost: DerivationCost::Ephemeral,
            ..ControllerOptions::default()
        };
        let restored = Controller::restore(PASSCODE, SecurityTier::Low, options, last.into_serialized())?;
        assert_eq!(restored.current_sequence_number(), u128::MAX);
        assert!(matches!(
            restored.plan_passcode_rotation(NEW_PASSCODE, &[]),
            Err(ControllerError::SequenceNumberOverflow)
        ));
        Ok(())
    }

    #[test]
    fn the_planned_signing_key_is_the_rotations_first_key() -> Result<(), Box<dyn Error>> {
        // The request that submits a rotation is checked against the keys it introduces, so the
        // client signs it with this key before the controller has moved.
        let controller = ephemeral()?;
        let planned = controller.plan_passcode_rotation(NEW_PASSCODE, &[])?;
        let Some(SadValue::Array(keys)) = planned.artifacts().rotation.sad().get("k") else {
            return Err("the rotation carries no keys".into());
        };
        let signer = planned.derive_signing_key()?;
        assert_eq!(keys.first(), Some(&SadValue::Text(signer.verifier().qb64()?)));
        assert_ne!(
            signer.verifier().qb64()?,
            controller.derive_signing_key()?.verifier().qb64()?,
            "the planned key is the key being replaced"
        );
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
        // The re-sealed salt is the identifier's own, unchanged — under the NEW passcode's key.
        let (_, new_decrypter) = prior_encryption(&controller)?;
        let opened = new_decrypter.decrypt_salt(sealed_salt, SecurityTier::Low)?;
        assert_eq!(opened.expose_qb64()?.as_str(), "0ABmZWRjYmE5ODc2NTQzMjEw");
        assert!(
            decrypter.decrypt_salt(sealed_salt, SecurityTier::Low).is_err(),
            "the identifier's salt still opens under the old passcode"
        );
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
        // Each re-sealed key opens to the same public key it was stored under — under the NEW
        // passcode's key, and no longer under the old one.
        let (_, new_decrypter) = prior_encryption(&controller)?;
        for (sealed, expected) in signing_keys.iter().zip(&public) {
            let signer = new_decrypter.decrypt_seed(sealed, KeyTransferability::Transferable)?;
            assert_eq!(signer.verifier().qb64()?, *expected);
            assert!(
                decrypter
                    .decrypt_seed(sealed, KeyTransferability::Transferable)
                    .is_err(),
                "a private key still opens under the old passcode"
            );
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
