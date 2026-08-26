//! The delegation endpoint: a delegator's approval of an identifier it has been asked to authorize.
//!
//! A delegated identifier cannot come into existence on its own. Its inception names a delegator,
//! and it stays pending until that delegator **anchors a seal of it** in its own key event log —
//! which is what this one call does. The delegate is watching the delegator's log, and the seal is
//! the only thing it is watching for.
//!
//! This ports the whole of the pinned `src/keri/app/delegating.ts`: one class with one method, and
//! thirty-three lines including its documentation. It is the smallest application module in the
//! port, one line shorter than Roadmap 7.6's `escrowing.ts`.
//!
//! # The approval *is* an interaction event
//!
//! `approve` calls `createInteract` and then posts the result to a different address. The event, the
//! signatures, and the key-manager block are byte for byte what
//! [`Identifiers::interact`](crate::endpoint::identifiers::Identifiers::interact) would send; only
//! the last path segment differs — `delegation` rather than `events`. So the two share one builder
//! here, as they share one in the reference, and what this module adds is the address and the seal.
//!
//! # The seal is a value, not a shape a caller guesses
//!
//! The reference declares the anchor `data?: any` and its own integration test assembles
//! `{ i: delegatePrefix, s: '0', d: delegatePrefix }` by hand, reading the delegate's prefix out of
//! a **string split of an operation name**. [`InceptionSeal::of`] builds the same three fields from
//! the delegate's inception event, so the identifier, the sequence number, and the digest cannot
//! disagree with each other or with the event they claim to anchor — and an event that is not a
//! delegated inception is refused, because nobody will ever approve one.
//!
//! # And the anchor is not optional
//!
//! `data` is optional upstream, and `createInteract` wraps a non-array in one — so `approve(name)`
//! with no anchor sends `"a": [null]`, an interaction whose seal list holds a JSON null and whose
//! SAID is computed over it. **The reference's own unit test does exactly that**, which is why the
//! only body the pinned tree publishes for this endpoint approves nothing at all. Here the seals
//! are a required argument and an empty list is refused. See `fixtures/client-delegations/`.

use signify_keri::event::kind::EventKind;
use signify_keri::identifier::IdentifierArtifact;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::serialization::Sad;

use crate::client::ConnectedClient;
use crate::endpoint::body::sad_error;
use crate::endpoint::identifiers::Submission;
use crate::error::ClientError;

/// Path segment a delegator's approvals are posted under.
///
/// The reference's `'/identifiers/' + name + '/delegation'`, and the only thing that distinguishes
/// this call from an ordinary interaction.
pub const DELEGATION_SEGMENT: &str = "delegation";

/// Wire label of a seal's identifier, `i`.
pub const SEAL_IDENTIFIER_LABEL: &str = "i";
/// Wire label of a seal's sequence number, `s`.
pub const SEAL_SEQUENCE_LABEL: &str = "s";
/// Wire label of a seal's digest, `d`.
pub const SEAL_DIGEST_LABEL: &str = "d";

/// The seal a delegator anchors to approve a delegated inception.
///
/// Three fields naming one event: the identifier it belongs to, where in that identifier's log it
/// sits, and its digest. The reference writes them by hand from three separately-obtained values —
/// and obtains the first by splitting an operation's name on a full stop — so nothing there
/// prevents a seal that names one identifier at another's sequence number with a third's digest.
/// Built from an event here, the three cannot disagree.
///
/// ```
/// use signify_client::endpoint::delegations::InceptionSeal;
/// use signify_keri::prefix::IdentifierPrefix;
/// use signify_keri::said::Said;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // A delegated inception is its own digest, so the seal names one value twice.
/// let delegate = IdentifierPrefix::from_qb64("ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK")?;
/// let digest: Said = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK".parse()?;
/// let seal = InceptionSeal::new(delegate, digest);
///
/// let written = seal.to_sad()?;
/// assert_eq!(written.get_text("i"), Some("ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK"));
/// assert_eq!(written.get_text("s"), Some("0"));
/// assert_eq!(written.get_text("d"), Some("ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK"));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InceptionSeal {
    delegate: IdentifierPrefix,
    digest: Said,
}

impl InceptionSeal {
    /// Names the inception of `delegate` whose digest is `digest`.
    #[must_use]
    pub const fn new(delegate: IdentifierPrefix, digest: Said) -> Self {
        Self { delegate, digest }
    }

    /// Names the inception a delegate just created, taking both values from the event itself.
    ///
    /// This is the form a delegate's own client uses: Roadmap 4.6's artifact carries the event, so
    /// neither field is transcribed and neither can be the wrong one. The reference's own
    /// integration test instead reads the delegate's prefix out of `op2.name.split('.')[1]` — the
    /// *name of a long-running operation*, split on a full stop — while the prefix is sitting in
    /// the inception the same call already returned.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NotADelegatedInception`] when the event is not a delegated inception,
    /// so a caller cannot wait for an approval that will never come: an undelegated identifier is
    /// complete when it is created and no delegator will ever anchor it.
    pub fn of(inception: &IdentifierArtifact) -> Result<Self, ClientError> {
        if inception.event.kind() != EventKind::DelegatedInception {
            return Err(ClientError::NotADelegatedInception {
                found: inception.event.kind().as_str(),
            });
        }
        Ok(Self {
            delegate: inception.event.identifier().clone(),
            digest: inception.event.said(),
        })
    }

    /// Returns the identifier this seal approves.
    #[must_use]
    pub const fn delegate(&self) -> &IdentifierPrefix {
        &self.delegate
    }

    /// Returns the digest of the event this seal names.
    #[must_use]
    pub const fn digest(&self) -> &Said {
        &self.digest
    }

    /// Writes the seal in the reference's own field order.
    ///
    /// The sequence number is `"0"` and always `"0"`: an inception is the first event of its log,
    /// and this seal approves an inception. A delegated *rotation* is Roadmap 8.6's, and will name
    /// a sequence number it is given.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Identifier`] when the delegate's prefix cannot be encoded,
    /// [`ClientError::Said`] when the digest cannot be, and [`ClientError::Serialization`] when the
    /// block cannot be written.
    pub fn to_sad(&self) -> Result<Sad, ClientError> {
        let mut seal = Sad::new();
        seal.insert(SEAL_IDENTIFIER_LABEL, self.delegate.qb64()?)
            .map_err(sad_error)?;
        seal.insert(SEAL_SEQUENCE_LABEL, "0".to_owned()).map_err(sad_error)?;
        seal.insert(SEAL_DIGEST_LABEL, self.digest.qb64()?).map_err(sad_error)?;
        Ok(seal)
    }
}

/// The delegation endpoint family.
///
/// Borrowed from a connected client, so it costs nothing to hold and cannot outlive the client it
/// speaks through — the shape Roadmap 6.5 settled.
#[derive(Debug)]
pub struct Delegations<'client> {
    client: &'client ConnectedClient,
}

impl<'client> Delegations<'client> {
    /// Binds this family to a connected client.
    #[must_use]
    pub const fn new(client: &'client ConnectedClient) -> Self {
        Self { client }
    }

    /// Approves a delegation by anchoring `seals` in the delegator's own log.
    ///
    /// `alias` names the **delegator** — the identifier doing the approving — not the delegate. The
    /// event this builds is an ordinary interaction; posting it to `delegation` rather than
    /// `events` is what tells the agent it completes a pending delegated inception.
    ///
    /// **At least one seal is required.** Upstream's anchor is optional and `createInteract` wraps
    /// a non-array, so an omitted one reaches the wire as `"a": [null]` — an approval of nothing,
    /// which is what the reference's own unit test sends.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NoDelegationSeals`] for an empty list, and whatever
    /// [`Identifiers::interact`](crate::endpoint::identifiers::Identifiers::interact) returns —
    /// which is everything reading the delegator's record, rebuilding its keeper, and signing can
    /// fail with.
    pub async fn approve(&self, alias: &str, seals: &[Sad]) -> Result<Submission<IdentifierArtifact>, ClientError> {
        if seals.is_empty() {
            return Err(ClientError::NoDelegationSeals);
        }
        self.client
            .identifiers()
            .submit_interaction(alias, DELEGATION_SEGMENT, seals.to_vec())
            .await
    }

    /// Approves one delegated inception, building the seal from the event it approves.
    ///
    /// The single-signature workflow's second half: a delegate has created an identifier naming
    /// this delegator and is waiting for it to appear in the delegator's log. `seal` names the
    /// event to anchor, and [`InceptionSeal::of`] builds one from the delegate's own artifact so
    /// the three fields cannot disagree.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::approve`] returns, plus [`ClientError::Identifier`] and
    /// [`ClientError::Said`] when the seal cannot be encoded.
    pub async fn approve_inception(
        &self,
        alias: &str,
        seal: &InceptionSeal,
    ) -> Result<Submission<IdentifierArtifact>, ClientError> {
        self.approve(alias, &[seal.to_sad()?]).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const DELEGATE: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
    const DELEGATOR: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
    const DIGEST: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

    /// One delegated inception, built the way Roadmap 4.6 builds one.
    fn delegated_inception() -> Result<IdentifierArtifact, Box<dyn Error>> {
        artifact(Some(DELEGATOR))
    }

    /// And one that is not delegated, which nobody will ever approve.
    fn plain_inception() -> Result<IdentifierArtifact, Box<dyn Error>> {
        artifact(None)
    }

    fn artifact(delegator: Option<&str>) -> Result<IdentifierArtifact, Box<dyn Error>> {
        use signify_crypto::salt::{Salt, SecurityTier};
        use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest, incept_identifier};
        use signify_keri::manager::{DerivationCost, KeeperFactory};

        let request = CreateIdentifierRequest {
            delegator: delegator.map(IdentifierPrefix::from_qb64).transpose()?,
            ..CreateIdentifierRequest::new(CreateAlgorithm::Salty {
                passcode: Some("0123456789abcdefghijk".to_owned()),
                tier: SecurityTier::Low,
                current_count: 1,
                next_count: 1,
                cost: DerivationCost::Ephemeral,
            })
        };
        let factory = KeeperFactory::new(Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)?);
        let mut keeper = factory.create(request.keeper_request(0)?)?;
        Ok(incept_identifier(keeper.as_mut(), &request)?)
    }

    fn seal(delegate: &str, digest: &str) -> Result<InceptionSeal, Box<dyn Error>> {
        Ok(InceptionSeal::new(
            IdentifierPrefix::from_qb64(delegate)?,
            digest.parse::<Said>()?,
        ))
    }

    #[test]
    fn the_path_segment_is_the_references_own() {
        assert_eq!(DELEGATION_SEGMENT, "delegation");
        // And the three seal labels, which the reference writes as an object literal.
        assert_eq!(
            [SEAL_IDENTIFIER_LABEL, SEAL_SEQUENCE_LABEL, SEAL_DIGEST_LABEL],
            ["i", "s", "d"]
        );
    }

    #[test]
    fn a_seal_writes_three_fields_in_the_references_order() -> Result<(), Box<dyn Error>> {
        let written = seal(DELEGATE, DIGEST)?.to_sad()?;
        // Field order is part of the wire form, so it is asserted on the bytes.
        assert_eq!(
            String::from_utf8(written.to_json_bytes()?)?,
            format!(r#"{{"i":"{DELEGATE}","s":"0","d":"{DIGEST}"}}"#)
        );
        assert_eq!(written.get_text(SEAL_IDENTIFIER_LABEL), Some(DELEGATE));
        assert_eq!(written.get_text(SEAL_SEQUENCE_LABEL), Some("0"));
        assert_eq!(written.get_text(SEAL_DIGEST_LABEL), Some(DIGEST));
        Ok(())
    }

    #[test]
    fn an_inception_seals_sequence_number_is_always_zero() -> Result<(), Box<dyn Error>> {
        // Whatever else varies, this does not: the seal approves an inception.
        for digest in [DELEGATE, DIGEST, DELEGATOR] {
            assert_eq!(
                seal(DELEGATE, digest)?.to_sad()?.get_text(SEAL_SEQUENCE_LABEL),
                Some("0")
            );
        }
        Ok(())
    }

    #[test]
    fn a_seal_built_from_an_event_takes_both_values_from_it() -> Result<(), Box<dyn Error>> {
        let artifact = delegated_inception()?;
        let built = InceptionSeal::of(&artifact)?;
        assert_eq!(built.delegate(), artifact.event.identifier());
        assert_eq!(built.digest().qb64()?, artifact.event.said().qb64()?);
        // Which is what the reference reads out of an operation's name instead.
        let written = built.to_sad()?;
        assert_eq!(
            written.get_text(SEAL_IDENTIFIER_LABEL),
            Some(artifact.event.identifier().qb64()?.as_str())
        );
        Ok(())
    }

    #[test]
    fn an_undelegated_inception_is_not_awaiting_anybodys_approval() -> Result<(), Box<dyn Error>> {
        let plain = plain_inception()?;
        let refused = matches!(
            InceptionSeal::of(&plain),
            Err(ClientError::NotADelegatedInception { found: "icp" })
        );
        assert!(refused, "a plain inception was offered for approval");
        Ok(())
    }

    #[test]
    fn a_seal_keeps_the_two_values_it_was_built_from() -> Result<(), Box<dyn Error>> {
        let built = seal(DELEGATE, DIGEST)?;
        assert_eq!(built.delegate().qb64()?, DELEGATE);
        assert_eq!(built.digest().qb64()?, DIGEST);
        // A delegated inception is its own digest, which is the usual case and not a required one.
        let usual = seal(DELEGATE, DELEGATE)?;
        assert_eq!(usual.delegate().qb64()?, usual.digest().qb64()?);
        Ok(())
    }
}
