//! The challenges endpoint: proving that somebody controls the identifier they claim.
//!
//! A challenge is a list of BIP39 words. One party asks the agent to [`generate`](Challenges::generate)
//! one and sends it out of band; the other signs those words into an exchange message; the first
//! then asks the agent to [`verify`](Challenges::verify) that the signature exists, and records the
//! answer with [`responded`](Challenges::responded), which is what puts an `authenticated` verdict
//! into that identifier's contact record.
//!
//! This ports `Challenges` from the pinned `src/keri/app/contacting.ts` — all four methods.
//!
//! # `respond` arrived with Roadmap 7.7
//!
//! The reference's fourth method reads the habitat and then calls
//! `exchanges.send(name, 'challenge', hab, '/challenge/response', {words}, {}, [recipient])`, so it
//! needs the whole generic submission that is Roadmap 7.7's write half. Roadmap 7.4 did not have
//! 7.7 as a prerequisite, so `PORTING.md` §5.13 moved the capability rather than duplicating it;
//! [`Challenges::respond`] is that capability, delivered here as a wrapper over
//! [`Exchanges::send`](crate::endpoint::exchanges::Exchanges::send) exactly as upstream is.
//!
//! # A strength is an entropy size, not a number
//!
//! `generate(strength = 128)` upstream stringifies whatever it is given straight into the query, so
//! `1.5`, `NaN`, and `-1` all reach the agent. [`ChallengeStrength`] accepts only the five entropy
//! sizes BIP39 defines, so a request that could not produce a mnemonic cannot be written. See
//! `fixtures/client-challenges/`.

use keria_types::api::{Challenge, ChallengeOperation};
use signify_http::request::ResourcePath;
use signify_http::transport::Method;
use signify_keri::event::timestamp::Timestamp;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::serialization::{Sad, SadValue};

use crate::client::{ClientRequest, ConnectedClient};
use crate::endpoint::body::sad_error;
use crate::endpoint::decode_json;
use crate::endpoint::exchanges::{ExchangeDraft, SentExchange};
use crate::error::ClientError;

/// Path segment a challenge word list is generated under.
pub const CHALLENGES_SEGMENT: &str = "challenges";

/// Path segment both verification calls address.
///
/// `verify` and `responded` share it exactly and differ only in method: `POST` asks the agent to
/// check for a signed answer, `PUT` records that the caller accepted one.
pub const CHALLENGES_VERIFY_SEGMENT: &str = "challenges_verify";

/// Query parameter naming the entropy size; the reference's `strength`.
pub const STRENGTH_PARAMETER: &str = "strength";

/// The exchange route a challenge answer is sent over.
///
/// Roadmap 7.7 owns the submission (see the module documentation); the constant is here because it
/// is a fact about *challenges* rather than about exchanges, and a caller answering one before then
/// needs it.
pub const CHALLENGE_RESPONSE_ROUTE: &str = "/challenge/response";

/// The exchange topic a challenge answer is filed under; the reference's `'challenge'`.
pub const CHALLENGE_TOPIC: &str = "challenge";

/// Field label carrying the word list, in both a verification body and a response message.
///
/// One label, two places: `verify` sends `{"words": …}` to the agent and `respond` writes the same
/// label into the exchange message's attribute block. Naming it once is what keeps them equal.
pub const CHALLENGE_WORDS_LABEL: &str = "words";

/// How much entropy a generated challenge carries, in bits.
///
/// BIP39 defines exactly five entropy sizes, and a mnemonic can be generated for no other. The
/// reference takes a bare `number` and stringifies it into the query, so a fraction, a negative, or
/// `NaN` reaches the agent as a request it cannot satisfy; this type refuses all three at
/// construction.
///
/// ```
/// use signify_client::endpoint::challenges::ChallengeStrength;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // The reference's own default, and the length of the word list it produces.
/// assert_eq!(ChallengeStrength::BITS_128.bits(), 128);
/// assert_eq!(ChallengeStrength::BITS_128.word_count(), 12);
/// assert_eq!(ChallengeStrength::BITS_256.word_count(), 24);
///
/// // Nothing BIP39 does not define.
/// assert!(ChallengeStrength::new(129).is_err());
/// assert!(ChallengeStrength::new(0).is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChallengeStrength(u32);

impl ChallengeStrength {
    /// Every entropy size BIP39 defines, in ascending order.
    pub const DECLARED: [u32; 5] = [128, 160, 192, 224, 256];

    /// 128 bits — twelve words, the reference's default and what both integration suites use.
    pub const BITS_128: Self = Self(128);
    /// 160 bits — fifteen words.
    pub const BITS_160: Self = Self(160);
    /// 192 bits — eighteen words.
    pub const BITS_192: Self = Self(192);
    /// 224 bits — twenty-one words.
    pub const BITS_224: Self = Self(224);
    /// 256 bits — twenty-four words; the larger of the two `challenge.test.ts` generates.
    pub const BITS_256: Self = Self(256);

    /// Validates one entropy size.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidChallengeStrength`] for anything outside [`Self::DECLARED`].
    pub const fn new(bits: u32) -> Result<Self, ClientError> {
        // A `match` rather than a slice search, so the accepted set is exhaustive at compile time.
        match bits {
            128 | 160 | 192 | 224 | 256 => Ok(Self(bits)),
            _ => Err(ClientError::InvalidChallengeStrength { bits }),
        }
    }

    /// Returns the entropy size in bits, which is what reaches the query.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns how many words the generated mnemonic will carry.
    ///
    /// BIP39's own relation: one word per eleven bits of entropy-plus-checksum, which reduces to
    /// `bits / 32 * 3`. The pinned unit test's twelve-word list is this at 128 bits.
    #[must_use]
    pub const fn word_count(self) -> u32 {
        self.0 / 32 * 3
    }
}

impl Default for ChallengeStrength {
    /// The reference's own `strength = 128` default.
    fn default() -> Self {
        Self::BITS_128
    }
}

/// The challenges endpoint family.
///
/// Borrowed from a connected client, so it costs nothing to hold and cannot outlive the client it
/// speaks through. This is the shape Roadmap 6.5 settled for every family.
#[derive(Debug)]
pub struct Challenges<'client> {
    client: &'client ConnectedClient,
}

impl<'client> Challenges<'client> {
    /// Binds this family to a connected client.
    #[must_use]
    pub const fn new(client: &'client ConnectedClient) -> Self {
        Self { client }
    }

    /// Asks the agent for a fresh challenge word list.
    ///
    /// The strength is a required argument, where the reference defaults it to 128 and writes that
    /// default into the query — so what is asked for is visible at the call site.
    /// [`ChallengeStrength::BITS_128`] is the reference's value.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer, [`ClientError::Api`] when the body
    /// is not a challenge, and the request, transport, and authentication failures
    /// [`ConnectedClient::fetch`] returns.
    pub async fn generate(&self, strength: ChallengeStrength) -> Result<Challenge, ClientError> {
        let path = ResourcePath::builder()
            .segment(CHALLENGES_SEGMENT)
            .parameter(STRENGTH_PARAMETER, &strength.bits().to_string())
            .build()?;
        let response = self.client.fetch(ClientRequest::new(Method::Get, path)).await?;
        decode_json(response.body())
    }

    /// Asks the agent to check that one identifier signed these words.
    ///
    /// The answer is a *long-running operation*, not a verdict: the agent has to find the exchange
    /// message. Drive it through [`Poller`](crate::operation::Poller), whose completed response
    /// carries the `exn` that answered — which is where [`Self::responded`]'s SAID comes from.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::EmptyChallengeWords`] when no words are given — where the reference
    /// asks the agent to confirm that nothing was signed — and whatever [`Self::generate`] returns.
    pub async fn verify(&self, source: &IdentifierPrefix, words: &[String]) -> Result<ChallengeOperation, ClientError> {
        if words.is_empty() {
            return Err(ClientError::EmptyChallengeWords);
        }
        let mut body = Sad::new();
        body.insert(
            CHALLENGE_WORDS_LABEL,
            SadValue::Array(words.iter().map(|word| SadValue::text(word.clone())).collect()),
        )
        .map_err(sad_error)?;
        let request =
            ClientRequest::new(Method::Post, Self::verify_path(source)?).body(body.to_json_bytes().map_err(sad_error)?);
        let response = self.client.fetch(request).await?;
        decode_json(response.body())
    }

    /// Records that a challenge answer was accepted.
    ///
    /// This is what writes the `authenticated` verdict into the challenged identifier's contact
    /// record, which [`contacts`](crate::endpoint::contacts) then reports. The SAID names the
    /// exchange message that answered — [`Self::verify`]'s completed operation carries it.
    ///
    /// Nothing is returned: the reference hands back the platform `Response` without reading it, so
    /// there is nothing a caller could use. A non-success status is already
    /// [`ClientError::Status`].
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::generate`] returns, apart from the decode failures.
    pub async fn responded(&self, source: &IdentifierPrefix, said: &Said) -> Result<(), ClientError> {
        let mut body = Sad::new();
        body.insert("said", said.qb64()?).map_err(sad_error)?;
        let request =
            ClientRequest::new(Method::Put, Self::verify_path(source)?).body(body.to_json_bytes().map_err(sad_error)?);
        self.client.fetch(request).await.map(|_| ())
    }

    /// Answers a challenge by signing its words into an exchange message.
    ///
    /// `alias` names the identifier being challenged — the one that signs and the one the message
    /// is posted under, which upstream are two arguments that need not agree (see
    /// [`Exchanges`](crate::endpoint::exchanges::Exchanges)). The message goes out on
    /// [`CHALLENGE_RESPONSE_ROUTE`] under [`CHALLENGE_TOPIC`], addressed and delivered to
    /// `recipient` — the challenger, who will then ask their own agent to
    /// [`verify`](Self::verify) it.
    ///
    /// The timestamp is a required argument, where the reference reads the system clock: a
    /// message's `dt` is inside its SAID and inside every signature over it. That is Roadmap 3.8's
    /// decision, applied again.
    ///
    /// An **empty word list** is refused, as [`Self::verify`] refuses one: it would answer a
    /// challenge nobody issued.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::EmptyChallengeWords`] for an empty word list, plus whatever
    /// [`Exchanges::send`](crate::endpoint::exchanges::Exchanges::send) returns.
    pub async fn respond(
        &self,
        alias: &str,
        recipient: &IdentifierPrefix,
        words: &[String],
        timestamp: Timestamp,
    ) -> Result<SentExchange, ClientError> {
        if words.is_empty() {
            return Err(ClientError::EmptyChallengeWords);
        }
        let mut payload = Sad::new();
        payload
            .insert(
                CHALLENGE_WORDS_LABEL,
                SadValue::Array(words.iter().map(|word| SadValue::text(word.clone())).collect()),
            )
            .map_err(sad_error)?;
        let draft = ExchangeDraft::new(CHALLENGE_RESPONSE_ROUTE, recipient.clone(), timestamp).payload(payload);
        self.client
            .exchanges()
            .send(alias, CHALLENGE_TOPIC, &draft, core::slice::from_ref(recipient))
            .await
    }

    /// Builds the path `verify` and `responded` share.
    fn verify_path(source: &IdentifierPrefix) -> Result<ResourcePath, ClientError> {
        Ok(ResourcePath::builder()
            .segment(CHALLENGES_VERIFY_SEGMENT)
            .segment(&source.qb64()?)
            .build()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const SOURCE: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
    const SAID: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

    /// The twelve words the pinned unit test uses.
    const WORDS: [&str; 12] = [
        "shell", "gloom", "mimic", "cereal", "stool", "furnace", "nominee", "nation", "sauce", "sausage", "rather",
        "venue",
    ];

    fn source() -> Result<IdentifierPrefix, Box<dyn Error>> {
        Ok(IdentifierPrefix::from_qb64(SOURCE)?)
    }

    fn words() -> Vec<String> {
        WORDS.iter().map(|word| (*word).to_owned()).collect()
    }

    fn generate_path(strength: ChallengeStrength) -> Result<ResourcePath, Box<dyn Error>> {
        Ok(ResourcePath::builder()
            .segment(CHALLENGES_SEGMENT)
            .parameter(STRENGTH_PARAMETER, &strength.bits().to_string())
            .build()?)
    }

    #[test]
    fn the_path_constants_are_the_references_own() {
        assert_eq!(CHALLENGES_SEGMENT, "challenges");
        assert_eq!(CHALLENGES_VERIFY_SEGMENT, "challenges_verify");
        assert_eq!(STRENGTH_PARAMETER, "strength");
        assert_eq!(CHALLENGE_RESPONSE_ROUTE, "/challenge/response");
        assert_eq!(CHALLENGE_TOPIC, "challenge");
        // The generation and verification resources are genuinely different addresses.
        assert_ne!(CHALLENGES_SEGMENT, CHALLENGES_VERIFY_SEGMENT);
    }

    #[test]
    fn a_generation_addresses_the_pinned_path() -> Result<(), Box<dyn Error>> {
        assert_eq!(
            generate_path(ChallengeStrength::BITS_128)?.as_str(),
            "/challenges?strength=128"
        );
        assert_eq!(
            generate_path(ChallengeStrength::BITS_256)?.as_str(),
            "/challenges?strength=256"
        );
        // Roadmap 3.10 strips the query, so every strength signs the same path.
        assert_eq!(generate_path(ChallengeStrength::BITS_128)?.path(), "/challenges");
        Ok(())
    }

    #[test]
    fn the_default_strength_is_the_references_own() -> Result<(), Box<dyn Error>> {
        assert_eq!(ChallengeStrength::default(), ChallengeStrength::BITS_128);
        // And the request it makes is indistinguishable from naming 128 outright.
        assert_eq!(
            generate_path(ChallengeStrength::default())?.as_str(),
            generate_path(ChallengeStrength::BITS_128)?.as_str()
        );
        Ok(())
    }

    #[test]
    fn only_the_five_entropy_sizes_bip39_defines_are_accepted() {
        for bits in ChallengeStrength::DECLARED {
            assert!(ChallengeStrength::new(bits).is_ok(), "{bits} was refused");
        }
        // Everything the reference stringifies straight into the query and no generator accepts.
        for bits in [0_u32, 1, 127, 129, 160 - 1, 255, 257, 512, u32::MAX] {
            assert!(
                ChallengeStrength::new(bits).is_err(),
                "{bits} was accepted as an entropy size"
            );
        }
    }

    #[test]
    fn a_strength_names_the_word_count_bip39_gives_it() {
        // One word per eleven bits of entropy plus checksum: `bits / 32 * 3`.
        assert_eq!(ChallengeStrength::BITS_128.word_count(), 12);
        assert_eq!(ChallengeStrength::BITS_160.word_count(), 15);
        assert_eq!(ChallengeStrength::BITS_192.word_count(), 18);
        assert_eq!(ChallengeStrength::BITS_224.word_count(), 21);
        assert_eq!(ChallengeStrength::BITS_256.word_count(), 24);
        // Which is the length of the pinned unit test's own list.
        assert_eq!(
            usize::try_from(ChallengeStrength::BITS_128.word_count()).unwrap_or_default(),
            WORDS.len()
        );
    }

    #[test]
    fn both_verification_calls_share_one_address() -> Result<(), Box<dyn Error>> {
        let path = Challenges::verify_path(&source()?)?;
        assert_eq!(path.as_str(), format!("/challenges_verify/{SOURCE}"));
        assert_eq!(path.query(), None);
        assert_eq!(path.path().split('/').count(), 3);
        Ok(())
    }

    #[test]
    fn a_value_that_would_escape_the_path_is_not_an_identifier_prefix() {
        // The reference interpolates any string into both verification paths.
        for hostile in ["a/b?c=d", "", "../identifiers", "not a prefix", "EG2XjQN"] {
            assert!(
                IdentifierPrefix::from_qb64(hostile).is_err(),
                "{hostile:?} was accepted as a challenged identifier"
            );
        }
    }

    #[test]
    fn a_verification_body_is_the_word_list() -> Result<(), Box<dyn Error>> {
        let mut body = Sad::new();
        body.insert(
            "words",
            SadValue::Array(words().into_iter().map(SadValue::Text).collect()),
        )?;
        let rendered = String::from_utf8(body.to_json_bytes()?)?;
        assert_eq!(
            rendered,
            r#"{"words":["shell","gloom","mimic","cereal","stool","furnace","nominee","nation","sauce","sausage","rather","venue"]}"#
        );
        Ok(())
    }

    #[test]
    fn a_response_writes_the_same_label_the_verification_does() -> Result<(), Box<dyn Error>> {
        // `verify` sends `{"words": …}` to the agent and `respond` writes the same label into the
        // message's attribute block; upstream they are two separate literals.
        assert_eq!(CHALLENGE_WORDS_LABEL, "words");

        let words = words();
        let mut verification = Sad::new();
        verification.insert(
            CHALLENGE_WORDS_LABEL,
            SadValue::Array(words.iter().map(|word| SadValue::text(word.clone())).collect()),
        )?;
        let mut attributes = Sad::new();
        attributes.insert(
            CHALLENGE_WORDS_LABEL,
            SadValue::Array(words.iter().map(|word| SadValue::text(word.clone())).collect()),
        )?;
        assert_eq!(verification.to_json_bytes()?, attributes.to_json_bytes()?);
        Ok(())
    }

    #[test]
    fn a_response_is_addressed_and_routed_by_the_references_own_constants() -> Result<(), Box<dyn Error>> {
        let recipient = IdentifierPrefix::from_qb64(SOURCE)?;
        let draft = ExchangeDraft::new(
            CHALLENGE_RESPONSE_ROUTE,
            recipient.clone(),
            "2023-11-14T22:13:20.123000+00:00".parse()?,
        );
        assert_eq!(draft.route(), "/challenge/response");
        // The challenger is both the addressee and the one recipient: unlike a multisig proposal,
        // an answer has exactly one reader.
        assert_eq!(draft.addressee(), &recipient);
        assert_eq!(CHALLENGE_TOPIC, "challenge");
        Ok(())
    }

    #[test]
    fn an_acceptance_body_is_the_exchange_said() -> Result<(), Box<dyn Error>> {
        let mut body = Sad::new();
        body.insert("said", Said::from_qb64(SAID)?.qb64()?)?;
        assert_eq!(
            String::from_utf8(body.to_json_bytes()?)?,
            format!(r#"{{"said":"{SAID}"}}"#)
        );
        Ok(())
    }

    #[test]
    fn a_said_that_names_no_message_is_refused() {
        // It reaches the body rather than the path, so it can change no address — but an
        // unparseable one records an acceptance of nothing.
        for hostile in ["E/../x?y=1", "", "not a said", "EBfdlu8R27Fbx"] {
            assert!(Said::from_qb64(hostile).is_err(), "{hostile:?} was accepted as a SAID");
        }
        assert!(Said::from_qb64(SAID).is_ok());
    }

    #[test]
    fn an_answer_of_the_wrong_shape_is_refused() {
        // The reference casts each of these and hands it to the caller.
        for wrong in [r#"{"unexpected":true}"#, "[]", "null", r#"{"dt":"2023-01-01"}"#] {
            assert!(
                serde_json::from_str::<Challenge>(wrong).is_err(),
                "{wrong} was accepted as a challenge"
            );
        }
        for wrong in [r#"{"unexpected":true}"#, r#"{"name":"challenge.E"}"#, "null"] {
            assert!(
                serde_json::from_str::<ChallengeOperation>(wrong).is_err(),
                "{wrong} was accepted as a challenge operation"
            );
        }
    }

    #[test]
    fn a_well_formed_challenge_decodes_with_its_verdict() -> Result<(), Box<dyn Error>> {
        let bare: Challenge = serde_json::from_str(r#"{"words":["shell","gloom"]}"#)?;
        assert_eq!(bare.words.len(), 2);
        // A freshly generated challenge has been answered by nobody, so all three stay absent.
        assert_eq!(bare.stamp, None);
        assert_eq!(bare.said, None);
        assert_eq!(bare.authenticated, None);

        // An answered one carries the verdict `responded` recorded.
        let answered: Challenge = serde_json::from_str(&format!(
            r#"{{"words":["shell"],"dt":"2023-11-14T22:13:20.123000+00:00","said":"{SAID}","authenticated":true}}"#
        ))?;
        assert_eq!(answered.authenticated, Some(true));
        assert_eq!(answered.said.as_deref(), Some(SAID));
        // And a refused one is told apart from an unanswered one.
        let refused: Challenge = serde_json::from_str(r#"{"words":["shell"],"authenticated":false}"#)?;
        assert_eq!(refused.authenticated, Some(false));
        assert_ne!(refused.authenticated, None);
        Ok(())
    }
}
