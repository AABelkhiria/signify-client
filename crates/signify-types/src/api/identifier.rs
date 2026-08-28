//! Identifier records: the local habitat KERIA keeps for each identifier a client manages.
//!
//! # The accepted/pending split
//!
//! A multisig group identifier exists locally before its inception is complete: the members are
//! still collecting one another's signatures, so the group has a name, a prefix, and key-manager
//! state, but no key state. Upstream models that with two type aliases over one schema — `HabState`
//! when `state` is present and `PendingHabState` when it is not — plus an `isAccepted` type guard
//! and a `requireKeyState` helper that throws.
//!
//! Here it is one enum. [`Hab::Accepted`] owns the key state, so reading it is a `match` rather
//! than a guard, and the throw has nothing to be: there is no value from which key state can be
//! demanded and be absent.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::error::ApiError;
use super::key_state::KeyState;

/// The security tier a salty key manager derives its keys under.
///
/// This is the wire spelling KERIA stores in a salty identifier's state. The Argon2id cost profile
/// it selects lives in `signify_crypto::salt::SecurityTier`, which this crate cannot reference:
/// `ARCHITECTURE.md` §4.3 keeps `signify-types` free of workspace dependencies so every upper crate
/// can depend on it. The two are converted where both are in scope, which is
/// `signify-keri::manager` (Roadmap 4.2).
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum KeyTier {
    /// Interactive profile.
    #[default]
    #[serde(rename = "low")]
    Low,
    /// Moderate profile.
    #[serde(rename = "med")]
    Medium,
    /// Sensitive profile.
    #[serde(rename = "high")]
    High,
}

impl KeyTier {
    /// Every tier the schema declares, in declaration order.
    pub const ALL: [Self; 3] = [Self::Low, Self::Medium, Self::High];

    /// Returns the exact wire text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "med",
            Self::High => "high",
        }
    }
}

/// State of a salty key manager: keys derived deterministically from an encrypted salt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SaltyState {
    /// Security tier the keys were derived under.
    pub tier: KeyTier,
    /// Encrypted salt, wire label `sxlt`.
    ///
    /// Ciphertext rather than a secret in the clear, but still not something to log.
    #[serde(rename = "sxlt")]
    pub encrypted_salt: String,
    /// Key-pair index, wire label `pidx`.
    #[serde(rename = "pidx")]
    pub key_pair_index: u32,
    /// Key index within the pair, wire label `kidx`.
    #[serde(rename = "kidx")]
    pub key_index: u32,
    /// Derivation-path stem.
    pub stem: String,
    /// Digest derivation code for the identifier prefix, wire label `dcode`.
    #[serde(rename = "dcode")]
    pub digest_code: String,
    /// Derivation codes of the current signing keys, wire label `icodes`.
    #[serde(rename = "icodes")]
    pub inception_codes: Vec<String>,
    /// Derivation codes of the next signing keys, wire label `ncodes`.
    #[serde(rename = "ncodes")]
    pub next_codes: Vec<String>,
    /// Whether the identifier can rotate.
    pub transferable: bool,
}

/// State of a randy key manager: randomly generated keys held encrypted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RandyState {
    /// Encrypted current signing keys, wire label `prxs`.
    #[serde(rename = "prxs")]
    pub encrypted_signing_keys: Vec<String>,
    /// Encrypted next signing keys, wire label `nxts`.
    #[serde(rename = "nxts")]
    pub encrypted_next_keys: Vec<String>,
}

/// State of a multisig group key manager.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GroupState {
    /// The local member identifier participating in the group, wire label `mhab`.
    ///
    /// The schema types this as the full habitat record, which would admit a member whose own
    /// inception is still pending. Upstream narrows it by hand to the accepted form, because a
    /// member must be fully inceptioned before it can sign for the group; that narrowing is kept.
    #[serde(rename = "mhab")]
    pub member: AcceptedHab,
    /// Current signing keys of every group member.
    pub keys: Vec<String>,
    /// Digests committing to the next signing keys of every member, wire label `ndigs`.
    #[serde(rename = "ndigs")]
    pub next_key_digests: Vec<String>,
}

/// State of an external key manager, such as an HSM or KMS.
///
/// The schema declares two fields and an open index signature, so whatever else the module stores
/// is captured and survives a round trip.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ExternState {
    /// Module name the agent dispatches to, wire label `extern_type`.
    pub extern_type: String,
    /// Key-pair index, wire label `pidx`.
    #[serde(rename = "pidx")]
    pub key_pair_index: u32,
    /// Every module-specific field the schema does not name, preserved as received.
    #[serde(flatten)]
    pub additional: Map<String, Value>,
}

/// Which key manager holds an identifier's keys.
///
/// Exactly one applies. The schema states that as a union of four single-field objects; a record
/// naming none or naming two is refused at decoding.
///
/// The four algorithms are a closed set the schema defines, so this enum is deliberately
/// exhaustive: a key manager must dispatch on all of them, and a fifth would be a protocol change
/// rather than an addition.
#[derive(Clone, Debug, PartialEq)]
pub enum KeyManagerState {
    /// Keys derived deterministically from an encrypted salt.
    Salty(SaltyState),
    /// Randomly generated keys held encrypted.
    Randy(RandyState),
    /// A multisig group.
    ///
    /// Boxed because a group names its local member, which is itself an identifier record.
    Group(Box<GroupState>),
    /// An externally managed key store.
    Extern(ExternState),
}

impl KeyManagerState {
    /// Returns the wire label this state is carried under.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Salty(_) => "salty",
            Self::Randy(_) => "randy",
            Self::Group(_) => "group",
            Self::Extern(_) => "extern",
        }
    }
}

/// A witness index as an agent writes it.
///
/// The reference's generated schema declares `windexes` a `string[]`, and a live KERIA 1.0.1
/// writes JSON numbers — `"windexes": [0, 1, 2]` — found by Roadmap 9.2c's wave 4, the first time
/// a *witnessed* identifier's record ever reached this decoder from a real agent; every checked-in
/// fixture carries the empty list, where the two spellings cannot disagree. The reference never
/// notices, because it casts the record instead of decoding it. Both spellings are accepted here
/// and neither is rewritten into the other, exactly as
/// [`EchoedSequence`](crate::api::EchoedSequence) keeps a sequence number's spelling.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum WitnessIndex {
    /// A JSON number, which is what a live KERIA writes.
    Number(u64),
    /// A JSON string, which is what the reference's generated schema declares.
    Text(String),
}

/// Everything an identifier record carries whether or not its inception is complete.
#[derive(Clone, Debug, PartialEq)]
pub struct HabCommon {
    /// Local alias the client gave this identifier.
    pub name: String,
    /// Identifier prefix.
    pub prefix: String,
    /// Inception timestamp, wire label `icp_dt`.
    pub inception_stamp: String,
    /// Whether the identifier can rotate.
    pub transferable: Option<bool>,
    /// Indexes of the witnesses this client is responsible for, wire label `windexes`, each kept
    /// in the spelling it arrived as.
    pub witness_indexes: Option<Vec<WitnessIndex>>,
    /// Which key manager holds the keys.
    pub key_manager: KeyManagerState,
}

/// A fully inceptioned identifier, whose key state is present.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(try_from = "HabRepr", into = "HabRepr")]
pub struct AcceptedHab {
    /// Fields shared with a pending identifier.
    pub common: HabCommon,
    /// Current key state.
    ///
    /// Boxed because a key state is several times the size of everything around it, which would
    /// otherwise make every [`Hab`] as large as its accepted form even while pending.
    pub state: Box<KeyState>,
}

/// A multisig group whose inception is still collecting member signatures.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(try_from = "HabRepr", into = "HabRepr")]
pub struct PendingHab {
    /// Fields shared with an accepted identifier.
    pub common: HabCommon,
}

/// One identifier record, accepted or still pending.
///
/// ```
/// use signify_types::api::{Hab, KeyManagerState};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let body = br#"{"name":"group","prefix":"EGRP","icp_dt":"2023-12-01T10:05:25.062609+00:00",
///   "transferable":true,"windexes":[],"randy":{"prxs":[],"nxts":[]}}"#;
///
/// let hab: Hab = serde_json::from_slice(body)?;
/// // No key state, so there is nothing to demand and no guard to forget.
/// assert!(matches!(hab, Hab::Pending(_)));
/// assert_eq!(hab.key_state(), None);
/// assert_eq!(hab.common().name, "group");
/// assert!(matches!(hab.common().key_manager, KeyManagerState::Randy(_)));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(try_from = "HabRepr", into = "HabRepr")]
pub enum Hab {
    /// Inception is complete and key state is present.
    Accepted(AcceptedHab),
    /// Inception is still collecting signatures.
    Pending(PendingHab),
}

impl Hab {
    /// Returns the fields both forms carry.
    #[must_use]
    pub const fn common(&self) -> &HabCommon {
        match self {
            Self::Accepted(hab) => &hab.common,
            Self::Pending(hab) => &hab.common,
        }
    }

    /// Returns the key state, or `None` while inception is still pending.
    ///
    /// This replaces upstream's `requireKeyState`, which throws instead.
    #[must_use]
    pub const fn key_state(&self) -> Option<&KeyState> {
        match self {
            Self::Accepted(hab) => Some(&hab.state),
            Self::Pending(_) => None,
        }
    }
}

impl From<AcceptedHab> for Hab {
    fn from(hab: AcceptedHab) -> Self {
        Self::Accepted(hab)
    }
}

impl From<PendingHab> for Hab {
    fn from(hab: PendingHab) -> Self {
        Self::Pending(hab)
    }
}

/// The flat document shape both forms decode from and encode to.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct HabRepr {
    name: String,
    prefix: String,
    icp_dt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state: Option<KeyState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transferable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    windexes: Option<Vec<WitnessIndex>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    salty: Option<SaltyState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    randy: Option<RandyState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    group: Option<Box<GroupState>>,
    #[serde(rename = "extern", default, skip_serializing_if = "Option::is_none")]
    external: Option<ExternState>,
}

impl HabRepr {
    /// Splits the flat document into the shared fields and the one key-manager state it names.
    fn into_parts(self) -> Result<(HabCommon, Option<KeyState>), ApiError> {
        let named: [(&'static str, bool); 4] = [
            ("salty", self.salty.is_some()),
            ("randy", self.randy.is_some()),
            ("group", self.group.is_some()),
            ("extern", self.external.is_some()),
        ];
        let mut present = named.into_iter().filter(|(_, found)| *found).map(|(name, _)| name);
        let (Some(first), second) = (present.next(), present.next()) else {
            return Err(ApiError::MissingKeyManagerState);
        };
        if let Some(second) = second {
            return Err(ApiError::AmbiguousKeyManagerState { names: [first, second] });
        }

        let key_manager = match (self.salty, self.randy, self.group, self.external) {
            (Some(salty), ..) => KeyManagerState::Salty(salty),
            (_, Some(randy), ..) => KeyManagerState::Randy(randy),
            (_, _, Some(group), _) => KeyManagerState::Group(group),
            (_, _, _, Some(external)) => KeyManagerState::Extern(external),
            // Unreachable: exactly one was found above, but expressed as a value rather than a
            // panic so no branch of this crate can abort.
            (None, None, None, None) => return Err(ApiError::MissingKeyManagerState),
        };

        Ok((
            HabCommon {
                name: self.name,
                prefix: self.prefix,
                inception_stamp: self.icp_dt,
                transferable: self.transferable,
                witness_indexes: self.windexes,
                key_manager,
            },
            self.state,
        ))
    }

    /// Rebuilds the flat document from the shared fields and an optional key state.
    fn from_parts(common: HabCommon, state: Option<KeyState>) -> Self {
        let mut repr = Self {
            name: common.name,
            prefix: common.prefix,
            icp_dt: common.inception_stamp,
            state,
            transferable: common.transferable,
            windexes: common.witness_indexes,
            salty: None,
            randy: None,
            group: None,
            external: None,
        };
        match common.key_manager {
            KeyManagerState::Salty(salty) => repr.salty = Some(salty),
            KeyManagerState::Randy(randy) => repr.randy = Some(randy),
            KeyManagerState::Group(group) => repr.group = Some(group),
            KeyManagerState::Extern(external) => repr.external = Some(external),
        }
        repr
    }
}

impl TryFrom<HabRepr> for Hab {
    type Error = ApiError;

    fn try_from(repr: HabRepr) -> Result<Self, Self::Error> {
        let (common, state) = repr.into_parts()?;
        Ok(match state {
            Some(state) => Self::Accepted(AcceptedHab {
                common,
                state: Box::new(state),
            }),
            None => Self::Pending(PendingHab { common }),
        })
    }
}

impl From<Hab> for HabRepr {
    fn from(hab: Hab) -> Self {
        match hab {
            Hab::Accepted(hab) => Self::from_parts(hab.common, Some(*hab.state)),
            Hab::Pending(hab) => Self::from_parts(hab.common, None),
        }
    }
}

impl TryFrom<HabRepr> for AcceptedHab {
    type Error = ApiError;

    fn try_from(repr: HabRepr) -> Result<Self, Self::Error> {
        let (common, state) = repr.into_parts()?;
        let state = state.ok_or(ApiError::MissingKeyState)?;
        Ok(Self {
            common,
            state: Box::new(state),
        })
    }
}

impl From<AcceptedHab> for HabRepr {
    fn from(hab: AcceptedHab) -> Self {
        Self::from_parts(hab.common, Some(*hab.state))
    }
}

impl TryFrom<HabRepr> for PendingHab {
    type Error = ApiError;

    fn try_from(repr: HabRepr) -> Result<Self, Self::Error> {
        let (common, state) = repr.into_parts()?;
        if state.is_some() {
            return Err(ApiError::UnexpectedKeyState);
        }
        Ok(Self { common })
    }
}

impl From<PendingHab> for HabRepr {
    fn from(hab: PendingHab) -> Self {
        Self::from_parts(hab.common, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    /// The `HabState` literal the pinned `test/app/registry.test.ts` declares, with the key state
    /// it declares alongside it.
    const PENDING_SOURCE: &str = r#"{"name":"test-hab","prefix":"hab prefix","icp_dt":"2023-12-01T10:05:25.062609+00:00","transferable":false,"windexes":[],"randy":{"prxs":[],"nxts":[]}}"#;
    /// The `KeyState` literal the same file declares, respelled in the schema's field order —
    /// upstream writes `s` and `d` first, which is a spelling the schema does not use and which
    /// re-encoding therefore does not reproduce.
    const KEY_STATE: &str = r#"{"i":"","s":"0","p":"","d":"a digest","f":"","dt":"","et":"","kt":"","k":[],"nt":"","n":[],"bt":"","b":[],"c":[],"ee":{"s":"","d":"","br":[],"ba":[]},"di":""}"#;

    fn accepted_source() -> String {
        PENDING_SOURCE.replace(r#""transferable""#, &format!(r#""state":{KEY_STATE},"transferable""#))
    }

    #[test]
    fn a_record_with_key_state_is_accepted_and_one_without_is_pending() -> Result<(), Box<dyn Error>> {
        let pending: Hab = serde_json::from_str(PENDING_SOURCE)?;
        assert!(matches!(pending, Hab::Pending(_)));
        assert_eq!(pending.key_state(), None);
        assert_eq!(pending.common().name, "test-hab");
        assert_eq!(pending.common().inception_stamp, "2023-12-01T10:05:25.062609+00:00");
        assert_eq!(pending.common().transferable, Some(false));
        assert_eq!(pending.common().key_manager.label(), "randy");
        assert_eq!(serde_json::to_string(&pending)?, PENDING_SOURCE);

        let source = accepted_source();
        let accepted: Hab = serde_json::from_str(&source)?;
        assert!(matches!(accepted, Hab::Accepted(_)));
        assert_eq!(
            accepted.key_state().map(|state| state.digest.as_str()),
            Some("a digest")
        );
        assert_eq!(serde_json::to_string(&accepted)?, source);
        Ok(())
    }

    #[test]
    fn witness_indexes_keep_the_spelling_they_arrived_as() -> Result<(), Box<dyn Error>> {
        // A live KERIA 1.0.1 writes numbers, the reference's generated schema declares strings,
        // and every checked-in fixture carries the empty list where the two cannot disagree —
        // found by Roadmap 9.2c's wave 4, the first witnessed record to reach this decoder from a
        // real agent. Both decode, and each re-encodes as it arrived.
        let numeric = PENDING_SOURCE.replace(r#""windexes":[]"#, r#""windexes":[0,1,2]"#);
        let hab: Hab = serde_json::from_str(&numeric)?;
        assert_eq!(
            hab.common().witness_indexes,
            Some(vec![
                WitnessIndex::Number(0),
                WitnessIndex::Number(1),
                WitnessIndex::Number(2)
            ])
        );
        assert_eq!(serde_json::to_string(&hab)?, numeric);

        let textual = PENDING_SOURCE.replace(r#""windexes":[]"#, r#""windexes":["0","1"]"#);
        let hab: Hab = serde_json::from_str(&textual)?;
        assert_eq!(
            hab.common().witness_indexes,
            Some(vec![
                WitnessIndex::Text("0".to_owned()),
                WitnessIndex::Text("1".to_owned())
            ])
        );
        assert_eq!(serde_json::to_string(&hab)?, textual);
        Ok(())
    }

    #[test]
    fn a_witness_index_that_is_neither_spelling_is_refused() {
        // A negative, a fraction, and a structure are none of the things either source declares.
        for value in ["-1", "1.5", "{}", "[[]]", "true"] {
            let source = PENDING_SOURCE.replace(r#""windexes":[]"#, &format!(r#""windexes":[{value}]"#));
            assert!(
                serde_json::from_str::<Hab>(&source).is_err(),
                "windexes [{value}] decoded"
            );
        }
    }

    #[test]
    fn the_narrow_forms_accept_only_their_own_half() -> Result<(), Box<dyn Error>> {
        let source = accepted_source();
        let accepted: AcceptedHab = serde_json::from_str(&source)?;
        assert_eq!(accepted.state.digest, "a digest");
        assert_eq!(serde_json::to_string(&accepted)?, source);
        assert!(serde_json::from_str::<AcceptedHab>(PENDING_SOURCE).is_err());

        let pending: PendingHab = serde_json::from_str(PENDING_SOURCE)?;
        assert_eq!(pending.common.prefix, "hab prefix");
        assert_eq!(serde_json::to_string(&pending)?, PENDING_SOURCE);
        assert!(serde_json::from_str::<PendingHab>(&source).is_err());

        assert!(matches!(Hab::from(accepted), Hab::Accepted(_)));
        assert!(matches!(Hab::from(pending), Hab::Pending(_)));
        Ok(())
    }

    #[test]
    fn a_record_must_name_exactly_one_key_manager() -> Result<(), Box<dyn Error>> {
        let none = r#"{"name":"a","prefix":"E","icp_dt":"2023-12-01T10:05:25.062609+00:00"}"#;
        let error = serde_json::from_str::<Hab>(none)
            .map(|_| ())
            .err()
            .ok_or("a record naming no key manager was accepted")?
            .to_string();
        assert!(error.contains("no key-manager state"), "{error}");

        let two = r#"{"name":"a","prefix":"E","icp_dt":"2023-12-01T10:05:25.062609+00:00","randy":{"prxs":[],"nxts":[]},"extern":{"extern_type":"m","pidx":0}}"#;
        let error = serde_json::from_str::<Hab>(two)
            .map(|_| ())
            .err()
            .ok_or("a record naming two key managers was accepted")?
            .to_string();
        assert!(error.contains("randy"), "{error}");
        assert!(error.contains("extern"), "{error}");
        Ok(())
    }

    #[test]
    fn every_key_manager_state_round_trips() -> Result<(), Box<dyn Error>> {
        let salty = r#"{"name":"aid1","prefix":"ELUv","icp_dt":"2023-08-21T22:30:46.473545+00:00","salty":{"tier":"low","sxlt":"1AAH","pidx":0,"kidx":0,"stem":"signify:aid","dcode":"E","icodes":["A"],"ncodes":["A"],"transferable":true}}"#;
        let hab: Hab = serde_json::from_str(salty)?;
        let KeyManagerState::Salty(state) = &hab.common().key_manager else {
            return Err("a salty record decoded as something else".into());
        };
        assert_eq!(state.tier, KeyTier::Low);
        assert_eq!(state.stem, "signify:aid");
        assert_eq!(serde_json::to_string(&hab)?, salty);

        let external = r#"{"name":"hsm","prefix":"EHSM","icp_dt":"2023-08-21T22:30:46.473545+00:00","extern":{"extern_type":"module","pidx":1,"slot":"7"}}"#;
        let hab: Hab = serde_json::from_str(external)?;
        let KeyManagerState::Extern(state) = &hab.common().key_manager else {
            return Err("an extern record decoded as something else".into());
        };
        assert_eq!(state.key_pair_index, 1);
        // The schema's index signature means module-specific fields survive.
        assert_eq!(state.additional.get("slot").and_then(Value::as_str), Some("7"));
        assert_eq!(serde_json::to_string(&hab)?, external);
        Ok(())
    }

    #[test]
    fn a_group_names_a_member_that_is_already_inceptioned() -> Result<(), Box<dyn Error>> {
        let member = accepted_source();
        let group = format!(
            r#"{{"name":"multisig","prefix":"EGRP","icp_dt":"2023-12-01T10:05:25.062609+00:00","group":{{"mhab":{member},"keys":["DAA"],"ndigs":["EAA"]}}}}"#
        );
        let hab: Hab = serde_json::from_str(&group)?;
        let KeyManagerState::Group(state) = &hab.common().key_manager else {
            return Err("a group record decoded as something else".into());
        };
        assert_eq!(state.member.state.digest, "a digest");
        assert_eq!(state.keys, ["DAA"]);
        assert_eq!(serde_json::to_string(&hab)?, group);

        // A member whose own inception is still pending cannot be a group member.
        let pending_member = format!(
            r#"{{"name":"multisig","prefix":"EGRP","icp_dt":"2023-12-01T10:05:25.062609+00:00","group":{{"mhab":{PENDING_SOURCE},"keys":[],"ndigs":[]}}}}"#
        );
        assert!(serde_json::from_str::<Hab>(&pending_member).is_err());
        Ok(())
    }

    #[test]
    fn a_key_tier_accepts_only_the_three_declared_values() -> Result<(), Box<dyn Error>> {
        for (tier, text) in [(KeyTier::Low, "low"), (KeyTier::Medium, "med"), (KeyTier::High, "high")] {
            assert_eq!(serde_json::to_string(&tier)?, format!(r#""{text}""#));
            assert_eq!(serde_json::from_str::<KeyTier>(&format!(r#""{text}""#))?, tier);
            assert_eq!(tier.as_str(), text);
        }
        assert_eq!(KeyTier::default(), KeyTier::Low);
        assert_eq!(KeyTier::ALL.len(), 3);
        for wrong in [r#""medium""#, r#""LOW""#, r#""ultra""#, r#""""#] {
            assert!(serde_json::from_str::<KeyTier>(wrong).is_err(), "{wrong} was accepted");
        }
        Ok(())
    }

    #[test]
    fn nested_groups_are_bounded_by_the_json_nesting_limit() {
        // A hostile agent could nest member records without end; the parser stops before the
        // stack does.
        let mut document = accepted_source();
        for _ in 0..super::super::MAX_NESTING_DEPTH {
            document = format!(
                r#"{{"name":"g","prefix":"E","icp_dt":"2023-12-01T10:05:25.062609+00:00","group":{{"mhab":{document},"keys":[],"ndigs":[]}}}}"#
            );
        }
        assert!(serde_json::from_str::<Hab>(&document).is_err());
    }
}
