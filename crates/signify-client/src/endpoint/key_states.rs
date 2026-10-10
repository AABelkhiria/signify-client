//! The key-states endpoint: what an agent believes about other identifiers, and how to refresh it.
//!
//! Three reads and one write: [`KeyStates::get`] for one identifier, [`KeyStates::list`] for
//! several, and [`KeyStates::query`], which asks the agent to go and *find out* — returning a
//! long-running operation rather than a state. This ports `KeyStates` from the pinned
//! `src/keri/app/coring.ts`.
//!
//! # The query's two ambiguous arguments
//!
//! `query(pre, sn?, anchor?)` upstream takes `sn?: string` and `anchor?: any`, and the pinned tree
//! disagrees with itself about both. Neither is guessed at here:
//!
//! - **The sequence number has no settled base.** The parameter is declared `string`, its own
//!   `JSDoc` says `number`, and the schema's `QueryMetadata.sn` is a `number`; every literal the
//!   reference passes is a single digit, where decimal and hexadecimal agree, and the one caller
//!   that passes a computed value hands over a key state's `s` — a field the protocol writes in
//!   *hexadecimal* — while the same file reads it back with a base-ten `parseInt`. So
//!   [`QuerySequence`] makes the caller choose, and the choice is visible at the call site.
//!
//!   Roadmap 9.2 then asked a deployment. Against a log of eleven events, a live KERIA 1.0.1
//!   resolved `a` and returned event ten, while `10` and `16` never resolved: **it reads the
//!   sequence number in base sixteen.** A caller who spells event ten `"10"` asks that deployment
//!   about event 16 and waits until the deadline. The evidence is recorded in
//!   `fixtures/keria-integration/observations/sequence_base.json` and asserted by
//!   `signify-keria-systest`'s `sequence_base_vectors`. It does not become a default here: one
//!   deployment is evidence about that deployment, and ADR `0030` keeps the choice with the
//!   caller — but it is now a choice made with an answer in hand rather than in the dark.
//! - **The anchor has three shapes.** The pinned unit test passes a bare SAID string, every
//!   integration caller passes a [`Seal`], and the schema types the *response* metadata's anchor as
//!   an `Anchor`. Only the integration shape has ever reached a live KERIA, so that is the one this
//!   port sends.
//!
//! See `fixtures/client-key-state/` and `PORTING.md` §10.

use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::serialization::{Sad, SadError, SadValue};
use keria_types::api::{KeyState, QueryOperation, Seal};
use signify_http::request::ResourcePath;
use signify_http::transport::Method;

use crate::client::{ClientRequest, ConnectedClient};
use crate::endpoint::decode_json;
use crate::error::ClientError;

/// Path segment the key-state resource lives under.
pub const STATES_SEGMENT: &str = "states";

/// Path segment a key-state refresh is posted to.
pub const QUERIES_SEGMENT: &str = "queries";

/// Query parameter naming an identifier; the reference's `pre`.
pub const PREFIX_PARAMETER: &str = "pre";

/// How a sequence number is rendered into a query's body.
///
/// The reference takes it as an already-rendered string and passes it through untouched, and the
/// pinned tree does not settle which base a KERIA agent reads: every literal it sends is a single
/// digit. This enum therefore refuses to pick one on the caller's behalf — the rendering is part
/// of the request, so it is part of the call.
///
/// [`Self::Decimal`] is what every recorded caller sends and what keripy's own HTTP surface reads
/// with falcon's base-ten `get_param_as_int`. [`Self::Hexadecimal`] is how a key state's own `s`
/// field is written, which is the value the reference's `singlesig-ixn` integration test forwards
/// here verbatim.
///
/// # What a deployment answered
///
/// A live KERIA 1.0.1, asked about event ten of an eleven-event log, resolved [`Self::Hexadecimal`]
/// and left both decimal spellings running until the deadline — so that deployment reads base
/// sixteen, and [`Self::Decimal`] above nine silently asks about a different event. Neither variant
/// is removed and neither becomes a default: the observation is about one deployment, and keripy's
/// own base-ten reader is still in the tree. See the module documentation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum QuerySequence {
    /// Rendered in base ten.
    Decimal(u64),
    /// Rendered in lowercase base sixteen, without a prefix — the KERI spelling.
    Hexadecimal(u64),
}

impl QuerySequence {
    /// Returns the exact text this sequence number is written as.
    #[must_use]
    pub fn to_text(self) -> String {
        match self {
            Self::Decimal(value) => value.to_string(),
            Self::Hexadecimal(value) => format!("{value:x}"),
        }
    }

    /// Returns the number itself, whichever way it is rendered.
    #[must_use]
    pub const fn value(self) -> u64 {
        match self {
            Self::Decimal(value) | Self::Hexadecimal(value) => value,
        }
    }
}

/// What to ask an agent to find out about an identifier's key state.
///
/// The reference's three positional arguments, with the two optional ones typed. A request naming
/// neither a sequence number nor an anchor asks only for the latest state, which is what the
/// reference sends when both are absent.
#[derive(Clone, Debug)]
pub struct KeyStateQuery {
    /// The identifier whose state is wanted; the reference's `pre`.
    pub prefix: IdentifierPrefix,
    /// The sequence number to wait for; the reference's `sn`.
    pub sequence_number: Option<QuerySequence>,
    /// The event to wait to see anchored; the reference's `anchor`.
    pub anchor: Option<Seal>,
}

impl KeyStateQuery {
    /// Asks only for an identifier's latest state.
    #[must_use]
    pub const fn latest(prefix: IdentifierPrefix) -> Self {
        Self {
            prefix,
            sequence_number: None,
            anchor: None,
        }
    }

    /// Asks for an identifier's state at or after one sequence number.
    #[must_use]
    pub const fn at(prefix: IdentifierPrefix, sequence_number: QuerySequence) -> Self {
        Self {
            prefix,
            sequence_number: Some(sequence_number),
            anchor: None,
        }
    }

    /// Asks for an identifier's state once it anchors one event.
    #[must_use]
    pub const fn anchoring(prefix: IdentifierPrefix, anchor: Seal) -> Self {
        Self {
            prefix,
            sequence_number: None,
            anchor: Some(anchor),
        }
    }

    /// Builds the exact JSON body the query carries.
    ///
    /// Exposed because it is the one part of a query that is pure, and because a caller may want
    /// to see what would be sent. The field order is the reference's own literal — `pre`, then
    /// `sn`, then `anchor` — and an absent field is not written, exactly as `JSON.stringify` drops
    /// an `undefined` one.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Identifier`] when the prefix cannot be encoded and
    /// [`ClientError::Serialization`] when the body cannot be written.
    pub fn body(&self) -> Result<Vec<u8>, ClientError> {
        let mut body = Sad::new();
        body.insert("pre", self.prefix.qb64()?).map_err(sad_error)?;
        if let Some(sequence_number) = self.sequence_number {
            body.insert("sn", sequence_number.to_text()).map_err(sad_error)?;
        }
        if let Some(anchor) = &self.anchor {
            body.insert("anchor", SadValue::Map(seal_document(anchor)?))
                .map_err(sad_error)?;
        }
        body.to_json_bytes().map_err(sad_error)
    }
}

/// The key-states endpoint family.
///
/// Borrowed from a connected client, so it costs nothing to hold and cannot outlive the client it
/// speaks through.
#[derive(Debug)]
pub struct KeyStates<'client> {
    client: &'client ConnectedClient,
}

impl<'client> KeyStates<'client> {
    /// Binds this family to a connected client.
    #[must_use]
    pub const fn new(client: &'client ConnectedClient) -> Self {
        Self { client }
    }

    /// Reads the agent's current key state for one identifier.
    ///
    /// The answer is a list, as upstream: an agent that knows nothing about the identifier returns
    /// an empty one rather than a failure.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer, [`ClientError::Api`] when the
    /// body is not a list of key states, and the request, transport, and authentication failures
    /// [`ConnectedClient::fetch`] returns.
    pub async fn get(&self, prefix: &IdentifierPrefix) -> Result<Vec<KeyState>, ClientError> {
        self.read(core::slice::from_ref(prefix)).await
    }

    /// Reads the agent's current key state for several identifiers at once.
    ///
    /// The prefixes become one repeated query parameter, in the order given, which is what the
    /// reference's `?pre=…&pre=…` produces.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::EmptyKeyStateListing`] when no prefix is given — where the reference
    /// sends a bare `/states?` and asks for nothing — [`ClientError::Request`] when the query
    /// exceeds Roadmap 5.3's bounds, and whatever [`Self::get`] returns.
    pub async fn list(&self, prefixes: &[IdentifierPrefix]) -> Result<Vec<KeyState>, ClientError> {
        if prefixes.is_empty() {
            return Err(ClientError::EmptyKeyStateListing);
        }
        self.read(prefixes).await
    }

    /// Asks the agent to refresh what it knows about an identifier.
    ///
    /// This returns a *long-running operation*, not a state: the agent has to go and ask. Poll it
    /// through [`operations`](crate::endpoint::operations), whose
    /// [`completed`](crate::endpoint::operations::completed) yields the key state once it arrives.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Api`] when the answer is not a query operation, and whatever
    /// [`Self::get`] returns.
    pub async fn query(&self, request: &KeyStateQuery) -> Result<QueryOperation, ClientError> {
        let path = ResourcePath::builder().segment(QUERIES_SEGMENT).build()?;
        let submitted = ClientRequest::new(Method::Post, path).body(request.body()?);
        let response = self.client.fetch(submitted).await?;
        decode_json(response.body())
    }

    /// Builds and sends the read both `get` and `list` perform.
    async fn read(&self, prefixes: &[IdentifierPrefix]) -> Result<Vec<KeyState>, ClientError> {
        let mut builder = ResourcePath::builder().segment(STATES_SEGMENT);
        for prefix in prefixes {
            builder = builder.parameter(PREFIX_PARAMETER, &prefix.qb64()?);
        }
        let response = self
            .client
            .fetch(ClientRequest::new(Method::Get, builder.build()?))
            .await?;
        decode_json(response.body())
    }
}

/// Writes a seal in the field order the reference's own callers build it: `i`, `s`, `d`.
///
/// [`Seal`] declares `s`, `d`, `i` because that is the schema's order, but every integration
/// caller writes the identifier first and the body is what the agent receives.
fn seal_document(seal: &Seal) -> Result<Sad, ClientError> {
    let mut document = Sad::new();
    if let Some(identifier) = &seal.identifier {
        document.insert("i", identifier.clone()).map_err(sad_error)?;
    }
    document.insert("s", seal.sequence_number.clone()).map_err(sad_error)?;
    document.insert("d", seal.digest.clone()).map_err(sad_error)?;
    Ok(document)
}

fn sad_error(source: SadError) -> ClientError {
    ClientError::Serialization {
        source: Box::new(source.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const PREFIX: &str = "EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX";
    const OTHER: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";

    fn prefix(text: &str) -> Result<IdentifierPrefix, Box<dyn Error>> {
        Ok(IdentifierPrefix::from_qb64(text)?)
    }

    fn rendered(query: &KeyStateQuery) -> Result<String, Box<dyn Error>> {
        Ok(String::from_utf8(query.body()?)?)
    }

    #[test]
    fn the_path_constants_are_the_references_own() {
        assert_eq!(STATES_SEGMENT, "states");
        assert_eq!(QUERIES_SEGMENT, "queries");
        assert_eq!(PREFIX_PARAMETER, "pre");
    }

    #[test]
    fn a_listing_repeats_its_parameter_in_order() -> Result<(), Box<dyn Error>> {
        let path = ResourcePath::builder()
            .segment(STATES_SEGMENT)
            .parameter(PREFIX_PARAMETER, PREFIX)
            .parameter(PREFIX_PARAMETER, OTHER)
            .build()?;
        assert_eq!(path.as_str(), format!("/states?pre={PREFIX}&pre={OTHER}"));
        // The signed path never carries the query, so a listing and a read sign identically.
        assert_eq!(path.path(), "/states");
        Ok(())
    }

    #[test]
    fn a_query_body_writes_only_what_it_was_given() -> Result<(), Box<dyn Error>> {
        let latest = KeyStateQuery::latest(prefix(PREFIX)?);
        assert_eq!(rendered(&latest)?, format!(r#"{{"pre":"{PREFIX}"}}"#));

        let at = KeyStateQuery::at(prefix(PREFIX)?, QuerySequence::Decimal(1));
        assert_eq!(rendered(&at)?, format!(r#"{{"pre":"{PREFIX}","sn":"1"}}"#));
        Ok(())
    }

    #[test]
    fn a_query_body_writes_a_seal_the_way_its_callers_build_one() -> Result<(), Box<dyn Error>> {
        let anchor = Seal {
            identifier: Some(OTHER.to_owned()),
            sequence_number: "0".to_owned(),
            digest: OTHER.to_owned(),
        };
        let query = KeyStateQuery::anchoring(prefix(PREFIX)?, anchor);
        assert_eq!(
            rendered(&query)?,
            format!(r#"{{"pre":"{PREFIX}","anchor":{{"i":"{OTHER}","s":"0","d":"{OTHER}"}}}}"#)
        );
        Ok(())
    }

    #[test]
    fn a_seal_without_an_identifier_omits_it() -> Result<(), Box<dyn Error>> {
        let anchor = Seal {
            identifier: None,
            sequence_number: "2".to_owned(),
            digest: OTHER.to_owned(),
        };
        let query = KeyStateQuery::anchoring(prefix(PREFIX)?, anchor);
        assert_eq!(
            rendered(&query)?,
            format!(r#"{{"pre":"{PREFIX}","anchor":{{"s":"2","d":"{OTHER}"}}}}"#)
        );
        Ok(())
    }

    #[test]
    fn a_sequence_number_renders_in_the_base_its_caller_chose() {
        // Below ten the two agree, which is exactly why the reference's own evidence cannot
        // distinguish them: every literal it sends is a single digit.
        for value in 0..10 {
            assert_eq!(
                QuerySequence::Decimal(value).to_text(),
                QuerySequence::Hexadecimal(value).to_text()
            );
        }
        // At ten they part company, and nothing upstream has ever exercised it.
        assert_eq!(QuerySequence::Decimal(10).to_text(), "10");
        assert_eq!(QuerySequence::Hexadecimal(10).to_text(), "a");
        assert_eq!(QuerySequence::Hexadecimal(255).to_text(), "ff");
        assert_eq!(QuerySequence::Decimal(255).value(), 255);
        assert_eq!(QuerySequence::Hexadecimal(255).value(), 255);
    }

    #[test]
    fn every_query_field_the_reference_writes_is_in_the_reference_order() -> Result<(), Box<dyn Error>> {
        let query = KeyStateQuery {
            prefix: prefix(PREFIX)?,
            sequence_number: Some(QuerySequence::Decimal(1)),
            anchor: Some(Seal {
                identifier: Some(OTHER.to_owned()),
                sequence_number: "0".to_owned(),
                digest: OTHER.to_owned(),
            }),
        };
        let body = rendered(&query)?;
        let pre = body.find(r#""pre""#);
        let sn = body.find(r#""sn""#);
        let anchor = body.find(r#""anchor""#);
        assert!(pre < sn && sn < anchor, "the body's field order changed: {body}");
        Ok(())
    }
}
