//! Reply messages.
//!
//! A reply carries routed data that a controller signs — authorising an endpoint role, announcing
//! a location scheme — rather than an entry in a key event log. It has no identifier prefix and no
//! sequence number: only its route, its timestamp, and the attributes being asserted.
//!
//! This module ports `reply` from `src/keri/core/eventing.ts`. It is the only supporting event
//! builder the pinned reference exports; receipt, query, and key-state messages have no
//! implementation there at all, which `PORTING.md` §5.3 records as `N/A` for this item.

use signify_crypto::digest::DigestAlgorithm;

use crate::event::error::EventError;
use crate::event::inception::ANCHORS_LABEL;
use crate::event::kind::EventKind;
use crate::event::timestamp::Timestamp;
use crate::said::{DEFAULT_SAID_LABEL, Said};
use crate::serialization::{KIND_LABEL, SAID_LABEL, Sad, SadValue, SerializedEvent, VERSION_LABEL};

/// Field label carrying the message timestamp.
pub const TIMESTAMP_LABEL: &str = "dt";
/// Field label carrying the message route.
pub const ROUTE_LABEL: &str = "r";

/// Largest route this builder accepts, in bytes.
///
/// The reference imposes no bound. Every route it uses is a short path such as `/end/role/add`;
/// this ceiling exists so an untrusted route cannot inflate a message without limit.
pub const MAX_ROUTE_BYTES: usize = 1024;

/// A finished, serialized reply message.
///
/// Unlike a key event this carries no identifier prefix or sequence number, so it is a distinct
/// type rather than a variant of [`KeyEvent`](crate::event::KeyEvent).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplyMessage {
    serialized: SerializedEvent,
    said: Said,
}

impl ReplyMessage {
    /// Returns the exact serialized message bytes.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        self.serialized.raw()
    }

    /// Borrows the ordered message fields.
    #[must_use]
    pub const fn sad(&self) -> &Sad {
        self.serialized.sad()
    }

    /// Borrows the serialized message, for version-string and parsing access.
    #[must_use]
    pub const fn serialized(&self) -> &SerializedEvent {
        &self.serialized
    }

    /// Returns the message's self-addressing identifier.
    ///
    /// A reply carries an ordinary SAID, so a recipient recomputes it with
    /// [`Said::verify`](crate::said::Said::verify).
    #[must_use]
    pub const fn said(&self) -> Said {
        self.said
    }

    /// Returns the route this reply is addressed to.
    #[must_use]
    pub fn route(&self) -> Option<&str> {
        self.sad().get_text(ROUTE_LABEL)
    }
}

/// Builds a reply (`rpy`) message.
///
/// ```
/// use signify_keri::event::reply::ReplyBuilder;
/// use signify_keri::event::timestamp::Timestamp;
/// use signify_keri::serialization::{Sad, SadValue};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut attributes = Sad::new();
/// attributes.insert("cid", SadValue::text("ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK"))?;
/// attributes.insert("role", SadValue::text("agent"))?;
///
/// let reply = ReplyBuilder::new("/end/role/add", "2021-06-27T21:26:21.233257+00:00".parse::<Timestamp>()?)
///     .attributes(attributes)
///     .build()?;
///
/// assert_eq!(reply.route(), Some("/end/role/add"));
/// assert_eq!(reply.said().qb64()?, "EGSzZ1QwvZwrb8-JaV6hOUp5DBqYOgYNWqiWHwVO2dyr");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct ReplyBuilder {
    route: String,
    timestamp: Timestamp,
    attributes: Sad,
}

impl ReplyBuilder {
    /// Starts a reply addressed to `route`, stamped at `timestamp`.
    ///
    /// The timestamp is required. The reference defaults it to the system clock, which makes the
    /// message — and therefore its SAID — depend on when it was built; a caller that wants "now"
    /// formats it and parses a [`Timestamp`].
    ///
    /// The route is a plain string because the typed route table is Roadmap 8.1, which owns the
    /// multisig and IPEX routes this one will join.
    #[must_use]
    pub fn new(route: impl Into<String>, timestamp: Timestamp) -> Self {
        Self {
            route: route.into(),
            timestamp,
            attributes: Sad::new(),
        }
    }

    /// Sets the attributes this reply asserts; empty by default.
    #[must_use]
    pub fn attributes(mut self, attributes: Sad) -> Self {
        self.attributes = attributes;
        self
    }

    /// Validates the route and serializes the message.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::RouteTooLong`] for a route above [`MAX_ROUTE_BYTES`], and layered
    /// [`EventError::Said`], [`EventError::Sad`], or [`EventError::Serialization`] failures for
    /// attributes that cannot be encoded.
    pub fn build(self) -> Result<ReplyMessage, EventError> {
        if self.route.len() > MAX_ROUTE_BYTES {
            return Err(EventError::RouteTooLong {
                length: self.route.len(),
            });
        }

        let mut fields = Sad::new();
        let mut insert = |label: &str, value: SadValue| -> Result<(), EventError> {
            fields.insert(label.to_owned(), value).map_err(EventError::sad)
        };
        insert(VERSION_LABEL, SadValue::text("KERI10JSON000000_"))?;
        insert(KIND_LABEL, SadValue::text(EventKind::Reply.as_str()))?;
        insert(SAID_LABEL, SadValue::text(""))?;
        insert(TIMESTAMP_LABEL, SadValue::Text(self.timestamp.into_string()))?;
        insert(ROUTE_LABEL, SadValue::Text(self.route))?;
        insert(ANCHORS_LABEL, SadValue::Map(self.attributes))?;

        let computation =
            Said::compute(&fields, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL).map_err(EventError::said)?;
        let (said, completed) = computation.into_parts();
        let serialized = SerializedEvent::from_sad(completed).map_err(EventError::serialization)?;
        Ok(ReplyMessage { serialized, said })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::said::SaidVerification;
    use std::error::Error;

    const STAMP: &str = "2021-06-27T21:26:21.233257+00:00";

    fn stamp() -> Result<Timestamp, Box<dyn Error>> {
        Ok(Timestamp::parse(STAMP)?)
    }

    fn end_role_attributes() -> Result<Sad, Box<dyn Error>> {
        let mut attributes = Sad::new();
        attributes.insert("cid", SadValue::text("ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK"))?;
        attributes.insert("role", SadValue::text("agent"))?;
        Ok(attributes)
    }

    #[test]
    fn field_order_is_the_protocol_order() -> Result<(), Box<dyn Error>> {
        let reply = ReplyBuilder::new("/end/role/add", stamp()?)
            .attributes(end_role_attributes()?)
            .build()?;
        let labels: Vec<&str> = reply.sad().entries().map(|(label, _)| label).collect();
        // A reply has no identifier and no sequence number.
        assert_eq!(labels, ["v", "t", "d", "dt", "r", "a"]);
        assert!(!reply.sad().contains("i"));
        assert!(!reply.sad().contains("s"));
        assert_eq!(reply.sad().get_text("t"), Some("rpy"));
        Ok(())
    }

    #[test]
    fn the_pinned_reference_routes_are_exact() -> Result<(), Box<dyn Error>> {
        // The two routes the pinned `test/app/aiding.test.ts` exercises.
        let end_role = ReplyBuilder::new("/end/role/add", stamp()?)
            .attributes(end_role_attributes()?)
            .build()?;
        assert_eq!(
            core::str::from_utf8(end_role.raw())?,
            concat!(
                r#"{"v":"KERI10JSON0000dc_","t":"rpy","d":"EGSzZ1QwvZwrb8-JaV6hOUp5DBqYOgYNWqiWHwVO2dyr","#,
                r#""dt":"2021-06-27T21:26:21.233257+00:00","r":"/end/role/add","#,
                r#""a":{"cid":"ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK","role":"agent"}}"#
            )
        );

        let mut location = Sad::new();
        location.insert("eid", SadValue::text("EHgwVwQT15OJvilVvW57HE4w0-GPs_Stj2OFoAHZSysY"))?;
        location.insert("url", SadValue::text("https://test.com"))?;
        location.insert("scheme", SadValue::text("https"))?;
        let loc_scheme = ReplyBuilder::new("/loc/scheme", stamp()?)
            .attributes(location)
            .build()?;
        assert_eq!(
            loc_scheme.said().qb64()?,
            "ENcFhO8u3Ahignxbuz5RQM0PH008LhKplWSVWueQdJz6"
        );
        Ok(())
    }

    #[test]
    fn an_empty_route_and_no_attributes_are_accepted() -> Result<(), Box<dyn Error>> {
        // The reference defaults both, so both have to remain expressible.
        let reply = ReplyBuilder::new("", stamp()?).build()?;
        assert_eq!(
            core::str::from_utf8(reply.raw())?,
            concat!(
                r#"{"v":"KERI10JSON00008c_","t":"rpy","d":"EOgYi0AO-lgeSXZJV9i5MDjlyOQoYEjC1D7avtVA5x7Q","#,
                r#""dt":"2021-06-27T21:26:21.233257+00:00","r":"","a":{}}"#
            )
        );
        assert_eq!(reply.route(), Some(""));
        Ok(())
    }

    #[test]
    fn a_route_is_bounded() -> Result<(), Box<dyn Error>> {
        let longest = "/".repeat(MAX_ROUTE_BYTES);
        ReplyBuilder::new(longest, stamp()?).build()?;

        let overlong = "/".repeat(MAX_ROUTE_BYTES + 1);
        assert!(matches!(
            ReplyBuilder::new(overlong, stamp()?).build(),
            Err(EventError::RouteTooLong { length }) if length == MAX_ROUTE_BYTES + 1
        ));
        Ok(())
    }

    #[test]
    fn a_non_ascii_route_is_measured_in_bytes() -> Result<(), Box<dyn Error>> {
        let reply = ReplyBuilder::new("/ünïcode", stamp()?).build()?;
        assert_eq!(reply.route(), Some("/ünïcode"));
        // Two of the characters are two bytes each, so the message is longer than its character
        // count suggests; the version string counts bytes.
        assert_eq!(reply.serialized().size(), reply.raw().len());
        assert_eq!(reply.sad().get_text("v"), Some("KERI10JSON000096_"));
        Ok(())
    }

    #[test]
    fn nested_attributes_are_preserved() -> Result<(), Box<dyn Error>> {
        let mut inner = Sad::new();
        inner.insert("b", SadValue::Array(vec![SadValue::Integer(1), SadValue::text("z")]))?;
        let mut attributes = Sad::new();
        attributes.insert("a", SadValue::Map(inner.clone()))?;

        let reply = ReplyBuilder::new("/x", stamp()?).attributes(attributes).build()?;
        assert_eq!(
            reply
                .sad()
                .get("a")
                .and_then(SadValue::as_map)
                .and_then(|map| map.get("a")),
            Some(&SadValue::Map(inner))
        );
        assert_eq!(reply.said().qb64()?, "EH9YxYvcFyTWH_oAOqizyXH8rue8Z5PIJIFDrSzlh2Dz");
        Ok(())
    }

    #[test]
    fn the_finished_message_is_self_consistent() -> Result<(), Box<dyn Error>> {
        let reply = ReplyBuilder::new("/end/role/add", stamp()?)
            .attributes(end_role_attributes()?)
            .build()?;
        assert_eq!(reply.serialized().size(), reply.raw().len());
        assert_eq!(SerializedEvent::parse(reply.raw())?.sad(), reply.sad());
        // A reply carries an ordinary SAID, so the ordinary check applies.
        reply
            .said()
            .verify(reply.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict())?;
        assert_eq!(reply.sad().get_text("dt"), Some(STAMP));
        Ok(())
    }

    #[test]
    fn the_timestamp_is_committed_to() -> Result<(), Box<dyn Error>> {
        let first = ReplyBuilder::new("/x", stamp()?).build()?;
        let second = ReplyBuilder::new("/x", Timestamp::parse("2021-06-27T21:26:21.233258+00:00")?).build()?;
        // One microsecond apart is a different message with a different identifier.
        assert_ne!(first.said(), second.said());
        assert_eq!(first.raw().len(), second.raw().len());
        Ok(())
    }
}
