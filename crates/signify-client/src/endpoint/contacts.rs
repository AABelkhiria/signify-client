//! The contacts endpoint: who this client knows, and what it has recorded about them.
//!
//! A contact is another identifier the agent has resolved an OOBI for, together with whatever the
//! client chose to file alongside it — an alias, a company, anything. This family is the five calls
//! that read and write those records: [`Contacts::list`], [`Contacts::get`], [`Contacts::add`],
//! [`Contacts::update`], and [`Contacts::delete`].
//!
//! This ports `Contacts` from the pinned `src/keri/app/contacting.ts`. The `Challenges` half of that
//! file is Roadmap 7.4.
//!
//! # Half a filter is not a filter
//!
//! `list(group?, filterField?, filterValue?)` upstream appends the filter only when *both* halves
//! are given, so `list(undefined, 'alias')` asks for a filtered listing and is answered with an
//! unfiltered one — a mistake that succeeds. Here the two are one [`ContactFilter`], so naming a
//! field without a value cannot be written. The group stays independent, because it genuinely is.
//!
//! # A contact's identifier is an identifier
//!
//! All four single-contact paths are `'/contacts/' + pre` with no encoding, so a value carrying `/`
//! or `?` addresses a different resource — Roadmap 5.3's own fixture recorded
//! `contacts().delete("a/b")` reaching two segments — and Roadmap 3.10 signs `@path`. Here the
//! argument is Roadmap 3.4's validated [`IdentifierPrefix`], which cannot hold a delimiter, and
//! Roadmap 5.3's builder would encode it exactly once even if it could. See
//! `fixtures/client-contacts/`.

use signify_http::request::ResourcePath;
use signify_http::transport::Method;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::serialization::Sad;
use signify_types::api::Contact;

use crate::client::{ClientRequest, ConnectedClient};
use crate::endpoint::body::sad_error;
use crate::endpoint::decode_json;
use crate::error::ClientError;

/// Path segment the contacts resource lives under.
pub const CONTACTS_SEGMENT: &str = "contacts";

/// Query parameter naming a contact group; the reference's `group`.
pub const GROUP_PARAMETER: &str = "group";

/// Query parameter naming the field a listing filters on; the reference's `filter_field`.
pub const FILTER_FIELD_PARAMETER: &str = "filter_field";

/// Query parameter naming the value that field must match; the reference's `filter_value`.
pub const FILTER_VALUE_PARAMETER: &str = "filter_value";

/// The field name the reference's own integration helper filters on.
///
/// `getOrCreateContact` looks a contact up by `alias`, which is the only filter field used anywhere
/// outside the pinned unit test.
pub const ALIAS_FIELD: &str = "alias";

/// Which contacts a listing should return.
///
/// The reference takes the field and the value as two separate optional arguments and writes them
/// only when both are present, so half a filter is silently no filter. Keeping them together makes
/// that unrepresentable.
///
/// The value's meaning is the agent's: the reference's own helper passes `^alice$`, so KERIA
/// matches it as a regular expression rather than for equality. Nothing here interprets it.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContactFilter {
    /// The contact field to match on; the reference's `filterField`.
    pub field: String,
    /// The value it must match; the reference's `filterValue`.
    pub value: String,
}

impl ContactFilter {
    /// Filters on one named field.
    #[must_use]
    pub fn new(field: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            value: value.into(),
        }
    }

    /// Filters on a contact's alias, which is what the reference's own helper does.
    ///
    /// ```
    /// use signify_client::endpoint::contacts::{ALIAS_FIELD, ContactFilter};
    ///
    /// let filter = ContactFilter::alias("^alice$");
    /// assert_eq!(filter.field, ALIAS_FIELD);
    /// assert_eq!(filter.value, "^alice$");
    /// ```
    #[must_use]
    pub fn alias(value: impl Into<String>) -> Self {
        Self::new(ALIAS_FIELD, value)
    }
}

/// The contacts endpoint family.
///
/// Borrowed from a connected client, so it costs nothing to hold and cannot outlive the client it
/// speaks through. This is the shape Roadmap 6.5 settled for every family.
#[derive(Debug)]
pub struct Contacts<'client> {
    client: &'client ConnectedClient,
}

impl<'client> Contacts<'client> {
    /// Binds this family to a connected client.
    #[must_use]
    pub const fn new(client: &'client ConnectedClient) -> Self {
        Self { client }
    }

    /// Lists the agent's contacts, optionally by group and by one field's value.
    ///
    /// A listing with neither addresses `/contacts`, where the reference addresses `/contacts?` —
    /// the same deliberate difference ADR `0028` argued for an unfiltered `/operations` listing,
    /// and for the same three reasons. The signed path is identical either way.
    ///
    /// There is no paging: the agent answers with every match in one body, bounded only by
    /// Roadmap 5.1's transport limit.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer, [`ClientError::Api`] when the body
    /// is not a list of contacts, and the request, transport, and authentication failures
    /// [`ConnectedClient::fetch`] returns.
    pub async fn list(&self, group: Option<&str>, filter: Option<&ContactFilter>) -> Result<Vec<Contact>, ClientError> {
        let mut builder = ResourcePath::builder()
            .segment(CONTACTS_SEGMENT)
            .optional_parameter(GROUP_PARAMETER, group);
        if let Some(filter) = filter {
            builder = builder
                .parameter(FILTER_FIELD_PARAMETER, &filter.field)
                .parameter(FILTER_VALUE_PARAMETER, &filter.value);
        }
        let response = self
            .client
            .fetch(ClientRequest::new(Method::Get, builder.build()?))
            .await?;
        decode_json(response.body())
    }

    /// Reads one contact.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Api`] when the body is not a contact, plus whatever [`Self::list`]
    /// returns.
    pub async fn get(&self, prefix: &IdentifierPrefix) -> Result<Contact, ClientError> {
        let response = self
            .client
            .fetch(ClientRequest::new(Method::Get, Self::record_path(prefix)?))
            .await?;
        decode_json(response.body())
    }

    /// Files a new contact under one identifier.
    ///
    /// `info` is an ordered document, which is what Roadmap 6.6 settled a request body is here: the
    /// reference hands the caller's object literal to `JSON.stringify`, so the field order on the
    /// wire is the caller's. Any field the agent does not recognise is stored and comes back in
    /// [`Contact::additional`](signify_types::api::Contact::additional).
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Serialization`] when the body cannot be written, plus whatever
    /// [`Self::get`] returns.
    pub async fn add(&self, prefix: &IdentifierPrefix, info: &Sad) -> Result<Contact, ClientError> {
        self.write(Method::Post, prefix, info).await
    }

    /// Replaces what is recorded about one contact.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::add`] returns.
    pub async fn update(&self, prefix: &IdentifierPrefix, info: &Sad) -> Result<Contact, ClientError> {
        self.write(Method::Put, prefix, info).await
    }

    /// Forgets one contact.
    ///
    /// The request carries **no body**, which is what the reference sends and what its own unit
    /// test asserts. The agent's answer carries nothing a caller can use, so nothing is returned.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::get`] returns, apart from the decode failures.
    pub async fn delete(&self, prefix: &IdentifierPrefix) -> Result<(), ClientError> {
        self.client
            .fetch(ClientRequest::new(Method::Delete, Self::record_path(prefix)?))
            .await
            .map(|_| ())
    }

    /// Sends the body `add` and `update` share, which differ only in method.
    async fn write(&self, method: Method, prefix: &IdentifierPrefix, info: &Sad) -> Result<Contact, ClientError> {
        let body = info.to_json_bytes().map_err(sad_error)?;
        let request = ClientRequest::new(method, Self::record_path(prefix)?).body(body);
        let response = self.client.fetch(request).await?;
        decode_json(response.body())
    }

    /// Builds the path all four single-contact calls share.
    fn record_path(prefix: &IdentifierPrefix) -> Result<ResourcePath, ClientError> {
        Ok(ResourcePath::builder()
            .segment(CONTACTS_SEGMENT)
            .segment(&prefix.qb64()?)
            .build()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signify_keri::serialization::SadValue;
    use std::error::Error;

    const CONTACT: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

    fn prefix(text: &str) -> Result<IdentifierPrefix, Box<dyn Error>> {
        Ok(IdentifierPrefix::from_qb64(text)?)
    }

    fn listing(group: Option<&str>, filter: Option<&ContactFilter>) -> Result<ResourcePath, Box<dyn Error>> {
        let mut builder = ResourcePath::builder()
            .segment(CONTACTS_SEGMENT)
            .optional_parameter(GROUP_PARAMETER, group);
        if let Some(filter) = filter {
            builder = builder
                .parameter(FILTER_FIELD_PARAMETER, &filter.field)
                .parameter(FILTER_VALUE_PARAMETER, &filter.value);
        }
        Ok(builder.build()?)
    }

    /// The `ContactInfo` the pinned unit test sends, in its own field order.
    fn pinned_info() -> Result<Sad, Box<dyn Error>> {
        let mut info = Sad::new();
        info.insert("name", "John Doe".to_owned())?;
        info.insert("company", "My Company".to_owned())?;
        Ok(info)
    }

    #[test]
    fn the_path_constants_are_the_references_own() {
        assert_eq!(CONTACTS_SEGMENT, "contacts");
        assert_eq!(GROUP_PARAMETER, "group");
        assert_eq!(FILTER_FIELD_PARAMETER, "filter_field");
        assert_eq!(FILTER_VALUE_PARAMETER, "filter_value");
        assert_eq!(ALIAS_FIELD, "alias");
    }

    #[test]
    fn a_filtered_listing_addresses_the_pinned_path() -> Result<(), Box<dyn Error>> {
        let filter = ContactFilter::new("company", "mycompany");
        let path = listing(Some("mygroup"), Some(&filter))?;
        assert_eq!(
            path.as_str(),
            "/contacts?group=mygroup&filter_field=company&filter_value=mycompany"
        );
        // Roadmap 3.10 strips the query, so every listing signs the same path.
        assert_eq!(path.path(), "/contacts");
        Ok(())
    }

    #[test]
    fn an_unfiltered_listing_omits_the_references_bare_question_mark() -> Result<(), Box<dyn Error>> {
        let path = listing(None, None)?;
        // Upstream concatenates `'?' + params.toString()` unconditionally, so it sends `/contacts?`.
        assert_eq!(path.as_str(), "/contacts");
        assert_eq!(path.query(), None);
        assert_eq!(path.path(), "/contacts");
        Ok(())
    }

    #[test]
    fn a_group_and_a_filter_are_independent() -> Result<(), Box<dyn Error>> {
        assert_eq!(listing(Some("mygroup"), None)?.as_str(), "/contacts?group=mygroup");
        let filter = ContactFilter::alias("^alice$");
        assert_eq!(
            listing(None, Some(&filter))?.as_str(),
            "/contacts?filter_field=alias&filter_value=%5Ealice%24"
        );
        Ok(())
    }

    #[test]
    fn a_filter_always_writes_both_halves_or_neither() -> Result<(), Box<dyn Error>> {
        // Upstream `list(undefined, 'alias')` drops the filter entirely and answers unfiltered.
        // There is no value of this type that names a field without a value.
        let filter = ContactFilter::new("alias", "");
        let path = listing(None, Some(&filter))?;
        let query = path.query().unwrap_or_default();
        assert!(query.contains(FILTER_FIELD_PARAMETER));
        assert!(query.contains(FILTER_VALUE_PARAMETER));
        assert_eq!(query.matches('&').count(), 1);
        // An empty value is still a value, and is written rather than dropped.
        assert_eq!(path.as_str(), "/contacts?filter_field=alias&filter_value=");
        Ok(())
    }

    #[test]
    fn a_filter_value_can_never_add_a_query_parameter() -> Result<(), Box<dyn Error>> {
        // The reference encodes this one — `URLSearchParams`, not interpolation — so this agrees
        // with it rather than diverging.
        let filter = ContactFilter::new("alias", "a&b=c");
        let path = listing(None, Some(&filter))?;
        assert_eq!(path.as_str(), "/contacts?filter_field=alias&filter_value=a%26b%3Dc");
        assert_eq!(path.query().map(|query| query.matches('&').count()), Some(1));
        Ok(())
    }

    #[test]
    fn a_record_path_is_two_segments() -> Result<(), Box<dyn Error>> {
        let path = Contacts::record_path(&prefix(CONTACT)?)?;
        assert_eq!(path.as_str(), format!("/contacts/{CONTACT}"));
        assert_eq!(path.query(), None);
        assert_eq!(path.path().split('/').count(), 3);
        Ok(())
    }

    #[test]
    fn a_value_that_would_escape_the_path_is_not_an_identifier_prefix() {
        // The reference concatenates any string, and Roadmap 5.3 already recorded
        // `contacts().delete("a/b")` reaching two segments.
        for hostile in ["a/b?c=d", "", "../identifiers", "not a prefix", "EBfdlu8R27Fbx"] {
            assert!(
                IdentifierPrefix::from_qb64(hostile).is_err(),
                "{hostile:?} was accepted as a contact identifier"
            );
        }
    }

    #[test]
    fn an_info_body_keeps_the_callers_field_order() -> Result<(), Box<dyn Error>> {
        let rendered = String::from_utf8(pinned_info()?.to_json_bytes()?)?;
        assert_eq!(rendered, r#"{"name":"John Doe","company":"My Company"}"#);

        // Reversed by the caller, reversed on the wire: the order is theirs, not this port's.
        let mut reversed = Sad::new();
        reversed.insert("company", "My Company".to_owned())?;
        reversed.insert("name", "John Doe".to_owned())?;
        assert_eq!(
            String::from_utf8(reversed.to_json_bytes()?)?,
            r#"{"company":"My Company","name":"John Doe"}"#
        );
        Ok(())
    }

    #[test]
    fn an_empty_info_body_is_written_rather_than_omitted() -> Result<(), Box<dyn Error>> {
        assert_eq!(String::from_utf8(Sad::new().to_json_bytes()?)?, "{}");
        Ok(())
    }

    #[test]
    fn an_info_body_carries_nested_and_ordered_values() -> Result<(), Box<dyn Error>> {
        let mut nested = Sad::new();
        nested.insert("nested", true)?;
        let mut info = Sad::new();
        info.insert("z", SadValue::Integer(1))?;
        info.insert("a", SadValue::Map(nested))?;
        info.insert(
            "list",
            SadValue::Array(vec![SadValue::Integer(1), SadValue::Integer(2), SadValue::Integer(3)]),
        )?;
        assert_eq!(
            String::from_utf8(info.to_json_bytes()?)?,
            r#"{"z":1,"a":{"nested":true},"list":[1,2,3]}"#
        );
        Ok(())
    }

    #[test]
    fn an_answer_of_the_wrong_shape_is_refused() {
        // The reference casts each of these to `Contact` and hands it to the caller.
        for wrong in [
            r#"{"unexpected":true}"#,
            r#"{"alias":"John Doe"}"#,
            "[]",
            "null",
            r#""text""#,
        ] {
            assert!(
                serde_json::from_str::<Contact>(wrong).is_err(),
                "{wrong} was accepted as a contact"
            );
        }
        assert!(serde_json::from_str::<Vec<Contact>>(r#"[{"alias":"John Doe"}]"#).is_err());
    }

    #[test]
    fn a_contact_keeps_every_field_the_agent_sent() -> Result<(), Box<dyn Error>> {
        let document = format!(
            r#"{{"id":"{CONTACT}","alias":"John Doe","oobi":"http://a/oobi/E","company":"My Company","challenges":[],"wellKnowns":[]}}"#
        );
        let contact: Contact = serde_json::from_str(&document)?;
        assert_eq!(contact.id, CONTACT);
        assert_eq!(contact.alias.as_deref(), Some("John Doe"));
        // `company` is not a field the schema names, so it lands in the open map and survives.
        assert_eq!(
            contact.additional.get("company").and_then(serde_json::Value::as_str),
            Some("My Company")
        );
        assert_eq!(contact.challenges.map(|challenges| challenges.len()), Some(0));

        // `id` is the one field the schema requires, and the only one a listing entry must carry.
        let minimal: Contact = serde_json::from_str(&format!(r#"{{"id":"{CONTACT}"}}"#))?;
        assert_eq!(minimal.id, CONTACT);
        assert_eq!(minimal.alias, None);
        Ok(())
    }
}
