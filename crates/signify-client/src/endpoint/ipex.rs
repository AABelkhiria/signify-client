//! The IPEX endpoint: handing a signed disclosure message to the agent for delivery.
//!
//! IPEX is a five-step conversation — apply, offer, agree, grant, admit — and this family is the
//! submission half of it. The messages themselves are Roadmap 6.3's, in `signify_acdc::ipex`: this
//! module assembles the request body around one, addresses the resource, and reads the operation
//! that comes back. Nothing here builds or signs a message.
//!
//! This ports the five `submit*` methods of `Ipex` in the pinned `src/keri/app/credentialing.ts`.
//!
//! # One submission, not five
//!
//! Upstream there is a method per route, each appending its own path segment and accepting any
//! `exn` — so posting a grant through `submitApply` addresses `/ipex/apply` with a message whose own
//! `r` field says `/ipex/grant`, and posting an apply through `submitGrant` attaches an `atc` the
//! message never had. Both are recorded in `fixtures/client-ipex/`. Here there is one
//! [`Ipex::submit`] and the path segment is read from the message's own
//! [`route`](signify_acdc::ipex::IpexMessage::route), so the resource and the route cannot disagree.
//!
//! # The route decides the body
//!
//! An apply and an agree send `{exn, sigs, rec}`; an offer, a grant, and an admit send
//! `{exn, sigs, atc, rec}`. That is upstream's own split: `submitApply` and `submitAgree` take no
//! `atc` parameter, although their builders return one. It costs nothing, because neither route
//! embeds anything and so neither attachment is ever non-empty — which a property asserts rather
//! than assumes.

use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::serialization::{Sad, SadValue};
use keria_types::api::ExchangeOperation;
use signify_acdc::ipex::{IpexMessage, IpexRoute};
use signify_http::request::ResourcePath;
use signify_http::response::ResponseError;
use signify_http::transport::Method;

use crate::client::{ClientRequest, ConnectedClient};
use crate::endpoint::body::{sad_error, text_array};
use crate::endpoint::decode_json;
use crate::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use crate::error::ClientError;

/// Path segment an identifier's IPEX submissions live under.
pub const IPEX_SEGMENT: &str = "ipex";

/// Returns the path segment one route is submitted to.
///
/// This is the last component of the route the message itself carries, which a test asserts, so
/// the address and the `r` field cannot drift apart.
#[must_use]
const fn route_segment(route: IpexRoute) -> &'static str {
    match route {
        IpexRoute::Apply => "apply",
        IpexRoute::Offer => "offer",
        IpexRoute::Agree => "agree",
        IpexRoute::Grant => "grant",
        IpexRoute::Admit => "admit",
    }
}

/// Returns whether a route's submission body carries an `atc` field.
///
/// Upstream this is not a decision at all — it is which of the five methods a caller happened to
/// call. `submitApply` and `submitAgree` declare no `atc` parameter; the other three do.
#[must_use]
const fn carries_attachment(route: IpexRoute) -> bool {
    match route {
        IpexRoute::Apply | IpexRoute::Agree => false,
        IpexRoute::Offer | IpexRoute::Grant | IpexRoute::Admit => true,
    }
}

/// One submitted IPEX message, with the agent's answer.
///
/// The reference's submitters return `response.json()` cast to an `ExchangeOperation`; here the
/// body is owned bytes and [`Self::operation`] decodes it, so a wrong-shaped answer is a typed
/// failure rather than something a caller reads as an operation.
#[derive(Clone, Debug)]
pub struct SubmittedIpexMessage {
    route: IpexRoute,
    response: Vec<u8>,
}

impl SubmittedIpexMessage {
    /// Returns which step of the conversation was submitted.
    #[must_use]
    pub const fn route(&self) -> IpexRoute {
        self.route
    }

    /// Returns the agent's answer, unparsed.
    #[must_use]
    pub fn response_body(&self) -> &[u8] {
        &self.response
    }

    /// Reads the agent's answer as the long-running operation that delivers the message.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Api`] when the answer is not an exchange operation.
    pub fn operation(&self) -> Result<ExchangeOperation, ClientError> {
        decode_json(&self.response)
    }
}

/// The IPEX endpoint family.
///
/// Borrowed from a connected client, so it costs nothing to hold and cannot outlive the client it
/// speaks through.
#[derive(Debug)]
pub struct Ipex<'client> {
    client: &'client ConnectedClient,
}

impl<'client> Ipex<'client> {
    /// Binds this family to a connected client.
    #[must_use]
    pub const fn new(client: &'client ConnectedClient) -> Self {
        Self { client }
    }

    /// Submits one signed IPEX message for delivery to `recipients`.
    ///
    /// `identifier` is the alias of the sending identifier — the resource the message is posted
    /// under, not the identifier it is addressed to. The route is the message's own, so it decides
    /// both the address and whether the body carries an attachment.
    ///
    /// **The recipients are not checked against the message.** An IPEX message names its addressee
    /// in its own `rp` and `a.i` fields, and neither this nor the reference compares the delivery
    /// list with it — a grant addressed to one identifier can be handed to the agent for delivery
    /// to another. Every call site in the pinned reference passes exactly one recipient and it is
    /// the addressee, but the endpoint accepts a list and a multisig sender plausibly needs more
    /// than one, so the list is the caller's. What is refused is an **empty** one, which asks the
    /// agent to deliver to nobody.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NoIpexRecipients`] for an empty recipient list — checked before
    /// anything is built — [`ClientError::Decode`] when the message's attachment stream is not
    /// UTF-8, [`ClientError::Serialization`] when the body cannot be written, and the request,
    /// transport, and authentication failures [`ConnectedClient::fetch`] returns.
    pub async fn submit(
        &self,
        identifier: &str,
        message: &IpexMessage,
        recipients: &[IdentifierPrefix],
    ) -> Result<SubmittedIpexMessage, ClientError> {
        if recipients.is_empty() {
            return Err(ClientError::NoIpexRecipients {
                route: message.route().as_str(),
            });
        }

        let route = message.route();
        let mut body = Sad::new();
        body.insert("exn", SadValue::Map(message.exchange().sad().clone()))
            .map_err(sad_error)?;
        body.insert("sigs", text_array(message.signatures().qb64()?))
            .map_err(sad_error)?;
        if carries_attachment(route) {
            body.insert("atc", attachment_text(message)?.to_owned())
                .map_err(sad_error)?;
        }
        let addresses = recipients
            .iter()
            .map(|recipient| Ok(recipient.qb64()?))
            .collect::<Result<Vec<String>, ClientError>>()?;
        body.insert("rec", text_array(addresses)).map_err(sad_error)?;

        let path = ResourcePath::builder()
            .segment(IDENTIFIERS_SEGMENT)
            .segment(identifier)
            .segment(IPEX_SEGMENT)
            .segment(route_segment(route))
            .build()?;
        let request = ClientRequest::new(Method::Post, path).body(body.to_json_bytes().map_err(sad_error)?);
        let response = self.client.fetch(request).await?;

        Ok(SubmittedIpexMessage {
            route,
            response: response.into_body(),
        })
    }
}

/// Reads a message's attachment stream as the text the body carries it as.
///
/// A CESR stream is text by definition and this one was produced by `keri-acdc`, so a failure
/// here would be a defect rather than hostile input; it is still typed rather than assumed.
fn attachment_text(message: &IpexMessage) -> Result<&str, ClientError> {
    core::str::from_utf8(message.attachments()).map_err(|error| ClientError::Decode {
        source: Box::new(ResponseError::NotUtf8 {
            offset: error.valid_up_to(),
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const SENDER: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";

    #[test]
    fn the_path_constant_is_the_references_own() {
        assert_eq!(IPEX_SEGMENT, "ipex");
    }

    #[test]
    fn every_segment_is_the_last_component_of_its_own_route() {
        // The address and the `r` field the message carries can only agree if this holds, and it
        // is what lets one `submit` replace the reference's five methods.
        for route in IpexRoute::ALL {
            assert_eq!(route.as_str(), format!("/{IPEX_SEGMENT}/{}", route_segment(route)));
        }
    }

    #[test]
    fn only_three_routes_carry_an_attachment() {
        // `submitApply` and `submitAgree` declare no `atc` parameter upstream.
        assert!(!carries_attachment(IpexRoute::Apply));
        assert!(!carries_attachment(IpexRoute::Agree));
        assert!(carries_attachment(IpexRoute::Offer));
        assert!(carries_attachment(IpexRoute::Grant));
        assert!(carries_attachment(IpexRoute::Admit));
        let carrying = IpexRoute::ALL
            .iter()
            .copied()
            .filter(|route| carries_attachment(*route))
            .count();
        assert_eq!(carrying, 3);
    }

    #[test]
    fn each_route_addresses_its_own_resource() -> Result<(), Box<dyn Error>> {
        for (route, expected) in [
            (IpexRoute::Apply, "/identifiers/multisig/ipex/apply"),
            (IpexRoute::Offer, "/identifiers/multisig/ipex/offer"),
            (IpexRoute::Agree, "/identifiers/multisig/ipex/agree"),
            (IpexRoute::Grant, "/identifiers/multisig/ipex/grant"),
            (IpexRoute::Admit, "/identifiers/multisig/ipex/admit"),
        ] {
            let path = ResourcePath::builder()
                .segment(IDENTIFIERS_SEGMENT)
                .segment("multisig")
                .segment(IPEX_SEGMENT)
                .segment(route_segment(route))
                .build()?;
            assert_eq!(path.as_str(), expected);
            assert_eq!(path.query(), None);
        }
        Ok(())
    }

    #[test]
    fn an_alias_can_never_leave_its_own_path_segment() -> Result<(), Box<dyn Error>> {
        // The reference concatenates the alias raw, so `a/b` addresses another identifier's
        // resource — and Roadmap 3.10 signs `@path`.
        let path = ResourcePath::builder()
            .segment(IDENTIFIERS_SEGMENT)
            .segment("a/b")
            .segment(IPEX_SEGMENT)
            .segment(route_segment(IpexRoute::Apply))
            .build()?;
        assert_eq!(path.as_str(), "/identifiers/a%2Fb/ipex/apply");
        assert_eq!(path.path().split('/').count(), 5);
        Ok(())
    }

    #[test]
    fn a_body_carries_the_reference_field_order() -> Result<(), Box<dyn Error>> {
        // Rendered here from the parts rather than from a message, so the two shapes are stated
        // side by side; the cross-language test compares whole bodies against the reference.
        let mut without = Sad::new();
        without.insert("exn", SadValue::Map(Sad::new()))?;
        without.insert("sigs", text_array(vec!["AAB".to_owned()]))?;
        without.insert("rec", text_array(vec![SENDER.to_owned()]))?;
        assert_eq!(
            String::from_utf8(without.to_json_bytes()?)?,
            format!(r#"{{"exn":{{}},"sigs":["AAB"],"rec":["{SENDER}"]}}"#)
        );

        let mut with = Sad::new();
        with.insert("exn", SadValue::Map(Sad::new()))?;
        with.insert("sigs", text_array(vec!["AAB".to_owned()]))?;
        with.insert("atc", String::new())?;
        with.insert("rec", text_array(vec![SENDER.to_owned()]))?;
        assert_eq!(
            String::from_utf8(with.to_json_bytes()?)?,
            format!(r#"{{"exn":{{}},"sigs":["AAB"],"atc":"","rec":["{SENDER}"]}}"#)
        );
        Ok(())
    }

    #[test]
    fn an_empty_recipient_list_names_the_route_it_refused() {
        // The reference sends `"rec":[]`, asking the agent to deliver to no one.
        let error = ClientError::NoIpexRecipients {
            route: IpexRoute::Grant.as_str(),
        };
        assert!(error.to_string().contains("/ipex/grant"));
    }

    #[test]
    fn a_recipient_is_a_validated_prefix() {
        // The reference copies any string into `rec`; here each is a parsed prefix.
        for hostile in ["", "not a prefix", "a/b", "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwr"] {
            assert!(
                IdentifierPrefix::from_qb64(hostile).is_err(),
                "{hostile:?} was accepted as a recipient"
            );
        }
        assert!(IdentifierPrefix::from_qb64(SENDER).is_ok());
    }
}
