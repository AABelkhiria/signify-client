//! The notifications endpoint: what the agent wants the controller to know about.
//!
//! A KERIA agent raises a notification when something arrives that the edge has to act on — a
//! multisig inception to join, a credential offered, a challenge answered. This family is the three
//! calls that read and clear them: [`Notifications::list`], [`Notifications::mark`], and
//! [`Notifications::delete`].
//!
//! This ports `Notifications` from the pinned `src/keri/app/notifying.ts`.
//!
//! # A notification's identifier is not a SAID
//!
//! Both single-notification methods name their parameter `said` and document it as "SAID of the
//! notification". It is not one. A notice is built with an empty `i` and filled with a random
//! nonce, and the two references do not even agree which code that nonce carries: signify-ts's own
//! `randomNonce` uses the Ed25519 **seed** code `A`, keripy's the 128-bit **salt** code `0A`.
//! Neither is a digest code, so reading the field as Roadmap 3.3's [`Said`](signify_keri::said::Said)
//! would refuse every identifier a real agent produces. The argument is therefore borrowed text,
//! encoded exactly once — the shape Roadmap 6.5 gave an operation name, and enough to close the
//! path injection Roadmap 5.3 already recorded here. See `fixtures/client-notifications/`.
//!
//! # The window is separate from the page
//!
//! `list` spreads the `Content-Range` numbers into the object it returns beside the notifications,
//! so a caller cannot tell the window apart from the page — and an *absent* header becomes three
//! zeroes, which reports a page of real notifications as an empty window. [`NotificationListing`]
//! keeps the two apart and makes an unreported window [`None`], which is what Roadmap 5.3 decided
//! and Roadmap 6.6 already applied to the identifier listing.

use signify_http::request::{ItemRange, RangeUnit, ResourcePath};
use signify_http::response::{ContentRange, ResponseError};
use signify_http::transport::Method;
use signify_types::api::Notification;

use crate::client::{ClientRequest, ConnectedClient};
use crate::endpoint::decode_json;
use crate::error::ClientError;

/// Path segment the notifications resource lives under.
pub const NOTIFICATIONS_SEGMENT: &str = "notifications";

/// Range unit a notification listing is windowed by; the reference's `notes`.
pub const NOTIFICATION_RANGE_UNIT: &str = "notes";

/// One page of the agent's notifications, with the window it came from.
///
/// The reference returns `{start, end, total, notes}` — the three window numbers spread beside the
/// page — and fills them with zeroes when the answer carried no `Content-Range` at all. Here the
/// window is an [`Option`], so an unreported one stays distinguishable from a genuinely empty page.
#[derive(Clone, Debug, PartialEq)]
pub struct NotificationListing {
    /// The window the agent reported, when it reported one.
    pub window: Option<ContentRange>,
    /// The notifications in this window, read and unread alike.
    pub notifications: Vec<Notification>,
}

impl NotificationListing {
    /// Returns the notifications the controller has not yet marked as read.
    ///
    /// The agent sends both, and the reference's own integration helper filters exactly this way
    /// to assert that nothing is outstanding.
    pub fn unread(&self) -> impl Iterator<Item = &Notification> {
        self.notifications.iter().filter(|notification| !notification.read)
    }
}

/// The notifications endpoint family.
///
/// Borrowed from a connected client, so it costs nothing to hold and cannot outlive the client it
/// speaks through. This is the shape Roadmap 6.5 settled for every family.
#[derive(Debug)]
pub struct Notifications<'client> {
    client: &'client ConnectedClient,
}

impl<'client> Notifications<'client> {
    /// Binds this family to a connected client.
    #[must_use]
    pub const fn new(client: &'client ConnectedClient) -> Self {
        Self { client }
    }

    /// Reads one page of notifications.
    ///
    /// The window is a required argument, where the reference defaults it to `0-24` and writes that
    /// default into the `Range` header — so what is asked for is visible at the call site.
    /// [`ItemRange::DEFAULT`] is the reference's own page.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer, [`ClientError::Api`] when the body
    /// is not a list of notifications, [`ClientError::Decode`] when the `Content-Range` is
    /// malformed, and the request, transport, and authentication failures
    /// [`ConnectedClient::fetch`] returns.
    pub async fn list(&self, window: ItemRange) -> Result<NotificationListing, ClientError> {
        let unit = RangeUnit::new(NOTIFICATION_RANGE_UNIT)?;
        let path = ResourcePath::builder().segment(NOTIFICATIONS_SEGMENT).build()?;
        let request = ClientRequest::new(Method::Get, path).header("range", &window.header_value(&unit))?;
        let response = self.client.fetch(request).await?;
        let window = match response.headers().get("content-range") {
            Some(value) => Some(ContentRange::parse(value, &unit)?),
            None => None,
        };
        Ok(NotificationListing {
            window,
            notifications: decode_json(response.body())?,
        })
    }

    /// Marks one notification as read.
    ///
    /// The agent's answer is returned as text, which is what the reference offers — but decoded
    /// **strictly**: a body that is not valid UTF-8 is a typed failure here, where `res.text()`
    /// substitutes U+FFFD and hands the caller something that reads as a message. That is the
    /// decision Roadmap 6.11 made for a CESR answer read the same way.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Decode`] when the answer is not valid UTF-8, plus whatever
    /// [`Self::list`] returns.
    pub async fn mark(&self, id: &str) -> Result<String, ClientError> {
        let response = self
            .client
            .fetch(ClientRequest::new(Method::Put, Self::record_path(id)?))
            .await?;
        let body = response.into_body();
        String::from_utf8(body).map_err(|error| ClientError::Decode {
            source: Box::new(ResponseError::NotUtf8 {
                offset: error.utf8_error().valid_up_to(),
            }),
        })
    }

    /// Removes one notification.
    ///
    /// The request carries **no body**, which is what the reference sends. Nothing is returned: the
    /// agent's answer carries nothing a caller can use.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::list`] returns, apart from the decode failures.
    pub async fn delete(&self, id: &str) -> Result<(), ClientError> {
        self.client
            .fetch(ClientRequest::new(Method::Delete, Self::record_path(id)?))
            .await
            .map(|_| ())
    }

    /// Builds the path `mark` and `delete` share.
    fn record_path(id: &str) -> Result<ResourcePath, ClientError> {
        Ok(ResourcePath::builder()
            .segment(NOTIFICATIONS_SEGMENT)
            .segment(id)
            .build()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    /// A notification identifier of the shape a KERIA agent produces: keripy's 128-bit salt nonce.
    const NONCE: &str = "0AADChEYHyYtNDtCSVBXXmVs";
    /// The literal the pinned unit test passes, which is not a qualified identifier at all.
    const PINNED_LITERAL: &str = "notificationSAID";

    fn unit() -> Result<RangeUnit, Box<dyn Error>> {
        Ok(RangeUnit::new(NOTIFICATION_RANGE_UNIT)?)
    }

    fn notification(id: &str, read: bool) -> String {
        format!(r#"{{"i":"{id}","dt":"2023-11-14T22:13:20.123000+00:00","r":{read},"a":{{"r":"/multisig/icp"}}}}"#)
    }

    #[test]
    fn the_path_constants_are_the_references_own() {
        assert_eq!(NOTIFICATIONS_SEGMENT, "notifications");
        assert_eq!(NOTIFICATION_RANGE_UNIT, "notes");
    }

    #[test]
    fn the_listing_addresses_the_pinned_path_and_header() -> Result<(), Box<dyn Error>> {
        let path = ResourcePath::builder().segment(NOTIFICATIONS_SEGMENT).build()?;
        assert_eq!(path.as_str(), "/notifications");
        assert_eq!(path.query(), None);
        // The pinned unit test asserts this header value exactly.
        assert_eq!(ItemRange::new(20, 40)?.header_value(&unit()?), "notes=20-40");
        Ok(())
    }

    #[test]
    fn the_default_window_is_the_references_own() -> Result<(), Box<dyn Error>> {
        // Roadmap 5.3 already named it: `start = 0`, `end = 24`.
        assert_eq!(ItemRange::DEFAULT.start(), 0);
        assert_eq!(ItemRange::DEFAULT.end(), 24);
        assert_eq!(ItemRange::DEFAULT.header_value(&unit()?), "notes=0-24");
        // Twenty-five positions, because the end is included.
        assert_eq!(ItemRange::DEFAULT.count(), 25);
        Ok(())
    }

    #[test]
    fn a_reversed_window_is_unrepresentable() {
        // The reference sends `notes=40-20`, asking for a page that cannot exist.
        assert!(ItemRange::new(40, 20).is_err());
        assert!(ItemRange::new(1, 0).is_err());
        // A single-item window is fine, because the end is inclusive.
        assert!(ItemRange::new(7, 7).is_ok());
    }

    #[test]
    fn a_record_path_is_two_segments() -> Result<(), Box<dyn Error>> {
        let path = Notifications::record_path(NONCE)?;
        assert_eq!(path.as_str(), format!("/notifications/{NONCE}"));
        assert_eq!(path.query(), None);
        assert_eq!(path.path().split('/').count(), 3);
        Ok(())
    }

    #[test]
    fn a_real_identifier_reaches_the_path_unchanged() -> Result<(), Box<dyn Error>> {
        // A qualified nonce's alphabet is URL-safe Base64, so encoding leaves it alone — which is
        // why taking borrowed text here costs nothing against what an agent actually sends.
        assert_eq!(
            Notifications::record_path(NONCE)?.as_str(),
            format!("/notifications/{NONCE}")
        );
        // Both spellings the two references produce, neither of them a digest code.
        for nonce in [NONCE, "AAMKERgfJi00O0JJUFdeZWxzeoGIj5adpKuyucDHztXc"] {
            let path = Notifications::record_path(nonce)?;
            assert_eq!(path.as_str(), format!("/notifications/{nonce}"));
        }
        Ok(())
    }

    #[test]
    fn an_identifier_can_never_leave_its_own_path_segment() -> Result<(), Box<dyn Error>> {
        // Upstream `mark("a?b=c")` turns the path into a query — the case Roadmap 5.3's own
        // fixture recorded.
        let path = Notifications::record_path("a?b=c")?;
        assert_eq!(path.as_str(), "/notifications/a%3Fb%3Dc");
        assert_eq!(path.query(), None);
        assert_eq!(path.path().split('/').count(), 3);

        for hostile in ["a/b", "../identifiers", "x#y"] {
            let path = Notifications::record_path(hostile)?;
            assert_eq!(path.path().split('/').count(), 3, "{hostile:?} escaped its segment");
            assert_eq!(path.query(), None);
        }
        Ok(())
    }

    #[test]
    fn the_pinned_literal_is_not_an_identifier_but_is_still_sent() -> Result<(), Box<dyn Error>> {
        // The unit test's own argument is neither a SAID nor a nonce — which is exactly why this
        // port does not type the argument. It reaches the path unchanged, as upstream sends it.
        assert_eq!(
            Notifications::record_path(PINNED_LITERAL)?.as_str(),
            format!("/notifications/{PINNED_LITERAL}")
        );
        Ok(())
    }

    #[test]
    fn a_listing_tells_an_unreported_window_from_an_empty_one() -> Result<(), Box<dyn Error>> {
        let empty = NotificationListing {
            window: Some(ContentRange::parse("notes 0-0/0", &unit()?)?),
            notifications: Vec::new(),
        };
        let unreported = NotificationListing {
            window: None,
            notifications: Vec::new(),
        };
        assert_ne!(empty.window, unreported.window);
        // Upstream both are `{start: 0, end: 0, total: 0}`.
        assert_eq!(empty.window.map(ContentRange::total), Some(0));
        assert_eq!(unreported.window, None);
        Ok(())
    }

    #[test]
    fn unread_filters_the_way_the_integration_helper_does() -> Result<(), Box<dyn Error>> {
        let page = format!(
            "[{},{},{}]",
            notification(NONCE, false),
            notification(NONCE, true),
            notification(NONCE, false)
        );
        let notifications: Vec<Notification> = serde_json::from_str(&page)?;
        let listing = NotificationListing {
            window: None,
            notifications,
        };
        assert_eq!(listing.notifications.len(), 3);
        assert_eq!(listing.unread().count(), 2);
        assert!(listing.unread().all(|notification| !notification.read));
        Ok(())
    }

    #[test]
    fn an_answer_of_the_wrong_shape_is_refused() {
        // `list` upstream is `Promise<any>` and its page is `res.json()` with no cast at all.
        for wrong in [
            r#"[{"i":"0AAD"}]"#,
            r#"[{"dt":"2023-01-01","r":false,"a":{}}]"#,
            r#"{"i":"0AAD"}"#,
            "null",
        ] {
            assert!(
                serde_json::from_str::<Vec<Notification>>(wrong).is_err(),
                "{wrong} was accepted as a notification page"
            );
        }
    }

    #[test]
    fn a_well_formed_notification_decodes_with_its_payload() -> Result<(), Box<dyn Error>> {
        let decoded: Notification = serde_json::from_str(&notification(NONCE, false))?;
        assert_eq!(decoded.id, NONCE);
        assert!(!decoded.read);
        assert_eq!(decoded.attributes.route.as_deref(), Some("/multisig/icp"));
        Ok(())
    }
}
