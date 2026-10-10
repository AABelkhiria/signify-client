//! Plumbing every live scenario needs: waiting operations out, and the reads that precede them.
//!
//! Extracted from the wave files, which had written `wait_and_delete` twelve times between them.

use core::time::Duration;
use std::error::Error;

use keri_protocol::said::Said;
use keria_types::api::{Notification, Role};
use serde_json::Value;
use signify_client::client::{ClientRequest, ConnectedClient};
use signify_client::endpoint::oobis::{OobiResolution, RESOLUTIONS_SEGMENT};
use signify_http::request::{ItemRange, ResourcePath};
use signify_http::retry::{Clock, TokioClock};
use signify_http::transport::Method;
use signify_http::transport::RequestUrl;

use crate::preset::Environment;

/// How long to wait between notification polls.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// How many times to poll before giving up on a notification.
const POLL_ATTEMPTS: usize = 60;

/// Waits one operation out and deletes it, and any operation it depends on.
///
/// The upstream postcondition every scenario asserts is that no operation is left behind, and a
/// delegation approval spawns a `witness.…` operation inside its own `metadata.depends`.
///
/// # Errors
///
/// Returns whatever reading, waiting on, or deleting the operation returns.
pub async fn wait_and_delete(client: &ConnectedClient, name: &str) -> Result<Value, Box<dyn Error>> {
    let operation = client.operations().get(name).await?;
    let completed = client.poller().wait(operation).await?;
    let (name, metadata, response) = completed.into_parts();
    client.operations().delete(&name).await?;
    if let Some(depends) = metadata
        .as_ref()
        .and_then(|metadata| metadata.get("depends"))
        .and_then(|depends| depends.get("name"))
        .and_then(Value::as_str)
    {
        client.operations().delete(depends).await?;
    }
    Ok(response)
}

/// Waits for a notification on `route` and returns the message it names, marking it read.
///
/// Polls rather than sleeping a fixed span, so a scenario waits exactly as long as it must.
///
/// # Errors
///
/// Returns an error when no notification arrives within `POLL_ATTEMPTS` polls, when the one that
/// does names no message, and whatever listing or marking returns.
pub async fn await_notification(client: &ConnectedClient, route: &str) -> Result<Said, Box<dyn Error>> {
    crate::progress(&format!("waiting for a notification on {route}"));
    for _ in 0..POLL_ATTEMPTS {
        let matching = unread_on(client, route).await?;
        if let Some(last) = matching.last() {
            let said = last
                .attributes
                .digest
                .clone()
                .ok_or("the notification names no message")?;
            for notification in &matching {
                client.notifications().mark(&notification.id).await?;
            }
            return Ok(Said::from_qb64(&said)?);
        }
        TokioClock.sleep(POLL_INTERVAL).await;
    }
    Err(format!("no notification on {route} arrived in time").into())
}

/// Waits for at least `minimum` unread notifications on `route` and returns what every one of
/// them names, marking them all.
///
/// [`await_notification`] answers one round with one proposal; a round that sends one message per
/// member — the agent end-role round does — needs every SAID rather than the last. Everything
/// unread on the route is returned, so a scenario that leaves a round's notifications unread on a
/// client and then waits on the same route with that client picks the old ones up too.
///
/// # Errors
///
/// Returns an error when `minimum` notifications do not arrive within `POLL_ATTEMPTS` polls, when
/// one names no message, and whatever listing or marking returns.
pub async fn await_proposals(
    client: &ConnectedClient,
    route: &str,
    minimum: usize,
) -> Result<Vec<Said>, Box<dyn Error>> {
    crate::progress(&format!("waiting for {minimum} notification(s) on {route}"));
    for _ in 0..POLL_ATTEMPTS {
        let matching = unread_on(client, route).await?;
        if matching.len() >= minimum {
            let mut proposals = Vec::with_capacity(matching.len());
            for notification in &matching {
                let said = notification
                    .attributes
                    .digest
                    .clone()
                    .ok_or("a notification names no message")?;
                proposals.push(Said::from_qb64(&said)?);
                client.notifications().mark(&notification.id).await?;
            }
            return Ok(proposals);
        }
        TokioClock.sleep(POLL_INTERVAL).await;
    }
    Err(format!("no {minimum} notifications on {route} arrived in time").into())
}

/// Lists every unread notification on `route`, however many notifications the agent holds.
///
/// The agent pages oldest first and counts read notifications in the page, and nothing here ever
/// deletes one, so a long scenario pushes its newest notifications past the default page. The
/// first page reports the total, and when the total exceeds the page everything is asked for.
async fn unread_on(client: &ConnectedClient, route: &str) -> Result<Vec<Notification>, Box<dyn Error>> {
    let mut listing = client.notifications().list(ItemRange::DEFAULT).await?;
    if let Some(window) = listing.window
        && window.total() > ItemRange::DEFAULT.end().saturating_add(1)
    {
        listing = client
            .notifications()
            .list(ItemRange::new(0, window.total().saturating_sub(1))?)
            .await?;
    }
    Ok(listing
        .unread()
        .filter(|notification| notification.attributes.route.as_deref() == Some(route))
        .cloned()
        .collect())
}

/// Resolves one OOBI URL under `alias` and returns the identifier the resolution answered with.
///
/// The identifier is returned rather than discarded because that is the thing a scenario asks
/// about: wave 9 proves a truncated OOBI still resolves by checking it answers the delegate's own
/// prefix.
///
/// # Errors
///
/// Returns whatever building the URL, resolving it, or waiting on the operation returns.
pub async fn resolve_oobi(client: &ConnectedClient, url: &str, alias: &str) -> Result<String, Box<dyn Error>> {
    crate::progress(&format!("resolving {alias}'s OOBI"));
    let resolution = OobiResolution {
        url: RequestUrl::new(url.to_owned())?,
        alias: Some(alias.to_owned()),
    };
    let submitted = client.oobis().resolve(&resolution).await?;
    let completed = client.poller().wait(submitted).await?;
    let name = completed.name().to_owned();
    let state = completed.into_response();
    client.operations().delete(&name).await?;
    Ok(state.identifier)
}

/// Returns the agent OOBI `alias` publishes.
///
/// # Errors
///
/// Returns an error when the identifier publishes no OOBI, which is what an identifier that has
/// not authorised its agent looks like.
pub async fn agent_oobi(client: &ConnectedClient, alias: &str) -> Result<String, Box<dyn Error>> {
    client
        .oobis()
        .get(alias, &Role::Agent)
        .await?
        .oobis
        .first()
        .cloned()
        .ok_or_else(|| format!("{alias} publishes no OOBI").into())
}

/// Resolves an ACDC schema so the agent will validate credentials against it.
///
/// The one step that must precede any issuance: KERIA refuses a credential whose schema it has
/// never seen. The URL is the environment's schema source, which is the vLEI server upstream and
/// may be any host serving `/oobi/{said}`.
///
/// # Errors
///
/// Returns whatever resolving the OOBI returns, including the refusal when the schema source is
/// unreachable or serves no such SAID.
pub async fn resolve_schema(
    client: &ConnectedClient,
    environment: &Environment,
    schema: &Said,
) -> Result<(), Box<dyn Error>> {
    let said = schema.qb64()?;
    let url = format!("{}/oobi/{said}", environment.schema_url);
    crate::progress(&format!("resolving the schema OOBI {said}"));
    // A schema resolution's operation answers with the schema, not a key state, which the typed
    // `oobis().resolve` cannot read (a live KERIA answers `missing field i`). The harness posts
    // the same body and waits on the operation untyped; the typed decoder is a separate defect.
    let resolution = OobiResolution {
        url: RequestUrl::new(url)?,
        alias: Some(said.clone()),
    };
    let path = ResourcePath::builder().segment(RESOLUTIONS_SEGMENT).build()?;
    let response = client
        .fetch(ClientRequest::new(Method::Post, path).body(resolution.body()?))
        .await?;
    let submitted: keria_types::api::UntypedOperation = serde_json::from_slice(response.body())?;
    wait_and_delete(client, &submitted.name).await?;
    Ok(())
}

/// Returns the environment's witness triple as identifier prefixes.
///
/// The waves that create witnessed identifiers each parsed this list themselves.
///
/// # Errors
///
/// Returns an error when one of the configured prefixes is not a qualified identifier.
pub fn witness_prefixes(
    environment: &Environment,
) -> Result<Vec<keri_protocol::prefix::IdentifierPrefix>, Box<dyn Error>> {
    Ok(environment
        .witness_prefixes
        .iter()
        .map(|prefix| keri_protocol::prefix::IdentifierPrefix::from_qb64(prefix))
        .collect::<Result<Vec<_>, _>>()?)
}
