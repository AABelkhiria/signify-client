//! The transport boundary: what a request and a response are, and who sends them.
//!
//! The pinned reference has no transport abstraction — `app/clienting.ts` calls the global
//! `fetch` and every endpoint module calls that client — so there is nothing here to translate.
//! The shape comes from `ARCHITECTURE.md` §8.1 instead, and the compatibility evidence is that
//! the reference's own requests can be expressed exactly.
//!
//! # The trait is dyn-compatible on purpose
//!
//! [`Transport::execute`] returns a boxed future rather than being an `async fn`, because a
//! client holds one transport for its whole life and must be able to hold it as
//! `Arc<dyn Transport>` — a production implementation in a binary, a [`ScriptedTransport`] in a
//! test, with no generic parameter spreading through every endpoint family. One allocation per
//! request is not measurable beside a network round trip.
//!
//! # What belongs here, and what does not
//!
//! This module has no timeout policy, no retries, and no KERIA endpoint knowledge: a timeout is
//! an *outcome* a transport reports ([`TransportError::Timeout`]), retry policy is Roadmap 5.4,
//! and the request builder that knows about JSON and content types is Roadmap 5.3. A non-success
//! status is not a failure here — it is a [`Response`] with that status, because deciding what a
//! `404` means belongs to the layer that knows what was asked for.

pub mod error;
pub mod message;
pub mod scripted;
pub mod url;

use core::future::Future;
use core::pin::Pin;

pub use error::TransportError;
pub use message::{
    DEFAULT_RESPONSE_BODY_LIMIT, MAX_REQUEST_BODY_BYTES, MAX_RESPONSE_BODY_LIMIT, Method, Request, RequestBuilder,
    Response, StatusCode,
};
pub use scripted::ScriptedTransport;
pub use url::{MAX_URL_BYTES, RequestUrl};

/// The future one request produces.
///
/// It is `Send` so a client works on multi-threaded executors, and boxed so [`Transport`] stays
/// usable as a trait object.
pub type TransportFuture<'transport> =
    Pin<Box<dyn Future<Output = Result<Response, TransportError>> + Send + 'transport>>;

/// Sends requests and returns responses.
///
/// An implementation must:
///
/// - leave the request's method, URL bytes, header order, and body exactly as given;
/// - stop reading a response body at [`Request::response_limit`] and report
///   [`TransportError::ResponseBodyTooLarge`] rather than buffering past it;
/// - return a [`Response`] for any status the server sent, including 4xx and 5xx;
/// - do nothing observable if its future is dropped before completion.
///
/// Implementations are shared across threads, so they are `Send + Sync`; per-request state
/// belongs in the returned future, not in the transport.
pub trait Transport: core::fmt::Debug + Send + Sync {
    /// Sends one request.
    ///
    /// The returned future performs the work; dropping it cancels the request.
    fn execute(&self, request: Request) -> TransportFuture<'_>;
}
