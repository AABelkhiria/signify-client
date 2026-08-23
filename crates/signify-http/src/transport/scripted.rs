//! A deterministic in-memory transport for tests.

use core::fmt;
use std::collections::VecDeque;
use std::sync::Mutex;

use crate::transport::error::TransportError;
use crate::transport::message::{Request, Response};
use crate::transport::{Transport, TransportFuture};

/// What a scripted transport answers one request with.
#[derive(Debug)]
enum Outcome {
    /// A response to return, subject to the request's own limit.
    Response(Box<Response>),
    /// A failure to return.
    Failure(TransportError),
}

/// The mutable half, behind one lock.
#[derive(Debug, Default)]
struct Script {
    outcomes: VecDeque<Outcome>,
    recorded: Vec<Request>,
}

/// A transport that answers from a script and records what it was asked.
///
/// Answers are served in the order they were scripted. Running out is
/// [`TransportError::ScriptExhausted`] rather than a hang or a panic, so a test that issues more
/// requests than it planned for fails with a message that says so.
///
/// The work happens when the future is **polled**, not when [`Transport::execute`] is called, so
/// dropping a future without awaiting it consumes no scripted answer and records no request —
/// which is what cancelling a real request does.
///
/// ```
/// use signify_http::header::Headers;
/// use signify_http::transport::{
///     Method, Request, RequestUrl, Response, ScriptedTransport, StatusCode, Transport,
/// };
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let transport = ScriptedTransport::new()
///     .respond(Response::new(StatusCode::new(202)?, Headers::new(), b"{}".to_vec())?);
///
/// let request = Request::builder(Method::Post, RequestUrl::new("https://keria.example/boot")?)
///     .body(b"{}".to_vec())
///     .build()?;
///
/// // Any executor will do; the future never yields.
/// let response = futures_lite_block_on(transport.execute(request))?;
/// assert_eq!(response.status().as_u16(), 202);
///
/// let recorded = transport.recorded();
/// assert_eq!(recorded.len(), 1);
/// assert_eq!(recorded.first().map(|request| request.url().path()), Some("/boot"));
/// # Ok(())
/// # }
/// #
/// # // A three-line executor, so the example needs no runtime dependency.
/// # fn futures_lite_block_on<F: core::future::Future>(future: F) -> F::Output {
/// #     use core::task::{Context, Poll, Waker};
/// #     let mut future = Box::pin(future);
/// #     let mut context = Context::from_waker(Waker::noop());
/// #     loop {
/// #         if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
/// #             return value;
/// #         }
/// #     }
/// # }
/// ```
#[derive(Debug, Default)]
pub struct ScriptedTransport {
    script: Mutex<Script>,
}

impl ScriptedTransport {
    /// Creates a transport with an empty script.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scripts one response.
    #[must_use]
    pub fn respond(self, response: Response) -> Self {
        self.push(Outcome::Response(Box::new(response)));
        self
    }

    /// Scripts one failure.
    #[must_use]
    pub fn fail(self, error: TransportError) -> Self {
        self.push(Outcome::Failure(error));
        self
    }

    /// Scripts one more response after construction.
    pub fn push_response(&self, response: Response) {
        self.push(Outcome::Response(Box::new(response)));
    }

    /// Scripts one more failure after construction.
    pub fn push_failure(&self, error: TransportError) {
        self.push(Outcome::Failure(error));
    }

    /// Returns every request this transport answered, in order.
    #[must_use]
    pub fn recorded(&self) -> Vec<Request> {
        self.with_script(|script| script.recorded.clone())
    }

    /// Returns the most recent request, which is what a test usually asserts against.
    #[must_use]
    pub fn last_request(&self) -> Option<Request> {
        self.with_script(|script| script.recorded.last().cloned())
    }

    /// Returns how many requests this transport has answered.
    #[must_use]
    pub fn answered(&self) -> usize {
        self.with_script(|script| script.recorded.len())
    }

    /// Returns how many scripted answers remain unused.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.with_script(|script| script.outcomes.len())
    }

    /// Records one request and takes the next scripted answer.
    fn answer(&self, request: Request) -> Result<Response, TransportError> {
        let limit = request.response_limit();
        let outcome = self.with_script(|script| {
            script.recorded.push(request);
            script.outcomes.pop_front()
        });
        match outcome {
            Some(Outcome::Response(response)) => (*response).within_limit(limit),
            Some(Outcome::Failure(error)) => Err(error),
            None => Err(TransportError::ScriptExhausted {
                answered: self.answered(),
            }),
        }
    }

    fn push(&self, outcome: Outcome) {
        self.with_script(|script| script.outcomes.push_back(outcome));
    }

    /// Runs one closure under the lock, recovering from a poisoned lock rather than panicking.
    ///
    /// A poisoned lock means an earlier test thread panicked while holding it; the state it
    /// guarded is a request log, so continuing with it is safe and losing the test's own failure
    /// message to a second panic is not.
    fn with_script<T>(&self, action: impl FnOnce(&mut Script) -> T) -> T {
        let mut guard = self.script.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        action(&mut guard)
    }
}

impl Transport for ScriptedTransport {
    fn execute(&self, request: Request) -> TransportFuture<'_> {
        // The answer is taken when the future is polled, not when `execute` is called, so a
        // dropped future consumes nothing.
        Box::pin(async move { self.answer(request) })
    }
}

/// Formats the script without cloning it.
impl fmt::Display for ScriptedTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "scripted transport: {} answered, {} remaining",
            self.answered(),
            self.remaining()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    use crate::header::Headers;
    use crate::transport::{Method, RequestUrl, StatusCode};

    /// A minimal executor: every future here is ready on its first poll.
    fn block_on<F: core::future::Future>(future: F) -> F::Output {
        use core::task::{Context, Poll, Waker};
        let mut future = Box::pin(future);
        let mut context = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
                return value;
            }
        }
    }

    fn request(method: Method, path: &str) -> Result<Request, Box<dyn Error>> {
        Ok(Request::builder(method, RequestUrl::new(format!("https://keria.example{path}"))?).build()?)
    }

    fn response(code: u16, body: &[u8]) -> Result<Response, Box<dyn Error>> {
        Ok(Response::new(StatusCode::new(code)?, Headers::new(), body.to_vec())?)
    }

    #[test]
    fn answers_are_served_in_order_and_requests_recorded() -> Result<(), Box<dyn Error>> {
        let transport = ScriptedTransport::new()
            .respond(response(200, b"first")?)
            .respond(response(202, b"second")?);
        assert_eq!(transport.remaining(), 2);
        assert_eq!(transport.answered(), 0);

        let first = block_on(transport.execute(request(Method::Get, "/one")?))?;
        assert_eq!(first.status().as_u16(), 200);
        assert_eq!(first.body(), b"first");

        let second = block_on(transport.execute(request(Method::Post, "/two")?))?;
        assert_eq!(second.status().as_u16(), 202);

        assert_eq!(transport.answered(), 2);
        assert_eq!(transport.remaining(), 0);
        let recorded = transport.recorded();
        let paths: Vec<&str> = recorded.iter().map(|request| request.url().path()).collect();
        assert_eq!(paths, ["/one", "/two"]);
        assert_eq!(recorded.first().map(Request::method), Some(Method::Get));
        assert_eq!(
            transport.last_request().map(|request| request.method()),
            Some(Method::Post)
        );
        Ok(())
    }

    #[test]
    fn a_scripted_failure_is_returned_as_given() -> Result<(), Box<dyn Error>> {
        let transport = ScriptedTransport::new().fail(TransportError::Timeout { milliseconds: 250 });
        let outcome = block_on(transport.execute(request(Method::Get, "/slow")?));
        assert!(matches!(outcome, Err(TransportError::Timeout { milliseconds: 250 })));
        // The request is still recorded: it was issued, and only its answer failed.
        assert_eq!(transport.answered(), 1);
        Ok(())
    }

    #[test]
    fn running_out_of_answers_is_a_typed_failure() -> Result<(), Box<dyn Error>> {
        let transport = ScriptedTransport::new().respond(response(200, b"")?);
        block_on(transport.execute(request(Method::Get, "/one")?))?;
        let outcome = block_on(transport.execute(request(Method::Get, "/two")?));
        assert!(matches!(outcome, Err(TransportError::ScriptExhausted { answered: 2 })));
        Ok(())
    }

    #[test]
    fn the_requests_own_limit_is_enforced() -> Result<(), Box<dyn Error>> {
        let transport = ScriptedTransport::new().respond(response(200, b"0123456789")?);
        let request = Request::builder(Method::Get, RequestUrl::new("https://keria.example/big")?)
            .response_limit(4)
            .build()?;
        let outcome = block_on(transport.execute(request));
        assert!(matches!(
            outcome,
            Err(TransportError::ResponseBodyTooLarge { limit: 4, actual: 10 })
        ));
        Ok(())
    }

    #[test]
    fn dropping_a_future_consumes_nothing() -> Result<(), Box<dyn Error>> {
        let transport = ScriptedTransport::new().respond(response(200, b"kept")?);
        let future = transport.execute(request(Method::Get, "/cancelled")?);
        drop(future);

        // Nothing was recorded and the answer is still available for the next request.
        assert_eq!(transport.answered(), 0);
        assert_eq!(transport.remaining(), 1);
        let response = block_on(transport.execute(request(Method::Get, "/kept")?))?;
        assert_eq!(response.body(), b"kept");
        assert_eq!(
            transport.last_request().map(|request| request.url().path().to_owned()),
            Some("/kept".to_owned())
        );
        Ok(())
    }

    #[test]
    fn a_script_can_grow_after_construction() -> Result<(), Box<dyn Error>> {
        let transport = ScriptedTransport::new();
        assert_eq!(transport.remaining(), 0);
        transport.push_response(response(200, b"later")?);
        transport.push_failure(TransportError::connect("refused"));
        assert_eq!(transport.remaining(), 2);

        assert_eq!(
            block_on(transport.execute(request(Method::Get, "/a")?))?.body(),
            b"later"
        );
        assert!(matches!(
            block_on(transport.execute(request(Method::Get, "/b")?)),
            Err(TransportError::Connect { .. })
        ));
        assert_eq!(transport.to_string(), "scripted transport: 2 answered, 0 remaining");
        Ok(())
    }

    #[test]
    fn a_transport_object_is_usable_behind_a_trait_object() -> Result<(), Box<dyn Error>> {
        // The client will hold its transport this way, so the trait must stay dyn-compatible.
        let transport: std::sync::Arc<dyn Transport> =
            std::sync::Arc::new(ScriptedTransport::new().respond(response(200, b"dyn")?));
        let response = block_on(transport.execute(request(Method::Get, "/dyn")?))?;
        assert_eq!(response.body(), b"dyn");
        Ok(())
    }

    #[test]
    fn the_transport_is_send_and_sync() {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ScriptedTransport>();
        assert_send_sync::<Request>();
        assert_send_sync::<Response>();
        assert_send_sync::<TransportError>();
    }
}
