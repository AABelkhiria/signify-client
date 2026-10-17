//! A transport that forwards to a real deployment and keeps a transcript.
//!
//! The transcript is the point. A system test that only passes leaves nothing behind; one that
//! records what it asked and what it was told leaves evidence a hermetic test can assert against
//! later, and a reader can diff when the deployment changes.
//!
//! What is recorded is deliberately verbatim on the response side. The request may be normalised —
//! a timestamp cannot be reproduced — but a response is exactly what the deployment sent, because
//! that is the thing under observation.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use signify_http::transport::{Request, Response, Transport, TransportFuture};

/// One exchange with the deployment.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Observation {
    /// Position in the scenario, from zero.
    pub sequence: usize,
    /// The request's method.
    pub method: String,
    /// The resource addressed, path and query.
    pub resource: String,
    /// The request's headers, in the order they were sent.
    pub request_headers: Vec<(String, String)>,
    /// The request's body as text, when it carried one that is UTF-8.
    pub request_body: Option<String>,
    /// The status the deployment answered with.
    pub status: u16,
    /// The response's headers, verbatim and in order.
    pub response_headers: Vec<(String, String)>,
    /// The response's body as text, when it is UTF-8.
    pub response_body: Option<String>,
    /// How long the exchange took, in milliseconds.
    ///
    /// Recorded because a system test states its timeout policy, and a measurement is a better
    /// basis for one than the reference's magic `AbortSignal.timeout(20_000)`.
    pub elapsed_ms: u128,
}

/// Forwards to a deployment and keeps every exchange.
pub struct Recorder {
    scenario: String,
    inner: Arc<dyn Transport>,
    observations: Mutex<Vec<Observation>>,
}

impl std::fmt::Debug for Recorder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Recorder")
            .field("scenario", &self.scenario)
            .field("observations", &self.observations().len())
            .finish_non_exhaustive()
    }
}

impl Recorder {
    /// Wraps `inner`, labelling the transcript with `scenario`.
    #[must_use]
    pub fn new(scenario: &str, inner: Arc<dyn Transport>) -> Arc<Self> {
        Arc::new(Self {
            scenario: scenario.to_owned(),
            inner,
            observations: Mutex::new(Vec::new()),
        })
    }

    /// Returns the scenario this transcript belongs to.
    #[must_use]
    pub fn scenario(&self) -> &str {
        &self.scenario
    }

    /// Returns everything recorded so far.
    #[must_use]
    pub fn observations(&self) -> Vec<Observation> {
        self.observations
            .lock()
            .map_or_else(|_| Vec::new(), |guard| guard.clone())
    }

    /// Returns the headers of a request or response as ordered pairs.
    fn pairs(headers: &signify_http::header::Headers) -> Vec<(String, String)> {
        headers
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_str().to_owned()))
            .collect()
    }

    /// Records one completed exchange.
    fn record(&self, request: &Request, response: &Response, elapsed_ms: u128) {
        let Ok(mut guard) = self.observations.lock() else {
            return;
        };
        let resource = match request.url().query() {
            Some(query) => format!("{}?{query}", request.url().path()),
            None => request.url().path().to_owned(),
        };
        let sequence = guard.len();
        guard.push(Observation {
            sequence,
            method: request.method().as_str().to_owned(),
            resource,
            request_headers: Self::pairs(request.headers()),
            request_body: request
                .body()
                .and_then(|bytes| core::str::from_utf8(bytes).ok())
                .map(ToOwned::to_owned),
            status: response.status().as_u16(),
            response_headers: Self::pairs(response.headers()),
            response_body: core::str::from_utf8(response.body()).ok().map(ToOwned::to_owned),
            elapsed_ms,
        });
    }
}

impl Transport for Recorder {
    fn execute(&self, request: Request) -> TransportFuture<'_> {
        Box::pin(async move {
            let started = Instant::now();
            let answered = self.inner.execute(request.clone()).await;
            let elapsed = started.elapsed().as_millis();
            // A failed exchange is still an observation, but there is no response to record; the
            // scenario's own assertion reports what went wrong.
            if let Ok(response) = &answered {
                self.record(&request, response, elapsed);
            }
            answered
        }) as TransportFuture<'_>
    }
}
