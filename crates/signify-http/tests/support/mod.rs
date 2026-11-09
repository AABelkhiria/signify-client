//! Helpers shared by the integration tests.

#![allow(
    dead_code,
    reason = "compiled once per test binary; not every binary uses every helper"
)]

use proptest::test_runner::TestCaseError;
use signify_http::transport::Method;

/// Turns any displayable error into a failed property case.
pub(crate) fn fail(error: impl core::fmt::Display) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

/// Picks a method by index, wrapping around the full set.
pub(crate) fn method_of(index: usize) -> Method {
    *Method::ALL.get(index % Method::ALL.len()).unwrap_or(&Method::Get)
}

/// A minimal executor; every future reachable from a scripted transport and a test clock is ready
/// on its first poll, so no runtime is needed and no wall-clock time passes.
pub(crate) fn block_on<F: core::future::Future>(future: F) -> F::Output {
    use core::task::{Context, Poll, Waker};
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
    }
}

/// One request as a loopback server saw it on the wire.
#[derive(Clone, Debug, Default)]
pub(crate) struct Seen {
    pub(crate) request_line: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl Seen {
    /// The first value of a header, matched case-insensitively.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(existing, _)| existing.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}
