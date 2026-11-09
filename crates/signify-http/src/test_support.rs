//! Helpers shared by the crate's unit tests.

#![allow(
    dead_code,
    reason = "compiled once per test binary; not every binary uses every helper"
)]

use std::error::Error;

/// Compile-time proof that a type can cross threads.
pub(crate) const fn assert_send_sync<T: Send + Sync + ?Sized>() {}

/// A minimal executor; every future reachable from a scripted transport and a test clock is ready
/// on its first poll.
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

/// Asserts an error's text holds every fragment and that it has a source exactly when expected.
pub(crate) fn displays_and_sources(error: &impl Error, fragments: &[&str], has_source: bool) {
    let rendered = error.to_string();
    for fragment in fragments {
        assert!(rendered.contains(fragment), "{rendered} lacks {fragment}");
    }
    assert_eq!(error.source().is_some(), has_source, "{error}");
}
