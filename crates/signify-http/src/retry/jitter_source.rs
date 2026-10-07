//! Where the randomness in a jittered delay comes from.
//!
//! `AGENTS.md` §2.3 requires that randomness come from an operating-system CSPRNG through a
//! standard crate, and that a test needing determinism inject a source rather than have production
//! code silently seed a pseudo-random one. That is the whole reason this is a trait: [`OsJitter`]
//! is the only thing a client ever uses, and [`FixedJitter`] exists so a schedule can be asserted
//! exactly.
//!
//! A backoff delay is not a secret and does not need cryptographic quality. It draws from the same
//! OS source anyway, because reaching for a weaker generator would mean adding a dependency to
//! avoid using one already in the tree.

use core::fmt;

/// Draws the values a jittered delay is randomised with.
///
/// Implementations are shared across threads, so they are `Send + Sync`.
pub trait JitterSource: fmt::Debug + Send + Sync {
    /// Returns a value uniformly distributed over the whole `u32` range.
    fn next_u32(&self) -> u32;
}

/// Draws from the operating system's entropy source.
///
/// The default for every policy. If the OS refuses — which on a healthy system does not happen —
/// the value falls back to `u32::MAX`, which yields the **longest** delay in the band rather than
/// the shortest. Failing towards a longer wait is the safe direction: the alternative would turn
/// an entropy failure into a burst of immediate retries against a server that is already
/// struggling.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsJitter;

impl JitterSource for OsJitter {
    fn next_u32(&self) -> u32 {
        let mut bytes = [0_u8; 4];
        match getrandom::fill(&mut bytes) {
            Ok(()) => u32::from_le_bytes(bytes),
            Err(_) => u32::MAX,
        }
    }
}

/// Returns the same value every time.
///
/// For tests that need an exact schedule. `0` yields the shortest delay in a band and `u32::MAX`
/// the longest, so a test can pin both edges without a generator.
///
/// ```
/// use core::time::Duration;
/// use signify_http::retry::{Jitter, JitterSource, FixedJitter};
///
/// let shortest = FixedJitter::new(0);
/// let longest = FixedJitter::new(u32::MAX);
/// let delay = Duration::from_millis(800);
///
/// assert_eq!(Jitter::Equal.apply(delay, shortest.next_u32()), Duration::from_millis(400));
/// assert_eq!(Jitter::Equal.apply(delay, longest.next_u32()), delay);
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FixedJitter {
    value: u32,
}

impl FixedJitter {
    /// Creates a source that always returns `value`.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self { value }
    }
}

impl JitterSource for FixedJitter {
    fn next_u32(&self) -> u32 {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;

    /// Compile-time proof that a value can cross threads.
    fn assert_send_sync<T: Send + Sync>(_: &T) {}

    #[test]
    fn a_fixed_source_is_fixed() {
        for value in [0_u32, 1, u32::MAX / 2, u32::MAX] {
            let source = FixedJitter::new(value);
            assert_eq!(source.next_u32(), value);
            assert_eq!(source.next_u32(), value);
        }
        assert_eq!(FixedJitter::default().next_u32(), 0);
    }

    #[test]
    fn the_os_source_varies() {
        // Not a statistical test: enough draws that a constant or a stuck source is caught, while
        // a genuine collision run remains vanishingly unlikely.
        let source = OsJitter;
        let drawn: HashSet<u32> = (0..64).map(|_| source.next_u32()).collect();
        assert!(drawn.len() > 32, "only {} distinct values in 64 draws", drawn.len());
    }

    #[test]
    fn sources_are_usable_behind_a_trait_object() {
        let sources: [Arc<dyn JitterSource>; 2] = [Arc::new(OsJitter), Arc::new(FixedJitter::new(7))];
        for source in &sources {
            let _ = source.next_u32();
            assert_ne!(format!("{source:?}"), "");
        }
        assert_send_sync(&sources);
        assert_eq!(sources.get(1).map(|source| source.next_u32()), Some(7));
    }
}
