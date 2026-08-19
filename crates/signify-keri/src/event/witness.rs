//! Witness fault tolerance.
//!
//! KERI events name a set of witnesses and a threshold — the reference's `toad` — of how many must
//! receipt an event for it to count as witnessed. [`ample`] computes the default threshold for a
//! witness set, the smallest count that still tolerates the expected number of faulty witnesses.
//!
//! This module ports `ample` from `src/keri/core/eventing.ts`. All arithmetic is exact integer
//! arithmetic: `AGENTS.md` §2.4 forbids floating point for protocol thresholds, and the reference's
//! `Math.ceil`/`Math.floor` results are reproduced with checked integer division.

use crate::event::error::EventError;

/// Which majority a witness threshold has to clear.
///
/// The distinction only matters for witness counts where the two candidate fault estimates
/// disagree — the smallest is six, where a weak threshold is 4 and a strong one 5.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum AmpleMode {
    /// The smallest sufficient majority; the reference's `weak = true` default.
    #[default]
    Weak,
    /// The larger majority, which keeps liveness under the worst tolerated fault estimate.
    Strong,
}

/// Returns the default witness threshold for `witnesses` witnesses.
///
/// When `faults` is `None` the tolerated fault count is derived from the witness count as the
/// largest `f` satisfying `witnesses >= 3 * f + 1`, evaluated for both the floor and the ceiling of
/// that division exactly as the reference does. When `faults` is given it is used directly.
///
/// ```
/// use signify_keri::event::witness::{AmpleMode, ample};
///
/// # fn main() -> Result<(), signify_keri::event::EventError> {
/// // Four witnesses tolerate one fault, so three receipts suffice.
/// assert_eq!(ample(4, None, AmpleMode::Weak)?, 3);
/// // Six is the smallest count where the two majorities disagree.
/// assert_eq!(ample(6, None, AmpleMode::Weak)?, 4);
/// assert_eq!(ample(6, None, AmpleMode::Strong)?, 5);
/// // An empty witness set needs no receipts.
/// assert_eq!(ample(0, None, AmpleMode::Weak)?, 0);
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns [`EventError::FaultToleranceTooHigh`] when an explicit `faults` is so large that no
/// threshold can satisfy both majorities, matching the reference's `f is too big for n` rejection.
/// The reference additionally clamps a negative witness count to zero; `u32` makes that
/// unrepresentable.
pub fn ample(witnesses: u32, faults: Option<u32>, mode: AmpleMode) -> Result<u32, EventError> {
    let total = u64::from(witnesses);
    if let Some(declared) = faults {
        let declared = u64::from(declared);
        // The two candidate majorities: more than half of the witnesses plus the faults, and
        // every non-faulty witness.
        let majority = half_up(total.saturating_add(declared).saturating_add(1))?;
        let non_faulty = total.saturating_sub(declared);
        if non_faulty < majority && total > 0 {
            return Err(EventError::FaultToleranceTooHigh {
                witnesses,
                faults: faults.unwrap_or(u32::MAX),
            });
        }
        let chosen = match mode {
            AmpleMode::Weak => total.min(majority).min(non_faulty),
            AmpleMode::Strong => total.min(majority.max(non_faulty)),
        };
        return narrow(chosen);
    }

    // The least and the most faults consistent with `witnesses >= 3 * faults + 1`.
    let span = total.saturating_sub(1);
    let least = 1.max(span / 3);
    let most = 1.max(div_up(span, 3)?);
    let chosen = match mode {
        AmpleMode::Weak => total
            .min(half_up(total.saturating_add(least).saturating_add(1))?)
            .min(half_up(total.saturating_add(most).saturating_add(1))?),
        AmpleMode::Strong => total.min(
            total
                .saturating_sub(least)
                .max(half_up(total.saturating_add(least).saturating_add(1))?),
        ),
    };
    narrow(chosen)
}

/// Returns `value / 2` rounded up.
fn half_up(value: u64) -> Result<u64, EventError> {
    div_up(value, 2)
}

/// Returns `value / divisor` rounded up, without floating point.
fn div_up(value: u64, divisor: u64) -> Result<u64, EventError> {
    let raised = value.checked_add(divisor - 1).ok_or(EventError::ValueOutOfRange {
        context: "witness fault tolerance",
    })?;
    Ok(raised / divisor)
}

/// Narrows a computed threshold back to the witness-count width.
fn narrow(value: u64) -> Result<u32, EventError> {
    u32::try_from(value).map_err(|_| EventError::ValueOutOfRange {
        context: "witness threshold",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exact `ample(n)` outputs for both majorities, taken from the pinned reference.
    const REFERENCE_TABLE: [(u32, u32, u32); 14] = [
        (0, 0, 0),
        (1, 1, 1),
        (2, 2, 2),
        (3, 3, 3),
        (4, 3, 3),
        (5, 4, 4),
        (6, 4, 5),
        (7, 5, 5),
        (8, 6, 6),
        (9, 6, 7),
        (10, 7, 7),
        (16, 11, 11),
        (17, 12, 12),
        (100, 67, 67),
    ];

    #[test]
    fn the_reference_table_is_reproduced() -> Result<(), EventError> {
        for (witnesses, weak, strong) in REFERENCE_TABLE {
            assert_eq!(ample(witnesses, None, AmpleMode::Weak)?, weak, "n = {witnesses}");
            assert_eq!(ample(witnesses, None, AmpleMode::Strong)?, strong, "n = {witnesses}");
        }
        assert_eq!(AmpleMode::default(), AmpleMode::Weak);
        Ok(())
    }

    #[test]
    fn the_two_majorities_agree_except_where_the_fault_estimates_differ() -> Result<(), EventError> {
        // Six and nine are the only counts below ten where the floor and ceiling fault estimates
        // disagree, which is the whole reason the reference evaluates both.
        for (witnesses, weak, strong) in REFERENCE_TABLE {
            if witnesses == 6 || witnesses == 9 {
                assert_ne!(weak, strong, "n = {witnesses}");
            } else {
                assert_eq!(weak, strong, "n = {witnesses}");
            }
            assert!(ample(witnesses, None, AmpleMode::Weak)? <= witnesses);
            assert!(ample(witnesses, None, AmpleMode::Strong)? <= witnesses);
        }
        Ok(())
    }

    #[test]
    fn explicit_fault_counts_match_the_reference() -> Result<(), EventError> {
        assert_eq!(ample(4, Some(1), AmpleMode::Weak)?, 3);
        assert_eq!(ample(4, Some(1), AmpleMode::Strong)?, 3);
        assert_eq!(ample(3, Some(0), AmpleMode::Weak)?, 2);
        assert_eq!(ample(3, Some(0), AmpleMode::Strong)?, 3);
        // No witnesses means no receipts, whatever fault count is claimed.
        assert_eq!(ample(0, Some(5), AmpleMode::Weak)?, 0);
        assert_eq!(ample(0, Some(5), AmpleMode::Strong)?, 0);
        Ok(())
    }

    #[test]
    fn an_impossible_fault_count_is_rejected() {
        // Four witnesses cannot tolerate two faults: the surviving two can never form the majority
        // of four that the remaining witnesses would need.
        assert!(matches!(
            ample(4, Some(2), AmpleMode::Weak),
            Err(EventError::FaultToleranceTooHigh {
                witnesses: 4,
                faults: 2
            })
        ));
        assert!(matches!(
            ample(4, Some(3), AmpleMode::Strong),
            Err(EventError::FaultToleranceTooHigh { .. })
        ));
    }

    #[test]
    fn extreme_counts_stay_in_range() -> Result<(), EventError> {
        // The reference clamps a negative count to zero; `u32` makes that unrepresentable, so the
        // only boundaries left are the width extremes. A threshold for the widest possible witness
        // set is still just over half of it, and the intermediate arithmetic does not overflow.
        assert_eq!(ample(u32::MAX, None, AmpleMode::Weak)?, 2_863_311_530);
        assert_eq!(ample(u32::MAX, Some(0), AmpleMode::Weak)?, 2_147_483_648);
        // Tolerating every witness as faulty leaves nobody to form a majority.
        assert!(matches!(
            ample(u32::MAX, Some(u32::MAX), AmpleMode::Weak),
            Err(EventError::FaultToleranceTooHigh { .. })
        ));
        assert_eq!(ample(1, Some(0), AmpleMode::Weak)?, 1);
        Ok(())
    }

    #[test]
    fn a_threshold_never_exceeds_its_witness_count() -> Result<(), EventError> {
        for witnesses in 0_u32..64 {
            for mode in [AmpleMode::Weak, AmpleMode::Strong] {
                let threshold = ample(witnesses, None, mode)?;
                assert!(threshold <= witnesses, "n = {witnesses}");
                // Any non-empty set needs at least one receipt.
                assert_eq!(threshold == 0, witnesses == 0, "n = {witnesses}");
            }
        }
        Ok(())
    }
}
