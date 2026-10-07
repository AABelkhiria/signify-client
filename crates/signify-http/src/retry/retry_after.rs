//! The `Retry-After` header: server guidance about when to come back.
//!
//! **The pinned reference has none of this.** All 117 TypeScript files under `src`, `test`, and
//! `test-integration` were searched for the header in every spelling and for the `429` and `503`
//! statuses that usually carry it; every count is zero, and that scan is recorded in
//! `fixtures/http-retry/v1.json` so the absence is evidence rather than a claim. A server asking to
//! be left alone for thirty seconds is retried on the client's own schedule regardless.
//!
//! `AGENTS.md` §2.5 requires that retry delay "honor server guidance when valid", so this exists
//! and is governed by RFC 9110 §10.2.3 alone.
//!
//! # What is accepted, and what is not
//!
//! RFC 9110 gives two forms: `delay-seconds`, a non-negative integer, and `HTTP-date`. Both are
//! parsed. Of the three date formats §5.6.7 lists, only the preferred `IMF-fixdate` is accepted;
//! the obsolete RFC 850 and asctime forms are refused. That is a deliberate narrowing of the
//! specification's "MUST accept", taken because refusing costs nothing — an unparseable value
//! falls back to the computed backoff, so the client still retries, just on its own schedule — and
//! a lenient date parser is attack surface bought for a format no modern server emits.

use core::fmt;
use core::time::Duration;
use std::error::Error;
use std::time::SystemTime;

/// Largest accepted `Retry-After` value, in bytes.
///
/// An IMF-fixdate is 29 bytes and a plausible delay is at most a handful of digits; the bound is
/// generous and exists so a hostile header cannot make the parser walk an arbitrary string.
pub const MAX_RETRY_AFTER_BYTES: usize = 64;

/// Largest accepted `delay-seconds`, in seconds.
///
/// A hundred days. Beyond this the value is not guidance any client could act on, and accepting it
/// would let one header park a caller past any plausible deadline; the policy's own ceiling
/// normally binds long before this does.
pub const MAX_DELAY_SECONDS: u64 = 100 * 24 * 60 * 60;

/// Server guidance about when to retry.
///
/// ```
/// use core::time::Duration;
/// use std::time::SystemTime;
/// use signify_http::retry::RetryAfter;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
///
/// // The common form: a whole number of seconds.
/// assert_eq!(RetryAfter::parse("120")?.delay_from(now), Duration::from_secs(120));
///
/// // The other form: an absolute moment, read against a caller-supplied `now`.
/// let date = RetryAfter::parse("Tue, 14 Nov 2023 22:15:00 GMT")?;
/// assert_eq!(date.delay_from(now), Duration::from_secs(100));
///
/// // A date already past means "come back now", not an error.
/// assert_eq!(date.delay_from(now + Duration::from_secs(9_999)), Duration::ZERO);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RetryAfter {
    /// A `delay-seconds` value: wait this long from now.
    Delay(Duration),
    /// An `HTTP-date`: wait until this moment.
    At(SystemTime),
}

impl RetryAfter {
    /// Parses one `Retry-After` field value.
    ///
    /// # Errors
    ///
    /// Returns [`RetryAfterError`] for an empty or oversized value, a `delay-seconds` that is
    /// signed, non-numeric, or above [`MAX_DELAY_SECONDS`], or a date that is not a well-formed
    /// `IMF-fixdate`.
    pub fn parse(value: &str) -> Result<Self, RetryAfterError> {
        if value.is_empty() {
            return Err(RetryAfterError::Empty);
        }
        if value.len() > MAX_RETRY_AFTER_BYTES {
            return Err(RetryAfterError::TooLong { length: value.len() });
        }
        // The two forms are told apart by their first byte: a delay is all digits, a date starts
        // with a weekday. Nothing is trimmed — `HeaderValue` already did that at construction, and
        // trimming again here would accept a value the signature layer never saw.
        if value.bytes().all(|byte| byte.is_ascii_digit()) {
            let seconds: u64 = value
                .parse()
                .map_err(|_| RetryAfterError::DelayOutOfRange { value: bounded(value) })?;
            if seconds > MAX_DELAY_SECONDS {
                return Err(RetryAfterError::DelayOutOfRange { value: bounded(value) });
            }
            return Ok(Self::Delay(Duration::from_secs(seconds)));
        }
        parse_imf_fixdate(value).map(Self::At)
    }

    /// Returns how long to wait, measured from `now`.
    ///
    /// A date already in the past yields [`Duration::ZERO`]: the server's guidance has expired, so
    /// there is nothing left to wait for. That is deliberately not an error — a slow response or a
    /// small clock skew should not turn usable guidance into a rejection.
    #[must_use]
    pub fn delay_from(self, now: SystemTime) -> Duration {
        match self {
            Self::Delay(delay) => delay,
            Self::At(moment) => moment.duration_since(now).unwrap_or(Duration::ZERO),
        }
    }
}

/// Parses the RFC 9110 `IMF-fixdate` form, `Sun, 06 Nov 1994 08:49:37 GMT`.
///
/// The format is fixed-width, so this validates position by position rather than splitting: every
/// separator must be exactly where the grammar puts it.
fn parse_imf_fixdate(value: &str) -> Result<SystemTime, RetryAfterError> {
    let invalid = |reason: &'static str| RetryAfterError::InvalidDate {
        value: bounded(value),
        reason,
    };
    let bytes = value.as_bytes();
    if bytes.len() != 29 {
        return Err(invalid("an IMF-fixdate is exactly 29 characters"));
    }
    let at = |index: usize| -> u8 { bytes.get(index).copied().unwrap_or(0) };

    // `Sun, ` — the weekday is validated as one of the seven but not checked against the date: a
    // server that computes it wrongly still means the date it wrote.
    let weekday = value.get(..3).unwrap_or_default();
    if !WEEKDAYS.contains(&weekday) {
        return Err(invalid("the weekday is not one of the seven"));
    }
    if at(3) != b',' || at(4) != b' ' {
        return Err(invalid("the weekday must be followed by a comma and a space"));
    }

    let day = two_digits(at(5), at(6)).ok_or_else(|| invalid("the day is not two digits"))?;
    if at(7) != b' ' {
        return Err(invalid("the day must be followed by a space"));
    }

    let month_name = value.get(8..11).unwrap_or_default();
    let month = MONTHS
        .iter()
        .position(|candidate| *candidate == month_name)
        .ok_or_else(|| invalid("the month is not one of the twelve"))?;
    // `position` returns a zero-based index; months are one-based.
    let month = u32::try_from(month).unwrap_or(0).saturating_add(1);
    if at(11) != b' ' {
        return Err(invalid("the month must be followed by a space"));
    }

    let year = two_digits(at(12), at(13))
        .and_then(|high| two_digits(at(14), at(15)).map(|low| u32::from(high) * 100 + u32::from(low)))
        .ok_or_else(|| invalid("the year is not four digits"))?;
    if at(16) != b' ' {
        return Err(invalid("the year must be followed by a space"));
    }

    let hour = two_digits(at(17), at(18)).ok_or_else(|| invalid("the hour is not two digits"))?;
    if at(19) != b':' {
        return Err(invalid("the hour must be followed by a colon"));
    }
    let minute = two_digits(at(20), at(21)).ok_or_else(|| invalid("the minute is not two digits"))?;
    if at(22) != b':' {
        return Err(invalid("the minute must be followed by a colon"));
    }
    let second = two_digits(at(23), at(24)).ok_or_else(|| invalid("the second is not two digits"))?;

    if value.get(25..) != Some(" GMT") {
        return Err(invalid("an IMF-fixdate must end with ` GMT`"));
    }

    if day == 0 || u32::from(day) > days_in_month(year, month) {
        return Err(invalid("the day is not a day of that month"));
    }
    // A leap second is spelled `:60`; it is accepted and treated as the end of the minute, which
    // is what every civil-time conversion does with it.
    if hour > 23 || minute > 59 || second > 60 {
        return Err(invalid("the time of day is out of range"));
    }

    let days = days_from_civil(year, month, u32::from(day)).ok_or_else(|| invalid("the date is out of range"))?;
    let seconds = days
        .checked_mul(86_400)
        .and_then(|value| value.checked_add(i64::from(hour) * 3_600))
        .and_then(|value| value.checked_add(i64::from(minute) * 60))
        .and_then(|value| value.checked_add(i64::from(second.min(59))))
        .ok_or_else(|| invalid("the date is out of range"))?;

    let moment = if seconds >= 0 {
        SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds.unsigned_abs()))
    } else {
        SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs(seconds.unsigned_abs()))
    };
    moment.ok_or_else(|| invalid("the date is out of range"))
}

/// The three-letter weekday names, in the order RFC 9110 lists them.
const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

/// The three-letter month names, January first.
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Reads two ASCII digits as a number.
const fn two_digits(high: u8, low: u8) -> Option<u8> {
    if !high.is_ascii_digit() || !low.is_ascii_digit() {
        return None;
    }
    Some((high - b'0') * 10 + (low - b'0'))
}

/// Returns whether a year is a leap year in the proleptic Gregorian calendar.
const fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

/// Returns how many days a month has.
const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Returns days since 1970-01-01 for a proleptic Gregorian date.
///
/// Howard Hinnant's `days_from_civil`, which is exact integer arithmetic with no floating point
/// and no lookup table. `AGENTS.md` §2.4 forbids floating point for exact protocol values, and a
/// retry instant is one.
fn days_from_civil(year: u32, month: u32, day: u32) -> Option<i64> {
    let year = i64::from(year);
    let month = i64::from(month);
    let day = i64::from(day);
    // The algorithm counts from March, so January and February belong to the previous year.
    let year = if month <= 2 { year.checked_sub(1)? } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era.checked_mul(146_097)?.checked_add(day_of_era)?.checked_sub(719_468)
}

/// Copies at most thirty-two characters of rejected text into an error.
fn bounded(text: &str) -> String {
    text.chars().take(32).collect()
}

/// Stable `Retry-After` parsing failures.
///
/// None of these stop a retry: an unusable value falls back to the computed backoff, so the worst
/// a malformed header costs is the server's preferred timing.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RetryAfterError {
    /// The value is empty.
    Empty,
    /// The value exceeds [`MAX_RETRY_AFTER_BYTES`].
    TooLong {
        /// Actual length in bytes.
        length: usize,
    },
    /// A numeric value does not fit, or exceeds [`MAX_DELAY_SECONDS`].
    DelayOutOfRange {
        /// Bounded copy of the rejected value.
        value: String,
    },
    /// A date is not a well-formed `IMF-fixdate`.
    InvalidDate {
        /// Bounded copy of the rejected value.
        value: String,
        /// Why it was refused.
        reason: &'static str,
    },
}

impl fmt::Display for RetryAfterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("a Retry-After value is empty"),
            Self::TooLong { length } => write!(
                formatter,
                "a Retry-After value of {length} bytes exceeds maximum {MAX_RETRY_AFTER_BYTES}"
            ),
            Self::DelayOutOfRange { value } => {
                write!(
                    formatter,
                    "Retry-After delay {value:?} is not a usable number of seconds"
                )
            }
            Self::InvalidDate { value, reason } => {
                write!(formatter, "Retry-After date {value:?} is malformed: {reason}")
            }
        }
    }
}

impl Error for RetryAfterError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    /// 2023-11-14T22:15:00Z, the moment the doctest uses.
    const REFERENCE_SECONDS: u64 = 1_700_000_100;

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn delay_seconds_parse_and_are_bounded() -> Result<(), Box<dyn Error>> {
        for (value, seconds) in [("0", 0_u64), ("1", 1), ("120", 120), ("3600", 3_600)] {
            assert_eq!(
                RetryAfter::parse(value)?,
                RetryAfter::Delay(Duration::from_secs(seconds))
            );
            assert_eq!(
                RetryAfter::parse(value)?.delay_from(at(REFERENCE_SECONDS)),
                Duration::from_secs(seconds),
            );
        }
        // The ceiling is inclusive.
        assert_eq!(
            RetryAfter::parse(&MAX_DELAY_SECONDS.to_string())?,
            RetryAfter::Delay(Duration::from_secs(MAX_DELAY_SECONDS)),
        );
        assert!(matches!(
            RetryAfter::parse(&(MAX_DELAY_SECONDS + 1).to_string()),
            Err(RetryAfterError::DelayOutOfRange { .. })
        ));
        // Leading zeros are digits, so they parse; the value is what matters.
        assert_eq!(RetryAfter::parse("007")?, RetryAfter::Delay(Duration::from_secs(7)));
        Ok(())
    }

    #[test]
    fn a_signed_or_fractional_delay_is_not_a_delay() {
        // `delay-seconds` is a non-negative integer, so each of these is a malformed *date*
        // rather than a number, and is refused as one.
        for value in ["-1", "+1", "1.5", "1e3", " 1", "1 ", "0x10", "١٢٣"] {
            assert!(RetryAfter::parse(value).is_err(), "{value:?} was accepted");
        }
    }

    #[test]
    fn imf_fixdates_parse_exactly() -> Result<(), Box<dyn Error>> {
        // RFC 9110's own example.
        assert_eq!(
            RetryAfter::parse("Sun, 06 Nov 1994 08:49:37 GMT")?,
            RetryAfter::At(at(784_111_777)),
        );
        // The epoch itself, and a leap day.
        assert_eq!(
            RetryAfter::parse("Thu, 01 Jan 1970 00:00:00 GMT")?,
            RetryAfter::At(at(0))
        );
        assert_eq!(
            RetryAfter::parse("Mon, 29 Feb 2016 12:00:00 GMT")?,
            RetryAfter::At(at(1_456_747_200)),
        );
        // A century year that is a leap year, and one that is not.
        assert_eq!(
            RetryAfter::parse("Tue, 29 Feb 2000 00:00:00 GMT")?,
            RetryAfter::At(at(951_782_400)),
        );
        assert!(RetryAfter::parse("Mon, 29 Feb 1900 00:00:00 GMT").is_err());
        // Every month boundary lands where it should.
        assert_eq!(
            RetryAfter::parse("Sun, 31 Dec 2023 23:59:59 GMT")?,
            RetryAfter::At(at(1_704_067_199)),
        );
        Ok(())
    }

    #[test]
    fn a_date_yields_the_remaining_wait_and_never_a_negative_one() -> Result<(), Box<dyn Error>> {
        let value = RetryAfter::parse("Tue, 14 Nov 2023 22:15:00 GMT")?;
        assert_eq!(value.delay_from(at(REFERENCE_SECONDS - 100)), Duration::from_secs(100));
        assert_eq!(value.delay_from(at(REFERENCE_SECONDS)), Duration::ZERO);
        // Already past: the guidance has expired, which is not an error.
        assert_eq!(value.delay_from(at(REFERENCE_SECONDS + 10_000)), Duration::ZERO);
        Ok(())
    }

    #[test]
    fn the_obsolete_date_formats_are_refused() {
        // RFC 9110 §5.6.7 lists these and says a recipient MUST accept them; this deliberately
        // does not, because falling back to the computed backoff costs nothing and a lenient date
        // parser is attack surface. See the module documentation.
        for value in [
            // RFC 850.
            "Sunday, 06-Nov-94 08:49:37 GMT",
            // asctime.
            "Sun Nov  6 08:49:37 1994",
        ] {
            assert!(
                matches!(RetryAfter::parse(value), Err(RetryAfterError::InvalidDate { .. }))
                    || matches!(RetryAfter::parse(value), Err(RetryAfterError::TooLong { .. })),
                "{value:?} was accepted",
            );
        }
    }

    #[test]
    fn malformed_dates_are_refused_position_by_position() {
        for value in [
            "",
            "Sun, 06 Nov 1994 08:49:37",      // truncated
            "Sun, 06 Nov 1994 08:49:37 GMT ", // trailing space
            "Xxx, 06 Nov 1994 08:49:37 GMT",  // bad weekday
            "Sun; 06 Nov 1994 08:49:37 GMT",  // bad separator
            "Sun, 06 Xxx 1994 08:49:37 GMT",  // bad month
            "Sun, 6 Nov 1994 08:49:37 GMT",   // one-digit day
            "Sun, 06 Nov 199A 08:49:37 GMT",  // non-digit year
            "Sun, 00 Nov 1994 08:49:37 GMT",  // day zero
            "Sun, 31 Nov 1994 08:49:37 GMT",  // November has thirty days
            "Sun, 06 Nov 1994 24:49:37 GMT",  // hour out of range
            "Sun, 06 Nov 1994 08:60:37 GMT",  // minute out of range
            "Sun, 06 Nov 1994 08:49:61 GMT",  // second past a leap second
            "Sun, 06 Nov 1994 08:49:37 UTC",  // wrong zone
            "Sun, 06 Nov 1994 08-49-37 GMT",  // wrong time separator
        ] {
            assert!(RetryAfter::parse(value).is_err(), "{value:?} was accepted");
        }
        // A leap second is accepted and clamped to the end of the minute.
        assert!(RetryAfter::parse("Sun, 06 Nov 1994 08:49:60 GMT").is_ok());
        assert!(matches!(
            RetryAfter::parse(&"9".repeat(MAX_RETRY_AFTER_BYTES + 1)),
            Err(RetryAfterError::TooLong { .. })
        ));
        assert!(matches!(RetryAfter::parse(""), Err(RetryAfterError::Empty)));
    }

    #[test]
    fn civil_days_agree_with_known_dates() {
        for (year, month, day, expected) in [
            (1970_u32, 1_u32, 1_u32, 0_i64),
            (1969, 12, 31, -1),
            (2000, 3, 1, 11_017),
            (2023, 11, 14, 19_675),
            (1900, 1, 1, -25_567),
        ] {
            assert_eq!(
                days_from_civil(year, month, day),
                Some(expected),
                "{year}-{month}-{day}"
            );
        }
    }

    #[test]
    fn errors_carry_readable_text() {
        for error in [
            RetryAfterError::Empty,
            RetryAfterError::TooLong { length: 999 },
            RetryAfterError::DelayOutOfRange { value: "-1".to_owned() },
            RetryAfterError::InvalidDate {
                value: "nope".to_owned(),
                reason: "not a date",
            },
        ] {
            assert_ne!(error.to_string(), "");
            assert!(error.source().is_none());
        }
        // Rejected text is bounded even when the input is not.
        let long = "x".repeat(MAX_RETRY_AFTER_BYTES);
        if let Err(error) = RetryAfter::parse(&long) {
            assert!(error.to_string().len() < long.len() + 64);
        }
    }
}
