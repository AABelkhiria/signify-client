//! Message timestamps.
//!
//! Reply messages carry a `dt` field holding an ISO-8601 datetime with microsecond precision and
//! an explicit UTC offset, for example `2021-06-27T21:26:21.233257+00:00`. The reference builds
//! one from the system clock and accepts any string a caller supplies without checking it, so a
//! typo silently becomes part of the message a SAID commits to.
//!
//! [`Timestamp`] validates the shape instead, and a caller always supplies it: reading the clock
//! inside a protocol crate would make event construction non-deterministic and untestable, which
//! `AGENTS.md` forbids. An application that wants "now" formats it with whatever time library it
//! already uses and parses the result here.

use core::fmt;
use std::error::Error;
use std::str::FromStr;

/// Exact length of a valid timestamp in bytes.
const TIMESTAMP_LENGTH: usize = 32;

/// One validated message timestamp.
///
/// The canonical form is `YYYY-MM-DDThh:mm:ss.ffffff±hh:mm`, exactly
/// [`Timestamp::LENGTH`] ASCII bytes. This is the form the reference emits: it takes
/// JavaScript's millisecond-precision `toISOString` and rewrites the trailing `Z` as
/// `000+00:00`, so the fractional part is always six digits and the offset always explicit.
///
/// ```
/// use signify_keri::event::timestamp::Timestamp;
///
/// # fn main() -> Result<(), signify_keri::event::timestamp::TimestampError> {
/// let stamp: Timestamp = "2021-06-27T21:26:21.233257+00:00".parse()?;
/// assert_eq!(stamp.as_str(), "2021-06-27T21:26:21.233257+00:00");
///
/// // The reference accepts any string here; a malformed one would be committed to by the SAID.
/// assert!("not-a-timestamp".parse::<Timestamp>().is_err());
/// assert!("2021-06-27T21:26:21.233Z".parse::<Timestamp>().is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Timestamp {
    text: String,
}

impl Timestamp {
    /// Exact length of the canonical text form in bytes.
    pub const LENGTH: usize = TIMESTAMP_LENGTH;

    /// Returns the canonical text form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Consumes the timestamp, returning its canonical text.
    #[must_use]
    pub fn into_string(self) -> String {
        self.text
    }

    /// Parses and validates one canonical timestamp.
    ///
    /// Every component is range-checked. Calendar validity is deliberately *not* checked — a
    /// 31st of February parses — because the protocol treats this field as an opaque stamp, no
    /// upstream implementation validates it, and doing so would mean adding a calendar dependency
    /// to a crate that never performs date arithmetic.
    ///
    /// # Errors
    ///
    /// Returns [`TimestampError::InvalidLength`] unless the input is exactly [`Self::LENGTH`]
    /// bytes, [`TimestampError::InvalidSeparator`] when a separator is not where the format puts
    /// it, [`TimestampError::NotADigit`] for a non-digit in a numeric field, and
    /// [`TimestampError::ComponentOutOfRange`] when a component is outside its calendar range.
    pub fn parse(input: &str) -> Result<Self, TimestampError> {
        let &[
            y0,
            y1,
            y2,
            y3,
            dash1,
            mo0,
            mo1,
            dash2,
            d0,
            d1,
            tee,
            h0,
            h1,
            colon1,
            mi0,
            mi1,
            colon2,
            s0,
            s1,
            dot,
            f0,
            f1,
            f2,
            f3,
            f4,
            f5,
            sign,
            oh0,
            oh1,
            colon3,
            om0,
            om1,
        ] = input.as_bytes()
        else {
            return Err(TimestampError::InvalidLength { length: input.len() });
        };

        for (byte, expected, position) in [
            (dash1, b'-', "date"),
            (dash2, b'-', "date"),
            (tee, b'T', "date-time"),
            (colon1, b':', "time"),
            (colon2, b':', "time"),
            (dot, b'.', "fraction"),
            (colon3, b':', "offset"),
        ] {
            if byte != expected {
                return Err(TimestampError::InvalidSeparator { position });
            }
        }
        if sign != b'+' && sign != b'-' {
            return Err(TimestampError::InvalidSeparator {
                position: "offset sign",
            });
        }

        // The year is range-free -- any four digits are a valid year -- but still has to be digits.
        number(&[y0, y1, y2, y3])?;
        let month = number(&[mo0, mo1])?;
        let day = number(&[d0, d1])?;
        let hour = number(&[h0, h1])?;
        let minute = number(&[mi0, mi1])?;
        let second = number(&[s0, s1])?;
        number(&[f0, f1, f2, f3, f4, f5])?;
        let offset_hour = number(&[oh0, oh1])?;
        let offset_minute = number(&[om0, om1])?;

        for (value, range, component) in [
            (month, 1..=12, "month"),
            (day, 1..=31, "day"),
            (hour, 0..=23, "hour"),
            (minute, 0..=59, "minute"),
            // A leap second is a legitimate value, so 60 is allowed.
            (second, 0..=60, "second"),
            (offset_hour, 0..=23, "offset hour"),
            (offset_minute, 0..=59, "offset minute"),
        ] {
            if !range.contains(&value) {
                return Err(TimestampError::ComponentOutOfRange { component, value });
            }
        }

        Ok(Self { text: input.to_owned() })
    }
}

/// Reads a fixed-width decimal field.
fn number(digits: &[u8]) -> Result<u32, TimestampError> {
    digits.iter().try_fold(0_u32, |value, byte| {
        if byte.is_ascii_digit() {
            // Every field is at most six digits, so this cannot overflow.
            Ok(value * 10 + u32::from(byte - b'0'))
        } else {
            Err(TimestampError::NotADigit)
        }
    })
}

impl FromStr for Timestamp {
    type Err = TimestampError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

impl TryFrom<&str> for Timestamp {
    type Error = TimestampError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Self::parse(input)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// Stable timestamp-parsing failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TimestampError {
    /// The input is not exactly [`Timestamp::LENGTH`] bytes.
    InvalidLength {
        /// Actual input length in bytes.
        length: usize,
    },
    /// A separator is missing or misplaced.
    InvalidSeparator {
        /// Part of the timestamp whose separator is wrong.
        position: &'static str,
    },
    /// A numeric field holds a character that is not an ASCII digit.
    NotADigit,
    /// A component is outside its calendar range.
    ComponentOutOfRange {
        /// Component name.
        component: &'static str,
        /// Rejected value.
        value: u32,
    },
}

impl fmt::Display for TimestampError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { length } => write!(
                formatter,
                "timestamp length {length} is not exactly {}",
                Timestamp::LENGTH
            ),
            Self::InvalidSeparator { position } => {
                write!(formatter, "{position} separator is missing or misplaced")
            }
            Self::NotADigit => formatter.write_str("timestamp contains a non-digit in a numeric field"),
            Self::ComponentOutOfRange { component, value } => {
                write!(formatter, "timestamp {component} {value} is out of range")
            }
        }
    }
}

impl Error for TimestampError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stamp the pinned `test/app/aiding.test.ts` asserts.
    const PINNED: &str = "2021-06-27T21:26:21.233257+00:00";

    #[test]
    fn the_pinned_reference_stamp_round_trips() -> Result<(), TimestampError> {
        let stamp = Timestamp::parse(PINNED)?;
        assert_eq!(stamp.as_str(), PINNED);
        assert_eq!(stamp.to_string(), PINNED);
        assert_eq!(PINNED.parse::<Timestamp>()?, stamp);
        assert_eq!(Timestamp::try_from(PINNED)?, stamp);
        assert_eq!(stamp.clone().into_string(), PINNED);
        assert_eq!(PINNED.len(), Timestamp::LENGTH);
        Ok(())
    }

    #[test]
    fn the_shape_the_reference_emits_is_accepted() -> Result<(), TimestampError> {
        // The reference rewrites JavaScript's trailing `Z` as `000+00:00`, so the fraction is
        // always six digits and the offset always explicit.
        for text in [
            "2026-08-19T11:09:42.076000+00:00",
            "2020-08-22T17:50:12.988921+00:00",
            "1970-01-01T00:00:00.000000+00:00",
            "9999-12-31T23:59:60.999999+00:00",
            // A non-UTC offset is legitimate even though the reference never emits one.
            "2021-06-27T21:26:21.233257-05:00",
            "2021-06-27T21:26:21.233257+05:30",
        ] {
            assert_eq!(Timestamp::parse(text)?.as_str(), text);
        }
        Ok(())
    }

    #[test]
    fn malformed_stamps_are_rejected_with_a_typed_reason() {
        // The reference accepts every one of these and commits the SAID to them.
        assert!(matches!(
            Timestamp::parse("not-a-timestamp"),
            Err(TimestampError::InvalidLength { length: 15 })
        ));
        assert!(matches!(
            Timestamp::parse(""),
            Err(TimestampError::InvalidLength { length: 0 })
        ));
        // JavaScript's own `toISOString` output is too short, which is why the reference pads it.
        assert!(matches!(
            Timestamp::parse("2021-06-27T21:26:21.233Z"),
            Err(TimestampError::InvalidLength { .. })
        ));
        assert!(matches!(
            Timestamp::parse("2021/06/27T21:26:21.233257+00:00"),
            Err(TimestampError::InvalidSeparator { position: "date" })
        ));
        assert!(matches!(
            Timestamp::parse("2021-06-27 21:26:21.233257+00:00"),
            Err(TimestampError::InvalidSeparator { position: "date-time" })
        ));
        assert!(matches!(
            Timestamp::parse("2021-06-27T21:26:21,233257+00:00"),
            Err(TimestampError::InvalidSeparator { position: "fraction" })
        ));
        assert!(matches!(
            Timestamp::parse("2021-06-27T21:26:21.233257Z00:00"),
            Err(TimestampError::InvalidSeparator {
                position: "offset sign"
            })
        ));
        assert!(matches!(
            Timestamp::parse("20x1-06-27T21:26:21.233257+00:00"),
            Err(TimestampError::NotADigit)
        ));
        for (text, component) in [
            ("2021-13-27T21:26:21.233257+00:00", "month"),
            ("2021-00-27T21:26:21.233257+00:00", "month"),
            ("2021-06-32T21:26:21.233257+00:00", "day"),
            ("2021-06-00T21:26:21.233257+00:00", "day"),
            ("2021-06-27T24:26:21.233257+00:00", "hour"),
            ("2021-06-27T21:60:21.233257+00:00", "minute"),
            ("2021-06-27T21:26:61.233257+00:00", "second"),
            ("2021-06-27T21:26:21.233257+24:00", "offset hour"),
            ("2021-06-27T21:26:21.233257+00:60", "offset minute"),
        ] {
            assert!(
                matches!(
                    Timestamp::parse(text),
                    Err(TimestampError::ComponentOutOfRange { component: found, .. }) if found == component
                ),
                "{text} was not rejected as {component}"
            );
        }
    }

    #[test]
    fn calendar_validity_is_deliberately_unchecked() -> Result<(), TimestampError> {
        // No upstream implementation checks this, and the protocol treats the field as opaque, so
        // range checking is where validation stops.
        assert_eq!(
            Timestamp::parse("2021-02-31T00:00:00.000000+00:00")?.as_str(),
            "2021-02-31T00:00:00.000000+00:00"
        );
        Ok(())
    }

    #[test]
    fn multi_byte_input_stays_safe() {
        // A multi-byte character makes the byte length wrong, so parsing never splits one.
        assert!(matches!(
            Timestamp::parse("2021-06-27T21:26:21.233257+00:0é"),
            Err(TimestampError::InvalidLength { length: 33 })
        ));
        assert!(!TimestampError::NotADigit.to_string().is_empty());
        assert!(TimestampError::NotADigit.source().is_none());
    }
}
