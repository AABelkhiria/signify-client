//! Protocol identifiers, serialization kinds, protocol versions, and CESR version strings.
//!
//! This module ports the Roadmap 3.1 declarations of the pinned reference's
//! `src/keri/core/core.ts`: the `Protocols` and `Serials` enums, the `Version` value with its
//! `Vrsn_1_0` default, the `VERFULLSIZE` bound, and the `versify`/`deversify` pair. The
//! stringly-typed reference values become validated Rust types; the version string itself is the
//! [`VersionString`] value whose canonical text form is produced by [`fmt::Display`] and parsed by
//! [`FromStr`].
//!
//! Parsing is strict: exactly [`VersionString::FULL_SIZE`] bytes, anchored at both ends, lowercase
//! hexadecimal digits, and a `_` terminator. The pinned reference instead scans with an unanchored
//! regular expression, accepts arbitrary surrounding text, coerces hexadecimal version digits with
//! decimal semantics (`a`–`f` become `NaN`), mutates a module-global default `Version` object on
//! every successful parse, and emits out-of-range sizes as overlong invalid strings. Those
//! behaviors are recorded as defects in `fixtures/keri-version/` and are deliberately not
//! reproduced.

use core::fmt;
use std::error::Error;
use std::str::FromStr;

/// Protocol identified by the first four characters of a CESR version string.
///
/// Source: `Protocols` in the pinned `src/keri/core/core.ts`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Protocol {
    /// The KERI key-event protocol, spelled `KERI`.
    Keri,
    /// The ACDC credential protocol, spelled `ACDC`.
    Acdc,
}

impl Protocol {
    /// Every protocol supported by the pinned reference, in table order.
    pub const ALL: [Self; 2] = [Self::Keri, Self::Acdc];

    /// Returns the exact four-character protocol text used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Keri => "KERI",
            Self::Acdc => "ACDC",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Protocol {
    type Err = VersionError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "KERI" => Ok(Self::Keri),
            "ACDC" => Ok(Self::Acdc),
            _ => Err(VersionError::UnsupportedProtocol {
                found: bounded_text(input),
            }),
        }
    }
}

impl TryFrom<&str> for Protocol {
    type Error = VersionError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        input.parse()
    }
}

/// Serialization kind identified by four uppercase characters of a CESR version string.
///
/// Source: `Serials` in the pinned `src/keri/core/core.ts`, which supports only JSON.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SerializationKind {
    /// JSON serialization, spelled `JSON`.
    Json,
}

impl SerializationKind {
    /// Every serialization kind supported by the pinned reference, in table order.
    pub const ALL: [Self; 1] = [Self::Json];

    /// Returns the exact four-character serialization text used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "JSON",
        }
    }
}

impl fmt::Display for SerializationKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for SerializationKind {
    type Err = VersionError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "JSON" => Ok(Self::Json),
            _ => Err(VersionError::UnsupportedSerialization {
                found: bounded_text(input),
            }),
        }
    }
}

impl TryFrom<&str> for SerializationKind {
    type Error = VersionError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        input.parse()
    }
}

/// Exact protocol version encoded as two single hexadecimal digits of a CESR version string.
///
/// Source: `Version` and `Vrsn_1_0` in the pinned `src/keri/core/core.ts`. Each component is one
/// lowercase hexadecimal digit on the wire, so values above [`ProtocolVersion::MAX_COMPONENT`] are
/// unrepresentable and rejected at construction. The reference instead emits two characters for
/// such values, producing an invalid version string; that defect is fixture-pinned.
///
/// Fields are private, so an unvalidated value cannot be built outside this module:
///
/// ```compile_fail
/// let bogus = signify_keri::serialization::ProtocolVersion { major: 99, minor: 0 };
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProtocolVersion {
    major: u8,
    minor: u8,
}

impl ProtocolVersion {
    /// Version 1.0, the reference's `Vrsn_1_0` default.
    pub const V1_0: Self = Self { major: 1, minor: 0 };

    /// Largest value of one version component; each is a single hexadecimal digit on the wire.
    pub const MAX_COMPONENT: u8 = 0xf;

    /// Constructs a validated protocol version.
    ///
    /// # Errors
    ///
    /// Returns [`VersionError::VersionComponentOutOfRange`] when either component exceeds
    /// [`Self::MAX_COMPONENT`].
    pub const fn new(major: u8, minor: u8) -> Result<Self, VersionError> {
        if major > Self::MAX_COMPONENT {
            return Err(VersionError::VersionComponentOutOfRange {
                component: "major",
                value: major,
            });
        }
        if minor > Self::MAX_COMPONENT {
            return Err(VersionError::VersionComponentOutOfRange {
                component: "minor",
                value: minor,
            });
        }
        Ok(Self { major, minor })
    }

    /// Returns the major version component.
    #[must_use]
    pub const fn major(self) -> u8 {
        self.major
    }

    /// Returns the minor version component.
    #[must_use]
    pub const fn minor(self) -> u8 {
        self.minor
    }
}

impl fmt::Display for ProtocolVersion {
    /// Formats the two wire digits, for example `10` for version 1.0.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:x}{:x}", self.major, self.minor)
    }
}

/// One complete, validated CESR version string.
///
/// Source: `versify`/`deversify` and `VERFULLSIZE` in the pinned `src/keri/core/core.ts`. The
/// canonical seventeen-character text form is `PPPPmkKKKDssssss_`: four protocol characters, one
/// hexadecimal major digit, one hexadecimal minor digit, four serialization characters, six
/// lowercase hexadecimal size digits, and the version 1 `_` terminator.
///
/// ```
/// use signify_keri::serialization::{
///     Protocol, ProtocolVersion, SerializationKind, VersionString,
/// };
///
/// # fn main() -> Result<(), signify_keri::serialization::VersionError> {
/// let version = VersionString::new(
///     Protocol::Keri,
///     ProtocolVersion::V1_0,
///     SerializationKind::Json,
///     284,
/// )?;
/// assert_eq!(version.to_string(), "KERI10JSON00011c_");
///
/// let parsed: VersionString = "KERI10JSON00011c_".parse()?;
/// assert_eq!(parsed, version);
/// assert_eq!(parsed.size(), 284);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct VersionString {
    protocol: Protocol,
    version: ProtocolVersion,
    kind: SerializationKind,
    size: u32,
}

impl VersionString {
    /// Exact size of a version string in bytes; the reference's `VERFULLSIZE`.
    pub const FULL_SIZE: usize = 17;

    /// Largest serialization size representable in the six hexadecimal size digits.
    pub const MAX_SIZE: u32 = 0xff_ffff;

    /// Constructs a validated version string value.
    ///
    /// # Errors
    ///
    /// Returns [`VersionError::SizeOutOfRange`] when `size` exceeds [`Self::MAX_SIZE`]. The
    /// reference's `versify` instead emits seven or more size digits, producing an invalid
    /// version string.
    pub const fn new(
        protocol: Protocol,
        version: ProtocolVersion,
        kind: SerializationKind,
        size: u32,
    ) -> Result<Self, VersionError> {
        if size > Self::MAX_SIZE {
            return Err(VersionError::SizeOutOfRange { size });
        }
        Ok(Self {
            protocol,
            version,
            kind,
            size,
        })
    }

    /// Returns the protocol identifier.
    #[must_use]
    pub const fn protocol(self) -> Protocol {
        self.protocol
    }

    /// Returns the protocol version.
    #[must_use]
    pub const fn version(self) -> ProtocolVersion {
        self.version
    }

    /// Returns the serialization kind.
    #[must_use]
    pub const fn kind(self) -> SerializationKind {
        self.kind
    }

    /// Returns the declared serialization size in bytes.
    #[must_use]
    pub const fn size(self) -> u32 {
        self.size
    }
}

impl fmt::Display for VersionString {
    /// Formats the canonical seventeen-character wire text; the reference's `versify`.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}{}{}{:06x}_",
            self.protocol, self.version, self.kind, self.size
        )
    }
}

impl FromStr for VersionString {
    type Err = VersionError;

    /// Parses one complete, anchored version string; the strict form of the reference's
    /// `deversify`.
    ///
    /// # Errors
    ///
    /// Returns [`VersionError::InvalidLength`] unless the input is exactly
    /// [`VersionString::FULL_SIZE`] bytes, [`VersionError::UnsupportedProtocol`] and
    /// [`VersionError::UnsupportedSerialization`] for unknown identifier fields,
    /// [`VersionError::InvalidVersionDigit`] and [`VersionError::InvalidSizeDigit`] for
    /// characters outside lowercase hexadecimal, and [`VersionError::MissingTerminator`] when the
    /// final byte is not `_`.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let &[
            p0,
            p1,
            p2,
            p3,
            major,
            minor,
            k0,
            k1,
            k2,
            k3,
            s0,
            s1,
            s2,
            s3,
            s4,
            s5,
            terminator,
        ] = input.as_bytes()
        else {
            return Err(VersionError::InvalidLength { length: input.len() });
        };
        let protocol = match [p0, p1, p2, p3] {
            [b'K', b'E', b'R', b'I'] => Protocol::Keri,
            [b'A', b'C', b'D', b'C'] => Protocol::Acdc,
            other => {
                return Err(VersionError::UnsupportedProtocol {
                    found: bounded_bytes(&other),
                });
            }
        };
        let major = hex_digit_value(major).ok_or(VersionError::InvalidVersionDigit { component: "major" })?;
        let minor = hex_digit_value(minor).ok_or(VersionError::InvalidVersionDigit { component: "minor" })?;
        let kind = match [k0, k1, k2, k3] {
            [b'J', b'S', b'O', b'N'] => SerializationKind::Json,
            other => {
                return Err(VersionError::UnsupportedSerialization {
                    found: bounded_bytes(&other),
                });
            }
        };
        // Six hexadecimal digits bound the accumulator below 2^24, so shift/or composition
        // cannot overflow the `u32`.
        let size = [s0, s1, s2, s3, s4, s5].iter().try_fold(0_u32, |value, byte| {
            let digit = hex_digit_value(*byte).ok_or(VersionError::InvalidSizeDigit)?;
            Ok((value << 4_u32) | u32::from(digit))
        })?;
        if terminator != b'_' {
            return Err(VersionError::MissingTerminator);
        }
        Ok(Self {
            protocol,
            version: ProtocolVersion { major, minor },
            kind,
            size,
        })
    }
}

impl TryFrom<&str> for VersionString {
    type Error = VersionError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        input.parse()
    }
}

/// Stable version-string and serialization-identifier failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum VersionError {
    /// The input is not exactly [`VersionString::FULL_SIZE`] bytes.
    InvalidLength {
        /// Actual input length in bytes.
        length: usize,
    },
    /// The protocol field names no protocol supported by the pinned reference.
    UnsupportedProtocol {
        /// Bounded copy of the rejected protocol text.
        found: String,
    },
    /// The serialization field names no kind supported by the pinned reference.
    UnsupportedSerialization {
        /// Bounded copy of the rejected serialization text.
        found: String,
    },
    /// A version component is not one lowercase hexadecimal digit.
    InvalidVersionDigit {
        /// Version component whose digit is invalid.
        component: &'static str,
    },
    /// A size character is not a lowercase hexadecimal digit.
    InvalidSizeDigit,
    /// The final byte is not the version 1 `_` terminator.
    MissingTerminator,
    /// A version component exceeds [`ProtocolVersion::MAX_COMPONENT`].
    VersionComponentOutOfRange {
        /// Version component whose value is out of range.
        component: &'static str,
        /// Rejected component value.
        value: u8,
    },
    /// A serialization size exceeds [`VersionString::MAX_SIZE`].
    SizeOutOfRange {
        /// Rejected size value.
        size: u32,
    },
}

impl fmt::Display for VersionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { length } => write!(
                formatter,
                "version string length {length} is not exactly {}",
                VersionString::FULL_SIZE
            ),
            Self::UnsupportedProtocol { found } => {
                write!(formatter, "unsupported protocol {found:?}")
            }
            Self::UnsupportedSerialization { found } => {
                write!(formatter, "unsupported serialization kind {found:?}")
            }
            Self::InvalidVersionDigit { component } => write!(
                formatter,
                "{component} version component is not one lowercase hexadecimal digit"
            ),
            Self::InvalidSizeDigit => formatter.write_str("size field contains a non-hexadecimal character"),
            Self::MissingTerminator => formatter.write_str("version string does not end with the `_` terminator"),
            Self::VersionComponentOutOfRange { component, value } => write!(
                formatter,
                "{component} version component {value} exceeds maximum {}",
                ProtocolVersion::MAX_COMPONENT
            ),
            Self::SizeOutOfRange { size } => write!(
                formatter,
                "serialization size {size} exceeds maximum {}",
                VersionString::MAX_SIZE
            ),
        }
    }
}

impl Error for VersionError {}

/// Returns the value of one lowercase hexadecimal digit, matching the reference's
/// `[0-9a-f]` version and size character classes exactly.
const fn hex_digit_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Copies at most sixteen characters of rejected identifier text into an error.
fn bounded_text(input: &str) -> String {
    input.chars().take(16).collect()
}

/// Renders rejected fixed-width identifier bytes losslessly and boundedly.
fn bounded_bytes(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).chars().take(16).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_reference_forms_match() -> Result<(), VersionError> {
        let default = VersionString::new(Protocol::Keri, ProtocolVersion::V1_0, SerializationKind::Json, 0)?;
        assert_eq!(default.to_string(), "KERI10JSON000000_");
        assert_eq!(default.to_string().len(), VersionString::FULL_SIZE);

        let serder = VersionString::new(Protocol::Keri, ProtocolVersion::V1_0, SerializationKind::Json, 284)?;
        assert_eq!(serder.to_string(), "KERI10JSON00011c_");

        let acdc = VersionString::new(Protocol::Acdc, ProtocolVersion::V1_0, SerializationKind::Json, 0)?;
        assert_eq!(acdc.to_string(), "ACDC10JSON000000_");

        let widest = VersionString::new(
            Protocol::Keri,
            ProtocolVersion::new(15, 15)?,
            SerializationKind::Json,
            VersionString::MAX_SIZE,
        )?;
        assert_eq!(widest.to_string(), "KERIffJSONffffff_");
        Ok(())
    }

    #[test]
    fn strict_parse_recovers_every_field() -> Result<(), VersionError> {
        let parsed: VersionString = "KERI10JSON00011c_".parse()?;
        assert_eq!(parsed.protocol(), Protocol::Keri);
        assert_eq!(parsed.version(), ProtocolVersion::V1_0);
        assert_eq!(parsed.kind(), SerializationKind::Json);
        assert_eq!(parsed.size(), 0x11c);

        let unsupported_version: VersionString = "ACDC2fJSONffffff_".parse()?;
        assert_eq!(unsupported_version.protocol(), Protocol::Acdc);
        assert_eq!(unsupported_version.version().major(), 2);
        assert_eq!(unsupported_version.version().minor(), 15);
        assert_eq!(unsupported_version.size(), VersionString::MAX_SIZE);

        assert_eq!(VersionString::try_from("KERI10JSON000000_")?.size(), 0);
        Ok(())
    }

    #[test]
    fn every_invalid_field_is_a_typed_error() {
        assert!(matches!(
            VersionString::from_str(""),
            Err(VersionError::InvalidLength { length: 0 })
        ));
        assert!(matches!(
            VersionString::from_str("KERI10JSON000000"),
            Err(VersionError::InvalidLength { length: 16 })
        ));
        assert!(matches!(
            VersionString::from_str("KERI10JSON000000__"),
            Err(VersionError::InvalidLength { length: 18 })
        ));
        assert!(matches!(
            VersionString::from_str("XERI10JSON000000_"),
            Err(VersionError::UnsupportedProtocol { .. })
        ));
        assert!(matches!(
            VersionString::from_str("KERI10CBOR000000_"),
            Err(VersionError::UnsupportedSerialization { .. })
        ));
        assert!(matches!(
            VersionString::from_str("KERI10json000000_"),
            Err(VersionError::UnsupportedSerialization { .. })
        ));
        assert!(matches!(
            VersionString::from_str("KERIA0JSON000000_"),
            Err(VersionError::InvalidVersionDigit { component: "major" })
        ));
        assert!(matches!(
            VersionString::from_str("KERI1GJSON000000_"),
            Err(VersionError::InvalidVersionDigit { component: "minor" })
        ));
        assert!(matches!(
            VersionString::from_str("KERI10JSON00011G_"),
            Err(VersionError::InvalidSizeDigit)
        ));
        assert!(matches!(
            VersionString::from_str("KERI10JSON00011C_"),
            Err(VersionError::InvalidSizeDigit)
        ));
        assert!(matches!(
            VersionString::from_str("KERI10JSON000000-"),
            Err(VersionError::MissingTerminator)
        ));
        // The reference's unanchored regular expression accepts this embedded form.
        assert!(matches!(
            VersionString::from_str("XXKERI10JSON00011c_YY"),
            Err(VersionError::InvalidLength { length: 21 })
        ));
        // A multi-byte character keeps parsing byte-oriented and safe.
        assert!(matches!(
            VersionString::from_str("KERI10JSON00000é_"),
            Err(VersionError::InvalidLength { length: 18 })
        ));
    }

    #[test]
    fn constructors_reject_unrepresentable_wire_values() -> Result<(), VersionError> {
        assert!(matches!(
            ProtocolVersion::new(16, 0),
            Err(VersionError::VersionComponentOutOfRange {
                component: "major",
                value: 16,
            })
        ));
        assert!(matches!(
            ProtocolVersion::new(0, 16),
            Err(VersionError::VersionComponentOutOfRange {
                component: "minor",
                value: 16,
            })
        ));
        assert!(matches!(
            VersionString::new(
                Protocol::Keri,
                ProtocolVersion::V1_0,
                SerializationKind::Json,
                VersionString::MAX_SIZE + 1,
            ),
            Err(VersionError::SizeOutOfRange { size: 0x100_0000 })
        ));
        assert_eq!(ProtocolVersion::new(1, 0)?, ProtocolVersion::V1_0);
        Ok(())
    }

    #[test]
    fn identifier_tables_are_exact_and_unique() -> Result<(), VersionError> {
        for (index, protocol) in Protocol::ALL.iter().enumerate() {
            assert_eq!(protocol.as_str().len(), 4);
            assert_eq!(Protocol::from_str(protocol.as_str())?, *protocol);
            for other in Protocol::ALL.iter().skip(index + 1) {
                assert_ne!(protocol.as_str(), other.as_str());
            }
        }
        for kind in SerializationKind::ALL {
            assert_eq!(kind.as_str().len(), 4);
            assert_eq!(SerializationKind::from_str(kind.as_str())?, kind);
        }
        assert!(matches!(
            Protocol::from_str("keri"),
            Err(VersionError::UnsupportedProtocol { .. })
        ));
        assert!(matches!(
            SerializationKind::try_from("CBOR"),
            Err(VersionError::UnsupportedSerialization { .. })
        ));
        assert_eq!(Protocol::try_from("ACDC")?, Protocol::Acdc);
        Ok(())
    }

    #[test]
    fn error_text_is_bounded_and_non_sensitive() {
        let long = "N".repeat(64);
        match Protocol::from_str(&long) {
            Err(VersionError::UnsupportedProtocol { found }) => {
                assert_eq!(found.chars().count(), 16);
            }
            other => assert!(
                matches!(other, Err(VersionError::UnsupportedProtocol { .. })),
                "unexpected result {other:?}"
            ),
        }
        let display = VersionError::SizeOutOfRange { size: u32::MAX }.to_string();
        assert!(display.contains("16777215"));
    }
}
