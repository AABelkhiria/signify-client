//! Exact numeric and weighted KERI signing thresholds.
//!
//! A threshold is either an unsigned hexadecimal signature count or one or more ordered clauses
//! of exact rational weights. Every weighted clause must independently sum to at least one. This
//! module deliberately uses checked integer arithmetic rather than the pinned TypeScript
//! reference's floating-point satisfaction checks.

use std::{error::Error, fmt, num::NonZeroU128, str::FromStr};

use serde_json::Value;
use signify_cesr::{CesrError, number::CesrNumber};

/// Maximum accepted byte length of a serialized signing-threshold expression.
pub const MAX_THRESHOLD_EXPRESSION_BYTES: usize = 512 * 1_024;

/// Maximum number of weights accepted across one weighted threshold.
pub const MAX_THRESHOLD_WEIGHTS: usize = 4_096;

/// Maximum byte length of one rational-weight string.
pub const MAX_WEIGHT_TEXT_BYTES: usize = 79;

/// An exact, reduced weight in the inclusive range zero through one.
///
/// The canonical textual form is an integer when the denominator is one and `numerator/denominator`
/// otherwise. Decimal input is accepted and converted exactly; exponent notation, signs, and
/// whitespace are rejected.
///
/// ```
/// use signify_keri::threshold::RationalWeight;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let half = RationalWeight::parse("0.5")?;
/// assert_eq!(half.to_string(), "1/2");
/// assert_eq!(half.numerator(), 1);
/// assert_eq!(half.denominator(), 2);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RationalWeight {
    numerator: u128,
    denominator: NonZeroU128,
}

/// Stable failure categories for rational-weight construction and parsing.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RationalWeightError {
    /// The weight string is empty.
    Empty,
    /// The weight string exceeds the parser's explicit byte limit.
    InputTooLarge {
        /// Actual input length in bytes.
        length: usize,
        /// Maximum accepted input length in bytes.
        maximum: usize,
    },
    /// A byte outside the strict unsigned decimal/rational grammar was encountered.
    InvalidCharacter {
        /// Zero-based byte position.
        index: usize,
        /// Rejected byte.
        byte: u8,
    },
    /// Separators or decimal components do not form one complete weight.
    InvalidFormat,
    /// A rational denominator is zero.
    ZeroDenominator,
    /// The exact value is outside the protocol weight range from zero through one.
    OutOfRange,
    /// Checked integer parsing or decimal scaling exceeded `u128`.
    ArithmeticOverflow,
}

/// One validated weighted-threshold clause.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WeightClause {
    weights: Vec<RationalWeight>,
}

/// A validated KERI signing threshold.
///
/// Private representation prevents empty weighted thresholds, underweight clauses, and invalid
/// rational values. Numeric thresholds retain the full exact CESR `u128` range.
///
/// ```
/// use signify_keri::threshold::{RationalWeight, SigningThreshold};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let threshold = SigningThreshold::weighted(vec![vec![
///     RationalWeight::parse("1/2")?,
///     RationalWeight::parse("1/2")?,
/// ]])?;
/// assert_eq!(threshold.canonical_json(), "[\"1/2\",\"1/2\"]");
/// assert!(threshold.is_satisfied_by(&[0, 1])?);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningThreshold {
    kind: ThresholdKind,
    size: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ThresholdKind {
    Numeric(CesrNumber),
    Weighted(Vec<WeightClause>),
}

/// Stable threshold construction, parsing, and satisfaction failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum ThresholdError {
    /// A serialized threshold expression is empty.
    EmptyExpression,
    /// A serialized threshold exceeds its explicit byte ceiling.
    ExpressionTooLarge {
        /// Actual input length in bytes.
        length: usize,
        /// Maximum accepted input length in bytes.
        maximum: usize,
    },
    /// Weighted JSON is syntactically malformed.
    MalformedJson {
        /// JSON parser failure.
        source: Box<serde_json::Error>,
    },
    /// JSON is valid but is not a numeric string, a string-weight array, or an array of clauses.
    InvalidExpressionShape,
    /// A weighted threshold has no clauses.
    EmptyThreshold,
    /// One clause has no weights.
    EmptyClause {
        /// Zero-based clause position.
        clause: usize,
    },
    /// A weighted threshold exceeds the configured total-weight bound.
    TooManyWeights {
        /// Observed total, or the first total beyond the bound.
        count: usize,
        /// Maximum accepted number of weights.
        maximum: usize,
    },
    /// A weight failed exact construction or parsing.
    InvalidWeight {
        /// Zero-based clause position.
        clause: usize,
        /// Zero-based weight position within the clause.
        index: usize,
        /// Exact weight failure.
        source: Box<RationalWeightError>,
    },
    /// A complete clause sums to less than one.
    ClauseBelowOne {
        /// Zero-based clause position.
        clause: usize,
    },
    /// Checked rational summation exceeded the exact `u128` representation.
    ArithmeticOverflow {
        /// Operation whose exact intermediate exceeded the bound.
        context: &'static str,
    },
    /// A selected signature index does not address any weight.
    IndexOutOfRange {
        /// Invalid selected index.
        index: usize,
        /// Number of weights in the threshold.
        size: usize,
    },
    /// Numeric CESR construction or parsing failed.
    Cesr {
        /// Underlying CESR failure.
        source: Box<CesrError>,
    },
}

impl RationalWeight {
    /// Constructs and reduces an exact rational weight.
    ///
    /// # Errors
    ///
    /// Returns [`RationalWeightError::ZeroDenominator`] for a zero denominator and
    /// [`RationalWeightError::OutOfRange`] when `numerator` is greater than `denominator`.
    pub fn new(numerator: u128, denominator: u128) -> Result<Self, RationalWeightError> {
        let denominator = NonZeroU128::new(denominator).ok_or(RationalWeightError::ZeroDenominator)?;
        if numerator > denominator.get() {
            return Err(RationalWeightError::OutOfRange);
        }
        let divisor = greatest_common_divisor(numerator, denominator.get());
        let reduced_denominator = denominator.get() / divisor;
        let denominator = NonZeroU128::new(reduced_denominator).ok_or(RationalWeightError::ZeroDenominator)?;
        Ok(Self {
            numerator: numerator / divisor,
            denominator,
        })
    }

    /// Parses one complete unsigned integer, ratio, or non-exponent decimal weight.
    ///
    /// # Errors
    ///
    /// Returns a typed syntax, range, denominator, size, or checked-arithmetic failure.
    pub fn parse(input: &str) -> Result<Self, RationalWeightError> {
        if input.is_empty() {
            return Err(RationalWeightError::Empty);
        }
        if input.len() > MAX_WEIGHT_TEXT_BYTES {
            return Err(RationalWeightError::InputTooLarge {
                length: input.len(),
                maximum: MAX_WEIGHT_TEXT_BYTES,
            });
        }

        if let Some((numerator, denominator)) = input.split_once('/') {
            if denominator.contains('/') || numerator.contains('.') || denominator.contains('.') {
                return Err(RationalWeightError::InvalidFormat);
            }
            return Self::new(parse_unsigned_decimal(numerator)?, parse_unsigned_decimal(denominator)?);
        }

        if let Some((whole, fractional)) = input.split_once('.') {
            if fractional.contains('.') || whole.is_empty() || fractional.is_empty() {
                return Err(RationalWeightError::InvalidFormat);
            }
            let whole = parse_unsigned_decimal(whole)?;
            let fractional_value = parse_unsigned_decimal(fractional)?;
            let scale = (0..fractional.len()).try_fold(1_u128, |value, _| {
                value.checked_mul(10).ok_or(RationalWeightError::ArithmeticOverflow)
            })?;
            let numerator = whole
                .checked_mul(scale)
                .and_then(|value| value.checked_add(fractional_value))
                .ok_or(RationalWeightError::ArithmeticOverflow)?;
            return Self::new(numerator, scale);
        }

        Self::new(parse_unsigned_decimal(input)?, 1)
    }

    /// Returns the reduced numerator.
    #[must_use]
    pub const fn numerator(self) -> u128 {
        self.numerator
    }

    /// Returns the reduced nonzero denominator.
    #[must_use]
    pub const fn denominator(self) -> u128 {
        self.denominator.get()
    }

    /// Returns whether the weight is exactly zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.numerator == 0
    }

    /// Returns whether the weight is exactly one.
    #[must_use]
    pub const fn is_one(self) -> bool {
        self.numerator == self.denominator.get()
    }
}

impl FromStr for RationalWeight {
    type Err = RationalWeightError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

impl TryFrom<&str> for RationalWeight {
    type Error = RationalWeightError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Self::parse(input)
    }
}

impl fmt::Display for RationalWeight {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.denominator.get() == 1 {
            write!(formatter, "{}", self.numerator)
        } else {
            write!(formatter, "{}/{}", self.numerator, self.denominator)
        }
    }
}

impl WeightClause {
    fn new(weights: Vec<RationalWeight>, clause: usize) -> Result<Self, ThresholdError> {
        if weights.is_empty() {
            return Err(ThresholdError::EmptyClause { clause });
        }
        if !sum_at_least_one(weights.iter().copied())? {
            return Err(ThresholdError::ClauseBelowOne { clause });
        }
        Ok(Self { weights })
    }

    /// Returns the ordered exact weights.
    #[must_use]
    pub fn weights(&self) -> &[RationalWeight] {
        &self.weights
    }

    /// Returns the number of key positions in this clause.
    #[must_use]
    pub fn len(&self) -> usize {
        self.weights.len()
    }

    /// Returns whether this clause has no weights.
    ///
    /// Valid clauses are never empty, so this method always returns `false`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.weights.is_empty()
    }
}

impl SigningThreshold {
    /// Constructs an exact numeric threshold.
    ///
    /// Zero represents a disabled threshold and is intentionally never satisfied.
    #[must_use]
    pub const fn numeric(required: u128) -> Self {
        Self {
            kind: ThresholdKind::Numeric(CesrNumber::new(required)),
            size: required,
        }
    }

    /// Constructs a weighted threshold from one or more ordered clauses.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for an empty threshold or clause, a clause whose weights sum below
    /// one, too many weights, or checked rational-summation overflow.
    pub fn weighted(clauses: Vec<Vec<RationalWeight>>) -> Result<Self, ThresholdError> {
        if clauses.is_empty() {
            return Err(ThresholdError::EmptyThreshold);
        }
        if clauses.len() > MAX_THRESHOLD_WEIGHTS {
            return Err(ThresholdError::TooManyWeights {
                count: clauses.len(),
                maximum: MAX_THRESHOLD_WEIGHTS,
            });
        }

        let mut total = 0_usize;
        let mut validated = Vec::with_capacity(clauses.len());
        for (clause_index, weights) in clauses.into_iter().enumerate() {
            total = total
                .checked_add(weights.len())
                .ok_or(ThresholdError::ArithmeticOverflow {
                    context: "weighted threshold size",
                })?;
            if total > MAX_THRESHOLD_WEIGHTS {
                return Err(ThresholdError::TooManyWeights {
                    count: total,
                    maximum: MAX_THRESHOLD_WEIGHTS,
                });
            }
            validated.push(WeightClause::new(weights, clause_index)?);
        }

        let size = u128::try_from(total).map_err(|_| ThresholdError::ArithmeticOverflow {
            context: "weighted threshold size conversion",
        })?;
        Ok(Self {
            kind: ThresholdKind::Weighted(validated),
            size,
        })
    }

    /// Parses the reference's direct `sith` form.
    ///
    /// Bare text is a complete unsigned hexadecimal numeric threshold. A JSON array is either one
    /// string-weight clause or an array of string-weight clauses.
    ///
    /// # Errors
    ///
    /// Returns a typed bound, JSON-shape, rational, clause, arithmetic, or CESR failure.
    pub fn from_sith(input: &str) -> Result<Self, ThresholdError> {
        validate_expression_length(input)?;
        if input.starts_with('[') {
            Self::from_json(input)
        } else {
            let number = CesrNumber::from_hex(input).map_err(ThresholdError::from)?;
            Ok(Self::numeric(number.value()))
        }
    }

    /// Parses canonical JSON threshold text.
    ///
    /// Numeric JSON is a hexadecimal string such as `"b"`; weighted JSON is a single array of
    /// strings or an array of clause arrays.
    ///
    /// # Errors
    ///
    /// Returns a typed bound, JSON syntax/shape, rational, clause, arithmetic, or CESR failure.
    pub fn from_json(input: &str) -> Result<Self, ThresholdError> {
        validate_expression_length(input)?;
        let value = serde_json::from_str::<Value>(input).map_err(|source| ThresholdError::MalformedJson {
            source: Box::new(source),
        })?;
        match value {
            Value::String(value) => {
                let number = CesrNumber::from_hex(&value).map_err(ThresholdError::from)?;
                Ok(Self::numeric(number.value()))
            }
            Value::Array(values) => Self::from_json_array(values),
            _ => Err(ThresholdError::InvalidExpressionShape),
        }
    }

    /// Parses numeric threshold limen from exact CESR qualified-Base64 text.
    ///
    /// The pinned reference does not implement weighted limen/Bexter construction, so this method
    /// accepts numeric material only.
    ///
    /// # Errors
    ///
    /// Returns the underlying strict CESR material error.
    pub fn from_limen_qb64(input: &str) -> Result<Self, ThresholdError> {
        let number = CesrNumber::from_qb64(input).map_err(ThresholdError::from)?;
        Ok(Self::numeric(number.value()))
    }

    /// Parses numeric threshold limen from UTF-8 qualified-Base64 bytes.
    ///
    /// # Errors
    ///
    /// Returns the underlying strict UTF-8 or CESR material error.
    pub fn from_limen(input: &[u8]) -> Result<Self, ThresholdError> {
        let number = CesrNumber::from_qb64_bytes(input).map_err(ThresholdError::from)?;
        Ok(Self::numeric(number.value()))
    }

    /// Returns whether this threshold uses rational weights.
    #[must_use]
    pub const fn is_weighted(&self) -> bool {
        matches!(&self.kind, ThresholdKind::Weighted(_))
    }

    /// Returns the required count for numeric thresholds.
    #[must_use]
    pub const fn numeric_value(&self) -> Option<u128> {
        match &self.kind {
            ThresholdKind::Numeric(number) => Some(number.value()),
            ThresholdKind::Weighted(_) => None,
        }
    }

    /// Returns weighted clauses, or `None` for a numeric threshold.
    #[must_use]
    pub fn clauses(&self) -> Option<&[WeightClause]> {
        match &self.kind {
            ThresholdKind::Numeric(_) => None,
            ThresholdKind::Weighted(clauses) => Some(clauses),
        }
    }

    /// Returns the numeric requirement or total weighted key positions.
    #[must_use]
    pub const fn size(&self) -> u128 {
        self.size
    }

    /// Returns canonical reference-compatible `sith` text.
    ///
    /// Numeric output is bare lowercase hexadecimal. Weighted output is canonical JSON, with a
    /// single clause flattened to one array exactly as in the pinned reference.
    #[must_use]
    pub fn canonical_sith(&self) -> String {
        match &self.kind {
            ThresholdKind::Numeric(number) => number.hex(),
            ThresholdKind::Weighted(clauses) => encode_weighted(clauses),
        }
    }

    /// Returns canonical JSON for the threshold.
    #[must_use]
    pub fn canonical_json(&self) -> String {
        match &self.kind {
            ThresholdKind::Numeric(number) => format!("\"{}\"", number.hex()),
            ThresholdKind::Weighted(clauses) => encode_weighted(clauses),
        }
    }

    /// Returns numeric limen as UTF-8 CESR qualified-Base64 bytes.
    ///
    /// Weighted limen is `None` because the pinned reference leaves Bexter-backed weighted limen
    /// unfinished.
    ///
    /// # Errors
    ///
    /// Returns a CESR invariant error if numeric material cannot be encoded.
    pub fn limen(&self) -> Result<Option<Vec<u8>>, ThresholdError> {
        match &self.kind {
            ThresholdKind::Numeric(number) => number.qb64_bytes().map(Some).map_err(ThresholdError::from),
            ThresholdKind::Weighted(_) => Ok(None),
        }
    }

    /// Evaluates a set of verified signature indices.
    ///
    /// Numeric thresholds count entries, matching the reference. Weighted thresholds deduplicate
    /// indices and apply them to the flattened clause order. A zero numeric threshold is never
    /// satisfied.
    ///
    /// # Errors
    ///
    /// Returns a typed out-of-range index or checked exact-summation failure.
    pub fn is_satisfied_by(&self, indices: &[usize]) -> Result<bool, ThresholdError> {
        match &self.kind {
            ThresholdKind::Numeric(number) => {
                let count = u128::try_from(indices.len()).map_err(|_| ThresholdError::ArithmeticOverflow {
                    context: "signature count conversion",
                })?;
                Ok(number.is_positive() && count >= number.value())
            }
            ThresholdKind::Weighted(clauses) => self.weighted_satisfaction(clauses, indices),
        }
    }

    fn from_json_array(values: Vec<Value>) -> Result<Self, ThresholdError> {
        if values.is_empty() {
            return Err(ThresholdError::EmptyThreshold);
        }
        if values.len() > MAX_THRESHOLD_WEIGHTS {
            return Err(ThresholdError::TooManyWeights {
                count: values.len(),
                maximum: MAX_THRESHOLD_WEIGHTS,
            });
        }

        if values.iter().all(Value::is_string) {
            return Self::weighted(vec![parse_json_clause(values, 0)?]);
        }
        if !values.iter().all(Value::is_array) {
            return Err(ThresholdError::InvalidExpressionShape);
        }

        let mut clauses = Vec::with_capacity(values.len());
        let mut total = 0_usize;
        for (clause_index, value) in values.into_iter().enumerate() {
            let Value::Array(weights) = value else {
                return Err(ThresholdError::InvalidExpressionShape);
            };
            total = total
                .checked_add(weights.len())
                .ok_or(ThresholdError::ArithmeticOverflow {
                    context: "parsed weighted threshold size",
                })?;
            if total > MAX_THRESHOLD_WEIGHTS {
                return Err(ThresholdError::TooManyWeights {
                    count: total,
                    maximum: MAX_THRESHOLD_WEIGHTS,
                });
            }
            clauses.push(parse_json_clause(weights, clause_index)?);
        }
        Self::weighted(clauses)
    }

    fn weighted_satisfaction(&self, clauses: &[WeightClause], indices: &[usize]) -> Result<bool, ThresholdError> {
        if indices.is_empty() {
            return Ok(false);
        }
        let size = usize::try_from(self.size).map_err(|_| ThresholdError::ArithmeticOverflow {
            context: "weighted threshold size conversion",
        })?;
        let mut selected = vec![false; size];
        for &index in indices {
            let slot = selected
                .get_mut(index)
                .ok_or(ThresholdError::IndexOutOfRange { index, size })?;
            *slot = true;
        }

        let mut offset = 0_usize;
        for clause in clauses {
            let mut selected_weights = Vec::with_capacity(clause.len());
            for (index, weight) in clause.weights.iter().enumerate() {
                let position = offset.checked_add(index).ok_or(ThresholdError::ArithmeticOverflow {
                    context: "weighted threshold key position",
                })?;
                let is_selected = selected
                    .get(position)
                    .copied()
                    .ok_or(ThresholdError::ArithmeticOverflow {
                        context: "weighted threshold internal position",
                    })?;
                if is_selected {
                    selected_weights.push(*weight);
                }
            }
            if !sum_at_least_one(selected_weights)? {
                return Ok(false);
            }
            offset = offset
                .checked_add(clause.len())
                .ok_or(ThresholdError::ArithmeticOverflow {
                    context: "weighted threshold clause offset",
                })?;
        }
        Ok(true)
    }
}

impl FromStr for SigningThreshold {
    type Err = ThresholdError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_sith(input)
    }
}

impl fmt::Display for SigningThreshold {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.canonical_sith())
    }
}

impl fmt::Display for RationalWeightError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("weight is empty"),
            Self::InputTooLarge { length, maximum } => {
                write!(formatter, "weight length {length} exceeds maximum {maximum}")
            }
            Self::InvalidCharacter { index, byte } => {
                write!(formatter, "invalid weight byte 0x{byte:02x} at position {index}")
            }
            Self::InvalidFormat => formatter.write_str("weight has invalid rational format"),
            Self::ZeroDenominator => formatter.write_str("weight denominator is zero"),
            Self::OutOfRange => formatter.write_str("weight is outside the inclusive range 0..=1"),
            Self::ArithmeticOverflow => formatter.write_str("weight arithmetic overflow"),
        }
    }
}

impl Error for RationalWeightError {}

impl fmt::Display for ThresholdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyExpression => formatter.write_str("threshold expression is empty"),
            Self::ExpressionTooLarge { length, maximum } => write!(
                formatter,
                "threshold expression length {length} exceeds maximum {maximum}"
            ),
            Self::MalformedJson { .. } => formatter.write_str("threshold JSON is malformed"),
            Self::InvalidExpressionShape => formatter.write_str("threshold expression has invalid shape"),
            Self::EmptyThreshold => formatter.write_str("weighted threshold has no clauses"),
            Self::EmptyClause { clause } => write!(formatter, "threshold clause {clause} is empty"),
            Self::TooManyWeights { count, maximum } => {
                write!(formatter, "threshold weight count {count} exceeds maximum {maximum}")
            }
            Self::InvalidWeight { clause, index, .. } => {
                write!(formatter, "invalid weight at clause {clause}, position {index}")
            }
            Self::ClauseBelowOne { clause } => {
                write!(formatter, "threshold clause {clause} sums below one")
            }
            Self::ArithmeticOverflow { context } => {
                write!(formatter, "threshold arithmetic overflow while {context}")
            }
            Self::IndexOutOfRange { index, size } => {
                write!(formatter, "signature index {index} is outside threshold size {size}")
            }
            Self::Cesr { .. } => formatter.write_str("numeric threshold CESR material is invalid"),
        }
    }
}

impl Error for ThresholdError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::MalformedJson { source } => Some(source.as_ref()),
            Self::InvalidWeight { source, .. } => Some(source.as_ref()),
            Self::Cesr { source } => Some(source.as_ref()),
            _ => None,
        }
    }
}

impl From<CesrError> for ThresholdError {
    fn from(source: CesrError) -> Self {
        Self::Cesr {
            source: Box::new(source),
        }
    }
}

fn validate_expression_length(input: &str) -> Result<(), ThresholdError> {
    if input.is_empty() {
        return Err(ThresholdError::EmptyExpression);
    }
    if input.len() > MAX_THRESHOLD_EXPRESSION_BYTES {
        return Err(ThresholdError::ExpressionTooLarge {
            length: input.len(),
            maximum: MAX_THRESHOLD_EXPRESSION_BYTES,
        });
    }
    Ok(())
}

fn parse_json_clause(values: Vec<Value>, clause: usize) -> Result<Vec<RationalWeight>, ThresholdError> {
    if values.is_empty() {
        return Err(ThresholdError::EmptyClause { clause });
    }
    if values.len() > MAX_THRESHOLD_WEIGHTS {
        return Err(ThresholdError::TooManyWeights {
            count: values.len(),
            maximum: MAX_THRESHOLD_WEIGHTS,
        });
    }
    let mut weights = Vec::with_capacity(values.len());
    for (index, value) in values.into_iter().enumerate() {
        let Value::String(text) = value else {
            return Err(ThresholdError::InvalidExpressionShape);
        };
        let weight = RationalWeight::parse(&text).map_err(|source| ThresholdError::InvalidWeight {
            clause,
            index,
            source: Box::new(source),
        })?;
        weights.push(weight);
    }
    Ok(weights)
}

fn parse_unsigned_decimal(input: &str) -> Result<u128, RationalWeightError> {
    if input.is_empty() {
        return Err(RationalWeightError::InvalidFormat);
    }
    input.bytes().enumerate().try_fold(0_u128, |value, (index, byte)| {
        if !byte.is_ascii_digit() {
            return Err(RationalWeightError::InvalidCharacter { index, byte });
        }
        value
            .checked_mul(10)
            .and_then(|scaled| scaled.checked_add(u128::from(byte - b'0')))
            .ok_or(RationalWeightError::ArithmeticOverflow)
    })
}

const fn greatest_common_divisor(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    if left == 0 { 1 } else { left }
}

fn sum_at_least_one<I>(weights: I) -> Result<bool, ThresholdError>
where
    I: IntoIterator<Item = RationalWeight>,
{
    let mut numerator = 0_u128;
    let mut denominator = 1_u128;
    for weight in weights {
        let divisor = greatest_common_divisor(denominator, weight.denominator());
        let left_scale = weight.denominator() / divisor;
        let right_scale = denominator / divisor;
        numerator = numerator
            .checked_mul(left_scale)
            .and_then(|left| {
                weight
                    .numerator()
                    .checked_mul(right_scale)
                    .and_then(|right| left.checked_add(right))
            })
            .ok_or(ThresholdError::ArithmeticOverflow {
                context: "summing rational weights",
            })?;
        denominator = denominator
            .checked_mul(left_scale)
            .ok_or(ThresholdError::ArithmeticOverflow {
                context: "summing rational denominators",
            })?;
        let reduction = greatest_common_divisor(numerator, denominator);
        numerator /= reduction;
        denominator /= reduction;
        if numerator >= denominator {
            return Ok(true);
        }
    }
    Ok(false)
}

fn encode_weighted(clauses: &[WeightClause]) -> String {
    let flatten = clauses.len() == 1;
    let mut output = String::new();
    output.push('[');
    for (clause_index, clause) in clauses.iter().enumerate() {
        if clause_index > 0 {
            output.push(',');
        }
        if !flatten {
            output.push('[');
        }
        for (weight_index, weight) in clause.weights.iter().enumerate() {
            if weight_index > 0 {
                output.push(',');
            }
            output.push('"');
            output.push_str(&weight.to_string());
            output.push('"');
        }
        if !flatten {
            output.push(']');
        }
    }
    output.push(']');
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn weight(input: &str) -> Result<RationalWeight, RationalWeightError> {
        RationalWeight::parse(input)
    }

    #[test]
    fn numeric_reference_forms_and_limen_match() -> Result<(), ThresholdError> {
        let eleven = SigningThreshold::from_sith("b")?;
        assert_eq!(eleven.numeric_value(), Some(11));
        assert_eq!(eleven.size(), 11);
        assert_eq!(eleven.canonical_sith(), "b");
        assert_eq!(eleven.canonical_json(), "\"b\"");
        assert_eq!(eleven.limen()?, Some(b"MAAL".to_vec()));
        assert!(!eleven.is_satisfied_by(&[1, 2, 3])?);
        assert!(eleven.is_satisfied_by(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])?);
        assert_eq!(SigningThreshold::from_limen(b"MAAL")?, eleven);
        assert_eq!(SigningThreshold::from_limen_qb64("MAAL")?, eleven);

        let zero = SigningThreshold::numeric(0);
        assert_eq!(zero.limen()?, Some(b"MAAA".to_vec()));
        assert!(!zero.is_satisfied_by(&[])?);
        assert!(!zero.is_satisfied_by(&[0])?);
        Ok(())
    }

    #[test]
    fn single_clause_reference_satisfaction_is_exact() -> Result<(), Box<dyn Error>> {
        let threshold = SigningThreshold::weighted(vec![vec![
            weight("1/2")?,
            weight("1/2")?,
            weight("1/4")?,
            weight("1/4")?,
            weight("1/4")?,
        ]])?;
        assert!(threshold.is_weighted());
        assert_eq!(threshold.size(), 5);
        assert_eq!(threshold.canonical_sith(), "[\"1/2\",\"1/2\",\"1/4\",\"1/4\",\"1/4\"]");
        for indices in [&[0, 1][..], &[0, 2, 4], &[1, 3, 4], &[0, 2, 3], &[0, 0, 1, 2, 1]] {
            assert!(threshold.is_satisfied_by(indices)?);
        }
        for indices in [&[0][..], &[0, 2], &[2, 3, 4], &[]] {
            assert!(!threshold.is_satisfied_by(indices)?);
        }
        Ok(())
    }

    #[test]
    fn multiple_clauses_match_reference_and_preserve_order() -> Result<(), ThresholdError> {
        let threshold = SigningThreshold::from_json("[[\"1/2\",\"1/2\",\"1/2\"],[\"1/3\",\"1/3\",\"1/3\",\"1/3\"]]")?;
        assert_eq!(threshold.size(), 7);
        assert!(threshold.is_satisfied_by(&[0, 2, 3, 5, 6])?);
        assert!(threshold.is_satisfied_by(&[1, 2, 3, 4, 5])?);
        assert!(!threshold.is_satisfied_by(&[0, 1])?);
        assert!(!threshold.is_satisfied_by(&[4, 5, 6])?);
        assert_eq!(SigningThreshold::from_sith(&threshold.canonical_sith())?, threshold);
        assert_eq!(SigningThreshold::from_json(&threshold.canonical_json())?, threshold);
        assert_eq!(threshold.limen()?, None);
        Ok(())
    }

    #[test]
    fn rational_weights_reduce_and_decimal_input_is_exact() -> Result<(), RationalWeightError> {
        for (input, numerator, denominator, canonical) in [
            ("0", 0, 1, "0"),
            ("1/1", 1, 1, "1"),
            ("2/4", 1, 2, "1/2"),
            ("0.5", 1, 2, "1/2"),
            ("0.10", 1, 10, "1/10"),
            ("0.9", 9, 10, "9/10"),
        ] {
            let parsed = RationalWeight::parse(input)?;
            assert_eq!(parsed.numerator(), numerator);
            assert_eq!(parsed.denominator(), denominator);
            assert_eq!(parsed.to_string(), canonical);
        }
        Ok(())
    }

    #[test]
    fn malformed_and_unsafe_weight_forms_are_rejected() {
        for (input, expected) in [
            ("", RationalWeightError::Empty),
            ("1/0", RationalWeightError::ZeroDenominator),
            ("2", RationalWeightError::OutOfRange),
            ("-1", RationalWeightError::InvalidCharacter { index: 0, byte: b'-' }),
            (".5", RationalWeightError::InvalidFormat),
            ("1.", RationalWeightError::InvalidFormat),
            ("1/2/3", RationalWeightError::InvalidFormat),
        ] {
            assert_eq!(RationalWeight::parse(input), Err(expected));
        }
        assert!(matches!(
            RationalWeight::parse(&"1".repeat(MAX_WEIGHT_TEXT_BYTES + 1)),
            Err(RationalWeightError::InputTooLarge { .. })
        ));
    }

    #[test]
    fn malformed_threshold_shapes_and_bounds_are_typed() -> Result<(), RationalWeightError> {
        assert!(matches!(
            SigningThreshold::from_sith(""),
            Err(ThresholdError::EmptyExpression)
        ));
        assert!(matches!(
            SigningThreshold::from_sith("-1"),
            Err(ThresholdError::Cesr { .. })
        ));
        assert!(matches!(
            SigningThreshold::from_json("["),
            Err(ThresholdError::MalformedJson { .. })
        ));
        assert!(matches!(
            SigningThreshold::from_json("[]"),
            Err(ThresholdError::EmptyThreshold)
        ));
        assert!(matches!(
            SigningThreshold::from_json("[[]]"),
            Err(ThresholdError::EmptyClause { .. })
        ));
        assert!(matches!(
            SigningThreshold::from_json("[\"1/2\",[\"1/2\"]]"),
            Err(ThresholdError::InvalidExpressionShape)
        ));
        assert!(matches!(
            SigningThreshold::from_json("[1]"),
            Err(ThresholdError::InvalidExpressionShape)
        ));
        assert!(matches!(
            SigningThreshold::from_json("[\"1/4\",\"1/4\",\"1/4\"]"),
            Err(ThresholdError::ClauseBelowOne { .. })
        ));

        let many = vec![weight("1")?; MAX_THRESHOLD_WEIGHTS + 1];
        assert!(matches!(
            SigningThreshold::weighted(vec![many]),
            Err(ThresholdError::TooManyWeights { .. })
        ));
        let many_json = serde_json::to_string(&vec!["1"; MAX_THRESHOLD_WEIGHTS + 1])
            .map_err(|_| RationalWeightError::InvalidFormat)?;
        assert!(matches!(
            SigningThreshold::from_json(&many_json),
            Err(ThresholdError::TooManyWeights { .. })
        ));
        let oversized = "[".repeat(MAX_THRESHOLD_EXPRESSION_BYTES + 1);
        assert!(matches!(
            SigningThreshold::from_json(&oversized),
            Err(ThresholdError::ExpressionTooLarge { .. })
        ));
        Ok(())
    }

    #[test]
    fn checked_sum_overflow_and_invalid_indices_are_errors() -> Result<(), Box<dyn Error>> {
        let first = RationalWeight::new(1, u128::MAX)?;
        let second = RationalWeight::new(1, u128::MAX - 1)?;
        assert!(matches!(
            SigningThreshold::weighted(vec![vec![first, second]]),
            Err(ThresholdError::ArithmeticOverflow { .. })
        ));

        let threshold = SigningThreshold::weighted(vec![vec![weight("1/2")?, weight("1/2")?]])?;
        assert!(matches!(
            threshold.is_satisfied_by(&[2]),
            Err(ThresholdError::IndexOutOfRange { .. })
        ));
        Ok(())
    }
}
