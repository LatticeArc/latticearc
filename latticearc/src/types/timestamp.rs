//! [`Timestamp`]: the crate's platform-independent UTC instant.
//!
//! Every timestamp in the public API is a [`Timestamp`] — nanoseconds since
//! the Unix epoch, held identically on every platform. `std::time::SystemTime`
//! is not used for stored values because its resolution and range are
//! platform-specific (100 ns and years 1601–60056 on Windows): a nanosecond
//! timestamp written on Linux would lose digits when loaded on Windows. No
//! third-party date/time type is part of the API either. Convert to and from
//! `SystemTime` with `TryFrom`.
//!
//! Text form: RFC 3339 in UTC. The encoder reproduces byte-for-byte what the
//! crate wrote when it used `chrono` (fractional seconds omitted when zero,
//! otherwise 3, 6 or 9 digits; `Z` in serde and [`Display`], `+00:00` in the
//! version-1 audit-chain hash transcript; years outside 0000–9999 with a sign
//! and at least four digits, e.g. `+10000`), so files written by earlier
//! versions load and re-encode identically.
//!
//! The parser accepts everything the encoder (and chrono before it) wrote,
//! plus the RFC 3339 variants a conforming producer may emit: `t` or a space
//! as the date/time separator, `z`, any `±HH:MM` offset, more than nine
//! fractional digits (truncated) and second `60`. It rejects the non-RFC
//! forms chrono's parser also tolerated (a `UTC` suffix, `+HHMM` offsets
//! without a colon, single-digit fields, embedded whitespace): nothing in
//! this crate ever wrote them.
//!
//! [`Display`]: std::fmt::Display

use std::fmt::{self, Write as _};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::{Date, Month, OffsetDateTime};

const NANOS_PER_SEC: i128 = 1_000_000_000;
const NANOS_PER_MILLI: i128 = 1_000_000;
const NANOS_PER_MICRO: i128 = 1_000;
const NANOS_PER_DAY: i128 = 86_400 * NANOS_PER_SEC;
/// Julian day number of 1970-01-01.
const UNIX_EPOCH_JULIAN_DAY: i128 = 2_440_588;
/// `-999999-01-01T00:00:00Z` in Unix seconds.
const MIN_UNIX_SECS: i128 = -31_619_087_596_800;
/// `+999999-12-31T23:59:59Z` in Unix seconds.
const MAX_UNIX_SECS: i128 = 31_494_784_780_799;
const MIN_NANOS: i128 = MIN_UNIX_SECS * NANOS_PER_SEC;
const MAX_NANOS: i128 = MAX_UNIX_SECS * NANOS_PER_SEC + (NANOS_PER_SEC - 1);

/// A UTC instant with nanosecond precision, independent of the platform.
///
/// Range: years −999,999 through +999,999 (a superset of every instant
/// `chrono` could represent), so every `Timestamp` has an RFC 3339 encoding.
/// Leap seconds are not represented: like Unix time, a parsed `:60` second
/// denotes the first instant of the following minute.
///
/// Serializes as an RFC 3339 string (`"2026-11-18T09:30:00.123456Z"`), and
/// [`Display`](fmt::Display) / [`FromStr`] use the same form.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp {
    /// Nanoseconds since 1970-01-01T00:00:00Z; always within
    /// `MIN_NANOS..=MAX_NANOS`.
    nanos: i128,
}

/// Why a [`Timestamp`] could not be built, parsed or converted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TimestampError {
    /// The instant lies outside the representable range — years ±999,999
    /// for a `Timestamp`, or the platform's range for a `SystemTime`.
    #[error("timestamp out of range")]
    OutOfRange,
    /// The text is not a valid RFC 3339 timestamp.
    #[error("invalid RFC 3339 timestamp")]
    InvalidFormat,
}

impl Timestamp {
    /// 1970-01-01T00:00:00Z.
    pub const UNIX_EPOCH: Self = Self { nanos: 0 };

    /// The earliest representable instant, `-999999-01-01T00:00:00Z`.
    pub const MIN: Self = Self { nanos: MIN_NANOS };

    /// The latest representable instant, `+999999-12-31T23:59:59.999999999Z`
    /// — e.g. a "never expires" `not_after`.
    pub const MAX: Self = Self { nanos: MAX_NANOS };

    /// The current wall-clock time.
    ///
    /// A system clock outside years ±999,999 (which no real clock reports)
    /// saturates to the nearest bound rather than failing.
    #[must_use]
    pub fn now() -> Self {
        Self { nanos: system_time_nanos(SystemTime::now()).clamp(MIN_NANOS, MAX_NANOS) }
    }

    /// The instant `secs` seconds plus `nanos` nanoseconds after the Unix
    /// epoch (`secs` may be negative).
    ///
    /// # Errors
    /// [`TimestampError::OutOfRange`] when `nanos >= 1_000_000_000` or the
    /// instant lies outside years ±999,999.
    pub fn from_unix(secs: i64, nanos: u32) -> Result<Self, TimestampError> {
        if nanos >= 1_000_000_000 {
            return Err(TimestampError::OutOfRange);
        }
        i128::from(secs)
            .checked_mul(NANOS_PER_SEC)
            .and_then(|n| n.checked_add(i128::from(nanos)))
            .and_then(Self::from_nanos)
            .ok_or(TimestampError::OutOfRange)
    }

    /// The instant `nanos` nanoseconds after the Unix epoch (negative
    /// before it). Lossless inverse of [`unix_nanos`](Self::unix_nanos).
    ///
    /// # Errors
    /// [`TimestampError::OutOfRange`] outside [`MIN`](Self::MIN)..=[`MAX`](Self::MAX).
    pub fn from_unix_nanos(nanos: i128) -> Result<Self, TimestampError> {
        Self::from_nanos(nanos).ok_or(TimestampError::OutOfRange)
    }

    /// Nanoseconds since the Unix epoch (negative before it), losslessly.
    #[must_use]
    pub fn unix_nanos(self) -> i128 {
        self.nanos
    }

    /// Whole seconds since the Unix epoch, rounded toward negative infinity.
    #[must_use]
    pub fn unix_seconds(self) -> i64 {
        self.unix_floor(NANOS_PER_SEC)
    }

    /// Nanoseconds past [`unix_seconds`](Self::unix_seconds), in `0..1_000_000_000`.
    #[must_use]
    pub fn subsec_nanos(self) -> u32 {
        u32::try_from(self.nanos.rem_euclid(NANOS_PER_SEC)).unwrap_or(0)
    }

    /// `self + duration`, or `None` if the result leaves the range.
    #[must_use]
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        Self::from_nanos(self.nanos.checked_add(duration_nanos(duration))?)
    }

    /// `self - duration`, or `None` if the result leaves the range.
    #[must_use]
    pub fn checked_sub(self, duration: Duration) -> Option<Self> {
        Self::from_nanos(self.nanos.checked_sub(duration_nanos(duration))?)
    }

    /// The time elapsed from `earlier` to `self`, or `None` if `earlier`
    /// is later than `self`.
    #[must_use]
    pub fn duration_since(self, earlier: Self) -> Option<Duration> {
        let diff = self.nanos.checked_sub(earlier.nanos)?;
        let secs = u64::try_from(diff.div_euclid(NANOS_PER_SEC)).ok()?;
        let subsec = u32::try_from(diff.rem_euclid(NANOS_PER_SEC)).ok()?;
        Some(Duration::new(secs, subsec))
    }

    fn from_nanos(nanos: i128) -> Option<Self> {
        (MIN_NANOS..=MAX_NANOS).contains(&nanos).then_some(Self { nanos })
    }

    /// Floor of `self` in `unit` nanoseconds since the epoch. The range
    /// bound keeps every unit used here (s, ms, µs) inside `i64`.
    fn unix_floor(self, unit: i128) -> i64 {
        let floored = self.nanos.div_euclid(unit);
        i64::try_from(floored).unwrap_or(if floored < 0 { i64::MIN } else { i64::MAX })
    }

    /// Whole milliseconds since the Unix epoch, rounded toward negative infinity.
    #[must_use]
    pub(crate) fn unix_millis(self) -> i64 {
        self.unix_floor(NANOS_PER_MILLI)
    }

    /// Whole microseconds since the Unix epoch, rounded toward negative infinity.
    #[must_use]
    pub(crate) fn unix_micros(self) -> i64 {
        self.unix_floor(NANOS_PER_MICRO)
    }

    /// UTC calendar fields. Always `Some` for an in-range `Timestamp` (the
    /// `time` crate's `large-dates` range is the same ±999,999 years).
    #[must_use]
    pub(crate) fn utc_fields(self) -> Option<OffsetDateTime> {
        OffsetDateTime::from_unix_timestamp_nanos(self.nanos).ok()
    }

    /// RFC 3339 text in UTC with the given offset designator.
    #[must_use]
    pub(crate) fn to_rfc3339(self, suffix: UtcSuffix) -> Option<String> {
        let dt = self.utc_fields()?;
        let mut out = String::with_capacity(35);
        let year = dt.year();
        if (0..=9999).contains(&year) {
            write!(out, "{year:04}").ok()?;
        } else {
            // chrono's extended form: explicit sign, at least four digits.
            write!(out, "{year:+05}").ok()?;
        }
        write!(
            out,
            "-{:02}-{:02}T{:02}:{:02}:{:02}",
            u8::from(dt.month()),
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        )
        .ok()?;
        // Fraction omitted when zero, else the shortest of 3, 6 or 9 digits
        // that is exact (chrono's `SecondsFormat::AutoSi`).
        let nanos = dt.nanosecond();
        if nanos != 0 {
            if nanos % 1_000_000 == 0 {
                write!(out, ".{:03}", nanos / 1_000_000).ok()?;
            } else if nanos % 1_000 == 0 {
                write!(out, ".{:06}", nanos / 1_000).ok()?;
            } else {
                write!(out, ".{nanos:09}").ok()?;
            }
        }
        out.push_str(match suffix {
            UtcSuffix::Z => "Z",
            UtcSuffix::PlusZero => "+00:00",
        });
        Some(out)
    }
}

/// Signed nanoseconds of `t` relative to the Unix epoch.
fn system_time_nanos(t: SystemTime) -> i128 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(after) => duration_nanos(after),
        Err(before) => duration_nanos(before.duration()).saturating_neg(),
    }
}

/// `Duration::as_nanos` is at most `u64::MAX * 10^9 + 999_999_999`, far
/// below `i128::MAX`, so the fallback is never taken.
fn duration_nanos(d: Duration) -> i128 {
    i128::try_from(d.as_nanos()).unwrap_or(i128::MAX)
}

impl TryFrom<SystemTime> for Timestamp {
    type Error = TimestampError;

    /// # Errors
    /// [`TimestampError::OutOfRange`] outside years ±999,999.
    fn try_from(t: SystemTime) -> Result<Self, Self::Error> {
        Self::from_nanos(system_time_nanos(t)).ok_or(TimestampError::OutOfRange)
    }
}

impl TryFrom<Timestamp> for SystemTime {
    type Error = TimestampError;

    /// # Errors
    /// [`TimestampError::OutOfRange`] when the platform's `SystemTime`
    /// cannot represent the instant. On Windows (100 ns resolution) the
    /// sub-100 ns digits are dropped.
    fn try_from(t: Timestamp) -> Result<Self, Self::Error> {
        let secs = t.nanos.div_euclid(NANOS_PER_SEC);
        let subsec = u32::try_from(t.nanos.rem_euclid(NANOS_PER_SEC))
            .map_err(|_e| TimestampError::OutOfRange)?;
        let converted = if let Ok(secs) = u64::try_from(secs) {
            UNIX_EPOCH.checked_add(Duration::new(secs, subsec))
        } else {
            u64::try_from(secs.unsigned_abs())
                .ok()
                .and_then(|back| UNIX_EPOCH.checked_sub(Duration::from_secs(back)))
                .and_then(|base| base.checked_add(Duration::from_nanos(u64::from(subsec))))
        };
        converted.ok_or(TimestampError::OutOfRange)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rfc3339(UtcSuffix::Z).ok_or(fmt::Error)?)
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timestamp({self})")
    }
}

impl FromStr for Timestamp {
    type Err = TimestampError;

    /// Parse RFC 3339 text (see the module docs for the accepted forms).
    ///
    /// # Errors
    /// [`TimestampError::InvalidFormat`] for malformed text or an impossible
    /// date/time; [`TimestampError::OutOfRange`] beyond years ±999,999.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let nanos = parse_rfc3339_nanos(text).ok_or(TimestampError::InvalidFormat)?;
        Self::from_nanos(nanos).ok_or(TimestampError::OutOfRange)
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text = self
            .to_rfc3339(UtcSuffix::Z)
            .ok_or_else(|| serde::ser::Error::custom(TimestampError::OutOfRange))?;
        serializer.serialize_str(&text)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Rfc3339Visitor;

        impl Visitor<'_> for Rfc3339Visitor {
            type Value = Timestamp;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an RFC 3339 timestamp string")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Timestamp, E> {
                v.parse().map_err(E::custom)
            }

            // Formats that carry strings as raw bytes (e.g. some binary
            // encodings) deliver UTF-8 text here.
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Timestamp, E> {
                std::str::from_utf8(v)
                    .map_err(|_e| E::custom(TimestampError::InvalidFormat))?
                    .parse()
                    .map_err(E::custom)
            }
        }

        deserializer.deserialize_str(Rfc3339Visitor)
    }
}

/// How the UTC offset is written after the time of day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UtcSuffix {
    /// `Z` — serde and `Display`.
    Z,
    /// `+00:00` — the version-1 audit-chain hash transcript encoding.
    PlusZero,
}

/// `later - earlier` in whole `unit`s, truncated toward zero. The range
/// bound keeps every unit used here inside `i64`.
fn signed_between(earlier: Timestamp, later: Timestamp, unit: i128) -> i64 {
    let units = later.nanos.saturating_sub(earlier.nanos).checked_div(unit).unwrap_or(0);
    i64::try_from(units).unwrap_or(if units < 0 { i64::MIN } else { i64::MAX })
}

/// Milliseconds from `earlier` to `later` (negative if `later` is earlier).
#[must_use]
pub(crate) fn signed_millis_between(earlier: Timestamp, later: Timestamp) -> i64 {
    signed_between(earlier, later, NANOS_PER_MILLI)
}

/// Seconds from `earlier` to `later` (negative if `later` is earlier).
#[must_use]
pub(crate) fn signed_seconds_between(earlier: Timestamp, later: Timestamp) -> i64 {
    signed_between(earlier, later, NANOS_PER_SEC)
}

/// Whole days from `earlier` to `later` (negative if `later` is earlier).
#[must_use]
pub(crate) fn signed_days_between(earlier: Timestamp, later: Timestamp) -> i64 {
    signed_between(earlier, later, NANOS_PER_DAY)
}

/// Milliseconds elapsed from `earlier` to `later`, clamped to zero when
/// `later` precedes `earlier` (clock stepped backwards).
#[must_use]
pub(crate) fn elapsed_millis_saturating(earlier: Timestamp, later: Timestamp) -> u64 {
    u64::try_from(signed_millis_between(earlier, later)).unwrap_or(0)
}

/// Byte cursor for [`parse_rfc3339_nanos`].
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos = self.pos.checked_add(1)?;
        Some(b)
    }

    fn expect(&mut self, want: u8) -> Option<()> {
        (self.bump()? == want).then_some(())
    }

    fn digit(&mut self) -> Option<u32> {
        let b = self.peek().filter(u8::is_ascii_digit)?;
        self.pos = self.pos.checked_add(1)?;
        Some(u32::from(b.checked_sub(b'0')?))
    }

    /// Exactly `n` ASCII digits as a number.
    fn fixed(&mut self, n: usize) -> Option<u32> {
        (0..n).try_fold(0u32, |acc, _| acc.checked_mul(10)?.checked_add(self.digit()?))
    }

    fn at_end(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

/// Nanoseconds since the Unix epoch denoted by RFC 3339 `text`, or `None`
/// if it is malformed or names an impossible date or time.
fn parse_rfc3339_nanos(text: &str) -> Option<i128> {
    let mut c = Cursor { bytes: text.as_bytes(), pos: 0 };

    // Year: four digits, or chrono's extended form — a sign and 4–6 digits.
    let year = match c.peek()? {
        sign @ (b'+' | b'-') => {
            c.bump()?;
            let mut value = c.fixed(4)?;
            for _ in 0..2 {
                match c.digit() {
                    Some(d) => value = value.checked_mul(10)?.checked_add(d)?,
                    None => break,
                }
            }
            let value = i32::try_from(value).ok()?;
            if sign == b'-' { value.checked_neg()? } else { value }
        }
        _ => i32::try_from(c.fixed(4)?).ok()?,
    };
    c.expect(b'-')?;
    let month = c.fixed(2)?;
    c.expect(b'-')?;
    let day = c.fixed(2)?;
    if !matches!(c.bump()?, b'T' | b't' | b' ') {
        return None;
    }
    let hour = c.fixed(2)?;
    c.expect(b':')?;
    let minute = c.fixed(2)?;
    c.expect(b':')?;
    let second = c.fixed(2)?;
    // RFC 3339 allows second 60 (leap second); like chrono, it denotes the
    // instant one second after :59, i.e. the start of the next minute.
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    // Fraction: one or more digits; the first nine are significant.
    let mut nanos: u32 = 0;
    if c.peek() == Some(b'.') {
        c.bump()?;
        let mut scale: u32 = 100_000_000;
        nanos = c.digit()?.checked_mul(scale)?;
        while let Some(d) = c.digit() {
            scale /= 10;
            nanos = nanos.checked_add(d.checked_mul(scale)?)?;
        }
    }

    // Offset: `Z`/`z` or `±HH:MM`.
    let offset_secs: i128 = match c.bump()? {
        b'Z' | b'z' => 0,
        sign @ (b'+' | b'-') => {
            let oh = c.fixed(2)?;
            c.expect(b':')?;
            let om = c.fixed(2)?;
            if oh > 23 || om > 59 {
                return None;
            }
            let secs = i128::from(oh.checked_mul(3_600)?.checked_add(om.checked_mul(60)?)?);
            if sign == b'-' { secs.checked_neg()? } else { secs }
        }
        _ => return None,
    };
    if !c.at_end() {
        return None;
    }

    let month = Month::try_from(u8::try_from(month).ok()?).ok()?;
    let date = Date::from_calendar_date(year, month, u8::try_from(day).ok()?).ok()?;
    let days = i128::from(date.to_julian_day()).checked_sub(UNIX_EPOCH_JULIAN_DAY)?;
    let secs = days
        .checked_mul(86_400)?
        .checked_add(i128::from(hour.checked_mul(3_600)?))?
        .checked_add(i128::from(minute.checked_mul(60)?))?
        .checked_add(i128::from(second))?
        .checked_sub(offset_secs)?;
    secs.checked_mul(NANOS_PER_SEC)?.checked_add(i128::from(nanos))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::arithmetic_side_effects, reason = "test scaffolding")]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn at(secs: i64, nanos: u32) -> Timestamp {
        Timestamp::from_unix(secs, nanos).unwrap()
    }

    fn parse(text: &str) -> Option<Timestamp> {
        text.parse().ok()
    }

    /// Captured from `chrono` 0.4.45 (`DateTime::<Utc>::to_rfc3339()` and
    /// its serde encoding) before the crate dropped the dependency. Every
    /// fractional-precision branch and a leap day are covered.
    const CHRONO_GOLDEN: &[(i64, u32, &str, &str)] = &[
        (1_700_000_000, 0, "2023-11-14T22:13:20+00:00", "2023-11-14T22:13:20Z"),
        (1_700_000_000, 123_000_000, "2023-11-14T22:13:20.123+00:00", "2023-11-14T22:13:20.123Z"),
        (
            1_700_000_000,
            123_456_000,
            "2023-11-14T22:13:20.123456+00:00",
            "2023-11-14T22:13:20.123456Z",
        ),
        (
            1_700_000_000,
            123_456_789,
            "2023-11-14T22:13:20.123456789+00:00",
            "2023-11-14T22:13:20.123456789Z",
        ),
        (1_700_000_000, 1, "2023-11-14T22:13:20.000000001+00:00", "2023-11-14T22:13:20.000000001Z"),
        (1_700_000_000, 1_000, "2023-11-14T22:13:20.000001+00:00", "2023-11-14T22:13:20.000001Z"),
        (1_700_000_000, 1_000_000, "2023-11-14T22:13:20.001+00:00", "2023-11-14T22:13:20.001Z"),
        (0, 0, "1970-01-01T00:00:00+00:00", "1970-01-01T00:00:00Z"),
        (951_782_400, 500_000_000, "2000-02-29T00:00:00.500+00:00", "2000-02-29T00:00:00.500Z"),
        (
            4_102_444_799,
            999_999_999,
            "2099-12-31T23:59:59.999999999+00:00",
            "2099-12-31T23:59:59.999999999Z",
        ),
    ];

    /// chrono's encoding of years outside 0000–9999, including its own
    /// `MAX_UTC` / `MIN_UTC` (captured from chrono 0.4.45). A key file whose
    /// `not_after` used `MAX_UTC` as "never expires" must round-trip.
    const CHRONO_EXTENDED_YEARS: &[(i64, u32, &str, &str)] = &[
        (253_402_300_800, 0, "+10000-01-01T00:00:00+00:00", "+10000-01-01T00:00:00Z"),
        (-62_167_219_201, 0, "-0001-12-31T23:59:59+00:00", "-0001-12-31T23:59:59Z"),
        (
            -62_198_755_200,
            500_000_000,
            "-0001-01-01T00:00:00.500+00:00",
            "-0001-01-01T00:00:00.500Z",
        ),
        (
            8_210_266_876_799,
            999_999_999,
            "+262142-12-31T23:59:59.999999999+00:00",
            "+262142-12-31T23:59:59.999999999Z",
        ),
        (-8_334_601_228_800, 0, "-262143-01-01T00:00:00+00:00", "-262143-01-01T00:00:00Z"),
    ];

    /// Inputs chrono 0.4.45's deserializer accepted, with the instant it
    /// produced (captured from chrono). The parser must agree on each.
    const CHRONO_ACCEPTED: &[(&str, i64, u32)] = &[
        ("2023-11-14T22:13:20Z", 1_700_000_000, 0),
        ("2023-11-14t22:13:20z", 1_700_000_000, 0),
        ("2023-11-14 22:13:20Z", 1_700_000_000, 0),
        ("2023-11-14T22:13:20+01:00", 1_699_996_400, 0),
        ("2023-11-14T22:13:20-00:00", 1_700_000_000, 0),
        ("2023-11-14T22:13:20+23:59", 1_699_913_660, 0),
        ("2023-11-14T22:13:20.1234567891Z", 1_700_000_000, 123_456_789),
        ("2023-12-31T23:59:60Z", 1_704_067_200, 0),
        ("2023-12-31T23:59:60.5Z", 1_704_067_200, 500_000_000),
        ("+2023-11-14T22:13:20Z", 1_700_000_000, 0),
        ("+10000-01-01T00:00:00Z", 253_402_300_800, 0),
        ("-0001-12-31T23:59:59Z", -62_167_219_201, 0),
        ("+262142-12-31T23:59:59.999999999Z", 8_210_266_876_799, 999_999_999),
    ];

    #[test]
    fn test_to_rfc3339_matches_chrono_golden_succeeds() {
        for &(secs, nanos, plus_zero, z) in CHRONO_GOLDEN.iter().chain(CHRONO_EXTENDED_YEARS) {
            let t = at(secs, nanos);
            assert_eq!(t.to_rfc3339(UtcSuffix::PlusZero).as_deref(), Some(plus_zero));
            assert_eq!(t.to_rfc3339(UtcSuffix::Z).as_deref(), Some(z));
            assert_eq!(t.to_string(), z);
        }
    }

    #[test]
    fn test_parse_reads_chrono_golden_succeeds() {
        for &(secs, nanos, plus_zero, z) in CHRONO_GOLDEN.iter().chain(CHRONO_EXTENDED_YEARS) {
            assert_eq!(parse(plus_zero), Some(at(secs, nanos)), "{plus_zero:?}");
            assert_eq!(parse(z), Some(at(secs, nanos)), "{z:?}");
        }
    }

    #[test]
    fn test_parse_agrees_with_chrono_succeeds() {
        for &(text, secs, nanos) in CHRONO_ACCEPTED {
            assert_eq!(parse(text), Some(at(secs, nanos)), "{text:?}");
        }
    }

    #[test]
    fn test_parse_applies_offset_succeeds() {
        assert_eq!(parse("2023-11-14T23:13:20+01:00"), Some(at(1_700_000_000, 0)));
        assert_eq!(parse("2023-11-14T17:13:20.5-05:00"), Some(at(1_700_000_000, 500_000_000)));
    }

    #[test]
    fn test_parse_rejects_malformed_fails() {
        for bad in [
            "",
            "not a date",
            "2023-11-14",
            "2023-11-14T22:13:20",
            "2023-13-01T00:00:00Z",
            "2023-02-30T00:00:00Z",
            "2023-11-14T24:00:00Z",
            "2023-11-14T22:60:00Z",
            "2023-11-14T22:13:61Z",
            "2023-11-14T22:13:20.Z",
            "2023-11-14X22:13:20Z",
            "2023-11-14_22:13:20Z",
            "10000-01-01T00:00:00Z",
            "+999-01-01T00:00:00Z",
            "2023-11-14T22:13:20+24:00",
            "2023-11-14T22:13:20+01:60",
            "2023-11-14T22:13:20Z ",
            " 2023-11-14T22:13:20Z",
            "2023-11-14T22:13:20ZZ",
            // Non-RFC forms chrono tolerated; never written by this crate.
            "2023-11-14T22:13:20 UTC",
            "2023-11-14T22:13:20+0100",
            "2023-1-14T22:13:20Z",
        ] {
            assert_eq!(bad.parse::<Timestamp>(), Err(TimestampError::InvalidFormat), "{bad:?}");
        }
    }

    #[test]
    fn test_range_bounds_match_time_crate_succeeds() {
        // The hard-coded bounds are exactly the `time` crate's large-dates
        // range, so every in-range Timestamp has calendar fields.
        let min = OffsetDateTime::new_utc(
            Date::from_calendar_date(-999_999, Month::January, 1).unwrap(),
            time::Time::MIDNIGHT,
        );
        let max = OffsetDateTime::new_utc(
            Date::from_calendar_date(999_999, Month::December, 31).unwrap(),
            time::Time::from_hms_nano(23, 59, 59, 999_999_999).unwrap(),
        );
        assert_eq!(min.unix_timestamp_nanos(), MIN_NANOS);
        assert_eq!(max.unix_timestamp_nanos(), MAX_NANOS);
        let lo = at(i64::try_from(MIN_UNIX_SECS).unwrap(), 0);
        let hi = at(i64::try_from(MAX_UNIX_SECS).unwrap(), 999_999_999);
        assert_eq!(lo.to_string(), "-999999-01-01T00:00:00Z");
        assert_eq!(hi.to_string(), "+999999-12-31T23:59:59.999999999Z");
        assert_eq!(parse("-999999-01-01T00:00:00Z"), Some(lo));
        assert_eq!(parse("+999999-12-31T23:59:59.999999999Z"), Some(hi));
    }

    #[test]
    fn test_out_of_range_inputs_fail() {
        let max = i64::try_from(MAX_UNIX_SECS).unwrap();
        assert_eq!(Timestamp::from_unix(max + 1, 0), Err(TimestampError::OutOfRange));
        assert_eq!(Timestamp::from_unix(0, 1_000_000_000), Err(TimestampError::OutOfRange));
        assert_eq!(Timestamp::from_unix(i64::MIN, 0), Err(TimestampError::OutOfRange));
        // +999999-12-31T23:59:60Z denotes the first instant of year 1,000,000.
        assert_eq!("+999999-12-31T23:59:60Z".parse::<Timestamp>(), Err(TimestampError::OutOfRange));
        let hi = at(max, 999_999_999);
        assert_eq!(hi.checked_add(Duration::from_nanos(1)), None);
        let lo = at(i64::try_from(MIN_UNIX_SECS).unwrap(), 0);
        assert_eq!(lo.checked_sub(Duration::from_nanos(1)), None);
    }

    #[test]
    fn test_unix_accessors_round_toward_negative_infinity_succeeds() {
        let t = at(1_700_000_000, 123_456_789);
        assert_eq!(t.unix_seconds(), 1_700_000_000);
        assert_eq!(t.subsec_nanos(), 123_456_789);
        assert_eq!(t.unix_millis(), 1_700_000_000_123);
        assert_eq!(t.unix_micros(), 1_700_000_000_123_456);
        let before = at(-1, 500_000_000); // 0.5 s before the epoch
        assert_eq!(before.unix_seconds(), -1);
        assert_eq!(before.subsec_nanos(), 500_000_000);
        assert_eq!(before.unix_millis(), -500);
        assert_eq!(before.unix_micros(), -500_000);
        assert_eq!(before.to_string(), "1969-12-31T23:59:59.500Z");
    }

    #[test]
    fn test_arithmetic_and_differences_succeeds() {
        let a = at(1_000, 0);
        let b = at(1_000 + 2 * 86_400 + 3_600, 999_999_999);
        let span = Duration::new(2 * 86_400 + 3_600, 999_999_999);
        assert_eq!(a.checked_add(span), Some(b));
        assert_eq!(b.checked_sub(span), Some(a));
        assert_eq!(b.duration_since(a), Some(span));
        assert_eq!(a.duration_since(b), None);
        assert_eq!(a.duration_since(a), Some(Duration::ZERO));
        assert_eq!(signed_days_between(a, b), 2);
        assert_eq!(signed_days_between(b, a), -2);
        assert_eq!(signed_seconds_between(a, b), 2 * 86_400 + 3_600);
        assert_eq!(signed_seconds_between(b, a), -(2 * 86_400 + 3_600));
        assert_eq!(signed_millis_between(a, at(1_000, 1_999_999)), 1);
        assert_eq!(signed_millis_between(at(1_000, 1_999_999), a), -1);
        assert_eq!(elapsed_millis_saturating(a, at(1_002, 0)), 2_000);
        assert_eq!(elapsed_millis_saturating(at(1_002, 0), a), 0);
    }

    #[test]
    fn test_system_time_conversions_succeeds() {
        // Multiples of 100 ns survive on every platform, Windows included.
        let t = at(1_700_000_000, 123_456_700);
        let st = SystemTime::try_from(t).unwrap();
        assert_eq!(Timestamp::try_from(st).unwrap(), t);
        let before = at(-86_400, 0);
        assert_eq!(Timestamp::try_from(SystemTime::try_from(before).unwrap()).unwrap(), before);
        let now = Timestamp::now();
        assert!(now > Timestamp::UNIX_EPOCH);
        assert!(Timestamp::now() >= now);
        // Beyond what some platforms' SystemTime can hold: either converts
        // back exactly or reports OutOfRange — never silently wraps.
        let hi = at(i64::try_from(MAX_UNIX_SECS).unwrap(), 0);
        match SystemTime::try_from(hi) {
            Ok(st) => assert_eq!(Timestamp::try_from(st).unwrap(), hi),
            Err(e) => assert_eq!(e, TimestampError::OutOfRange),
        }
    }

    #[test]
    fn test_serde_roundtrip_and_reject_garbage_succeeds() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Probe {
            at: Timestamp,
            maybe: Option<Timestamp>,
        }
        let probe = Probe { at: at(1_700_000_000, 123_456_000), maybe: None };
        let json = serde_json::to_string(&probe).unwrap();
        assert_eq!(json, r#"{"at":"2023-11-14T22:13:20.123456Z","maybe":null}"#);
        assert_eq!(serde_json::from_str::<Probe>(&json).unwrap(), probe);
        // A missing optional field still deserializes as `None`.
        let missing: Probe =
            serde_json::from_str(r#"{"at":"2023-11-14T22:13:20.123456Z"}"#).unwrap();
        assert_eq!(missing, probe);
        let some = Probe { at: at(0, 0), maybe: Some(at(1, 1_000)) };
        let json = serde_json::to_string(&some).unwrap();
        assert_eq!(json, r#"{"at":"1970-01-01T00:00:00Z","maybe":"1970-01-01T00:00:01.000001Z"}"#);
        assert_eq!(serde_json::from_str::<Probe>(&json).unwrap(), some);
        assert!(serde_json::from_str::<Probe>(r#"{"at":"yesterday"}"#).is_err());
        assert!(serde_json::from_str::<Probe>(r#"{"at":1700000000}"#).is_err());
        assert!(
            serde_json::from_str::<Probe>(r#"{"at":"1970-01-01T00:00:00Z","maybe":"x"}"#).is_err()
        );
        assert_eq!(format!("{:?}", at(0, 0)), "Timestamp(1970-01-01T00:00:00Z)");
    }

    #[test]
    fn test_min_max_and_nanos_accessors_succeeds() {
        assert_eq!(Timestamp::MIN.to_string(), "-999999-01-01T00:00:00Z");
        assert_eq!(Timestamp::MAX.to_string(), "+999999-12-31T23:59:59.999999999Z");
        assert_eq!(Timestamp::MAX.checked_add(Duration::from_nanos(1)), None);
        assert_eq!(Timestamp::MIN.checked_sub(Duration::from_nanos(1)), None);
        let t = at(-1, 500_000_000);
        assert_eq!(t.unix_nanos(), -500_000_000);
        assert_eq!(Timestamp::from_unix_nanos(t.unix_nanos()), Ok(t));
        assert_eq!(Timestamp::from_unix_nanos(MAX_NANOS + 1), Err(TimestampError::OutOfRange));
        assert_eq!(Timestamp::from_unix_nanos(MIN_NANOS - 1), Err(TimestampError::OutOfRange));
    }

    #[test]
    fn test_deserialize_from_bytes_succeeds() {
        use serde::de::IntoDeserializer;
        use serde::de::value::{BytesDeserializer, Error as DeError};
        let ok = Timestamp::deserialize(BytesDeserializer::<DeError>::new(b"2023-11-14T22:13:20Z"));
        assert_eq!(ok.unwrap(), at(1_700_000_000, 0));
        assert!(Timestamp::deserialize(BytesDeserializer::<DeError>::new(b"\xff\xfe")).is_err());
        let s: Result<Timestamp, DeError> =
            Timestamp::deserialize("2023-11-14T22:13:20Z".into_deserializer());
        assert_eq!(s.unwrap(), at(1_700_000_000, 0));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Every representable instant survives encode → parse exactly, for
        /// both suffixes, on every platform.
        #[test]
        fn prop_rfc3339_roundtrip_succeeds(nanos in MIN_NANOS..=MAX_NANOS) {
            let t = Timestamp::from_nanos(nanos).unwrap();
            for suffix in [UtcSuffix::Z, UtcSuffix::PlusZero] {
                let text = t.to_rfc3339(suffix).unwrap();
                prop_assert_eq!(parse(&text), Some(t));
            }
        }

        /// Cross-validation: within four-digit years, the hand-written
        /// encoder and parser agree with the `time` crate's independent
        /// RFC 3339 parser and encoder on every instant and offset.
        #[test]
        fn prop_rfc3339_agrees_with_time_crate_succeeds(
            secs in -62_167_219_200i64..=253_402_300_799,
            nanos in 0u32..1_000_000_000,
            offset_minutes in -1_439i32..=1_439,
        ) {
            use time::format_description::well_known::Rfc3339;
            let t = at(secs, nanos);
            let text = t.to_string();
            let reference = OffsetDateTime::parse(&text, &Rfc3339).unwrap();
            prop_assert_eq!(reference.unix_timestamp_nanos(), t.nanos);
            let offset = time::UtcOffset::from_whole_seconds(offset_minutes * 60).unwrap();
            if let Ok(shifted) = reference.to_offset(offset).format(&Rfc3339) {
                prop_assert_eq!(parse(&shifted), Some(t), "{}", shifted);
            }
        }
    }
}
