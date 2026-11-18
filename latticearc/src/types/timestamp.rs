//! Wall-clock timestamps: `std::time::SystemTime` and its RFC 3339 text form.
//!
//! The public API carries every timestamp as [`SystemTime`], so no
//! third-party date/time type is part of the crate's API surface. This
//! module holds the conversions the crate needs internally: Unix-epoch
//! arithmetic, signed differences, and the RFC 3339 encoding used by serde,
//! by the audit-chain hash transcript and by audit filenames.
//!
//! The encoder reproduces byte-for-byte the text the crate emitted when it
//! used `chrono` (fractional seconds omitted when zero, otherwise 3, 6 or 9
//! digits; UTC written as `Z` in serde and as `+00:00` in the audit hash
//! transcript; years outside 0000–9999 written with a sign and at least
//! four digits, e.g. `+10000`). That is a compatibility requirement, not a
//! style choice: audit integrity hashes cover the encoded timestamp, so a
//! different encoding would make every audit chain written by an earlier
//! version fail verification.
//!
//! The parser accepts everything the encoder (and chrono before it) wrote,
//! plus the RFC 3339 variants a conforming producer may emit: `t` or a space
//! as the date/time separator, `z`, any `±HH:MM` offset, more than nine
//! fractional digits (truncated) and second `60`. It rejects the non-RFC
//! forms chrono's parser also tolerated (a `UTC` suffix, `+HHMM` offsets
//! without a colon, single-digit fields, embedded whitespace): nothing in
//! this crate ever wrote them.

use std::fmt::Write as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use time::{Date, Month, OffsetDateTime};

const NANOS_PER_SEC: i128 = 1_000_000_000;
const NANOS_PER_MILLI: i128 = 1_000_000;
const NANOS_PER_MICRO: i128 = 1_000;
const NANOS_PER_DAY: i128 = 86_400 * NANOS_PER_SEC;
/// Julian day number of 1970-01-01.
const UNIX_EPOCH_JULIAN_DAY: i128 = 2_440_588;

/// How the UTC offset is written after the time of day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UtcSuffix {
    /// `Z` — the serde encoding of every timestamp field.
    Z,
    /// `+00:00` — the audit-chain hash transcript encoding.
    PlusZero,
}

/// Signed nanoseconds since the Unix epoch.
#[must_use]
pub(crate) fn unix_nanos(t: SystemTime) -> i128 {
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

/// The `SystemTime` that lies `nanos` nanoseconds from the Unix epoch, or
/// `None` when the platform's `SystemTime` cannot represent it.
#[must_use]
pub(crate) fn from_unix_nanos(nanos: i128) -> Option<SystemTime> {
    let secs = nanos.checked_div_euclid(NANOS_PER_SEC)?;
    let subsec = u32::try_from(nanos.checked_rem_euclid(NANOS_PER_SEC)?).ok()?;
    if let Ok(secs) = u64::try_from(secs) {
        UNIX_EPOCH.checked_add(Duration::new(secs, subsec))
    } else {
        let back = Duration::from_secs(u64::try_from(secs.checked_neg()?).ok()?);
        UNIX_EPOCH.checked_sub(back)?.checked_add(Duration::from_nanos(u64::from(subsec)))
    }
}

/// Floor of `t` measured in `unit` nanoseconds since the epoch, saturated to
/// the `i64` range.
fn unix_floor(t: SystemTime, unit: i128) -> i64 {
    let floored = unix_nanos(t).checked_div_euclid(unit).unwrap_or(0);
    i64::try_from(floored).unwrap_or(if floored < 0 { i64::MIN } else { i64::MAX })
}

/// Whole seconds since the Unix epoch, rounded toward negative infinity.
#[must_use]
pub(crate) fn unix_seconds(t: SystemTime) -> i64 {
    unix_floor(t, NANOS_PER_SEC)
}

/// Whole milliseconds since the Unix epoch, rounded toward negative infinity.
#[must_use]
pub(crate) fn unix_millis(t: SystemTime) -> i64 {
    unix_floor(t, NANOS_PER_MILLI)
}

/// Whole microseconds since the Unix epoch, rounded toward negative infinity.
#[must_use]
pub(crate) fn unix_micros(t: SystemTime) -> i64 {
    unix_floor(t, NANOS_PER_MICRO)
}

/// `later - earlier` in whole `unit`s, truncated toward zero and saturated
/// to the `i64` range. Negative when `later` precedes `earlier`.
fn signed_between(earlier: SystemTime, later: SystemTime, unit: i128) -> i64 {
    let diff = unix_nanos(later).saturating_sub(unix_nanos(earlier));
    let units = diff.checked_div(unit).unwrap_or(0);
    i64::try_from(units).unwrap_or(if units < 0 { i64::MIN } else { i64::MAX })
}

/// Milliseconds from `earlier` to `later` (negative if `later` is earlier).
#[must_use]
pub(crate) fn signed_millis_between(earlier: SystemTime, later: SystemTime) -> i64 {
    signed_between(earlier, later, NANOS_PER_MILLI)
}

/// Seconds from `earlier` to `later` (negative if `later` is earlier).
#[must_use]
pub(crate) fn signed_seconds_between(earlier: SystemTime, later: SystemTime) -> i64 {
    signed_between(earlier, later, NANOS_PER_SEC)
}

/// Whole days from `earlier` to `later` (negative if `later` is earlier).
#[must_use]
pub(crate) fn signed_days_between(earlier: SystemTime, later: SystemTime) -> i64 {
    signed_between(earlier, later, NANOS_PER_DAY)
}

/// Milliseconds elapsed from `earlier` to `later`, clamped to zero when
/// `later` precedes `earlier` (clock stepped backwards).
#[must_use]
pub(crate) fn elapsed_millis_saturating(earlier: SystemTime, later: SystemTime) -> u64 {
    u64::try_from(signed_millis_between(earlier, later)).unwrap_or(0)
}

/// UTC calendar fields of `t`, or `None` outside years ±999,999 (the
/// `time` crate's `large-dates` range, which covers every instant chrono
/// could represent).
#[must_use]
pub(crate) fn utc_fields(t: SystemTime) -> Option<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp_nanos(unix_nanos(t)).ok()
}

/// RFC 3339 text for `t` in UTC, or `None` outside years ±999,999.
#[must_use]
pub(crate) fn to_rfc3339(t: SystemTime, suffix: UtcSuffix) -> Option<String> {
    let dt = utc_fields(t)?;
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

/// Human-readable RFC 3339 rendering for log and error messages. Falls
/// back to the `Debug` form for instants outside years ±999,999.
#[must_use]
pub(crate) fn display(t: SystemTime) -> String {
    to_rfc3339(t, UtcSuffix::Z).unwrap_or_else(|| format!("{t:?}"))
}

/// Byte cursor for [`parse_rfc3339`].
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

/// Parse an RFC 3339 timestamp (see the module docs for the accepted
/// forms), or `None` if it is malformed, names an impossible date or time,
/// or is not representable as a `SystemTime`.
#[must_use]
pub(crate) fn parse_rfc3339(text: &str) -> Option<SystemTime> {
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

    let date = Date::from_calendar_date(
        year,
        Month::try_from(u8::try_from(month).ok()?).ok()?,
        u8::try_from(day).ok()?,
    )
    .ok()?;
    let days = i128::from(date.to_julian_day()).checked_sub(UNIX_EPOCH_JULIAN_DAY)?;
    let secs = days
        .checked_mul(86_400)?
        .checked_add(i128::from(hour.checked_mul(3_600)?))?
        .checked_add(i128::from(minute.checked_mul(60)?))?
        .checked_add(i128::from(second))?
        .checked_sub(offset_secs)?;
    from_unix_nanos(secs.checked_mul(NANOS_PER_SEC)?.checked_add(i128::from(nanos))?)
}

/// Serde adapter: a `SystemTime` field encoded as an RFC 3339 string.
pub(crate) mod serde_rfc3339 {
    use std::time::SystemTime;

    use serde::{Deserialize, Deserializer, Serializer, de, ser};

    /// Serialize as RFC 3339 text with a `Z` suffix.
    ///
    /// # Errors
    /// Fails when `t` lies outside years ±999,999.
    pub(crate) fn serialize<S: Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
        let text = super::to_rfc3339(*t, super::UtcSuffix::Z).ok_or_else(|| {
            <S::Error as ser::Error>::custom("timestamp outside the encodable year range")
        })?;
        s.serialize_str(&text)
    }

    /// Deserialize from RFC 3339 text (see the module docs for accepted forms).
    ///
    /// # Errors
    /// Fails when the input is not a valid RFC 3339 timestamp.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SystemTime, D::Error> {
        let text = String::deserialize(d)?;
        super::parse_rfc3339(&text)
            .ok_or_else(|| <D::Error as de::Error>::custom("invalid RFC 3339 timestamp"))
    }
}

/// Serde adapter: an `Option<SystemTime>` field encoded as an RFC 3339
/// string or `null`. Pair it with `#[serde(default)]` so a missing field
/// still deserializes as `None`.
pub(crate) mod serde_rfc3339_option {
    use std::time::SystemTime;

    use serde::{Deserialize, Deserializer, Serializer, de, ser};

    /// Serialize `Some` as RFC 3339 text with a `Z` suffix and `None` as `null`.
    ///
    /// # Errors
    /// Fails when the timestamp lies outside years ±999,999.
    pub(crate) fn serialize<S: Serializer>(
        t: &Option<SystemTime>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match t {
            Some(t) => {
                let text = super::to_rfc3339(*t, super::UtcSuffix::Z).ok_or_else(|| {
                    <S::Error as ser::Error>::custom("timestamp outside the encodable year range")
                })?;
                s.serialize_some(&text)
            }
            None => s.serialize_none(),
        }
    }

    /// Deserialize `null` as `None` and RFC 3339 text as `Some`.
    ///
    /// # Errors
    /// Fails when the input is neither `null` nor a valid RFC 3339 timestamp.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<SystemTime>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|text| {
                super::parse_rfc3339(&text)
                    .ok_or_else(|| <D::Error as de::Error>::custom("invalid RFC 3339 timestamp"))
            })
            .transpose()
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::arithmetic_side_effects, reason = "test scaffolding")]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn at(secs: i64, nanos: u32) -> SystemTime {
        from_unix_nanos(i128::from(secs) * NANOS_PER_SEC + i128::from(nanos)).unwrap()
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

    #[test]
    fn test_to_rfc3339_matches_chrono_golden_succeeds() {
        for &(secs, nanos, plus_zero, z) in CHRONO_GOLDEN {
            let t = at(secs, nanos);
            assert_eq!(to_rfc3339(t, UtcSuffix::PlusZero).as_deref(), Some(plus_zero));
            assert_eq!(to_rfc3339(t, UtcSuffix::Z).as_deref(), Some(z));
        }
    }

    #[test]
    fn test_parse_rfc3339_reads_chrono_golden_succeeds() {
        for &(secs, nanos, plus_zero, z) in CHRONO_GOLDEN {
            assert_eq!(parse_rfc3339(plus_zero), Some(at(secs, nanos)));
            assert_eq!(parse_rfc3339(z), Some(at(secs, nanos)));
        }
    }

    #[test]
    fn test_parse_rfc3339_applies_offset_succeeds() {
        assert_eq!(parse_rfc3339("2023-11-14T23:13:20+01:00"), Some(at(1_700_000_000, 0)));
        assert_eq!(
            parse_rfc3339("2023-11-14T17:13:20.5-05:00"),
            Some(at(1_700_000_000, 500_000_000))
        );
    }

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
    fn test_parse_rfc3339_agrees_with_chrono_succeeds() {
        for &(text, secs, nanos) in CHRONO_ACCEPTED {
            assert_eq!(parse_rfc3339(text), Some(at(secs, nanos)), "{text:?}");
        }
    }

    #[test]
    fn test_parse_rfc3339_rejects_malformed_fails() {
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
            assert_eq!(parse_rfc3339(bad), None, "{bad:?} must not parse");
        }
    }

    #[test]
    fn test_to_rfc3339_before_epoch_succeeds() {
        assert_eq!(
            to_rfc3339(at(-1, 500_000_000), UtcSuffix::Z).as_deref(),
            Some("1969-12-31T23:59:59.500Z")
        );
        assert_eq!(parse_rfc3339("1969-12-31T23:59:59.500Z"), Some(at(-1, 500_000_000)));
    }

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

    #[test]
    fn test_extended_years_match_chrono_golden_succeeds() {
        for &(secs, nanos, plus_zero, z) in CHRONO_EXTENDED_YEARS {
            let t = at(secs, nanos);
            assert_eq!(to_rfc3339(t, UtcSuffix::PlusZero).as_deref(), Some(plus_zero));
            assert_eq!(to_rfc3339(t, UtcSuffix::Z).as_deref(), Some(z));
            assert_eq!(parse_rfc3339(plus_zero), Some(t));
            assert_eq!(parse_rfc3339(z), Some(t));
        }
        // Four-digit boundary years keep the unsigned form.
        assert_eq!(
            to_rfc3339(at(253_402_300_799, 999_999_999), UtcSuffix::Z).as_deref(),
            Some("9999-12-31T23:59:59.999999999Z")
        );
        assert_eq!(
            to_rfc3339(at(-62_167_219_200, 0), UtcSuffix::Z).as_deref(),
            Some("0000-01-01T00:00:00Z")
        );
    }

    #[test]
    fn test_to_rfc3339_beyond_large_date_range_fails() {
        // ~year 1.27 million: representable as a Unix `SystemTime`, beyond
        // the ±999,999-year range the encoder supports.
        assert_eq!(to_rfc3339(at(40_000_000_000_000, 0), UtcSuffix::Z), None);
    }

    #[test]
    fn test_unix_floor_helpers_round_toward_negative_infinity_succeeds() {
        let t = at(1_700_000_000, 123_456_789);
        assert_eq!(unix_seconds(t), 1_700_000_000);
        assert_eq!(unix_millis(t), 1_700_000_000_123);
        assert_eq!(unix_micros(t), 1_700_000_000_123_456);
        let before = at(-1, 500_000_000); // 0.5 s before the epoch
        assert_eq!(unix_seconds(before), -1);
        assert_eq!(unix_millis(before), -500);
        assert_eq!(unix_micros(before), -500_000);
    }

    #[test]
    fn test_signed_between_truncates_toward_zero_succeeds() {
        let a = at(1_000, 0);
        let b = at(1_000 + 2 * 86_400 + 3_600, 999_999_999);
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
    fn test_serde_adapters_roundtrip_and_reject_garbage_succeeds() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Probe {
            #[serde(with = "serde_rfc3339")]
            at: SystemTime,
            #[serde(default, with = "serde_rfc3339_option")]
            maybe: Option<SystemTime>,
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
        let far = Probe { at: at(40_000_000_000_000, 0), maybe: None };
        assert!(serde_json::to_string(&far).is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Every instant chrono could represent survives format → parse
        /// exactly, for both suffixes.
        #[test]
        fn prop_rfc3339_roundtrip_succeeds(
            secs in -8_334_601_228_800i64..=8_210_266_876_799,
            nanos in 0u32..1_000_000_000,
        ) {
            let t = at(secs, nanos);
            for suffix in [UtcSuffix::Z, UtcSuffix::PlusZero] {
                let text = to_rfc3339(t, suffix).unwrap();
                prop_assert_eq!(parse_rfc3339(&text), Some(t));
            }
        }

        /// Cross-validation: within four-digit years, the hand-written
        /// encoder and parser agree with the `time` crate's independent
        /// RFC 3339 parser on every instant.
        #[test]
        fn prop_rfc3339_agrees_with_time_crate_succeeds(
            secs in -62_167_219_200i64..=253_402_300_799,
            nanos in 0u32..1_000_000_000,
            offset_minutes in -1_439i32..=1_439,
        ) {
            use time::format_description::well_known::Rfc3339;
            let t = at(secs, nanos);
            let text = to_rfc3339(t, UtcSuffix::Z).unwrap();
            let reference = OffsetDateTime::parse(&text, &Rfc3339).unwrap();
            prop_assert_eq!(reference.unix_timestamp_nanos(), unix_nanos(t));
            // Same instant written with a non-UTC offset by `time`.
            let offset = time::UtcOffset::from_whole_seconds(offset_minutes * 60).unwrap();
            if let Ok(shifted) = reference.to_offset(offset).format(&Rfc3339) {
                prop_assert_eq!(parse_rfc3339(&shifted), Some(t), "{}", shifted);
            }
        }

        #[test]
        fn prop_unix_nanos_roundtrip_succeeds(nanos in -(1i128 << 90)..(1i128 << 90)) {
            if let Some(t) = from_unix_nanos(nanos) {
                prop_assert_eq!(unix_nanos(t), nanos);
            }
        }
    }
}
