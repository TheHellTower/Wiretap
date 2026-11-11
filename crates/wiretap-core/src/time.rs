//! Wall-clock timestamps.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Microseconds since the Unix epoch (UTC), serialized as a JSON integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(pub i64);

impl Timestamp {
    /// The current wall-clock time, saturating outside the representable range.
    #[must_use]
    pub fn now() -> Self {
        let micros = |d: Duration| i64::try_from(d.as_micros()).unwrap_or(i64::MAX);
        Self(match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => micros(d),
            Err(e) => -micros(e.duration()),
        })
    }
}

impl Timestamp {
    /// Formats as `YYYY-MM-DD HH:MM:SS.mmm` (UTC); valid for every `i64` value.
    #[must_use]
    pub fn utc(self) -> String {
        let millis = self.0.div_euclid(1000);
        let (days, ms) = (millis.div_euclid(86_400_000), millis.rem_euclid(86_400_000));
        // Civil-from-days (H. Hinnant).
        let z = days + 719_468;
        let (era, doe) = (z.div_euclid(146_097), z.rem_euclid(146_097));
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        let (h, m, s, f) = (ms / 3_600_000, ms / 60_000 % 60, ms / 1000 % 60, ms % 1000);
        format!("{year:04}-{month:02}-{day:02} {h:02}:{m:02}:{s:02}.{f:03}")
    }
}
