// SPDX-License-Identifier: MIT OR Apache-2.0
//! Timestamp utilities for ASTRA_.
//!
//! Provides a `Timestamp` newtype wrapping `DateTime<Utc>` with convenience
//! methods for common temporal operations.
//!
//! # Example
//!
//! ```
//! use astra_types::Timestamp;
//!
//! let ts = Timestamp::now();
//! assert!(!ts.is_future());
//! println!("Current time: {}", ts);
//! ```

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// UTC timestamp with convenience methods.
///
/// Wraps `DateTime<Utc>` to provide a consistent timestamp type throughout
/// ASTRA_ with useful helper methods for temporal comparisons.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(DateTime<Utc>);

impl Timestamp {
    /// Create a timestamp for the current moment.
    pub fn now() -> Self {
        Self(Utc::now())
    }

    /// Create a timestamp from Unix milliseconds.
    ///
    /// Returns `None` if the value is out of range for a valid timestamp.
    pub fn from_millis(millis: i64) -> Option<Self> {
        DateTime::from_timestamp_millis(millis).map(Self)
    }

    /// Convert to Unix milliseconds.
    pub fn as_millis(&self) -> i64 {
        self.0.timestamp_millis()
    }

    /// Check if this timestamp is in the past (before now).
    pub fn is_past(&self) -> bool {
        self.0 < Utc::now()
    }

    /// Check if this timestamp is in the future (after now).
    pub fn is_future(&self) -> bool {
        self.0 > Utc::now()
    }

    /// Duration elapsed since this timestamp.
    ///
    /// Returns `TimeDelta::zero()` if the timestamp is in the future.
    pub fn elapsed(&self) -> TimeDelta {
        let now = Utc::now();
        if self.0 < now {
            now - self.0
        } else {
            TimeDelta::zero()
        }
    }

    /// Access the inner `DateTime<Utc>`.
    pub fn inner(&self) -> &DateTime<Utc> {
        &self.0
    }

    /// Consume and return the inner `DateTime<Utc>`.
    pub fn into_inner(self) -> DateTime<Utc> {
        self.0
    }
}

impl Default for Timestamp {
    fn default() -> Self {
        Self::now()
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // ISO 8601 format: "2026-02-03T12:34:56Z"
        write!(f, "{}", self.0.format("%Y-%m-%dT%H:%M:%SZ"))
    }
}

impl From<DateTime<Utc>> for Timestamp {
    fn from(dt: DateTime<Utc>) -> Self {
        Self(dt)
    }
}

impl From<Timestamp> for DateTime<Utc> {
    fn from(ts: Timestamp) -> Self {
        ts.0
    }
}

impl AsRef<DateTime<Utc>> for Timestamp {
    fn as_ref(&self) -> &DateTime<Utc> {
        &self.0
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn now_creates_current_time() {
        let before = Utc::now();
        let ts = Timestamp::now();
        let after = Utc::now();

        assert!(*ts.inner() >= before);
        assert!(*ts.inner() <= after);
    }

    #[test]
    fn from_millis_valid() {
        let millis: i64 = 1_704_067_200_000; // 2024-01-01 00:00:00 UTC
        let Some(ts) = Timestamp::from_millis(millis) else {
            panic!("valid millis should create timestamp");
        };
        assert_eq!(ts.as_millis(), millis);
    }

    #[test]
    fn from_millis_roundtrip() {
        let original = Timestamp::now();
        let millis = original.as_millis();
        let Some(recovered) = Timestamp::from_millis(millis) else {
            panic!("roundtrip should succeed");
        };
        // Within 1ms tolerance due to truncation
        assert!((original.as_millis() - recovered.as_millis()).abs() <= 1);
    }

    #[test]
    fn is_past_for_old_timestamp() {
        let past = Utc::now() - Duration::hours(1);
        let ts = Timestamp::from(past);
        assert!(ts.is_past());
        assert!(!ts.is_future());
    }

    #[test]
    fn is_future_for_upcoming_timestamp() {
        let future = Utc::now() + Duration::hours(1);
        let ts = Timestamp::from(future);
        assert!(ts.is_future());
        assert!(!ts.is_past());
    }

    #[test]
    fn elapsed_returns_positive_for_past() {
        let past = Utc::now() - Duration::seconds(10);
        let ts = Timestamp::from(past);
        let elapsed = ts.elapsed();
        // Should be approximately 10 seconds (allow some tolerance)
        assert!(elapsed.num_seconds() >= 9);
        assert!(elapsed.num_seconds() <= 11);
    }

    #[test]
    fn elapsed_returns_zero_for_future() {
        let future = Utc::now() + Duration::hours(1);
        let ts = Timestamp::from(future);
        let elapsed = ts.elapsed();
        assert_eq!(elapsed, TimeDelta::zero());
    }

    #[test]
    fn display_is_iso8601() {
        let millis: i64 = 1_704_067_200_000; // 2024-01-01 00:00:00 UTC
        let Some(ts) = Timestamp::from_millis(millis) else {
            panic!("valid millis should create timestamp");
        };
        assert_eq!(ts.to_string(), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn serialization_roundtrip() {
        let ts = Timestamp::now();
        let Ok(json) = serde_json::to_string(&ts) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<Timestamp>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(ts, decoded);
    }

    #[test]
    fn default_is_now() {
        let before = Utc::now();
        let ts = Timestamp::default();
        let after = Utc::now();

        assert!(*ts.inner() >= before);
        assert!(*ts.inner() <= after);
    }

    #[test]
    fn ordering_works() {
        let ts1 = Timestamp::from(Utc::now() - Duration::hours(1));
        let ts2 = Timestamp::now();
        let ts3 = Timestamp::from(Utc::now() + Duration::hours(1));

        assert!(ts1 < ts2);
        assert!(ts2 < ts3);
        assert!(ts1 < ts3);
    }

    #[test]
    fn into_inner_works() {
        let dt = Utc::now();
        let ts = Timestamp::from(dt);
        let recovered: DateTime<Utc> = ts.into();
        assert_eq!(recovered, dt);
    }

    #[test]
    fn as_ref_works() {
        let ts = Timestamp::now();
        let dt_ref: &DateTime<Utc> = ts.as_ref();
        assert_eq!(dt_ref, ts.inner());
    }
}
