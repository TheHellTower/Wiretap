//! Time-ordered unique identifiers (RFC 9562 UUID version 7).

use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::BuildHasher;
use std::str::FromStr;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::Timestamp;

/// A 128-bit UUID, serialized as the canonical hyphenated lowercase string.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Uuid(u128);

/// Per-process random seed, drawn from the OS RNG through std's `RandomState` keys.
static SEED: LazyLock<u64> =
    LazyLock::new(|| RandomState::new().hash_one(0x5749_5245_5441_5000_u64));
static COUNTER: AtomicU64 = AtomicU64::new(0);

impl Uuid {
    /// Generates a version 7 UUID: 48-bit Unix milliseconds, then 74 bits derived from a
    /// per-process random seed plus a counter. IDs are unique within a process (the counter
    /// never repeats), collide across processes with negligible probability, and sort by
    /// creation time. They are not secrets and must never be used as credentials.
    #[must_use]
    pub fn now_v7() -> Self {
        let ms = u128::try_from(Timestamp::now().0 / 1000).unwrap_or(0) & ((1 << 48) - 1);
        let seed = *SEED;
        let seq = seed.wrapping_add(COUNTER.fetch_add(1, Ordering::Relaxed));
        let rand_a = u128::from(seed >> 52);
        let rand_b = u128::from(seq) & ((1 << 62) - 1);
        Self((ms << 80) | (0x7 << 76) | (rand_a << 64) | (0b10 << 62) | rand_b)
    }

    /// Builds a UUID from its 16-byte big-endian representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(u128::from_be_bytes(bytes))
    }

    /// Returns the 16-byte big-endian representation.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0.to_be_bytes()
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = self.0;
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
            v >> 96,
            (v >> 80) & 0xFFFF,
            (v >> 64) & 0xFFFF,
            (v >> 48) & 0xFFFF,
            v & 0xFFFF_FFFF_FFFF
        )
    }
}

impl fmt::Debug for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Error returned when a string is not a hyphenated UUID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseUuidError;

impl fmt::Display for ParseUuidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected a UUID in 8-4-4-4-12 hexadecimal form")
    }
}

impl std::error::Error for ParseUuidError {}

impl FromStr for Uuid {
    type Err = ParseUuidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 36 {
            return Err(ParseUuidError);
        }
        let mut v = 0u128;
        for (i, c) in s.bytes().enumerate() {
            if matches!(i, 8 | 13 | 18 | 23) {
                if c != b'-' {
                    return Err(ParseUuidError);
                }
            } else {
                let digit = char::from(c).to_digit(16).ok_or(ParseUuidError)?;
                v = (v << 4) | u128::from(digit);
            }
        }
        Ok(Self(v))
    }
}

impl Serialize for Uuid {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Uuid {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct UuidVisitor;
        impl Visitor<'_> for UuidVisitor {
            type Value = Uuid;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a hyphenated UUID string")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Uuid, E> {
                v.parse().map_err(E::custom)
            }
        }
        d.deserialize_str(UuidVisitor)
    }
}

/// Declares strongly typed identifiers so IDs of different entities cannot be mixed up.
macro_rules! typed_ids {
    ($($(#[$doc:meta])* $name:ident;)*) => {$(
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            /// Generates a new time-ordered identifier.
            #[must_use]
            pub fn generate() -> Self {
                Self(Uuid::now_v7())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }
    )*};
}

typed_ids! {
    /// Identifies a capture [`Session`](crate::Session).
    SessionId;
    /// Identifies a [`NetworkEvent`](crate::NetworkEvent).
    EventId;
    /// Identifies an HTTP [`Flow`](crate::Flow).
    FlowId;
    /// Identifies stored payload bytes.
    PayloadId;
    /// Identifies an automatic-response rule.
    RuleId;
}
