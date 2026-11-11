//! Live messages: streamed by the elevated capture process to the UI server, and by the UI
//! server to the browser (as server-sent events). One JSON object per line, externally
//! tagged: `{"session": ..}`, `{"event": ..}`, `{"flow": ..}`, `{"stats": ..}`.

use serde::{Deserialize, Serialize};
use wiretap_core::{Flow, ModelError, NetworkEvent, Session};

/// Capture counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stats {
    /// Observations so far.
    pub observations: u64,
    /// Records the driver dropped (ring full).
    pub dropped: u64,
    /// Outputs rejected by validation.
    pub rejected: u64,
}

/// One live message.
#[allow(
    clippy::large_enum_variant,
    reason = "short-lived; boxing would add an allocation per message"
)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Message {
    /// The capture session that the following messages belong to.
    Session(Session),
    /// A connection or TLS event.
    Event(NetworkEvent),
    /// An HTTP flow (new, or updated with its response).
    Flow(Flow),
    /// Counters (also a heartbeat).
    Stats(Stats),
}

impl Message {
    /// Validates the model data inside (messages cross a process boundary).
    ///
    /// # Errors
    /// The first violated model rule.
    pub fn validate(&self) -> Result<(), ModelError> {
        match self {
            Self::Session(s) => s.validate(),
            Self::Event(e) => e.validate(),
            Self::Flow(f) => f.validate(),
            Self::Stats(_) => Ok(()),
        }
    }
}
