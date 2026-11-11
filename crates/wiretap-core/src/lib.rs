//! Wiretap core: the unified network event model shared by every subsystem.
//!
//! Every type serializes to a stable, language-neutral JSON shape (snake_case fields,
//! string enums, UUID strings, integer microsecond timestamps) so SDKs in any language
//! can consume it. Data from untrusted sources (imports, API clients, addons) must pass
//! `validate()` before use.
#![forbid(unsafe_code)]

mod id;
mod model;
mod time;
mod validate;

pub use id::{EventId, FlowId, ParseUuidError, PayloadId, RuleId, SessionId, Uuid};
pub use model::{
    CaptureSource, Direction, Endpoint, EventMetadata, Flow, FlowTiming, HttpHeader, HttpRequest,
    HttpResponse, HttpVersion, Inspection, NetworkEvent, PayloadEncryption, PayloadReference,
    ProcessInfo, Protocol, Session,
};
pub use time::Timestamp;
pub use validate::{ModelError, limits};
