//! The Wiretap app.
//!
//! A loopback-only web server (unelevated) serves the embedded UI to Wiretap's own native
//! window (WebView2 with every browser feature off, InPrivate, no browser profile). Access requires a per-run random token exchanged for an `HttpOnly`,
//! `SameSite=Strict` cookie; the `Host` header is pinned and state-changing requests must
//! carry our `Origin`. Captured data is rendered with DOM text APIs only and a strict CSP, so
//! hostile traffic cannot script the UI.
//!
//! Captures run in a separate elevated process started through UAC, which streams validated
//! [`message::Message`]s back over a keyed loopback feed and stops (unloading the driver) the
//! moment the feed closes. The always-on HTTP proxy (automatic responses, optional HTTPS
//! decryption with the Wiretap root CA) runs in-process.

mod har;
#[cfg(windows)]
mod launch;
#[cfg(windows)]
mod redirect;
mod server;
#[cfg(windows)]
mod tls;
#[cfg(windows)]
mod window;

pub mod http;
pub mod message;

pub use server::{Config, PROXY_PORT, Running, run, start};

#[cfg(test)]
mod tests;
