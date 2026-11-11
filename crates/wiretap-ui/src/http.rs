//! Request routing and authorization for the UI server. Pure (no I/O) so every decision is
//! unit-tested and fuzzed.
//!
//! Rules: the `Host` header must be exactly the server's `127.0.0.1:port` (defeats DNS
//! rebinding); every route except the one-time login needs the session cookie; state-changing
//! requests also need our exact `Origin` (defeats CSRF); the capture feed needs its own key.

use wiretap_core::{FlowId, PayloadId, SessionId, Timestamp, Uuid};
use wiretap_protocol::{Head, StartLine};

/// Name of the session cookie.
pub const COOKIE: &str = "wiretap";
/// Feed acknowledgement header naming the session a capture process records into.
pub const SESSION_HEADER: &str = "X-Wiretap-Session";
/// Feed acknowledgement header `<pid> <port v4> <port v6>`: the proxy that capture redirects
/// outbound HTTP(S) to (port 0: that IP version is not redirected).
pub const PROXY_HEADER: &str = "X-Wiretap-Proxy";

/// Static files embedded in the binary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Asset {
    /// `index.html`.
    Index,
    /// `app.js`.
    Script,
    /// `app.css`.
    Style,
    /// `icon.svg`.
    Icon,
}

impl Asset {
    /// Content and media type.
    #[must_use]
    pub const fn content(self) -> (&'static [u8], &'static str) {
        match self {
            Self::Index => (
                include_bytes!("../web/index.html"),
                "text/html; charset=utf-8",
            ),
            Self::Script => (
                include_bytes!("../web/app.js"),
                "text/javascript; charset=utf-8",
            ),
            Self::Style => (include_bytes!("../web/app.css"), "text/css; charset=utf-8"),
            Self::Icon => (include_bytes!("../web/icon.svg"), "image/svg+xml"),
        }
    }
}

/// Pagination cursor `(timestamp, id)` of the last record already received.
pub type Cursor = Option<(Timestamp, Uuid)>;

/// An authorized request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// `GET /?t=<token>`: sets the cookie and redirects to `/`.
    Login,
    /// A static file.
    Asset(Asset),
    /// `GET /api/state`.
    State,
    /// `GET /api/sessions`.
    Sessions,
    /// `POST /api/sessions/<id>/delete`.
    DeleteSession(SessionId),
    /// `GET /api/sessions/<id>/flows?after=`.
    Flows(SessionId, Cursor),
    /// `GET /api/sessions/<id>/events?after=`.
    Events(SessionId, Cursor),
    /// `GET /api/flows/<id>`.
    Flow(FlowId),
    /// `GET /api/payloads/<id>?coding=`: the stored body, with its content codings (`gzip`,
    /// `br,gzip`...) undone when `coding` is given.
    Payload(PayloadId, Option<String>),
    /// `GET /api/live` (server-sent events).
    Live,
    /// `POST /api/capture/start`.
    CaptureStart,
    /// `POST /api/capture/stop`.
    CaptureStop,
    /// `POST /api/tls/enable`: create and trust the Wiretap root, decrypt HTTPS.
    TlsEnable,
    /// `POST /api/tls/disable`: stop decrypting, untrust the root and delete its keys.
    TlsDisable,
    /// `GET /api/tls/root.cer`: the Wiretap root certificate (DER).
    TlsRoot,
    /// `POST /api/browser`: open a browser that uses the proxy.
    Browser,
    /// `POST /api/prefs` with `{"dev": bool}`: developer mode (diagnostics).
    Prefs,
    /// `GET /api/sessions/<id>/har`: the session as a HAR 1.2 file.
    HarExport(SessionId),
    /// `POST /api/har` with a HAR file: imports it as a new session.
    HarImport,
    /// `GET /api/rules`.
    Rules,
    /// `POST /api/rules` with the full rule list.
    SaveRules,
    /// `POST /api/rules/from-flow` with `{"flow": id}`.
    RuleFromFlow,
    /// `POST /api/rules/test` with `{"rule": .., "session": id}`.
    TestRule,
    /// `POST /internal/feed`: the elevated capture process streams messages.
    Feed,
}

/// Why a request was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// 400.
    BadRequest,
    /// 403.
    Forbidden,
    /// 404.
    NotFound,
    /// 405.
    MethodNotAllowed,
}

impl Reject {
    /// Status code and reason.
    #[must_use]
    pub const fn status(self) -> (u16, &'static str) {
        match self {
            Self::BadRequest => (400, "Bad Request"),
            Self::Forbidden => (403, "Forbidden"),
            Self::NotFound => (404, "Not Found"),
            Self::MethodNotAllowed => (405, "Method Not Allowed"),
        }
    }
}

/// Secrets and identity the router checks against.
#[derive(Clone, Copy, Debug)]
pub struct Auth<'a> {
    /// Expected `Host` header, e.g. `127.0.0.1:49731`.
    pub host: &'a str,
    /// Session token (also the cookie value).
    pub token: &'a str,
    /// Key of the capture process expected to connect, if any.
    pub feed_key: Option<&'a str>,
}

/// Constant-time comparison for secrets.
#[must_use]
pub fn same_secret(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn single<'h>(head: &'h Head, name: &str) -> Result<Option<&'h str>, Reject> {
    let mut values = head
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str());
    let first = values.next();
    if values.next().is_some() {
        Err(Reject::BadRequest)
    } else {
        Ok(first)
    }
}

fn cookie(head: &Head) -> Option<&str> {
    head.headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("cookie"))
        .flat_map(|h| h.value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == COOKIE)
        .map(|(_, value)| value)
}

fn param<'q>(query: &'q str, name: &str) -> Option<&'q str> {
    query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

/// Parses `after=<micros>_<uuid>`.
fn cursor(query: &str) -> Result<Cursor, Reject> {
    let Some(value) = param(query, "after") else {
        return Ok(None);
    };
    let (ts, id) = value.split_once('_').ok_or(Reject::BadRequest)?;
    let ts = ts.parse().map_err(|_| Reject::BadRequest)?;
    let id = id.parse().map_err(|_| Reject::BadRequest)?;
    Ok(Some((Timestamp(ts), id)))
}

/// Parses `coding=<token>[,<token>...]` (lowercase content-coding names).
fn coding(query: &str) -> Result<Option<String>, Reject> {
    let Some(value) = param(query, "coding") else {
        return Ok(None);
    };
    let valid = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b',' || b == b'-');
    if valid {
        Ok(Some(value.to_owned()))
    } else {
        Err(Reject::BadRequest)
    }
}

fn id<T>(s: &str, wrap: fn(Uuid) -> T) -> Result<T, Reject> {
    s.parse().map(wrap).map_err(|_| Reject::NotFound)
}

/// Authorizes and routes one request.
///
/// # Errors
/// The rejection to send.
pub fn route(head: &Head, auth: &Auth<'_>) -> Result<Route, Reject> {
    let StartLine::Request { method, target, .. } = &head.start else {
        return Err(Reject::BadRequest);
    };
    let post = match method.as_str() {
        "GET" => false,
        "POST" => true,
        _ => return Err(Reject::MethodNotAllowed),
    };
    if !single(head, "host")?.is_some_and(|h| h == auth.host) {
        return Err(Reject::Forbidden);
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if !path.starts_with('/') {
        return Err(Reject::BadRequest);
    }
    if path == "/internal/feed" {
        let key = single(head, "authorization")?.and_then(|v| v.strip_prefix("Bearer "));
        return match (post, key, auth.feed_key) {
            (true, Some(given), Some(expected)) if same_secret(given, expected) => Ok(Route::Feed),
            _ => Err(Reject::Forbidden),
        };
    }
    if !post
        && path == "/"
        && let Some(given) = param(query, "t")
    {
        return if same_secret(given, auth.token) {
            Ok(Route::Login)
        } else {
            Err(Reject::Forbidden)
        };
    }
    if !cookie(head).is_some_and(|c| same_secret(c, auth.token)) {
        return Err(Reject::Forbidden);
    }
    if post && single(head, "origin")? != Some(format!("http://{}", auth.host).as_str()) {
        return Err(Reject::Forbidden);
    }
    let segments: Vec<&str> = path.split('/').skip(1).collect();
    let route = match (post, segments.as_slice()) {
        (false, [""]) => Route::Asset(Asset::Index),
        (false, ["app.js"]) => Route::Asset(Asset::Script),
        (false, ["app.css"]) => Route::Asset(Asset::Style),
        (false, ["icon.svg"]) => Route::Asset(Asset::Icon),
        (false, ["api", "state"]) => Route::State,
        (false, ["api", "sessions"]) => Route::Sessions,
        (true, ["api", "sessions", s, "delete"]) => Route::DeleteSession(id(s, SessionId)?),
        (false, ["api", "sessions", s, "flows"]) => Route::Flows(id(s, SessionId)?, cursor(query)?),
        (false, ["api", "sessions", s, "events"]) => {
            Route::Events(id(s, SessionId)?, cursor(query)?)
        }
        (false, ["api", "flows", f]) => Route::Flow(id(f, FlowId)?),
        (false, ["api", "payloads", p]) => Route::Payload(id(p, PayloadId)?, coding(query)?),
        (false, ["api", "live"]) => Route::Live,
        (true, ["api", "capture", "start"]) => Route::CaptureStart,
        (true, ["api", "capture", "stop"]) => Route::CaptureStop,
        (true, ["api", "tls", "enable"]) => Route::TlsEnable,
        (true, ["api", "tls", "disable"]) => Route::TlsDisable,
        (false, ["api", "tls", "root.cer"]) => Route::TlsRoot,
        (true, ["api", "browser"]) => Route::Browser,
        (true, ["api", "prefs"]) => Route::Prefs,
        (false, ["api", "sessions", s, "har"]) => Route::HarExport(id(s, SessionId)?),
        (true, ["api", "har"]) => Route::HarImport,
        (false, ["api", "rules"]) => Route::Rules,
        (true, ["api", "rules"]) => Route::SaveRules,
        (true, ["api", "rules", "from-flow"]) => Route::RuleFromFlow,
        (true, ["api", "rules", "test"]) => Route::TestRule,
        _ => return Err(Reject::NotFound),
    };
    Ok(route)
}

/// Largest request body accepted for `route`.
#[must_use]
pub const fn body_limit(route: &Route) -> usize {
    match route {
        Route::SaveRules | Route::TestRule => 32 << 20,
        Route::HarImport => 128 << 20,
        Route::RuleFromFlow | Route::Prefs => 4096,
        _ => 0,
    }
}
