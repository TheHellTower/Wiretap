//! Request predicates.

use std::borrow::Cow;
use std::cell::OnceCell;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use wiretap_core::HttpHeader;

/// How a text value is compared.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    /// Whole value equals the pattern.
    Equals,
    /// Value contains the pattern.
    Contains,
    /// Value starts with the pattern.
    StartsWith,
    /// Value ends with the pattern.
    EndsWith,
    /// Glob: `*` matches any run of bytes, `?` exactly one byte.
    Wildcard,
}

/// A text comparison (case-insensitive unless `case_sensitive`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Text {
    /// Comparison.
    pub op: Op,
    /// Pattern.
    pub value: String,
    /// Compare case-sensitively.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub case_sensitive: bool,
}

impl Text {
    /// Case-insensitive equality.
    #[must_use]
    pub fn equals(value: impl Into<String>) -> Self {
        Self {
            op: Op::Equals,
            value: value.into(),
            case_sensitive: false,
        }
    }
}

/// A request predicate. Combine with `all` (AND), `any` (OR) and `not`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Condition {
    /// Every condition holds (an empty list always holds).
    All(Vec<Condition>),
    /// At least one condition holds.
    Any(Vec<Condition>),
    /// The condition does not hold.
    Not(Box<Condition>),
    /// Request method.
    Method(Text),
    /// Absolute request URL.
    Url(Text),
    /// Host name (without port).
    Host(Text),
    /// URL path.
    Path(Text),
    /// URL query string (without `?`).
    Query(Text),
    /// A header with this name exists and, if given, one of its values matches.
    Header {
        /// Header name (case-insensitive).
        name: String,
        /// Value test; `None` tests presence only.
        value: Option<Text>,
    },
    /// A cookie with this name exists and, if given, its value matches.
    Cookie {
        /// Cookie name (case-sensitive, as in RFC 6265).
        name: String,
        /// Value test; `None` tests presence only.
        value: Option<Text>,
    },
    /// Request body, as UTF-8 (invalid bytes replaced).
    Body(Text),
    /// `Content-Type` header.
    ContentType(Text),
    /// Client process image name.
    Process(Text),
    /// Client IP address.
    ClientIp(Text),
    /// Server IP address.
    ServerIp(Text),
    /// Server port (URL port or scheme default).
    ServerPort(u16),
}

/// The request being matched.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    /// Method.
    pub method: &'a str,
    /// Absolute URL.
    pub url: &'a str,
    /// Header fields.
    pub headers: &'a [HttpHeader],
    /// Body bytes (may be a truncated prefix).
    pub body: &'a [u8],
    /// Client process image name.
    pub process: Option<&'a str>,
    /// Client address.
    pub client: Option<IpAddr>,
    /// Server address.
    pub server: Option<IpAddr>,
}

/// Bytes of body considered by `Body` conditions.
pub const BODY_MATCH_LIMIT: usize = 1 << 20;

/// URL parts and lazily lower-cased fields, computed once per request.
pub(crate) struct Ctx<'a> {
    pub(crate) req: Request<'a>,
    pub(crate) host: &'a str,
    pub(crate) path: &'a str,
    pub(crate) query: &'a str,
    port: u16,
    body: OnceCell<String>,
}

/// Splits `scheme://[userinfo@]host[:port]/path?query` into host, port (scheme default
/// when absent), path (`/` when empty) and query.
pub fn split_url(url: &str) -> (&str, u16, &str, &str) {
    let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
    let (authority, tail) = rest
        .find(['/', '?', '#'])
        .map_or((rest, ""), |i| rest.split_at(i));
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let (host, port) = match authority.strip_prefix('[') {
        Some(v6) => v6
            .split_once(']')
            .map_or((v6, ""), |(h, p)| (h, p.trim_start_matches(':'))),
        None => authority.split_once(':').unwrap_or((authority, "")),
    };
    let default = if scheme.eq_ignore_ascii_case("https") {
        443
    } else {
        80
    };
    let port = port.parse().unwrap_or(default);
    let tail = tail.split('#').next().unwrap_or("");
    let (path, query) = tail.split_once('?').unwrap_or((tail, ""));
    (host, port, if path.is_empty() { "/" } else { path }, query)
}

impl<'a> Ctx<'a> {
    pub(crate) fn new(req: Request<'a>) -> Self {
        let (host, port, path, query) = split_url(req.url);
        Self {
            req,
            host,
            path,
            query,
            port,
            body: OnceCell::new(),
        }
    }

    fn header<'n>(&self, name: &'n str) -> impl Iterator<Item = &'a str> + use<'a, 'n> {
        let headers: &'a [HttpHeader] = self.req.headers;
        headers
            .iter()
            .filter(move |h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    fn cookie(&self, name: &str) -> Option<&'a str> {
        self.header("cookie")
            .flat_map(|v| v.split(';'))
            .filter_map(|pair| pair.trim().split_once('='))
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v)
    }

    fn body(&self) -> &str {
        self.body.get_or_init(|| {
            let end = self.req.body.len().min(BODY_MATCH_LIMIT);
            String::from_utf8_lossy(self.req.body.get(..end).unwrap_or_default()).into_owned()
        })
    }
}

/// Glob match with `*` and `?`; every step consumes `budget` (false once exhausted).
fn glob(pattern: &[u8], text: &[u8], budget: &mut u64) -> bool {
    let (mut p, mut t, mut star, mut mark) = (0usize, 0usize, None, 0usize);
    while t < text.len() {
        if *budget == 0 {
            return false;
        }
        *budget -= 1;
        match (pattern.get(p), text.get(t)) {
            (Some(b'*'), _) => {
                star = Some(p);
                mark = t;
                p += 1;
            }
            (Some(&c), Some(&b)) if c == b'?' || c == b => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some(s) => {
                    p = s + 1;
                    mark += 1;
                    t = mark;
                }
                None => return false,
            },
        }
    }
    pattern
        .get(p..)
        .unwrap_or_default()
        .iter()
        .all(|&c| c == b'*')
}

impl Condition {
    /// Whether a request to `host` would match, knowing only the host: `Some` when host (or
    /// full-URL) tests alone decide, `None` when other parts of the request decide.
    /// Whether the condition looks at the request body.
    pub(crate) fn uses_body(&self) -> bool {
        match self {
            Self::All(c) | Self::Any(c) => c.iter().any(Self::uses_body),
            Self::Not(c) => c.uses_body(),
            Self::Body(_) => true,
            _ => false,
        }
    }

    pub(crate) fn on_host(&self, host: &str, budget: &mut u64) -> Option<bool> {
        match self {
            // One definite miss decides an AND; one definite hit decides an OR.
            Self::All(c) => {
                let mut all = Some(true);
                for v in c.iter().map(|c| c.on_host(host, budget)) {
                    match v {
                        Some(false) => return Some(false),
                        None => all = None,
                        Some(true) => {}
                    }
                }
                all
            }
            Self::Any(c) => {
                let mut any = Some(false);
                for v in c.iter().map(|c| c.on_host(host, budget)) {
                    match v {
                        Some(true) => return Some(true),
                        None => any = None,
                        Some(false) => {}
                    }
                }
                any
            }
            Self::Not(c) => c.on_host(host, budget).map(|v| !v),
            Self::Host(t) => Some(t.matches(host, budget)),
            // An exact or prefix URL naming another host can never match.
            Self::Url(t)
                if matches!(t.op, Op::Equals | Op::StartsWith) && t.value.contains("://") =>
            {
                let (named, ..) = split_url(&t.value);
                (!named.eq_ignore_ascii_case(host)).then_some(false)
            }
            _ => None,
        }
    }
}

impl Text {
    pub(crate) fn matches(&self, value: &str, budget: &mut u64) -> bool {
        let (v, pat): (Cow<'_, str>, Cow<'_, str>) = if self.case_sensitive {
            (value.into(), self.value.as_str().into())
        } else {
            (
                value.to_lowercase().into(),
                self.value.to_lowercase().into(),
            )
        };
        match self.op {
            Op::Equals => v == pat,
            Op::Contains => v.contains(pat.as_ref()),
            Op::StartsWith => v.starts_with(pat.as_ref()),
            Op::EndsWith => v.ends_with(pat.as_ref()),
            Op::Wildcard => glob(pat.as_bytes(), v.as_bytes(), budget),
        }
    }
}

impl Condition {
    pub(crate) fn eval(&self, cx: &Ctx<'_>, budget: &mut u64) -> bool {
        let ip = |a: Option<IpAddr>, t: &Text, b: &mut u64| {
            a.is_some_and(|a| t.matches(&a.to_string(), b))
        };
        match self {
            Self::All(list) => list.iter().all(|c| c.eval(cx, budget)),
            Self::Any(list) => list.iter().any(|c| c.eval(cx, budget)),
            Self::Not(c) => !c.eval(cx, budget),
            Self::Method(t) => t.matches(cx.req.method, budget),
            Self::Url(t) => t.matches(cx.req.url, budget),
            Self::Host(t) => t.matches(cx.host, budget),
            Self::Path(t) => t.matches(cx.path, budget),
            Self::Query(t) => t.matches(cx.query, budget),
            Self::Header { name, value } => {
                let mut values = cx.header(name);
                match value {
                    None => values.next().is_some(),
                    Some(t) => values.any(|v| t.matches(v, budget)),
                }
            }
            Self::Cookie { name, value } => cx
                .cookie(name)
                .is_some_and(|v| value.as_ref().is_none_or(|t| t.matches(v, budget))),
            Self::Body(t) => t.matches(cx.body(), budget),
            Self::ContentType(t) => cx
                .header("content-type")
                .next()
                .is_some_and(|v| t.matches(v, budget)),
            Self::Process(t) => cx.req.process.is_some_and(|p| t.matches(p, budget)),
            Self::ClientIp(t) => ip(cx.req.client, t, budget),
            Self::ServerIp(t) => ip(cx.req.server, t, budget),
            Self::ServerPort(port) => cx.port == *port,
        }
    }

    /// Node count and depth, for validation.
    pub(crate) fn size(&self) -> (usize, usize) {
        match self {
            Self::All(list) | Self::Any(list) => list.iter().fold((1, 1), |(n, d), c| {
                let (cn, cd) = c.size();
                (n.saturating_add(cn), d.max(cd + 1))
            }),
            Self::Not(c) => {
                let (n, d) = c.size();
                (n.saturating_add(1), d + 1)
            }
            _ => (1, 1),
        }
    }

    /// Visits every text pattern and name, for validation.
    pub(crate) fn texts(&self, visit: &mut dyn FnMut(Option<&str>, Option<&Text>)) {
        match self {
            Self::All(list) | Self::Any(list) => list.iter().for_each(|c| c.texts(visit)),
            Self::Not(c) => c.texts(visit),
            Self::Method(t)
            | Self::Url(t)
            | Self::Host(t)
            | Self::Path(t)
            | Self::Query(t)
            | Self::Body(t)
            | Self::ContentType(t)
            | Self::Process(t)
            | Self::ClientIp(t)
            | Self::ServerIp(t) => visit(None, Some(t)),
            Self::Header { name, value } | Self::Cookie { name, value } => {
                visit(Some(name), value.as_ref())
            }
            Self::ServerPort(_) => {}
        }
    }
}
