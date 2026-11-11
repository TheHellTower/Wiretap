//! Response templates and their HTTP/1.1 serialization.

use serde::{Deserialize, Serialize};
use wiretap_core::{HttpHeader, HttpResponse};

use crate::base64;
use crate::condition::Ctx;

/// Header names the template may not set: Wiretap frames the response itself.
pub(crate) const FRAMING_HEADERS: [&str; 8] = [
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "proxy-connection",
    "te",
    "trailer",
];

/// Response body of a template.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Body {
    /// No body.
    Empty,
    /// UTF-8 text; `{{request.*}}` variables are substituted.
    Text {
        /// Text.
        text: String,
    },
    /// Binary data, base64-encoded (no substitution).
    Base64 {
        /// Standard base64 with padding.
        data: String,
    },
}

/// The response sent when a rule matches.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseTemplate {
    /// Status code (200-999).
    pub status: u16,
    /// Reason phrase.
    pub reason: String,
    /// Header fields, in order. Values may use `{{request.*}}` variables.
    pub headers: Vec<HttpHeader>,
    /// Body.
    pub body: Body,
    /// Delay before responding, in milliseconds.
    #[serde(default)]
    pub delay_ms: u32,
}

/// A rendered response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rendered {
    /// Status code.
    pub status: u16,
    /// Reason phrase.
    pub reason: String,
    /// Header fields (without framing headers).
    pub headers: Vec<HttpHeader>,
    /// Body bytes.
    pub body: Vec<u8>,
}

impl ResponseTemplate {
    /// `200 OK` with an empty body.
    #[must_use]
    pub fn ok() -> Self {
        Self {
            status: 200,
            reason: "OK".into(),
            headers: Vec::new(),
            body: Body::Empty,
            delay_ms: 0,
        }
    }

    /// Starts from a captured response: same status, reason, headers (minus framing headers)
    /// and body. Text bodies stay editable as text; anything else is kept as base64.
    #[must_use]
    pub fn from_original(response: &HttpResponse, body: Option<&[u8]>) -> Self {
        let headers = response
            .headers
            .iter()
            .filter(|h| {
                !FRAMING_HEADERS
                    .iter()
                    .any(|f| h.name.eq_ignore_ascii_case(f))
            })
            .cloned()
            .collect();
        let body = match body {
            None | Some([]) => Body::Empty,
            Some(bytes) => match std::str::from_utf8(bytes) {
                Ok(text) if !text.contains('\0') => Body::Text {
                    text: text.to_owned(),
                },
                _ => Body::Base64 {
                    data: base64::encode(bytes),
                },
            },
        };
        let reason = if response.reason.is_empty() {
            "OK".into()
        } else {
            response.reason.clone()
        };
        Self {
            status: response.status,
            reason,
            headers,
            body,
            delay_ms: 0,
        }
    }

    pub(crate) fn render(&self, cx: &Ctx<'_>) -> Rendered {
        let headers = self
            .headers
            .iter()
            .map(|h| HttpHeader {
                name: h.name.clone(),
                value: sanitize(&substitute(&h.value, cx), MAX_HEADER_VALUE),
            })
            .collect();
        let body = match &self.body {
            Body::Empty => Vec::new(),
            Body::Text { text } => substitute(text, cx).into_bytes(),
            Body::Base64 { data } => base64::decode(data).unwrap_or_default(),
        };
        let body = if cx.req.method.eq_ignore_ascii_case("HEAD") {
            Vec::new()
        } else {
            body
        };
        Rendered {
            status: self.status,
            reason: self.reason.clone(),
            headers,
            body,
        }
    }
}

/// Longest header value after substitution.
pub(crate) const MAX_HEADER_VALUE: usize = 8 * 1024;
/// Longest text body after substitution.
pub(crate) const MAX_BODY: usize = 16 << 20;

/// Replaces `{{request.method|url|host|path|query|body}}` and `{{request.header.NAME}}`.
/// Unknown variables are kept verbatim; output is bounded by [`MAX_BODY`].
fn substitute(template: &str, cx: &Ctx<'_>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let (before, tail) = rest.split_at(start);
        out.push_str(before);
        let Some(end) = tail.find("}}") else {
            out.push_str(tail);
            return out;
        };
        let name = tail.get(2..end).unwrap_or("").trim();
        let value = match name {
            "request.method" => Some(cx.req.method),
            "request.url" => Some(cx.req.url),
            "request.host" => Some(cx.host),
            "request.path" => Some(cx.path),
            "request.query" => Some(cx.query),
            "request.body" => std::str::from_utf8(cx.req.body).ok(),
            _ => name.strip_prefix("request.header.").map(|h| {
                cx.req
                    .headers
                    .iter()
                    .find(|x| x.name.eq_ignore_ascii_case(h))
                    .map_or("", |x| x.value.as_str())
            }),
        };
        match value {
            Some(v) => out.push_str(v),
            None => out.push_str(tail.get(..end + 2).unwrap_or("")),
        }
        if out.len() > MAX_BODY {
            out.truncate(out.floor_char_boundary(MAX_BODY));
            return out;
        }
        rest = tail.get(end + 2..).unwrap_or("");
    }
    out.push_str(rest);
    out
}

/// Removes control characters (except tab) so substituted values cannot inject headers.
fn sanitize(value: &str, max: usize) -> String {
    let mut v: String = value
        .chars()
        .filter(|c| !c.is_control() || *c == '\t')
        .collect();
    v.truncate(v.floor_char_boundary(max));
    v
}

impl Rendered {
    /// Serializes as an HTTP/1.1 response with `Content-Length` (and `Connection: close` with
    /// `close`; otherwise the connection stays open for the client's next request).
    #[must_use]
    pub fn to_bytes(&self, head_only: bool, close: bool) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {} {}\r\n", self.status, self.reason).into_bytes();
        for h in &self.headers {
            out.extend_from_slice(format!("{}: {}\r\n", h.name, h.value).as_bytes());
        }
        let connection = if close { "Connection: close\r\n" } else { "" };
        out.extend_from_slice(
            format!("Content-Length: {}\r\n{connection}\r\n", self.body.len()).as_bytes(),
        );
        if !head_only {
            out.extend_from_slice(&self.body);
        }
        out
    }

    /// The response as model data (for recording the flow).
    #[must_use]
    pub fn to_model(&self) -> HttpResponse {
        let mut headers = self.headers.clone();
        headers.push(HttpHeader {
            name: "Content-Length".into(),
            value: self.body.len().to_string(),
        });
        HttpResponse {
            status: self.status,
            reason: self.reason.clone(),
            version: wiretap_core::HttpVersion::Http11,
            headers,
            body: None,
        }
    }
}
