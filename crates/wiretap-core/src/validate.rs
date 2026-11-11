//! Validation of model data from untrusted sources (imports, API clients, addons, storage).
//!
//! Guarantees after a successful `validate()`:
//! * every collection and string is bounded by [`limits`];
//! * no string contains control characters (header values and reason phrases may contain
//!   tabs), so values cannot inject CR/LF into re-serialized HTTP or escape sequences into
//!   terminals;
//! * HTTP methods and header names are RFC 9110 tokens;
//! * encrypted traffic is never labelled as decrypted unless the source could intercept it.

use std::fmt;

use crate::CaptureSource;
use crate::model::{
    Flow, HttpHeader, Inspection, NetworkEvent, PayloadEncryption, PayloadReference, ProcessInfo,
    Session,
};

/// Upper bounds enforced by validation.
pub mod limits {
    /// Maximum bytes in a URL.
    pub const URL: usize = 64 * 1024;
    /// Maximum bytes in any other free-text field.
    pub const TEXT: usize = 32 * 1024;
    /// Maximum bytes in a short label (session name, tag, attribute key).
    pub const LABEL: usize = 256;
    /// Maximum header fields per HTTP message.
    pub const HEADERS: usize = 512;
    /// Maximum total header name and value bytes per HTTP message.
    pub const HEADER_BYTES: usize = 256 * 1024;
    /// Maximum tags per flow.
    pub const TAGS: usize = 64;
    /// Maximum attributes per event.
    pub const ATTRIBUTES: usize = 128;
}

/// Why model data was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelError {
    /// Offending field.
    pub field: &'static str,
    /// Violated rule.
    pub reason: &'static str,
}

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid {}: {}", self.field, self.reason)
    }
}

impl std::error::Error for ModelError {}

fn check(ok: bool, field: &'static str, reason: &'static str) -> Result<(), ModelError> {
    if ok {
        Ok(())
    } else {
        Err(ModelError { field, reason })
    }
}

/// Bounded text without control characters.
fn text(s: &str, max: usize, field: &'static str) -> Result<(), ModelError> {
    check(s.len() <= max, field, "too long")?;
    check(
        !s.chars().any(char::is_control),
        field,
        "contains control characters",
    )
}

/// Non-empty bounded label without control characters.
fn label(s: &str, field: &'static str) -> Result<(), ModelError> {
    check(!s.is_empty(), field, "empty")?;
    text(s, limits::LABEL, field)
}

/// HTTP field value or reason phrase: tabs allowed, other control characters rejected.
fn field_value(s: &str, field: &'static str) -> Result<(), ModelError> {
    check(
        !s.chars().any(|c| c.is_control() && c != '\t'),
        field,
        "contains control characters",
    )
}

/// RFC 9110 token (`tchar`).
fn token(s: &str, field: &'static str) -> Result<(), ModelError> {
    let tchar = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
    check(
        !s.is_empty() && s.len() <= limits::LABEL && s.bytes().all(tchar),
        field,
        "not a token",
    )
}

fn headers(list: &[HttpHeader], field: &'static str) -> Result<(), ModelError> {
    check(list.len() <= limits::HEADERS, field, "too many")?;
    let mut total = 0usize;
    for h in list {
        token(&h.name, field)?;
        field_value(&h.value, field)?;
        total = total
            .saturating_add(h.name.len())
            .saturating_add(h.value.len());
    }
    check(total <= limits::HEADER_BYTES, field, "too large")
}

fn body(
    p: Option<&PayloadReference>,
    source: CaptureSource,
    field: &'static str,
) -> Result<(), ModelError> {
    let Some(p) = p else { return Ok(()) };
    p.validate()?;
    match p.encryption {
        PayloadEncryption::Cleartext => Ok(()),
        PayloadEncryption::Encrypted => Err(ModelError {
            field,
            reason: "HTTP bodies cannot be ciphertext",
        }),
        PayloadEncryption::Decrypted => check(
            source.can_carry_decrypted(),
            field,
            "source cannot provide decrypted content",
        ),
    }
}

impl Session {
    /// Validates bounds and character rules.
    ///
    /// # Errors
    /// Returns the first violated rule.
    pub fn validate(&self) -> Result<(), ModelError> {
        label(&self.name, "session.name")
    }
}

impl ProcessInfo {
    /// Validates bounds and character rules.
    ///
    /// # Errors
    /// Returns the first violated rule.
    pub fn validate(&self) -> Result<(), ModelError> {
        if let Some(name) = &self.name {
            text(name, limits::TEXT, "process.name")?;
        }
        if let Some(path) = &self.path {
            text(path, limits::TEXT, "process.path")?;
        }
        Ok(())
    }
}

impl PayloadReference {
    /// Validates that the stored length does not exceed the wire length.
    ///
    /// # Errors
    /// Returns the violated rule.
    pub fn validate(&self) -> Result<(), ModelError> {
        check(
            self.stored <= self.size,
            "payload.stored",
            "exceeds payload size",
        )
    }
}

impl NetworkEvent {
    /// Validates bounds, character rules and inspection honesty.
    ///
    /// # Errors
    /// Returns the first violated rule.
    pub fn validate(&self) -> Result<(), ModelError> {
        if let Some(p) = &self.process {
            p.validate()?;
        }
        let meta = &self.metadata;
        check(
            meta.attributes.len() <= limits::ATTRIBUTES,
            "metadata.attributes",
            "too many",
        )?;
        for (key, value) in &meta.attributes {
            label(key, "metadata.attributes")?;
            text(value, limits::TEXT, "metadata.attributes")?;
        }
        if meta.inspection == Inspection::Intercepted {
            check(
                self.source.can_carry_decrypted(),
                "metadata.inspection",
                "source cannot intercept",
            )?;
        }
        if let Some(p) = &self.payload {
            p.validate()?;
            match p.encryption {
                PayloadEncryption::Cleartext => {}
                PayloadEncryption::Encrypted => check(
                    !matches!(
                        meta.inspection,
                        Inspection::Plaintext | Inspection::Intercepted
                    ),
                    "payload.encryption",
                    "ciphertext cannot be plaintext-inspected",
                )?,
                PayloadEncryption::Decrypted => check(
                    meta.inspection == Inspection::Intercepted,
                    "payload.encryption",
                    "decrypted payload requires interception",
                )?,
            }
        }
        Ok(())
    }
}

impl Flow {
    /// Validates bounds, character rules, HTTP syntax and inspection honesty.
    ///
    /// # Errors
    /// Returns the first violated rule.
    pub fn validate(&self) -> Result<(), ModelError> {
        if let Some(p) = &self.process {
            p.validate()?;
        }
        check(self.tags.len() <= limits::TAGS, "tags", "too many")?;
        for tag in &self.tags {
            label(tag, "tags")?;
        }
        let t = &self.timing;
        for ts in [t.request_complete, t.response_started, t.response_complete]
            .into_iter()
            .flatten()
        {
            check(ts >= t.started, "timing", "precedes flow start")?;
        }
        if let Some(r) = &self.request {
            token(&r.method, "request.method")?;
            check(!r.url.is_empty(), "request.url", "empty")?;
            text(&r.url, limits::URL, "request.url")?;
            headers(&r.headers, "request.headers")?;
            body(r.body.as_ref(), self.source, "request.body")?;
        }
        if let Some(r) = &self.response {
            check(
                (100..=999).contains(&r.status),
                "response.status",
                "not a three-digit code",
            )?;
            check(
                r.reason.len() <= limits::LABEL,
                "response.reason",
                "too long",
            )?;
            field_value(&r.reason, "response.reason")?;
            headers(&r.headers, "response.headers")?;
            body(r.body.as_ref(), self.source, "response.body")?;
        }
        Ok(())
    }
}
