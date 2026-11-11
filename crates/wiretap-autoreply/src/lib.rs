//! Rules for matching HTTP requests: *redirects* send them to another server, *automatic
//! responses* answer them without contacting any server.
//!
//! A [`RuleSet`] is an ordered list and every request gets at most one outcome
//! ([`RuleSet::decide`]): the first enabled matching redirect, else the first enabled
//! matching automatic response, else none (the request goes to its server). Rules can be
//! grouped, and groups are shared as files. Rules are plain, language-neutral JSON data and are fully validated
//! when a set is built (bounded sizes and condition trees, safe header names and values).
//! Evaluation is bounded as well: wildcard comparisons draw from a per-request step budget.
//! Templates can only reference fixed `{{request.*}}` variables; they cannot run code or reach
//! files or the network. A rule created from a captured flow starts from the original response.
#![forbid(unsafe_code)]

pub mod base64;
mod condition;
mod template;

use std::fmt;

use serde::{Deserialize, Serialize};
use wiretap_core::{Flow, RuleId};

pub use condition::{BODY_MATCH_LIMIT, Condition, Op, Request, Text, split_url};
pub use template::{Body, Rendered, ResponseTemplate};

use condition::Ctx;
use template::{FRAMING_HEADERS, MAX_BODY, MAX_HEADER_VALUE};

/// Limits enforced by [`RuleSet::new`].
pub mod limits {
    /// Rules per set.
    pub const RULES: usize = 1000;
    /// Condition nodes per rule.
    pub const NODES: usize = 64;
    /// Condition nesting depth.
    pub const DEPTH: usize = 8;
    /// Bytes per pattern.
    pub const PATTERN: usize = 4096;
    /// Response headers per template.
    pub const HEADERS: usize = 100;
    /// Response delay, in milliseconds.
    pub const DELAY_MS: u32 = 60_000;
    /// Wildcard steps per request across all rules.
    pub const STEPS: u64 = 10_000_000;
}

/// One automatic-response rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Identifier.
    pub id: RuleId,
    /// Display name.
    pub name: String,
    /// Whether the rule is active.
    pub enabled: bool,
    /// When to answer.
    pub condition: Condition,
    /// What to answer (automatic responses; ignored by redirects).
    #[serde(default = "ResponseTemplate::ok")]
    pub response: ResponseTemplate,
    /// Group the rule belongs to (enabled, shared and exported together); empty for none.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub group: String,
    /// Sends matching requests to another server instead of answering them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect: Option<Redirect>,
}

/// Where a redirect rule sends matching requests. `to` replaces scheme, host and port (and
/// prefixes the path when it has one); the request's path and query are kept.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Redirect {
    /// Absolute `http://` or `https://` base URL, e.g. `http://localhost:3000`.
    pub to: String,
    /// Keep the original `Host` header (by default the target's host is sent).
    #[serde(default)]
    pub keep_host: bool,
}

impl Redirect {
    /// The URL a request to `url` is sent to.
    #[must_use]
    pub fn target(&self, url: &str) -> String {
        let (_, _, path, query) = split_url(url);
        let base = self.to.trim_end_matches('/');
        if query.is_empty() {
            format!("{base}{path}")
        } else {
            format!("{base}{path}?{query}")
        }
    }

    fn validate(&self) -> Result<(), &'static str> {
        let to = self.to.as_str();
        let scheme_ok = ["http://", "https://"]
            .iter()
            .any(|s| to.get(..s.len()).is_some_and(|p| p.eq_ignore_ascii_case(s)));
        let (host, ..) = split_url(to);
        let authority = to
            .split_once("://")
            .map_or("", |(_, rest)| rest.split('/').next().unwrap_or(""));
        let port_ok = authority
            .rsplit_once(':')
            .filter(|_| !authority.ends_with(']'))
            .is_none_or(|(_, p)| p.parse::<u16>().is_ok_and(|p| p != 0));
        if !scheme_ok
            || to.len() > 2048
            || host.is_empty()
            || !port_ok
            || to
                .bytes()
                .any(|b| b <= b' ' || b == 0x7F || b"?#@\\\"<>".contains(&b))
        {
            return Err(
                "redirects need an http:// or https:// base URL (no query, credentials or spaces)",
            );
        }
        Ok(())
    }
}

/// What to do with a request (see [`RuleSet::decide`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision<'a> {
    /// Send it to another server.
    Redirect {
        /// The rule that matched.
        rule: &'a Rule,
        /// The URL to send it to.
        url: String,
    },
    /// Answer it without contacting any server.
    Reply(Reply<'a>),
}

/// Why a rule set was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleError {
    /// Index of the offending rule.
    pub rule: usize,
    /// Violated constraint.
    pub reason: &'static str,
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rule #{}: {}", self.rule + 1, self.reason)
    }
}

impl std::error::Error for RuleError {}

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn no_controls(s: &str) -> bool {
    !s.chars().any(|c| c.is_control() && c != '\t')
}

impl Rule {
    /// Creates a rule answering this exact method and URL with the flow's original response
    /// (status, reason, headers and `response_body`), or `200 OK` if none was captured.
    #[must_use]
    pub fn from_flow(flow: &Flow, response_body: Option<&[u8]>) -> Option<Self> {
        let request = flow.request.as_ref()?;
        let response = flow
            .response
            .as_ref()
            .map_or_else(ResponseTemplate::ok, |r| {
                ResponseTemplate::from_original(r, response_body)
            });
        let mut name = format!("{} {}", request.method, request.url);
        name.truncate(name.floor_char_boundary(200));
        Some(Self {
            id: RuleId::generate(),
            name,
            enabled: true,
            group: String::new(),
            redirect: None,
            condition: Condition::All(vec![
                Condition::Method(Text::equals(&request.method)),
                Condition::Url(Text {
                    case_sensitive: true,
                    ..Text::equals(&request.url)
                }),
            ]),
            response,
        })
    }

    fn validate(&self) -> Result<(), &'static str> {
        if self.name.is_empty() || self.name.len() > 256 || !no_controls(&self.name) {
            return Err("name must be 1-256 characters without control characters");
        }
        if self.group.len() > 128 || !no_controls(&self.group) {
            return Err("group names must be at most 128 characters without control characters");
        }
        if let Some(r) = &self.redirect {
            r.validate()?;
        }
        let (nodes, depth) = self.condition.size();
        if nodes > limits::NODES || depth > limits::DEPTH {
            return Err("condition is too large or too deeply nested");
        }
        let mut problem = None;
        self.condition.texts(&mut |name, text| {
            if name.is_some_and(|n| !is_token(n)) {
                problem = Some("header and cookie names must be tokens");
            }
            if text.is_some_and(|t| t.value.len() > limits::PATTERN || !no_controls(&t.value)) {
                problem = Some("patterns must be at most 4096 bytes without control characters");
            }
        });
        if let Some(p) = problem {
            return Err(p);
        }
        let r = &self.response;
        if !(200..=999).contains(&r.status) {
            return Err("status must be 200-999 (informational responses cannot be sent)");
        }
        if r.reason.len() > 256 || !no_controls(&r.reason) {
            return Err("reason must be at most 256 characters without control characters");
        }
        if r.headers.len() > limits::HEADERS {
            return Err("too many response headers");
        }
        for h in &r.headers {
            if !is_token(&h.name) || h.value.len() > MAX_HEADER_VALUE || !no_controls(&h.value) {
                return Err(
                    "header names must be tokens and values at most 8 KiB without control characters",
                );
            }
            if FRAMING_HEADERS
                .iter()
                .any(|f| h.name.eq_ignore_ascii_case(f))
            {
                return Err("Content-Length, Transfer-Encoding and Connection are set by Wiretap");
            }
        }
        match &r.body {
            Body::Empty => {}
            Body::Text { text } if text.len() > MAX_BODY => return Err("body exceeds 16 MiB"),
            Body::Text { .. } => {}
            Body::Base64 { data } => match base64::decode(data) {
                Some(bytes) if bytes.len() <= MAX_BODY => {}
                Some(_) => return Err("body exceeds 16 MiB"),
                None => return Err("body is not valid base64"),
            },
        }
        if r.delay_ms > limits::DELAY_MS {
            return Err("delay exceeds 60 s");
        }
        Ok(())
    }
}

/// A validated, ordered rule set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

/// The outcome of matching a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply<'a> {
    /// The rule that matched.
    pub rule: &'a Rule,
    /// The response to send.
    pub response: Rendered,
    /// Delay before sending, in milliseconds.
    pub delay_ms: u32,
}

impl RuleSet {
    /// Validates `rules` (in priority order).
    ///
    /// # Errors
    /// The first invalid rule and why. Duplicate IDs are rejected.
    pub fn new(rules: Vec<Rule>) -> Result<Self, RuleError> {
        if rules.len() > limits::RULES {
            return Err(RuleError {
                rule: limits::RULES,
                reason: "too many rules",
            });
        }
        for (index, rule) in rules.iter().enumerate() {
            rule.validate().map_err(|reason| RuleError {
                rule: index,
                reason,
            })?;
            if rules.iter().take(index).any(|r| r.id == rule.id) {
                return Err(RuleError {
                    rule: index,
                    reason: "duplicate rule id",
                });
            }
        }
        Ok(Self { rules })
    }

    /// Parses and validates a JSON array of rules (import).
    ///
    /// # Errors
    /// Malformed JSON or an invalid rule.
    pub fn from_json(json: &[u8]) -> Result<Self, RuleError> {
        let rules: Vec<Rule> = serde_json::from_slice(json).map_err(|_| RuleError {
            rule: 0,
            reason: "not a valid rule list",
        })?;
        Self::new(rules)
    }

    /// The rules, in priority order.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The one outcome for `request`: the first enabled matching redirect (redirects come
    /// first, so a request is never both redirected and answered), else the first enabled
    /// matching automatic response, else `None` (send it to its server).
    #[must_use]
    pub fn decide(&self, request: Request<'_>) -> Option<Decision<'_>> {
        let cx = Ctx::new(request);
        let mut budget = limits::STEPS;
        let mut matching = |redirect: bool| {
            self.rules.iter().find(|r| {
                r.enabled && r.redirect.is_some() == redirect && r.condition.eval(&cx, &mut budget)
            })
        };
        if let Some(rule) = matching(true) {
            let url = rule.redirect.as_ref()?.target(request.url);
            return Some(Decision::Redirect { rule, url });
        }
        let rule = matching(false)?;
        Some(Decision::Reply(Reply {
            rule,
            response: rule.response.render(&cx),
            delay_ms: rule.response.delay_ms,
        }))
    }

    /// The automatic response for `request`, if [`RuleSet::decide`] answers it.
    #[must_use]
    pub fn reply(&self, request: Request<'_>) -> Option<Reply<'_>> {
        match self.decide(request)? {
            Decision::Reply(reply) => Some(reply),
            Decision::Redirect { .. } => None,
        }
    }

    /// Whether an enabled rule could answer a request to `host` (it does not exclude that
    /// host). Such hosts are intercepted without contacting the server first, so rules answer
    /// even when it is unreachable; every other host is verified first and relayed untouched
    /// when it cannot be reached or trusted.
    #[must_use]
    pub fn targets_host(&self, host: &str) -> bool {
        let mut budget = limits::STEPS;
        self.rules
            .iter()
            .any(|r| r.enabled && r.condition.on_host(host, &mut budget) != Some(false))
    }

    /// Whether a rule that may apply to `host` looks at request bodies. Protocols that stream
    /// requests (HTTP/2) decide on the request head otherwise, and wait for the body only then.
    #[must_use]
    pub fn needs_body(&self, host: &str) -> bool {
        let mut budget = limits::STEPS;
        self.rules.iter().any(|r| {
            r.enabled
                && r.condition.uses_body()
                && r.condition.on_host(host, &mut budget) != Some(false)
        })
    }
    /// Indexes of the rules matching `request` (for testing rules in the editor).
    #[must_use]
    pub fn matching(&self, request: Request<'_>) -> Vec<usize> {
        let cx = Ctx::new(request);
        let mut budget = limits::STEPS;
        self.rules
            .iter()
            .enumerate()
            .filter(|(_, r)| r.condition.eval(&cx, &mut budget))
            .map(|(i, _)| i)
            .collect()
    }
}

#[cfg(test)]
mod tests;
