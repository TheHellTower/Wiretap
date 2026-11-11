//! The unified network event model (specification section 7).

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::{EventId, FlowId, PayloadId, SessionId, Timestamp};

/// A named capture session that owns events, flows and payloads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    /// Unique session identifier.
    pub id: SessionId,
    /// Human-readable name.
    pub name: String,
    /// Creation time.
    pub created: Timestamp,
}

impl Session {
    /// Creates a session named `name`, stamped with the current time.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: SessionId::generate(),
            name: name.into(),
            created: Timestamp::now(),
        }
    }
}

/// One observation produced by any capture mechanism.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkEvent {
    /// Unique event identifier.
    pub id: EventId,
    /// Session the event belongs to.
    pub session_id: SessionId,
    /// When the event was observed.
    pub timestamp: Timestamp,
    /// Mechanism that produced the event (provenance).
    pub source: CaptureSource,
    /// Highest protocol layer identified.
    pub protocol: Protocol,
    /// Direction relative to the local host.
    pub direction: Direction,
    /// Owning local process, when attributed.
    pub process: Option<ProcessInfo>,
    /// Local endpoint, for IP traffic.
    pub local_endpoint: Option<Endpoint>,
    /// Remote endpoint, for IP traffic.
    pub remote_endpoint: Option<Endpoint>,
    /// Captured bytes, stored separately from the event.
    pub payload: Option<PayloadReference>,
    /// Inspection depth, correlation and dissector output.
    pub metadata: EventMetadata,
}

/// Mechanism that produced an event or flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureSource {
    /// Explicit (forward) proxy.
    ExplicitProxy,
    /// Transparent proxy fed by connection redirection.
    TransparentProxy,
    /// Reverse proxy in front of a fixed upstream.
    ReverseProxy,
    /// Built-in Windows packet capture (ETW or Packet Monitor).
    PacketCapture,
    /// User-mode Windows Filtering Platform events.
    Wfp,
    /// The optional Wiretap kernel driver.
    Driver,
    /// A file imported by the user (HAR, PCAP, PCAPNG or session archive).
    Import,
    /// A request issued by Wiretap replay.
    Replay,
}

impl CaptureSource {
    /// Whether this source can legitimately carry decrypted TLS content: Wiretap terminated
    /// the TLS session itself, originated the traffic, or the user supplied the plaintext.
    /// Passive sources only ever see the ciphertext of encrypted protocols.
    #[must_use]
    pub const fn can_carry_decrypted(self) -> bool {
        matches!(
            self,
            Self::ExplicitProxy
                | Self::TransparentProxy
                | Self::ReverseProxy
                | Self::Import
                | Self::Replay
        )
    }
}

/// Protocol identified for an event (the highest layer decoded).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// Ethernet framing.
    Ethernet,
    /// Address Resolution Protocol.
    Arp,
    /// Internet Protocol version 4.
    Ipv4,
    /// Internet Protocol version 6.
    Ipv6,
    /// ICMP for IPv4.
    Icmp,
    /// ICMP for IPv6.
    Icmpv6,
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// Domain Name System.
    Dns,
    /// Dynamic Host Configuration Protocol.
    Dhcp,
    /// Transport Layer Security.
    Tls,
    /// QUIC transport.
    Quic,
    /// HTTP/1.x.
    Http1,
    /// HTTP/2.
    Http2,
    /// HTTP/3.
    Http3,
    /// WebSocket.
    Websocket,
    /// Server-Sent Events.
    Sse,
    /// gRPC.
    Grpc,
    /// MQTT.
    Mqtt,
    /// AMQP.
    Amqp,
    /// SMTP.
    Smtp,
    /// POP3.
    Pop3,
    /// IMAP.
    Imap,
    /// FTP.
    Ftp,
    /// SSH (metadata only).
    Ssh,
    /// SOCKS5.
    Socks5,
}

/// Traffic direction relative to the local host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Received by the local host.
    Inbound,
    /// Sent by the local host.
    Outbound,
    /// Not determinable (for example in imported captures).
    Unknown,
}

/// How deeply Wiretap could inspect the traffic. Encrypted traffic is never reported
/// above [`Inspection::Metadata`] unless Wiretap actively intercepted it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Inspection {
    /// Raw packets were captured; nothing was decoded.
    Packet,
    /// The protocol was identified, but its content was not decoded.
    Protocol,
    /// Protocol metadata was decoded (e.g. DNS names, TLS SNI); the payload stays opaque.
    Metadata,
    /// The payload is cleartext on the wire and was decoded.
    Plaintext,
    /// The payload was obtained through active interception (proxy or TLS termination).
    Intercepted,
}

/// Owning process of a connection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessInfo {
    /// Process identifier.
    pub pid: u32,
    /// Executable name.
    pub name: Option<String>,
    /// Full executable path.
    pub path: Option<String>,
    /// Process start time; disambiguates reused PIDs.
    pub started: Option<Timestamp>,
}

/// An IP endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    /// IPv4 or IPv6 address.
    pub ip: IpAddr,
    /// Transport port; absent for portless protocols such as ICMP.
    pub port: Option<u16>,
}

/// Confidentiality of stored payload bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadEncryption {
    /// Unencrypted on the wire.
    Cleartext,
    /// Ciphertext as seen on the wire.
    Encrypted,
    /// Plaintext recovered through interception.
    Decrypted,
}

/// Reference to payload bytes held by storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadReference {
    /// Storage key.
    pub id: PayloadId,
    /// Length observed on the wire, in bytes.
    pub size: u64,
    /// Bytes actually stored; less than `size` when truncated by capture limits.
    pub stored: u64,
    /// Confidentiality of the stored bytes.
    pub encryption: PayloadEncryption,
}

/// Event metadata: inspection depth, correlation and dissector output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventMetadata {
    /// Inspection depth reached.
    pub inspection: Inspection,
    /// HTTP flow this event belongs to, if any.
    pub flow_id: Option<FlowId>,
    /// Protocol-specific key/value pairs produced by dissectors.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
}

/// An HTTP request/response exchange.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Flow {
    /// Unique flow identifier.
    pub id: FlowId,
    /// Session the flow belongs to.
    pub session_id: SessionId,
    /// Mechanism that produced the flow (provenance).
    pub source: CaptureSource,
    /// Client process, when attributed.
    pub process: Option<ProcessInfo>,
    /// Client endpoint.
    pub client: Option<Endpoint>,
    /// Server endpoint.
    pub server: Option<Endpoint>,
    /// The request, once received.
    pub request: Option<HttpRequest>,
    /// The response, once received.
    pub response: Option<HttpResponse>,
    /// Timing information.
    pub timing: FlowTiming,
    /// User-assigned tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// HTTP protocol version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpVersion {
    /// HTTP/1.0.
    #[serde(rename = "HTTP/1.0")]
    Http10,
    /// HTTP/1.1.
    #[serde(rename = "HTTP/1.1")]
    Http11,
    /// HTTP/2.
    #[serde(rename = "HTTP/2")]
    Http2,
    /// HTTP/3.
    #[serde(rename = "HTTP/3")]
    Http3,
}

/// One header field; order and duplicates are preserved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpHeader {
    /// Field name as received.
    pub name: String,
    /// Field value.
    pub value: String,
}

/// An HTTP request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRequest {
    /// Request method.
    pub method: String,
    /// Absolute request URL.
    pub url: String,
    /// Protocol version.
    pub version: HttpVersion,
    /// Header fields in wire order.
    pub headers: Vec<HttpHeader>,
    /// Message body.
    pub body: Option<PayloadReference>,
}

/// An HTTP response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// Reason phrase (empty for HTTP/2 and HTTP/3).
    pub reason: String,
    /// Protocol version.
    pub version: HttpVersion,
    /// Header fields in wire order.
    pub headers: Vec<HttpHeader>,
    /// Message body.
    pub body: Option<PayloadReference>,
}

/// Flow timing milestones.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowTiming {
    /// First byte of the request received from the client.
    pub started: Timestamp,
    /// Last byte of the request received.
    pub request_complete: Option<Timestamp>,
    /// First byte of the response received.
    pub response_started: Option<Timestamp>,
    /// Last byte of the response received.
    pub response_complete: Option<Timestamp>,
}
