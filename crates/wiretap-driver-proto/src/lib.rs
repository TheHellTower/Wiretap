//! Protocol shared by `WiretapDriver` (kernel) and its user-mode client.
//!
//! Contains the device and IOCTL definitions, WFP object keys, the event record wire format,
//! and the two bounded data structures the driver uses at `DISPATCH_LEVEL`: a byte ring of
//! records and a fixed-size per-flow capture budget. `no_std`, dependency-free and free of
//! `unsafe`, so exactly the code that runs in the kernel is unit-tested and fuzzed in user mode.
//! Decoding never panics and validates every length.
#![no_std]
#![forbid(unsafe_code)]

/// Version of this protocol; the client refuses drivers reporting a different value.
pub const PROTOCOL_VERSION: u32 = 2;

/// NT device name created by the driver.
pub const DEVICE_NAME: &str = r"\Device\WiretapDriver";
/// Symbolic link created by the driver.
pub const SYMLINK_NAME: &str = r"\DosDevices\WiretapDriver";
/// Path the client opens.
pub const CLIENT_PATH: &str = r"\\.\WiretapDriver";
/// Device ACL: kernel, SYSTEM and Administrators only.
pub const DEVICE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

/// Device type of the driver's device object (custom range, used in the IOCTL codes).
pub const DEVICE_TYPE: u32 = 0x8A71;
const METHOD_BUFFERED: u32 = 0;
const FILE_READ_ACCESS: u32 = 1;
const FILE_WRITE_ACCESS: u32 = 2;

const fn ctl_code(function: u32, access: u32) -> u32 {
    (DEVICE_TYPE << 16) | (access << 14) | (function << 2) | METHOD_BUFFERED
}

/// Returns `[PROTOCOL_VERSION, driver version]` as two little-endian `u32`s.
pub const IOCTL_GET_VERSION: u32 = ctl_code(0x800, FILE_READ_ACCESS);
/// Fills the output buffer with `u64` dropped-record count followed by whole records.
/// Waits up to [`READ_WAIT_MS`] when no record is queued.
pub const IOCTL_READ_EVENTS: u32 = ctl_code(0x801, FILE_READ_ACCESS);
/// Input: a [`Redirect`] (all zero: stop). While set, outbound TCP connections matched by the
/// redirect filters go to the proxy instead; it learns their destination from an [`Original`].
/// Cleared whenever the device is opened or closed.
pub const IOCTL_SET_REDIRECT: u32 = ctl_code(0x802, FILE_WRITE_ACCESS);
/// Maximum time a read waits for the first record.
pub const READ_WAIT_MS: i64 = 100;
/// Largest output buffer a read accepts.
pub const MAX_READ: usize = 256 * 1024;
/// Smallest output buffer a read accepts: the dropped counter plus one maximal record.
pub const MIN_READ: usize = 8 + MAX_RECORD;

/// WFP provider key.
pub const PROVIDER_KEY: u128 = 0x899A_2C70_B181_43CC_92A6_B428_7316_EE34;
/// WFP sublayer key.
pub const SUBLAYER_KEY: u128 = 0x1AAA_0800_2C83_40EF_934D_51DD_CBE8_5ADC;
/// Callout at `FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4`.
pub const CALLOUT_FLOW_V4: u128 = 0xE881_8E18_B653_433C_8D9B_9617_940E_3D89;
/// Callout at `FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6`.
pub const CALLOUT_FLOW_V6: u128 = 0x6BB2_96D5_2FA4_4D82_B60C_BC48_039A_6E7C;
/// Callout at `FWPM_LAYER_STREAM_V4`.
pub const CALLOUT_STREAM_V4: u128 = 0x9DFE_F4B8_E0A6_4F29_B877_B14A_8E4C_BB0B;
/// Callout at `FWPM_LAYER_STREAM_V6`.
pub const CALLOUT_STREAM_V6: u128 = 0x414E_29F4_5C83_400E_B04D_74DD_6F06_5DFA;
/// Callout at `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4`.
pub const CALLOUT_REDIRECT_V4: u128 = 0x1532_5688_6F2A_4B76_B1B9_A5A7_3100_9E3B;
/// Callout at `FWPM_LAYER_ALE_CONNECT_REDIRECT_V6`.
pub const CALLOUT_REDIRECT_V6: u128 = 0xDBFD_33BF_E6D5_4431_A227_544E_7670_CBD8;
/// Device class GUID (lets administrators override the device ACL in the registry).
pub const DEVICE_CLASS: u128 = 0xE18F_BD2E_32A6_47A3_914E_9A0F_C93B_3CC6;

/// Bytes of stream data copied per segment.
pub const SEGMENT_CAP: usize = 16 * 1024;
/// Bytes of stream data captured per flow and direction.
pub const FLOW_BUDGET: u32 = 64 * 1024;
/// Bytes of process path (UTF-16LE) kept per flow record.
pub const MAX_PATH_BYTES: usize = 1024;

const HEADER: usize = 24;
/// Size of a flow record without its path.
pub const FLOW_FIXED: usize = HEADER + 48;
/// Size of a data record without its payload.
pub const DATA_FIXED: usize = HEADER + 8;
/// Largest record the driver emits.
pub const MAX_RECORD: usize = DATA_FIXED + SEGMENT_CAP;

const _: () = assert!(MIN_READ <= MAX_READ && MAX_RECORD <= u16::MAX as usize);

const KIND_FLOW: u8 = 1;
const KIND_DATA: u8 = 2;
const FLAG_INBOUND: u8 = 1;
const FLAG_IPV6: u8 = 2;

/// A connection observed at the ALE flow-established layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowRecord<'a> {
    /// Time in 100 ns units since 1601-01-01 UTC.
    pub timestamp: u64,
    /// WFP flow handle; correlates data records.
    pub flow: u64,
    /// Whether the remote side initiated the connection.
    pub inbound: bool,
    /// Whether addresses are IPv6 (otherwise the first 4 bytes hold IPv4).
    pub ipv6: bool,
    /// Owning process.
    pub pid: u64,
    /// IP protocol number (6 = TCP, 17 = UDP).
    pub protocol: u8,
    /// Local port.
    pub local_port: u16,
    /// Remote port.
    pub remote_port: u16,
    /// Local address in network byte order.
    pub local_addr: [u8; 16],
    /// Remote address in network byte order.
    pub remote_addr: [u8; 16],
    /// NT path of the process image, UTF-16LE.
    pub path: &'a [u8],
}

/// Stream bytes observed on a TCP flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataRecord<'a> {
    /// Time in 100 ns units since 1601-01-01 UTC.
    pub timestamp: u64,
    /// WFP flow handle.
    pub flow: u64,
    /// Whether the bytes were received (otherwise sent).
    pub inbound: bool,
    /// Length of the segment on the wire.
    pub wire_len: u32,
    /// Captured prefix of the segment.
    pub data: &'a [u8],
}

/// A decoded event record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Record<'a> {
    /// Connection established.
    Flow(FlowRecord<'a>),
    /// Stream data.
    Data(DataRecord<'a>),
}

/// Malformed record stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeError;

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("malformed driver record")
    }
}

impl core::error::Error for DecodeError {}

/// Panic-free little-endian writer over a fixed buffer.
struct Writer<'a>(&'a mut [u8]);

impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) {
        let buf = core::mem::take(&mut self.0);
        let n = bytes.len().min(buf.len());
        let (head, rest) = buf.split_at_mut(n);
        head.copy_from_slice(bytes.get(..n).unwrap_or_default());
        self.0 = rest;
    }
}

fn header(out: &mut Writer<'_>, len: usize, kind: u8, flags: u8, timestamp: u64, flow: u64) {
    out.put(&u16::try_from(len).unwrap_or(u16::MAX).to_le_bytes());
    out.put(&[kind, flags, 0, 0, 0, 0]);
    out.put(&timestamp.to_le_bytes());
    out.put(&flow.to_le_bytes());
}

/// Encodes the fixed part of a flow record; the caller appends `path` (at most
/// [`MAX_PATH_BYTES`], even length).
#[must_use]
pub fn flow_header(r: &FlowRecord<'_>) -> [u8; FLOW_FIXED] {
    let mut buf = [0u8; FLOW_FIXED];
    let mut w = Writer(&mut buf);
    let flags = (u8::from(r.inbound) * FLAG_INBOUND) | (u8::from(r.ipv6) * FLAG_IPV6);
    header(
        &mut w,
        FLOW_FIXED.saturating_add(r.path.len()),
        KIND_FLOW,
        flags,
        r.timestamp,
        r.flow,
    );
    w.put(&r.pid.to_le_bytes());
    w.put(&[r.protocol, 0]);
    w.put(&r.local_port.to_le_bytes());
    w.put(&r.remote_port.to_le_bytes());
    w.put(
        &u16::try_from(r.path.len())
            .unwrap_or(u16::MAX)
            .to_le_bytes(),
    );
    w.put(&r.local_addr);
    w.put(&r.remote_addr);
    buf
}

/// Encodes the fixed part of a data record; the caller appends `captured` payload bytes.
#[must_use]
pub fn data_header(
    timestamp: u64,
    flow: u64,
    inbound: bool,
    wire_len: u32,
    captured: usize,
) -> [u8; DATA_FIXED] {
    let mut buf = [0u8; DATA_FIXED];
    let mut w = Writer(&mut buf);
    header(
        &mut w,
        DATA_FIXED.saturating_add(captured),
        KIND_DATA,
        u8::from(inbound) * FLAG_INBOUND,
        timestamp,
        flow,
    );
    w.put(&wire_len.to_le_bytes());
    buf
}

/// Panic-free little-endian reader.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let (head, rest) = self.0.split_first_chunk::<N>().ok_or(DecodeError)?;
        self.0 = rest;
        Ok(*head)
    }
    fn u16(&mut self) -> Result<u16, DecodeError> {
        self.take().map(u16::from_le_bytes)
    }
    fn u32(&mut self) -> Result<u32, DecodeError> {
        self.take().map(u32::from_le_bytes)
    }
    fn u64(&mut self) -> Result<u64, DecodeError> {
        self.take().map(u64::from_le_bytes)
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if n > self.0.len() {
            return Err(DecodeError);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
}

/// Iterates over the records in `buf` (the bytes after a read's dropped counter). Stops at the
/// first malformed record after yielding an error.
pub fn records(buf: &[u8]) -> impl Iterator<Item = Result<Record<'_>, DecodeError>> {
    let mut rest = buf;
    core::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let item = decode_one(rest);
        rest = match item {
            Ok((_, tail)) => tail,
            Err(_) => &[],
        };
        Some(item.map(|(record, _)| record))
    })
}

fn decode_one(buf: &[u8]) -> Result<(Record<'_>, &[u8]), DecodeError> {
    let mut outer = Reader(buf);
    let len = usize::from(outer.u16()?);
    if !(HEADER..=MAX_RECORD.max(FLOW_FIXED + MAX_PATH_BYTES)).contains(&len) {
        return Err(DecodeError);
    }
    outer.0 = buf;
    let mut r = Reader(outer.bytes(len)?);
    let tail = outer.0;
    r.u16()?;
    let [kind, flags, ..] = r.take::<6>()?;
    let (timestamp, flow) = (r.u64()?, r.u64()?);
    let inbound = flags & FLAG_INBOUND != 0;
    let record = match kind {
        KIND_FLOW => {
            let pid = r.u64()?;
            let [protocol, _] = r.take::<2>()?;
            let (local_port, remote_port, path_len) = (r.u16()?, r.u16()?, usize::from(r.u16()?));
            let (local_addr, remote_addr) = (r.take::<16>()?, r.take::<16>()?);
            let path = r.bytes(path_len)?;
            if path_len > MAX_PATH_BYTES || path_len % 2 != 0 {
                return Err(DecodeError);
            }
            let ipv6 = flags & FLAG_IPV6 != 0;
            Record::Flow(FlowRecord {
                timestamp,
                flow,
                inbound,
                ipv6,
                pid,
                protocol,
                local_port,
                remote_port,
                local_addr,
                remote_addr,
                path,
            })
        }
        KIND_DATA => {
            let wire_len = r.u32()?;
            r.u32()?;
            let data = r.0;
            if data.len() > SEGMENT_CAP || data.len() as u64 > u64::from(wire_len) {
                return Err(DecodeError);
            }
            r.0 = &[];
            Record::Data(DataRecord {
                timestamp,
                flow,
                inbound,
                wire_len,
                data,
            })
        }
        _ => return Err(DecodeError),
    };
    if r.0.is_empty() {
        Ok((record, tail))
    } else {
        Err(DecodeError)
    }
}

/// Fixed-capacity byte ring of length-prefixed records. Writers never block: a record that
/// does not fit is dropped and counted. All-zero memory is a valid empty ring, so the driver
/// can place it in zero-initialized pool memory.
pub struct Ring<const N: usize> {
    buf: [u8; N],
    head: usize,
    len: usize,
    dropped: u64,
}

impl<const N: usize> Ring<N> {
    /// An empty ring (prefer zeroed allocation for large `N`).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: [0; N],
            head: 0,
            len: 0,
            dropped: 0,
        }
    }

    /// Whether no record is queued.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Appends one record made of `parts` (whose first two bytes are its total length).
    /// Returns `false` and counts a drop when it does not fit.
    pub fn push(&mut self, parts: &[&[u8]]) -> bool {
        let total = parts
            .iter()
            .fold(0usize, |acc, p| acc.saturating_add(p.len()));
        if total == 0 || total > N.saturating_sub(self.len) {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        // Indices stay below N (`head < N`, `len <= N`): wrapping arithmetic never wraps, and the
        // driver keeps no overflow checks (it must not contain panic paths).
        let mut pos = self.head.wrapping_add(self.len) % N;
        for part in parts {
            pos = copy_in(&mut self.buf, pos, part);
        }
        self.len = self.len.saturating_add(total);
        true
    }

    /// Moves whole records into `out` while they fit. Returns the number of bytes written.
    pub fn pop_into(&mut self, out: &mut [u8]) -> usize {
        let mut written = 0usize;
        while self.len >= 2 {
            let mut prefix = [0u8; 2];
            copy_out(&self.buf, self.head, &mut prefix);
            let record = usize::from(u16::from_le_bytes(prefix));
            if record < 2 || record > self.len {
                // Unreachable through `push`; recover instead of looping forever.
                self.clear();
                break;
            }
            let Some(dst) = out.get_mut(written..written.saturating_add(record)) else {
                break;
            };
            copy_out(&self.buf, self.head, dst);
            self.head = self.head.wrapping_add(record) % N;
            self.len -= record;
            written = written.saturating_add(record);
        }
        written
    }

    /// Returns and resets the number of dropped records.
    pub fn take_dropped(&mut self) -> u64 {
        core::mem::take(&mut self.dropped)
    }

    /// Discards all queued records and the drop counter (a new reader starts clean).
    pub fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
        self.dropped = 0;
    }
}

impl<const N: usize> Default for Ring<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Copies `data` into the ring at `pos`, wrapping around; returns the position after it.
fn copy_in(buf: &mut [u8], pos: usize, data: &[u8]) -> usize {
    let (front, back) = buf.split_at_mut(pos.min(buf.len()));
    let (first, second) = data.split_at(data.len().min(back.len()));
    back.iter_mut().zip(first).for_each(|(d, s)| *d = *s);
    front.iter_mut().zip(second).for_each(|(d, s)| *d = *s);
    pos.wrapping_add(data.len()) % buf.len().max(1)
}

/// Fills `out` from the ring starting at `pos`, wrapping around.
fn copy_out(buf: &[u8], pos: usize, out: &mut [u8]) {
    let (front, back) = buf.split_at(pos.min(buf.len()));
    let split = out.len().min(back.len());
    let (first, second) = out.split_at_mut(split);
    first.iter_mut().zip(back).for_each(|(d, s)| *d = *s);
    second.iter_mut().zip(front).for_each(|(d, s)| *d = *s);
}

/// Per-flow, per-direction capture budget in a fixed open-addressed table. Flows hashing to
/// an occupied slot evict its previous owner (who then restarts with a fresh budget), so
/// memory stays constant and no per-flow lifetime tracking is needed. All-zero memory is a
/// valid empty table.
pub struct FlowBudget<const SLOTS: usize> {
    flows: [u64; SLOTS],
    used: [[u32; 2]; SLOTS],
}

impl<const SLOTS: usize> FlowBudget<SLOTS> {
    /// An empty table (prefer zeroed allocation for large `SLOTS`).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            flows: [0; SLOTS],
            used: [[0; 2]; SLOTS],
        }
    }

    fn slot(&mut self, flow: u64) -> Option<(&mut u64, &mut [u32; 2])> {
        let slots = u64::try_from(SLOTS).ok().filter(|&s| s > 0)?;
        let index =
            usize::try_from(flow.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(32) % slots)
                .ok()?;
        Some((self.flows.get_mut(index)?, self.used.get_mut(index)?))
    }

    /// Starts a fresh budget for a newly established flow.
    pub fn reset(&mut self, flow: u64) {
        if let Some((owner, used)) = self.slot(flow) {
            *owner = flow;
            *used = [0, 0];
        }
    }

    /// Grants up to `want` bytes from the flow's remaining budget in one direction.
    pub fn grant(&mut self, flow: u64, inbound: bool, want: usize, budget: u32) -> usize {
        let Some((owner, used)) = self.slot(flow) else {
            return 0;
        };
        if *owner != flow {
            *owner = flow;
            *used = [0, 0];
        }
        let [sent, received] = used;
        let spent = if inbound { received } else { sent };
        let granted = budget
            .saturating_sub(*spent)
            .min(u32::try_from(want).unwrap_or(u32::MAX));
        *spent = spent.saturating_add(granted);
        usize::try_from(granted).unwrap_or(0)
    }
}

impl<const SLOTS: usize> Default for FlowBudget<SLOTS> {
    fn default() -> Self {
        Self::new()
    }
}

/// Where redirected connections go: the proxy process and its loopback ports (0: that IP
/// version is not redirected).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Redirect {
    /// The proxy's process ID: its own connections are never redirected.
    pub pid: u32,
    /// Port of the proxy on `127.0.0.1`.
    pub port_v4: u16,
    /// Port of the proxy on `[::1]`.
    pub port_v6: u16,
}

impl Redirect {
    /// Encoded size.
    pub const SIZE: usize = 8;

    /// Little-endian `pid, port_v4, port_v6`.
    #[must_use]
    pub fn encode(&self) -> [u8; Self::SIZE] {
        let mut b = [0u8; Self::SIZE];
        let (pid, ports) = b.split_at_mut(4);
        pid.copy_from_slice(&self.pid.to_le_bytes());
        let (v4, v6) = ports.split_at_mut(2);
        v4.copy_from_slice(&self.port_v4.to_le_bytes());
        v6.copy_from_slice(&self.port_v6.to_le_bytes());
        b
    }

    /// `None` for a malformed configuration; `Some(None)` for "stop redirecting" (all zero).
    #[must_use]
    pub fn decode(b: &[u8]) -> Option<Option<Self>> {
        let b: &[u8; Self::SIZE] = b.try_into().ok()?;
        let [p0, p1, p2, p3, a0, a1, c0, c1] = *b;
        let r = Self {
            pid: u32::from_le_bytes([p0, p1, p2, p3]),
            port_v4: u16::from_le_bytes([a0, a1]),
            port_v6: u16::from_le_bytes([c0, c1]),
        };
        match r {
            Self {
                pid: 0,
                port_v4: 0,
                port_v6: 0,
            } => Some(None),
            Self { pid: 0, .. }
            | Self {
                port_v4: 0,
                port_v6: 0,
                ..
            } => None,
            _ => Some(Some(r)),
        }
    }
}

/// The real destination of a redirected connection, attached by the driver as its WFP
/// redirect context and read back by the proxy from the accepted socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Original {
    /// Process that opened the connection.
    pub pid: u32,
    /// IPv6 (`addr` holds 16 bytes) or IPv4 (the first 4).
    pub ipv6: bool,
    /// Remote port.
    pub port: u16,
    /// Remote address, network byte order.
    pub addr: [u8; 16],
}

impl Original {
    /// Encoded size.
    pub const SIZE: usize = 28;
    const MAGIC: [u8; 4] = *b"WTRD";

    /// `MAGIC, pid (LE), family (4/6), port (BE), address (16 bytes)`.
    #[must_use]
    pub fn encode(&self) -> [u8; Self::SIZE] {
        let mut b = [0u8; Self::SIZE];
        let (magic, rest) = b.split_at_mut(4);
        magic.copy_from_slice(&Self::MAGIC);
        let (pid, rest) = rest.split_at_mut(4);
        pid.copy_from_slice(&self.pid.to_le_bytes());
        let (family, rest) = rest.split_at_mut(2);
        family.copy_from_slice(&u16::from(if self.ipv6 { 6u8 } else { 4 }).to_le_bytes());
        let (port, addr) = rest.split_at_mut(2);
        port.copy_from_slice(&self.port.to_be_bytes());
        addr.copy_from_slice(&self.addr);
        b
    }

    /// Validates magic, family and port.
    #[must_use]
    pub fn decode(b: &[u8]) -> Option<Self> {
        let b: &[u8; Self::SIZE] = b.try_into().ok()?;
        let (head, addr) = b.split_first_chunk::<12>()?;
        let [m0, m1, m2, m3, p0, p1, p2, p3, f0, f1, port0, port1] = *head;
        let ipv6 = match u16::from_le_bytes([f0, f1]) {
            4 => false,
            6 => true,
            _ => return None,
        };
        let port = u16::from_be_bytes([port0, port1]);
        if [m0, m1, m2, m3] != Self::MAGIC || port == 0 {
            return None;
        }
        Some(Self {
            pid: u32::from_le_bytes([p0, p1, p2, p3]),
            ipv6,
            port,
            addr: addr.try_into().ok()?,
        })
    }
}
#[cfg(test)]
mod tests;
