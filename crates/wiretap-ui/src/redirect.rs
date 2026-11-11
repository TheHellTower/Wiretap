//! Reads the original destination of connections the capture driver redirected to the proxy
//! (the WFP redirect context, `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT`).
#![allow(
    unsafe_code,
    reason = "one WSAIoctl call; the block carries a SAFETY comment"
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::os::windows::io::AsRawSocket;
use std::ptr::null_mut;

use windows_sys::Win32::Networking::WinSock::{
    SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, WSAIoctl,
};
use wiretap_driver_proto::Original;

/// `Some((destination, process id))` when `client` was redirected by WiretapDriver; `None` for
/// ordinary (explicit proxy) connections, which carry no redirect context.
pub(crate) fn original(client: &TcpStream) -> Option<(SocketAddr, u32)> {
    let mut buf = [0u8; Original::SIZE];
    let mut returned = 0u32;
    let size = u32::try_from(buf.len()).ok()?;
    let socket = usize::try_from(client.as_raw_socket()).ok()?;
    // SAFETY: `socket` is a live socket owned by `client`; `buf` is writable for `size` bytes;
    // no input buffer and no overlapped I/O.
    let status = unsafe {
        WSAIoctl(
            socket,
            SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
            std::ptr::null(),
            0,
            buf.as_mut_ptr().cast(),
            size,
            &mut returned,
            null_mut(),
            None,
        )
    };
    if status != 0 {
        return None;
    }
    let o = Original::decode(buf.get(..usize::try_from(returned).ok()?)?)?;
    let ip = if o.ipv6 {
        IpAddr::V6(Ipv6Addr::from(o.addr))
    } else {
        let [a, b, c, d, ..] = o.addr;
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    };
    Some((SocketAddr::new(ip, o.port), o.pid))
}
