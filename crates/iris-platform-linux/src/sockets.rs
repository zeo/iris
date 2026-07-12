//! sock_diag (INET_DIAG) socket enumeration. one dump lists every TCP and UDP
//! socket with its four-tuple, owning uid, inode, and a stable cookie, plus the
//! per-socket byte counters from tcp_info for TCP. this is the Linux equivalent
//! of the Windows IP Helper tables: the connection view reads the tuples and the
//! inode (to find the owning pid), and the byte monitor diffs the counters.

use crate::netlink::{self, NlSocket, NLM_F_DUMP, NLM_F_REQUEST};
use iris_core::Protocol;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const NETLINK_INET_DIAG: libc::c_int = 4;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const SOCK_DESTROY: u16 = 21;

// the tcp_info extension carries the byte counters; extensions are 1-indexed in
// the request bitmask, so INET_DIAG_INFO (2) is bit 1
const INET_DIAG_INFO: u16 = 2;
const EXT_INFO_BIT: u8 = 1 << (INET_DIAG_INFO - 1);

// tcp states we care about: everything an active or closing connection passes
// through, but never LISTEN, which is a bound server socket with no peer
const TCP_ESTABLISHED: u32 = 1;
const TCP_LISTEN: u32 = 10;
// all-states mask for UDP, whose "state" is not meaningful
const STATES_ALL: u32 = 0xFFFF_FFFF;

/// one socket as reported by sock_diag
#[derive(Clone)]
pub struct SockInfo {
    pub protocol: Protocol,
    pub state: u8,
    pub local: (IpAddr, u16),
    pub remote: (IpAddr, u16),
    pub uid: u32,
    pub inode: u32,
    /// stable across dumps for the life of the socket; the byte monitor keys its
    /// per-socket counter diff on it
    pub cookie: u64,
    /// cumulative bytes sent/received from tcp_info, present for TCP only
    pub bytes: Option<(u64, u64)>,
}

impl SockInfo {
    pub fn is_tcp(&self) -> bool {
        matches!(self.protocol, Protocol::Tcp)
    }
}

/// dump every TCP and UDP socket (v4 and v6). a family/proto whose dump fails is
/// logged and skipped so a partial result still drives the UI.
pub fn dump() -> Vec<SockInfo> {
    dump_with_tcp_states(tcp_states())
}

/// dump sockets used to attribute a queued packet, including TCP listeners
pub fn dump_for_attribution() -> Vec<SockInfo> {
    dump_with_tcp_states(STATES_ALL)
}

fn dump_with_tcp_states(tcp_state_mask: u32) -> Vec<SockInfo> {
    let mut out = Vec::new();
    for (family, proto, ipproto, states) in [
        (
            libc::AF_INET,
            Protocol::Tcp,
            libc::IPPROTO_TCP,
            tcp_state_mask,
        ),
        (
            libc::AF_INET6,
            Protocol::Tcp,
            libc::IPPROTO_TCP,
            tcp_state_mask,
        ),
        (libc::AF_INET, Protocol::Udp, libc::IPPROTO_UDP, STATES_ALL),
        (libc::AF_INET6, Protocol::Udp, libc::IPPROTO_UDP, STATES_ALL),
    ] {
        if let Err(e) = dump_one(family as u8, proto, ipproto as u8, states, &mut out) {
            tracing::debug!("sock_diag dump failed (family {family}): {e}");
        }
    }
    out
}

// every state bit set except LISTEN
fn tcp_states() -> u32 {
    STATES_ALL & !(1 << TCP_LISTEN)
}

fn dump_one(
    family: u8,
    proto: Protocol,
    ipproto: u8,
    states: u32,
    out: &mut Vec<SockInfo>,
) -> std::io::Result<()> {
    let sock = NlSocket::open(NETLINK_INET_DIAG)?;
    sock.send(&build_request(family, ipproto, states))?;
    sock.recv_dump(|msg_type, payload| {
        if msg_type == SOCK_DIAG_BY_FAMILY {
            if let Some(info) = parse_msg(family, proto, payload) {
                out.push(info);
            }
        }
    })?;
    Ok(())
}

/// build the nlmsghdr + inet_diag_req_v2 that asks for a full dump
fn build_request(family: u8, ipproto: u8, states: u32) -> Vec<u8> {
    // inet_diag_req_v2 is 56 bytes: family, protocol, ext, pad, states(4), then
    // the 48-byte sockid (all zero for a dump)
    const REQ_LEN: usize = 56;
    const TOTAL: usize = 16 + REQ_LEN;
    let mut buf = vec![0u8; TOTAL];

    buf[0..4].copy_from_slice(&(TOTAL as u32).to_ne_bytes());
    buf[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    buf[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    // seq 1, pid 0 left as zero

    let body = 16;
    buf[body] = family;
    buf[body + 1] = ipproto;
    buf[body + 2] = EXT_INFO_BIT;
    // byte 3 is padding
    buf[body + 4..body + 8].copy_from_slice(&states.to_ne_bytes());
    buf
}

/// parse one inet_diag_msg plus its attributes into a SockInfo
fn parse_msg(family: u8, proto: Protocol, payload: &[u8]) -> Option<SockInfo> {
    // inet_diag_msg: family(1) state(1) timer(1) retrans(1) then the 48-byte
    // sockid, then expires(4) rqueue(4) wqueue(4) uid(4) inode(4)
    if payload.len() < 72 {
        return None;
    }
    let state = payload[1];
    let sport = u16::from_be_bytes([payload[4], payload[5]]);
    let dport = u16::from_be_bytes([payload[6], payload[7]]);
    let src = read_addr(family, &payload[8..24]);
    let dst = read_addr(family, &payload[24..40]);
    // idiag_if at 40..44, cookie at 44..52
    let cookie_lo = u32::from_ne_bytes(payload[44..48].try_into().ok()?);
    let cookie_hi = u32::from_ne_bytes(payload[48..52].try_into().ok()?);
    let cookie = ((cookie_hi as u64) << 32) | cookie_lo as u64;
    let uid = u32::from_ne_bytes(payload[64..68].try_into().ok()?);
    let inode = u32::from_ne_bytes(payload[68..72].try_into().ok()?);

    let mut bytes = None;
    netlink::for_each_attr(&payload[72..], |nla_type, value| {
        if nla_type == INET_DIAG_INFO {
            bytes = tcp_info_bytes(value);
        }
    });

    Some(SockInfo {
        protocol: proto,
        state,
        local: (src, sport),
        remote: (dst, dport),
        uid,
        inode,
        cookie,
        bytes,
    })
}

fn read_addr(family: u8, raw: &[u8]) -> IpAddr {
    if family == libc::AF_INET as u8 {
        IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))
    } else {
        let mut o = [0u8; 16];
        o.copy_from_slice(&raw[0..16]);
        IpAddr::V6(Ipv6Addr::from(o))
    }
}

// tcpi_bytes_acked and tcpi_bytes_received live at fixed offsets in tcp_info
// (120 and 128); the struct only ever grows by appending fields, so these are
// stable on every kernel since 4.6. guard on the attribute length in case a very
// old kernel returns a shorter struct.
const TCPI_BYTES_ACKED: usize = 120;
const TCPI_BYTES_RECEIVED: usize = 128;

fn tcp_info_bytes(info: &[u8]) -> Option<(u64, u64)> {
    if info.len() < TCPI_BYTES_RECEIVED + 8 {
        return None;
    }
    let sent = u64::from_ne_bytes(
        info[TCPI_BYTES_ACKED..TCPI_BYTES_ACKED + 8]
            .try_into()
            .ok()?,
    );
    let recv = u64::from_ne_bytes(
        info[TCPI_BYTES_RECEIVED..TCPI_BYTES_RECEIVED + 8]
            .try_into()
            .ok()?,
    );
    Some((sent, recv))
}

/// true once a TCP socket has a real peer (past LISTEN/SYN); UDP is always ready
pub fn is_established(state: u8) -> bool {
    state as u32 == TCP_ESTABLISHED
}

/// ask the kernel to close a socket via SOCK_DESTROY. needs
/// CONFIG_INET_DIAG_DESTROY; returns Ok(false) if the kernel lacks it so the
/// caller can fall back. `family`/`ipproto` and the tuple identify the socket.
pub fn destroy(
    family: u8,
    ipproto: u8,
    local: (IpAddr, u16),
    remote: (IpAddr, u16),
) -> std::io::Result<bool> {
    let sock = NlSocket::open(NETLINK_INET_DIAG)?;
    sock.send(&build_destroy(family, ipproto, local, remote))?;
    match sock.recv_dump(|_, _| {}) {
        Ok(()) => Ok(true),
        Err(e) => {
            // the kernel reports the missing feature as EOPNOTSUPP; a socket the
            // kernel already closed reports ENOENT, which is a success for us
            match e.raw_os_error() {
                Some(libc::EOPNOTSUPP) => Ok(false),
                Some(libc::ENOENT) => Ok(true),
                _ => Err(e),
            }
        }
    }
}

fn build_destroy(family: u8, ipproto: u8, local: (IpAddr, u16), remote: (IpAddr, u16)) -> Vec<u8> {
    use crate::netlink::NLM_F_ACK;
    const REQ_LEN: usize = 56;
    const TOTAL: usize = 16 + REQ_LEN;
    let mut buf = vec![0u8; TOTAL];
    buf[0..4].copy_from_slice(&(TOTAL as u32).to_ne_bytes());
    buf[4..6].copy_from_slice(&SOCK_DESTROY.to_ne_bytes());
    buf[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());

    let body = 16;
    buf[body] = family;
    buf[body + 1] = ipproto;
    // states: target exactly the established socket
    buf[body + 4..body + 8].copy_from_slice(&(1u32 << TCP_ESTABLISHED).to_ne_bytes());

    // the 48-byte sockid begins at body+8: sport, dport (big-endian), src, dst
    let id = body + 8;
    buf[id..id + 2].copy_from_slice(&local.1.to_be_bytes());
    buf[id + 2..id + 4].copy_from_slice(&remote.1.to_be_bytes());
    write_addr(&mut buf[id + 4..id + 20], local.0);
    write_addr(&mut buf[id + 20..id + 36], remote.0);
    buf
}

fn write_addr(dst: &mut [u8], ip: IpAddr) {
    match ip {
        IpAddr::V4(v4) => dst[0..4].copy_from_slice(&v4.octets()),
        IpAddr::V6(v6) => dst[0..16].copy_from_slice(&v6.octets()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_dump_excludes_listeners() {
        assert_eq!(tcp_states() & (1 << TCP_LISTEN), 0);
    }

    #[test]
    fn attribution_dump_requests_listeners() {
        assert_ne!(STATES_ALL & (1 << TCP_LISTEN), 0);
    }
}
