//! conntrack (ctnetlink) access: a flow dump with byte counters for UDP
//! accounting, and a single-flow delete used as the connection-kill fallback on
//! kernels without SOCK_DESTROY. TCP byte accounting comes from tcp_info in
//! [`crate::sockets`]; conntrack fills the UDP gap, where per-socket counters do
//! not exist. all of this degrades to a no-op if conntrack is not present.

use crate::netlink::{self, NlSocket, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST};
use iris_core::Protocol;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const NETLINK_NETFILTER: libc::c_int = 12;
const NFNL_SUBSYS_CTNETLINK: u16 = 1;
const IPCTNL_MSG_CT_GET: u16 = 1;
const IPCTNL_MSG_CT_DELETE: u16 = 2;

// top-level conntrack attributes
const CTA_TUPLE_ORIG: u16 = 1;
const CTA_COUNTERS_ORIG: u16 = 9;
const CTA_COUNTERS_REPLY: u16 = 10;
// tuple attributes
const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_IP_V6_SRC: u16 = 3;
const CTA_IP_V6_DST: u16 = 4;
const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;
// counter attributes
const CTA_COUNTERS_BYTES: u16 = 2;

const NLA_F_NESTED: u16 = 0x8000;

fn ct_msg_type(msg: u16) -> u16 {
    (NFNL_SUBSYS_CTNETLINK << 8) | msg
}

/// one conntrack flow: its original-direction tuple plus the byte counters in
/// each direction. `orig` counts bytes the initiator sent; `reply` counts bytes
/// coming back.
pub struct Flow {
    pub protocol: Protocol,
    pub orig_src: IpAddr,
    pub orig_dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub orig_bytes: u64,
    pub reply_bytes: u64,
}

/// enable byte/packet accounting so conntrack counters are populated. off by
/// default on most kernels; a best-effort write, since UDP accounting simply
/// stays empty if it fails.
pub fn enable_acct() {
    let _ = std::fs::write("/proc/sys/net/netfilter/nf_conntrack_acct", "1\n");
}

/// dump every conntrack flow with counters. an empty vec on any failure (no
/// conntrack, no permission) so the monitor degrades cleanly.
pub fn dump() -> Vec<Flow> {
    match dump_inner() {
        Ok(flows) => flows,
        Err(e) => {
            tracing::debug!("conntrack dump unavailable: {e}");
            Vec::new()
        }
    }
}

fn dump_inner() -> io::Result<Vec<Flow>> {
    let sock = NlSocket::open(NETLINK_NETFILTER)?;
    sock.send(&build_dump())?;
    let mut flows = Vec::new();
    sock.recv_dump(|_, payload| {
        // skip the 4-byte nfgenmsg header, then walk the attributes
        if payload.len() > 4 {
            if let Some(flow) = parse_flow(&payload[4..]) {
                flows.push(flow);
            }
        }
    })?;
    Ok(flows)
}

fn build_dump() -> Vec<u8> {
    // nlmsghdr(16) + nfgenmsg(4)
    let mut buf = vec![0u8; 20];
    buf[0..4].copy_from_slice(&20u32.to_ne_bytes());
    buf[4..6].copy_from_slice(&ct_msg_type(IPCTNL_MSG_CT_GET).to_ne_bytes());
    buf[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    // nfgenmsg: family AF_UNSPEC (dump all), version 0, res_id 0
    buf[16] = libc::AF_UNSPEC as u8;
    buf
}

fn parse_flow(attrs: &[u8]) -> Option<Flow> {
    let mut proto = None;
    let mut orig_src = None;
    let mut orig_dst = None;
    let mut sport = 0u16;
    let mut dport = 0u16;
    let mut orig_bytes = 0u64;
    let mut reply_bytes = 0u64;

    netlink::for_each_attr(attrs, |ty, value| match ty & !NLA_F_NESTED {
        CTA_TUPLE_ORIG => {
            parse_tuple(
                value,
                &mut proto,
                &mut orig_src,
                &mut orig_dst,
                &mut sport,
                &mut dport,
            );
        }
        CTA_COUNTERS_ORIG => orig_bytes = counter_bytes(value),
        CTA_COUNTERS_REPLY => reply_bytes = counter_bytes(value),
        _ => {}
    });

    Some(Flow {
        protocol: proto?,
        orig_src: orig_src?,
        orig_dst: orig_dst?,
        sport,
        dport,
        orig_bytes,
        reply_bytes,
    })
}

fn parse_tuple(
    data: &[u8],
    proto: &mut Option<Protocol>,
    src: &mut Option<IpAddr>,
    dst: &mut Option<IpAddr>,
    sport: &mut u16,
    dport: &mut u16,
) {
    netlink::for_each_attr(data, |ty, value| match ty & !NLA_F_NESTED {
        CTA_TUPLE_IP => {
            netlink::for_each_attr(value, |ity, ivalue| match ity & !NLA_F_NESTED {
                CTA_IP_V4_SRC if ivalue.len() == 4 => *src = Some(v4(ivalue)),
                CTA_IP_V4_DST if ivalue.len() == 4 => *dst = Some(v4(ivalue)),
                CTA_IP_V6_SRC if ivalue.len() == 16 => *src = Some(v6(ivalue)),
                CTA_IP_V6_DST if ivalue.len() == 16 => *dst = Some(v6(ivalue)),
                _ => {}
            });
        }
        CTA_TUPLE_PROTO => {
            netlink::for_each_attr(value, |pty, pvalue| match pty & !NLA_F_NESTED {
                CTA_PROTO_NUM if !pvalue.is_empty() => {
                    *proto = match pvalue[0] as i32 {
                        libc::IPPROTO_TCP => Some(Protocol::Tcp),
                        libc::IPPROTO_UDP => Some(Protocol::Udp),
                        _ => None,
                    };
                }
                CTA_PROTO_SRC_PORT if pvalue.len() == 2 => {
                    *sport = u16::from_be_bytes([pvalue[0], pvalue[1]]);
                }
                CTA_PROTO_DST_PORT if pvalue.len() == 2 => {
                    *dport = u16::from_be_bytes([pvalue[0], pvalue[1]]);
                }
                _ => {}
            });
        }
        _ => {}
    });
}

fn counter_bytes(data: &[u8]) -> u64 {
    let mut bytes = 0u64;
    netlink::for_each_attr(data, |ty, value| {
        if ty & !NLA_F_NESTED == CTA_COUNTERS_BYTES && value.len() == 8 {
            bytes = u64::from_be_bytes(value.try_into().unwrap());
        }
    });
    bytes
}

fn v4(b: &[u8]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
}

fn v6(b: &[u8]) -> IpAddr {
    let mut o = [0u8; 16];
    o.copy_from_slice(&b[0..16]);
    IpAddr::V6(Ipv6Addr::from(o))
}

/// delete the conntrack entry for one flow, identified by its original tuple.
/// used as the kill fallback when the kernel has no SOCK_DESTROY.
pub fn delete_flow(local: (IpAddr, u16), remote: (IpAddr, u16), ipproto: u8) -> io::Result<bool> {
    let sock = NlSocket::open(NETLINK_NETFILTER)?;
    sock.send(&build_delete(local, remote, ipproto))?;
    match sock.recv_dump(|_, _| {}) {
        Ok(()) => Ok(true),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(false),
        Err(e) => Err(e),
    }
}

fn build_delete(local: (IpAddr, u16), remote: (IpAddr, u16), ipproto: u8) -> Vec<u8> {
    let family = if local.0.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    } as u8;

    let mut body = Vec::new();
    // nfgenmsg
    body.push(family);
    body.push(0); // version
    body.extend_from_slice(&0u16.to_ne_bytes()); // res_id

    // CTA_TUPLE_ORIG { CTA_TUPLE_IP { src, dst }, CTA_TUPLE_PROTO { num, sport, dport } }
    let mut ip = Vec::new();
    match (local.0, remote.0) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            push_attr(&mut ip, CTA_IP_V4_SRC, &s.octets());
            push_attr(&mut ip, CTA_IP_V4_DST, &d.octets());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            push_attr(&mut ip, CTA_IP_V6_SRC, &s.octets());
            push_attr(&mut ip, CTA_IP_V6_DST, &d.octets());
        }
        _ => {}
    }
    let mut proto = Vec::new();
    push_attr(&mut proto, CTA_PROTO_NUM, &[ipproto]);
    push_attr(&mut proto, CTA_PROTO_SRC_PORT, &local.1.to_be_bytes());
    push_attr(&mut proto, CTA_PROTO_DST_PORT, &remote.1.to_be_bytes());

    let mut tuple = Vec::new();
    push_attr(&mut tuple, CTA_TUPLE_IP | NLA_F_NESTED, &ip);
    push_attr(&mut tuple, CTA_TUPLE_PROTO | NLA_F_NESTED, &proto);
    push_attr(&mut body, CTA_TUPLE_ORIG | NLA_F_NESTED, &tuple);

    let total = 16 + body.len();
    let mut buf = Vec::with_capacity(netlink::align4(total));
    buf.extend_from_slice(&(total as u32).to_ne_bytes());
    buf.extend_from_slice(&ct_msg_type(IPCTNL_MSG_CT_DELETE).to_ne_bytes());
    buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes()); // seq
    buf.extend_from_slice(&0u32.to_ne_bytes()); // pid
    buf.extend_from_slice(&body);
    buf
}

/// append one rtattr (type, payload) with 4-byte padding
fn push_attr(buf: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    let len = 4 + payload.len();
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&ty.to_ne_bytes());
    buf.extend_from_slice(payload);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
}
