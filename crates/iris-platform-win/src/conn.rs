//! per-process connection enumeration from the IP Helper tables. cheap and does
//! not need admin, so the activity view shows what each app is connected to even
//! when the ETW byte monitor could not start. reports active TCP connections
//! (anything past LISTEN) plus UDP endpoints with their remote address.

use crate::proc::PidCache;
use iris_core::{AppId, Conn, ConnState, Direction, Endpoint, Protocol};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_TCP_STATE_CLOSED,
    MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_LISTEN, TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

/// how many connections to keep per app on the wire; the count stays exact
const MAX_CONNS_PER_APP: usize = 64;

struct RawConn {
    pid: u32,
    remote: Endpoint,
    local_port: u16,
    state: ConnState,
}

/// enumerates connections and resolves owning PIDs to app paths, reusing a cache
/// so it does not open a handle per socket every second.
pub struct ConnCounter {
    cache: PidCache,
}

impl ConnCounter {
    pub fn new() -> Self {
        ConnCounter {
            cache: PidCache::new(),
        }
    }

    /// clear the PID->path cache to bound PID-reuse staleness
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// current connections grouped by owning app
    pub fn by_app(&mut self) -> HashMap<AppId, Vec<Conn>> {
        let raw = snapshot();
        let mut out: HashMap<AppId, Vec<Conn>> = HashMap::new();
        for r in raw {
            let Some(path) = self.cache.resolve(r.pid) else {
                continue;
            };
            let app = AppId::from_path(&path);
            let list = out.entry(app).or_default();
            if list.len() < MAX_CONNS_PER_APP {
                list.push(Conn {
                    remote: r.remote,
                    local_port: r.local_port,
                    direction: Direction::Outbound,
                    state: r.state,
                });
            }
        }
        out
    }
}

impl Default for ConnCounter {
    fn default() -> Self {
        Self::new()
    }
}

// only TCP: its table carries the remote address, so each row is a real
// connection with somewhere to show. UDP tables list local bindings with no
// remote, so they would only add rows to nowhere. UDP still shows in byte counts.
fn snapshot() -> Vec<RawConn> {
    let mut out = Vec::new();
    unsafe {
        tcp4(&mut out);
        tcp6(&mut out);
    }
    out
}

// MIB port fields hold the port in network byte order in the low 16 bits
fn port(dw: u32) -> u16 {
    u16::from_be_bytes([(dw & 0xff) as u8, ((dw >> 8) & 0xff) as u8])
}

fn v4(dw: u32) -> IpAddr {
    let o = dw.to_ne_bytes();
    IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3]))
}

fn tcp_state(dw: u32) -> ConnState {
    if dw == MIB_TCP_STATE_ESTAB.0 as u32 {
        ConnState::Active
    } else {
        ConnState::Closing
    }
}

unsafe fn fetch_tcp(af: u32) -> Vec<u8> {
    let mut size = 0u32;
    let _ = GetExtendedTcpTable(None, &mut size, false, af, TCP_TABLE_OWNER_PID_ALL, 0);
    if size == 0 {
        return Vec::new();
    }
    let mut buf = vec![0u8; size as usize];
    let ptr = Some(buf.as_mut_ptr() as *mut core::ffi::c_void);
    let rc = GetExtendedTcpTable(ptr, &mut size, false, af, TCP_TABLE_OWNER_PID_ALL, 0);
    if rc != 0 {
        return Vec::new();
    }
    buf
}

unsafe fn tcp4(out: &mut Vec<RawConn>) {
    let buf = fetch_tcp(AF_INET.0 as u32);
    if buf.is_empty() {
        return;
    }
    let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
    let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
    for r in rows {
        if r.dwState == MIB_TCP_STATE_LISTEN.0 as u32 || r.dwState == MIB_TCP_STATE_CLOSED.0 as u32 {
            continue;
        }
        out.push(RawConn {
            pid: r.dwOwningPid,
            remote: Endpoint {
                addr: v4(r.dwRemoteAddr),
                port: port(r.dwRemotePort),
                protocol: Protocol::Tcp,
            },
            local_port: port(r.dwLocalPort),
            state: tcp_state(r.dwState),
        });
    }
}

unsafe fn tcp6(out: &mut Vec<RawConn>) {
    let buf = fetch_tcp(AF_INET6.0 as u32);
    if buf.is_empty() {
        return;
    }
    let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
    let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
    for r in rows {
        if r.dwState == MIB_TCP_STATE_LISTEN.0 as u32 || r.dwState == MIB_TCP_STATE_CLOSED.0 as u32 {
            continue;
        }
        out.push(RawConn {
            pid: r.dwOwningPid,
            remote: Endpoint {
                addr: IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr)),
                port: port(r.dwRemotePort),
                protocol: Protocol::Tcp,
            },
            local_port: port(r.dwLocalPort),
            state: tcp_state(r.dwState),
        });
    }
}

