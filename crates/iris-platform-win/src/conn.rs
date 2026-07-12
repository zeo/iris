//! per-process connection enumeration from the IP Helper tables. cheap and does
//! not need admin, so the activity view shows what each app is connected to even
//! when the ETW byte monitor could not start. reports active TCP connections
//! (anything past LISTEN) plus UDP endpoints with their remote address.

use crate::dns::{self, DnsMap};
use crate::proc::PidCache;
use iris_core::{Conn, ConnState, Direction, Endpoint, Protocol};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, SetTcpEntry, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_LH,
    MIB_TCPTABLE_OWNER_PID, MIB_TCP_STATE_CLOSED, MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_LISTEN,
    TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

// MIB_TCP_STATE_DELETE_TCB: writing this state via SetTcpEntry tears the
// connection down
const DELETE_TCB: u32 = 12;

// true if the pid runs in session 0 (system services) or its session cannot be
// determined. used to keep the kill primitive off system-owned connections;
// failing closed (treat unknown as system) is the safe choice for a teardown.
unsafe fn in_system_session(pid: u32) -> bool {
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    let mut session: u32 = 0;
    match ProcessIdToSessionId(pid, &mut session) {
        Ok(()) => session == 0,
        Err(_) => true,
    }
}

/// terminate an established TCP connection matching the tuple. IPv4 only, since
/// SetTcpEntry has no v6 form. returns true if a matching connection was killed.
pub fn kill_connection(local_port: u16, remote: IpAddr, remote_port: u16) -> bool {
    let IpAddr::V4(rip) = remote else {
        return false;
    };
    let want_remote = u32::from_ne_bytes(rip.octets());
    unsafe {
        let buf = fetch_tcp(AF_INET.0 as u32);
        if buf.is_empty() {
            return false;
        }
        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
        for r in rows {
            if port(r.dwLocalPort) == local_port
                && r.dwRemoteAddr == want_remote
                && port(r.dwRemotePort) == remote_port
            {
                // refuse to tear down a system-service connection (session 0):
                // the engine runs as LocalSystem, so without this an unprivileged
                // caller could kill Defender/EDR/svchost uplinks it could never
                // touch on its own. interactive-session connections stay killable.
                if in_system_session(r.dwOwningPid) {
                    return false;
                }
                let mut row: MIB_TCPROW_LH = std::mem::zeroed();
                row.Anonymous.dwState = DELETE_TCB;
                row.dwLocalAddr = r.dwLocalAddr;
                row.dwLocalPort = r.dwLocalPort;
                row.dwRemoteAddr = r.dwRemoteAddr;
                row.dwRemotePort = r.dwRemotePort;
                return SetTcpEntry(&row) == 0;
            }
        }
    }
    false
}

/// how many connections to keep per process on the wire; the count stays exact
const MAX_CONNS_PER_PROC: usize = 64;

struct RawConn {
    pid: u32,
    remote: Endpoint,
    local_port: u16,
    state: ConnState,
}

// the endpoint with the lower port is almost always the server; if that is us,
// the connection came inbound, otherwise we dialed out
fn direction(local_port: u16, remote_port: u16) -> Direction {
    if local_port < remote_port {
        Direction::Inbound
    } else {
        Direction::Outbound
    }
}

/// connection enumeration keyed by process, with host names filled from captured
/// DNS. reuses a PID cache so it does not open a handle per socket every second.
pub struct ConnCounter {
    cache: PidCache,
    dns: DnsMap,
}

impl ConnCounter {
    pub fn new(dns: DnsMap) -> Self {
        ConnCounter {
            cache: PidCache::new(),
            dns,
        }
    }

    /// clear the PID->path cache to bound PID-reuse staleness
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// current connections grouped by owning PID, each with the process path
    pub fn by_pid(&mut self) -> HashMap<u32, (String, Vec<Conn>)> {
        let raw = snapshot();
        let mut out: HashMap<u32, (String, Vec<Conn>)> = HashMap::new();
        for r in raw {
            let Some(path) = self.cache.resolve(r.pid) else {
                continue;
            };
            let entry = out.entry(r.pid).or_insert_with(|| (path, Vec::new()));
            if entry.1.len() < MAX_CONNS_PER_PROC {
                let host = dns::lookup(&self.dns, &r.remote.addr);
                let dir = direction(r.local_port, r.remote.port);
                entry.1.push(Conn {
                    remote: r.remote,
                    host,
                    local_port: r.local_port,
                    direction: dir,
                    state: r.state,
                });
            }
        }
        out
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
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    let mut size = 0u32;
    // prime the required size, then fetch. on a busy machine the table can grow
    // between the probe and the fetch; on ERROR_INSUFFICIENT_BUFFER the call
    // updates `size` to the new requirement, so retry rather than blanking the
    // whole connection view for this tick
    let _ = GetExtendedTcpTable(None, &mut size, false, af, TCP_TABLE_OWNER_PID_ALL, 0);
    for _ in 0..5 {
        if size == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u8; size as usize];
        let ptr = Some(buf.as_mut_ptr() as *mut core::ffi::c_void);
        match GetExtendedTcpTable(ptr, &mut size, false, af, TCP_TABLE_OWNER_PID_ALL, 0) {
            0 => return buf,
            ERROR_INSUFFICIENT_BUFFER => continue,
            _ => return Vec::new(),
        }
    }
    Vec::new()
}

unsafe fn tcp4(out: &mut Vec<RawConn>) {
    let buf = fetch_tcp(AF_INET.0 as u32);
    if buf.is_empty() {
        return;
    }
    let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
    let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
    for r in rows {
        if r.dwState == MIB_TCP_STATE_LISTEN.0 as u32 || r.dwState == MIB_TCP_STATE_CLOSED.0 as u32
        {
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
        if r.dwState == MIB_TCP_STATE_LISTEN.0 as u32 || r.dwState == MIB_TCP_STATE_CLOSED.0 as u32
        {
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
