//! per-process connection enumeration from sock_diag, the Linux counterpart to
//! the Windows IP Helper tables. it lists active TCP connections (past LISTEN)
//! with their owning process, resolved by mapping each socket's inode to the pid
//! that holds it open. cheap and unprivileged, so the activity view shows what
//! each app is connected to even when the byte monitor could not start.

use crate::dns::{self, DnsMap};
use crate::proc;
use crate::proc::PidCache;
use crate::sockets::{self, SockInfo};
use iris_core::{Conn, ConnState, Direction, Endpoint, Protocol};
use std::collections::HashMap;
use std::net::IpAddr;

// interactive apps run at uid 1000 and up; system daemons run below it. refuse
// to kill a connection owned by a system account so an unprivileged UI cannot
// tear down a service's uplink it could never touch on its own, mirroring the
// Windows session-0 refusal.
const FIRST_NORMAL_UID: u32 = 1000;

/// how many connections to keep per process; the count stays exact
const MAX_CONNS_PER_PROC: usize = 64;

// the endpoint with the lower port is almost always the server; if that is us,
// the connection came inbound, otherwise we dialed out
fn direction(local_port: u16, remote_port: u16) -> Direction {
    if local_port < remote_port {
        Direction::Inbound
    } else {
        Direction::Outbound
    }
}

fn conn_state(s: &SockInfo) -> ConnState {
    if sockets::is_established(s.state) {
        ConnState::Active
    } else {
        ConnState::Closing
    }
}

/// connection enumeration keyed by process, with host names filled from captured
/// DNS. reuses a pid cache so it does not readlink every socket every second.
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

    /// clear the pid->path cache to bound pid-reuse staleness
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// current connections grouped by owning pid, each with the process path
    pub fn by_pid(&mut self) -> HashMap<u32, (String, Vec<Conn>)> {
        let snapshot = dns::sockets(&self.dns);
        let (socks, owners) = match snapshot {
            Some(snapshot) => (snapshot.socks, snapshot.owners),
            None => (sockets::dump(), proc::socket_inode_owners()),
        };
        let mut out: HashMap<u32, (String, Vec<Conn>)> = HashMap::new();

        for s in socks {
            // only TCP has a real peer to show; a UDP socket usually has no
            // connected remote, matching the Windows view which lists TCP only
            if !s.is_tcp() {
                continue;
            }
            // an unconnected socket has a zero remote; skip it
            if s.remote.1 == 0 || s.remote.0.is_unspecified() {
                continue;
            }
            let Some(&pid) = owners.get(&(s.inode as u64)) else {
                continue;
            };
            let Some(path) = self.cache.resolve(pid) else {
                continue;
            };
            let entry = out.entry(pid).or_insert_with(|| (path, Vec::new()));
            if entry.1.len() >= MAX_CONNS_PER_PROC {
                continue;
            }
            let host = dns::lookup(&self.dns, &s.remote.0);
            entry.1.push(Conn {
                remote: Endpoint {
                    addr: s.remote.0,
                    port: s.remote.1,
                    protocol: Protocol::Tcp,
                },
                host,
                local_port: s.local.1,
                direction: direction(s.local.1, s.remote.1),
                state: conn_state(&s),
            });
        }
        out
    }
}

/// terminate an established TCP connection matching the tuple. tries the clean
/// SOCK_DESTROY path and return false when the kernel cannot close the socket
pub fn kill_connection(local_port: u16, remote: IpAddr, remote_port: u16) -> bool {
    // find the live socket so we know its local address, family, and owner
    let Some(target) = sockets::dump().into_iter().find(|s| {
        s.is_tcp() && s.local.1 == local_port && s.remote.0 == remote && s.remote.1 == remote_port
    }) else {
        return false;
    };
    if target.uid < FIRST_NORMAL_UID {
        tracing::warn!(
            "refusing to kill a system-owned connection (uid {})",
            target.uid
        );
        return false;
    }

    let family = if target.local.0.is_ipv4() {
        libc::AF_INET as u8
    } else {
        libc::AF_INET6 as u8
    };
    match sockets::destroy(family, libc::IPPROTO_TCP as u8, target.local, target.remote) {
        Ok(true) => return true,
        Ok(false) => {
            tracing::warn!("kernel lacks SOCK_DESTROY; connection kill is unavailable");
        }
        Err(e) => {
            tracing::warn!("SOCK_DESTROY failed: {e}");
        }
    }
    false
}
