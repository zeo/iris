//! the Linux engine backend for iris. it mirrors the public surface of
//! `iris-platform-win` so the service depends on whichever platform crate fits
//! the target and calls the same names: sock_diag connection enumeration and
//! per-socket byte accounting, DNS name capture off the wire, nftables + a
//! NFQUEUE verdict thread for allow/block rules, per-uid egress pinning for
//! sandboxed plugins, adapter classification from sysfs, and a setuid+seccomp
//! restricted spawn. everything here is `cfg(target_os = "linux")`; the crate is
//! empty on other targets so the service can depend on it unconditionally.

#[cfg(target_os = "linux")]
mod adapters;
#[cfg(target_os = "linux")]
mod conn;
#[cfg(target_os = "linux")]
mod ct;
#[cfg(target_os = "linux")]
mod dns;
#[cfg(target_os = "linux")]
mod egress;
#[cfg(target_os = "linux")]
mod fw;
#[cfg(target_os = "linux")]
mod monitor;
#[cfg(target_os = "linux")]
mod netlink;
#[cfg(target_os = "linux")]
mod proc;
#[cfg(target_os = "linux")]
mod sockets;
#[cfg(target_os = "linux")]
mod spawn;
#[cfg(target_os = "linux")]
mod svc;

#[cfg(target_os = "linux")]
pub use adapters::AdapterMap;
#[cfg(target_os = "linux")]
pub use conn::{kill_connection, ConnCounter};
#[cfg(target_os = "linux")]
pub use dns::{new_map, DnsMap};
#[cfg(target_os = "linux")]
pub use egress::{AppPin, PluginNet};
#[cfg(target_os = "linux")]
pub use fw::Wfp;
#[cfg(target_os = "linux")]
pub use monitor::Monitor;
#[cfg(target_os = "linux")]
pub use spawn::{random_token, spawn_restricted, RestrictedChild};
#[cfg(target_os = "linux")]
pub use svc::ServiceMap;
