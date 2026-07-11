//! the Windows engine backend for iris: ETW per-app network monitoring, DNS
//! name capture, and connection enumeration today, WFP allow/block rules in a
//! later slice. everything here is `cfg(windows)`; the crate is empty on other
//! targets so the service can depend on it unconditionally.

#[cfg(windows)]
mod conn;
#[cfg(windows)]
mod dns;
#[cfg(windows)]
mod etw;
#[cfg(windows)]
mod proc;

#[cfg(windows)]
pub use conn::ConnCounter;
#[cfg(windows)]
pub use dns::{new_map, DnsMap};
#[cfg(windows)]
pub use etw::Monitor;
