//! the Windows engine backend for iris: ETW per-app network monitoring today,
//! WFP allow/block rules in a later slice. everything here is `cfg(windows)`;
//! the crate is empty on other targets so the service can depend on it
//! unconditionally.

#[cfg(windows)]
mod etw;
#[cfg(windows)]
mod proc;

#[cfg(windows)]
pub use etw::Monitor;
