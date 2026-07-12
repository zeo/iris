//! the active OS backend, re-exported under one name so the engine calls
//! `platform::Foo` regardless of target. both backend crates expose the identical
//! surface (`Monitor`, `ConnCounter`, `ServiceMap`, `DnsMap`/`new_map`,
//! `AdapterMap`, `kill_connection`, `Wfp`, `PluginNet`/`AppPin`,
//! `spawn_restricted`/`RestrictedChild`/`random_token`), so the gated code that
//! uses them is written once behind the `has_platform` cfg.

#[cfg(windows)]
pub use iris_platform_win::*;

#[cfg(target_os = "linux")]
pub use iris_platform_linux::*;
