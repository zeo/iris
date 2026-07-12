//! network pinning for sandboxed plugin children. every plugin runs as the
//! dedicated `iris-plugin` user, so a single nftables table constrains that
//! user's egress: default-drop, with narrow permits for exactly the remote
//! endpoints the user consented to (plus port 53 when a plugin resolves names
//! itself) and loopback for local IPC. the table is rebuilt whenever a plugin's
//! grant changes, and torn down when the last plugin stops. this is named
//! `PluginNet`/`AppPin` to match the Windows egress seam.
//!
//! all plugins share the sandbox uid, so the permitted set is the union across
//! active plugins. the per-process restricted spawn is the primary isolation;
//! this pin is defence-in-depth against exfiltration, so union semantics are an
//! acceptable, documented trade rather than a hole.

use iris_core::{EngineError, EngineResult};
use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const TABLE: &str = "iris_plugins";
const PLUGIN_USER: &str = "iris-plugin";

/// the shared table pinning every plugin child's egress
pub struct PluginNet {
    uid: u32,
    pins: HashMap<PathBuf, Grant>,
}

#[derive(Clone)]
struct Grant {
    allowed: Vec<SocketAddr>,
    allow_dns: bool,
}

/// identifies one plugin's pin so its permits can be swapped or dropped. the
/// permit set lives in the shared table keyed by exe path, so this carries no
/// per-pin state of its own; it exists to match the Windows `AppPin` seam.
#[allow(dead_code)]
pub struct AppPin {
    exe: PathBuf,
}

// the netlink/nft side is guarded by the supervisor's mutex
unsafe impl Send for PluginNet {}

impl PluginNet {
    /// resolve the sandbox uid and install the default-drop table. fails closed
    /// if the plugin account is missing, so no child ever runs unpinned.
    pub fn open() -> EngineResult<PluginNet> {
        let uid = plugin_uid()?;
        let mut net = PluginNet {
            uid,
            pins: HashMap::new(),
        };
        net.rebuild()?;
        Ok(net)
    }

    /// pin one plugin binary to its granted endpoints
    pub fn pin(
        &mut self,
        exe: &Path,
        allowed: &[SocketAddr],
        allow_dns: bool,
    ) -> EngineResult<AppPin> {
        self.pins.insert(
            exe.to_path_buf(),
            Grant {
                allowed: allowed.to_vec(),
                allow_dns,
            },
        );
        self.rebuild()?;
        Ok(AppPin {
            exe: exe.to_path_buf(),
        })
    }

    /// swap a pinned plugin's permits for a re-resolved endpoint set
    pub fn repin(
        &mut self,
        exe: &Path,
        _pin: &mut AppPin,
        allowed: &[SocketAddr],
        allow_dns: bool,
    ) -> EngineResult<()> {
        self.pins.insert(
            exe.to_path_buf(),
            Grant {
                allowed: allowed.to_vec(),
                allow_dns,
            },
        );
        self.rebuild()
    }

    /// regenerate the whole table from the current union of grants. the plugin
    /// user's traffic is dropped by default; everything else is untouched.
    fn rebuild(&mut self) -> EngineResult<()> {
        let mut permits = String::new();
        let mut any_dns = false;
        for grant in self.pins.values() {
            any_dns |= grant.allow_dns;
            for addr in &grant.allowed {
                let (proto_fam, ip) = match addr {
                    SocketAddr::V4(v4) => ("ip", v4.ip().to_string()),
                    SocketAddr::V6(v6) => ("ip6", v6.ip().to_string()),
                };
                // permit both TCP and UDP to the granted endpoint
                permits.push_str(&format!(
                    "        {proto_fam} daddr {ip} th dport {port} accept\n",
                    port = addr.port()
                ));
            }
        }
        let dns = if any_dns {
            "        udp dport 53 accept\n        tcp dport 53 accept\n"
        } else {
            ""
        };

        let ruleset = format!(
            "table inet {TABLE} {{
    chain out {{
        type filter hook output priority -5; policy accept;
        meta skuid != {uid} accept
        oif \"lo\" accept
{dns}{permits}        meta skuid {uid} drop
    }}
}}
",
            uid = self.uid
        );
        remove_table();
        run_nft(&ruleset)
    }
}

impl Drop for PluginNet {
    fn drop(&mut self) {
        remove_table();
    }
}

fn plugin_uid() -> EngineResult<u32> {
    let name = std::ffi::CString::new(PLUGIN_USER).unwrap();
    let pw = unsafe { libc::getpwnam(name.as_ptr()) };
    if pw.is_null() {
        return Err(EngineError::NotFound(format!(
            "plugin account '{PLUGIN_USER}' does not exist"
        )));
    }
    Ok(unsafe { (*pw).pw_uid })
}

fn remove_table() {
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", TABLE])
        .output();
}

fn run_nft(ruleset: &str) -> EngineResult<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| EngineError::Os(format!("cannot run nft: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(ruleset.as_bytes())
            .map_err(|e| EngineError::Os(format!("cannot write nft ruleset: {e}")))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| EngineError::Os(format!("nft did not complete: {e}")))?;
    if !out.status.success() {
        return Err(EngineError::Os(format!(
            "nft failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}
