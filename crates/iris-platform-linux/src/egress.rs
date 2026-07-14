//! network pinning for sandboxed plugin children. every plugin gets its own
//! cgroup-v2 leaf below the engine service. nftables matches the originating
//! socket's leaf and grants only that plugin's approved endpoints. the shared
//! sandbox uid remains the final default-drop boundary.

use iris_core::{EngineError, EngineResult};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
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
    cgroup: Cgroup,
}

#[derive(Clone)]
struct Cgroup {
    path: PathBuf,
    nft_path: String,
    level: usize,
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
        let net = PluginNet {
            uid,
            pins: HashMap::new(),
        };
        remove_table();
        net.install()?;
        Ok(net)
    }

    /// pin one plugin binary to its granted endpoints
    pub fn pin(
        &mut self,
        exe: &Path,
        allowed: &[SocketAddr],
        allow_dns: bool,
    ) -> EngineResult<AppPin> {
        let cgroup = create_cgroup(exe)?;
        self.reject_cgroup_collision(exe, &cgroup)?;
        let previous = self.pins.insert(
            exe.to_path_buf(),
            Grant {
                allowed: allowed.to_vec(),
                allow_dns,
                cgroup: cgroup.clone(),
            },
        );
        if let Err(error) = self.rebuild() {
            restore_grant(&mut self.pins, exe, previous);
            let _ = std::fs::remove_dir(cgroup.path);
            return Err(error);
        }
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
        let cgroup = create_cgroup(exe)?;
        self.reject_cgroup_collision(exe, &cgroup)?;
        let previous = self.pins.insert(
            exe.to_path_buf(),
            Grant {
                allowed: allowed.to_vec(),
                allow_dns,
                cgroup,
            },
        );
        if let Err(error) = self.rebuild() {
            restore_grant(&mut self.pins, exe, previous);
            return Err(error);
        }
        Ok(())
    }

    /// regenerate the table from each plugin's private grant
    fn rebuild(&mut self) -> EngineResult<()> {
        run_nft(&format!("flush table inet {TABLE}\n{}", self.chain_rules()))
    }

    fn install(&self) -> EngineResult<()> {
        run_nft(&format!("add table inet {TABLE}\n{}", self.chain_rules()))
    }

    fn reject_cgroup_collision(&self, exe: &Path, cgroup: &Cgroup) -> EngineResult<()> {
        if self
            .pins
            .iter()
            .any(|(pinned, grant)| pinned != exe && grant.cgroup.path == cgroup.path)
        {
            return Err(EngineError::Os(format!(
                "plugin cgroup identity collision for {}",
                exe.display()
            )));
        }
        Ok(())
    }

    fn chain_rules(&self) -> String {
        let mut permits = String::new();
        for grant in self.pins.values() {
            let scope = format!(
                "socket cgroupv2 level {} \"{}\"",
                grant.cgroup.level, grant.cgroup.nft_path
            );
            if grant.allow_dns {
                permits.push_str(&resolver_rules(&scope));
            }
            for addr in &grant.allowed {
                let (proto_fam, ip) = match addr {
                    SocketAddr::V4(v4) => ("ip", v4.ip().to_string()),
                    SocketAddr::V6(v6) => ("ip6", v6.ip().to_string()),
                };
                permits.push_str(&format!(
                    "add rule inet {TABLE} out {scope} {proto_fam} daddr {ip} th dport {port} accept\n",
                    port = addr.port()
                ));
            }
        }

        format!(
            "add chain inet {TABLE} out {{ type filter hook output priority -5; policy accept; }}
add rule inet {TABLE} out meta skuid != {uid} accept
{permits}add rule inet {TABLE} out meta skuid {uid} drop
",
            uid = self.uid
        )
    }
}

fn restore_grant(pins: &mut HashMap<PathBuf, Grant>, exe: &Path, previous: Option<Grant>) {
    match previous {
        Some(grant) => {
            pins.insert(exe.to_path_buf(), grant);
        }
        None => {
            pins.remove(exe);
        }
    }
}

fn resolver_rules(scope: &str) -> String {
    let Ok(config) = std::fs::read_to_string("/etc/resolv.conf") else {
        return String::new();
    };
    config
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            if fields.next()? != "nameserver" {
                return None;
            }
            fields.next()?.parse::<std::net::IpAddr>().ok()
        })
        .map(|ip| {
            let family = if ip.is_ipv4() { "ip" } else { "ip6" };
            format!(
                "add rule inet {TABLE} out {scope} {family} daddr {ip} udp dport 53 accept\nadd rule inet {TABLE} out {scope} {family} daddr {ip} tcp dport 53 accept\n"
            )
        })
        .collect()
}

pub(crate) fn cgroup_for(exe: &Path) -> EngineResult<PathBuf> {
    let current = std::fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| EngineError::Os(format!("cannot read cgroup membership: {error}")))?;
    let relative = current
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| EngineError::Os("cgroup v2 is required for plugin isolation".into()))?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    exe.hash(&mut hasher);
    let leaf = format!("{:016x}", hasher.finish());
    Ok(Path::new("/sys/fs/cgroup")
        .join(relative.trim_start_matches('/'))
        .join("iris-plugins")
        .join(leaf))
}

fn create_cgroup(exe: &Path) -> EngineResult<Cgroup> {
    let path = cgroup_for(exe)?;
    std::fs::create_dir_all(&path)
        .map_err(|error| EngineError::Os(format!("cannot create plugin cgroup: {error}")))?;
    let relative = path
        .strip_prefix("/sys/fs/cgroup")
        .map_err(|_| EngineError::Os("plugin cgroup is outside cgroup v2".into()))?;
    let nft_path = relative
        .to_string_lossy()
        .trim_start_matches('/')
        .to_string();
    let level = relative.components().count();
    Ok(Cgroup {
        path,
        nft_path,
        level,
    })
}

impl Drop for PluginNet {
    fn drop(&mut self) {
        remove_table();
        for grant in self.pins.values() {
            let _ = std::fs::remove_dir(&grant.cgroup.path);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_policy_has_no_loopback_escape() {
        let net = PluginNet {
            uid: 997,
            pins: HashMap::new(),
        };
        let rules = net.chain_rules();
        assert!(!rules.contains("oif"));
        assert!(rules.contains("meta skuid 997 drop"));
    }

    #[test]
    fn granted_endpoint_is_exact() {
        let mut pins = HashMap::new();
        pins.insert(
            PathBuf::from("/plugin"),
            Grant {
                allowed: vec!["192.0.2.4:443".parse().unwrap()],
                allow_dns: false,
                cgroup: Cgroup {
                    path: PathBuf::from("/sys/fs/cgroup/system.slice/iris.service/iris-plugins/a"),
                    nft_path: "system.slice/iris.service/iris-plugins/a".into(),
                    level: 4,
                },
            },
        );
        let rules = PluginNet { uid: 997, pins }.chain_rules();
        assert!(
            rules.contains("socket cgroupv2 level 4 \"system.slice/iris.service/iris-plugins/a\"")
        );
        assert!(rules.contains("ip daddr 192.0.2.4 th dport 443 accept"));
        assert!(!rules.contains("dport 53"));
    }

    #[test]
    fn grants_stay_scoped_to_their_plugin() {
        let mut pins = HashMap::new();
        for (name, endpoint) in [("a", "192.0.2.4:443"), ("b", "198.51.100.8:8443")] {
            pins.insert(
                PathBuf::from(format!("/plugin-{name}")),
                Grant {
                    allowed: vec![endpoint.parse().unwrap()],
                    allow_dns: false,
                    cgroup: Cgroup {
                        path: PathBuf::from(format!("/sys/fs/cgroup/iris-plugins/{name}")),
                        nft_path: format!("iris-plugins/{name}"),
                        level: 2,
                    },
                },
            );
        }

        let rules = PluginNet { uid: 997, pins }.chain_rules();
        assert!(rules.contains(
            "socket cgroupv2 level 2 \"iris-plugins/a\" ip daddr 192.0.2.4 th dport 443 accept"
        ));
        assert!(rules.contains(
            "socket cgroupv2 level 2 \"iris-plugins/b\" ip daddr 198.51.100.8 th dport 8443 accept"
        ));
        assert!(!rules.contains("socket cgroupv2 level 2 \"iris-plugins/a\" ip daddr 198.51.100.8"));
        assert!(!rules.contains("socket cgroupv2 level 2 \"iris-plugins/b\" ip daddr 192.0.2.4"));
    }
}
