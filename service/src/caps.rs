//! per-app upload caps. on windows each cap is a policy-based qos throttle in
//! the active store, which does not survive a reboot, so the json file beside
//! the rules is the source of truth and the engine re-applies it at start. qos
//! throttles what a host sends; download caps would need a callout driver. on
//! linux each cap is an htb class keyed by a flow mark the verdict thread sets,
//! so the store also hands back the mark each capped app's flows must carry.

use iris_core::{AppId, RateCap};
use std::path::PathBuf;

fn caps_path() -> PathBuf {
    crate::paths::rules_file().with_file_name("caps.json")
}

pub struct CapStore {
    caps: Vec<RateCap>,
    backend: platform::Backend,
}

impl CapStore {
    /// load the saved caps and put them in force
    pub fn open() -> CapStore {
        let caps: Vec<RateCap> = std::fs::read_to_string(caps_path())
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default();
        let mut backend = platform::Backend::default();
        if let Err(error) = backend.clear() {
            tracing::warn!("could not clear stale upload caps: {error}");
        }
        for cap in &caps {
            if let Err(error) = backend.apply(cap) {
                tracing::warn!(app = cap.app.as_str(), "could not apply upload cap: {error}");
            }
        }
        CapStore { caps, backend }
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    /// the flow mark each capped app's connections must carry; empty where the
    /// os shaper keys on the app itself
    pub fn marks(&self) -> Vec<(AppId, u32)> {
        self.caps
            .iter()
            .filter_map(|cap| Some((cap.app.clone(), self.backend.mark(&cap.app)?)))
            .collect()
    }

    /// follow the default route when it moves to another interface
    pub fn follow_route(&mut self) {
        if let Err(error) = self.backend.follow_route() {
            tracing::warn!("could not move upload caps to the new interface: {error}");
        }
    }

    pub fn list(&self) -> Vec<RateCap> {
        self.caps.clone()
    }

    /// cap an app's upload at `up_bytes_per_sec`, or lift its cap with none.
    /// returns the mark its flows must now carry, if the platform uses one
    pub fn set(&mut self, app: AppId, up_bytes_per_sec: Option<u64>) -> anyhow::Result<Option<u32>> {
        match up_bytes_per_sec {
            Some(0) => anyhow::bail!("an upload cap must be above zero; block the app instead"),
            Some(rate) => {
                let cap = RateCap { app: app.clone(), up_bytes_per_sec: rate };
                self.backend.apply(&cap)?;
                self.caps.retain(|existing| existing.app != app);
                self.caps.push(cap);
            }
            None => {
                self.backend.remove(&app)?;
                self.caps.retain(|existing| existing.app != app);
            }
        }
        let tmp = caps_path().with_extension("json.tmp");
        if let Some(parent) = tmp.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&tmp, serde_json::to_vec_pretty(&self.caps)?)?;
        std::fs::rename(&tmp, caps_path())?;
        Ok(self.backend.mark(&app))
    }
}

/// a stable policy name per app, so re-applying replaces rather than stacks
fn policy_name(app: &AppId) -> String {
    // fnv-1a: short, stable across runs, and needs no dependency
    let hash = app
        .as_str()
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
        });
    format!("iris-cap-{hash:016x}")
}

#[cfg(windows)]
mod platform {
    use super::policy_name;
    use iris_core::{AppId, RateCap};

    #[derive(Default)]
    pub struct Backend {}

    /// run a powershell snippet whose inputs arrive as environment variables,
    /// so a path never needs quoting into the script text
    fn run(script: &str, env: &[(&str, String)]) -> anyhow::Result<()> {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let shell = format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe");
        let output = std::process::Command::new(shell)
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
            .envs(env.iter().map(|(key, value)| (*key, value.as_str())))
            .output()?;
        if output.status.success() {
            Ok(())
        } else {
            anyhow::bail!("{}", String::from_utf8_lossy(&output.stderr).trim())
        }
    }

    impl Backend {
        pub fn apply(&mut self, cap: &RateCap) -> anyhow::Result<()> {
            run(
                "$ErrorActionPreference = 'Stop'; \
                 Remove-NetQosPolicy -Name $env:IRIS_NAME -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue; \
                 New-NetQosPolicy -Name $env:IRIS_NAME -AppPathNameMatchCondition $env:IRIS_APP \
                   -ThrottleRateActionBitsPerSecond ([uint64]$env:IRIS_BITS) -PolicyStore ActiveStore | Out-Null",
                &[
                    ("IRIS_NAME", policy_name(&cap.app)),
                    ("IRIS_APP", cap.app.as_str().to_string()),
                    ("IRIS_BITS", cap.up_bytes_per_sec.saturating_mul(8).to_string()),
                ],
            )
        }

        pub fn remove(&mut self, app: &AppId) -> anyhow::Result<()> {
            run(
                "Remove-NetQosPolicy -Name $env:IRIS_NAME -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue",
                &[("IRIS_NAME", policy_name(app))],
            )
        }

        pub fn clear(&mut self) -> anyhow::Result<()> {
            run(
                "Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction SilentlyContinue | \
                 Where-Object Name -like 'iris-cap-*' | Remove-NetQosPolicy -Confirm:$false",
                &[],
            )
        }

        /// qos matches the app itself, so no flow mark is involved
        pub fn mark(&self, _app: &AppId) -> Option<u32> {
            None
        }

        /// qos policies apply on every interface already
        pub fn follow_route(&mut self) -> anyhow::Result<()> {
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use iris_core::{AppId, RateCap};
    use std::collections::HashMap;

    #[derive(Default)]
    pub struct Backend {
        shaper: crate::platform::Shaper,
        ids: HashMap<AppId, u16>,
        routed: bool,
    }

    impl Backend {
        pub fn apply(&mut self, cap: &RateCap) -> anyhow::Result<()> {
            self.ensure_device()?;
            let id = match self.ids.get(&cap.app) {
                Some(id) => *id,
                None => {
                    // ids 0 and 0xffff are the qdisc's own; reuse the lowest free
                    let id = (1..0xffff)
                        .find(|id| !self.ids.values().any(|taken| taken == id))
                        .ok_or_else(|| anyhow::anyhow!("too many upload caps"))?;
                    self.ids.insert(cap.app.clone(), id);
                    id
                }
            };
            if let Err(error) = self.shaper.set(id, cap.up_bytes_per_sec) {
                self.ids.remove(&cap.app);
                return Err(error.into());
            }
            Ok(())
        }

        pub fn remove(&mut self, app: &AppId) -> anyhow::Result<()> {
            if let Some(id) = self.ids.remove(app) {
                self.shaper.remove(id)?;
            }
            Ok(())
        }

        /// a fresh shaper tears its own root down, so only the id map resets
        pub fn clear(&mut self) -> anyhow::Result<()> {
            self.ids.clear();
            Ok(())
        }

        pub fn mark(&self, app: &AppId) -> Option<u32> {
            self.ids.get(app).map(|id| crate::platform::mark_for(*id))
        }

        pub fn follow_route(&mut self) -> anyhow::Result<()> {
            if self.ids.is_empty() {
                return Ok(());
            }
            Ok(self.shaper.retarget(crate::platform::default_device())?)
        }

        fn ensure_device(&mut self) -> anyhow::Result<()> {
            if !self.routed {
                let device = crate::platform::default_device()
                    .ok_or_else(|| anyhow::anyhow!("no default route to shape"))?;
                self.shaper.retarget(Some(device))?;
                self.routed = true;
            }
            Ok(())
        }
    }
}

#[cfg(not(has_platform))]
mod platform {
    use iris_core::{AppId, RateCap};

    #[derive(Default)]
    pub struct Backend {}

    impl Backend {
        pub fn apply(&mut self, _cap: &RateCap) -> anyhow::Result<()> {
            anyhow::bail!("upload caps are not available on this platform")
        }

        pub fn remove(&mut self, _app: &AppId) -> anyhow::Result<()> {
            Ok(())
        }

        pub fn clear(&mut self) -> anyhow::Result<()> {
            Ok(())
        }

        pub fn mark(&self, _app: &AppId) -> Option<u32> {
            None
        }

        pub fn follow_route(&mut self) -> anyhow::Result<()> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::policy_name;
    use iris_core::AppId;

    #[test]
    fn policy_names_are_stable_and_distinct_per_app() {
        let game = AppId::from_path(r"C:\Games\game.exe");
        assert_eq!(policy_name(&game), policy_name(&game.clone()));
        assert_ne!(policy_name(&game), policy_name(&AppId::from_path(r"C:\Games\other.exe")));
        assert!(policy_name(&game).starts_with("iris-cap-"));
    }
}
