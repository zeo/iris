//! per-app upload caps. on windows each cap is a policy-based qos throttle in
//! the active store, which does not survive a reboot, so the json file beside
//! the rules is the source of truth and the engine re-applies it at start. qos
//! throttles what a host sends; download caps would need a callout driver.

use iris_core::{AppId, RateCap};
use std::path::PathBuf;

fn caps_path() -> PathBuf {
    crate::paths::rules_file().with_file_name("caps.json")
}

pub struct CapStore {
    caps: Vec<RateCap>,
}

impl CapStore {
    /// load the saved caps and put them in force
    pub fn open() -> CapStore {
        let caps: Vec<RateCap> = std::fs::read_to_string(caps_path())
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default();
        if let Err(error) = platform::clear() {
            tracing::warn!("could not clear stale upload caps: {error}");
        }
        for cap in &caps {
            if let Err(error) = platform::apply(cap) {
                tracing::warn!(app = cap.app.as_str(), "could not apply upload cap: {error}");
            }
        }
        CapStore { caps }
    }

    pub fn list(&self) -> Vec<RateCap> {
        self.caps.clone()
    }

    /// cap an app's upload at `up_bytes_per_sec`, or lift its cap with none
    pub fn set(&mut self, app: AppId, up_bytes_per_sec: Option<u64>) -> anyhow::Result<()> {
        match up_bytes_per_sec {
            Some(0) => anyhow::bail!("an upload cap must be above zero; block the app instead"),
            Some(rate) => {
                let cap = RateCap { app: app.clone(), up_bytes_per_sec: rate };
                platform::apply(&cap)?;
                self.caps.retain(|existing| existing.app != app);
                self.caps.push(cap);
            }
            None => {
                platform::remove(&app)?;
                self.caps.retain(|existing| existing.app != app);
            }
        }
        let tmp = caps_path().with_extension("json.tmp");
        if let Some(parent) = tmp.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&tmp, serde_json::to_vec_pretty(&self.caps)?)?;
        std::fs::rename(&tmp, caps_path())?;
        Ok(())
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

    pub fn apply(cap: &RateCap) -> anyhow::Result<()> {
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

    pub fn remove(app: &AppId) -> anyhow::Result<()> {
        run(
            "Remove-NetQosPolicy -Name $env:IRIS_NAME -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue",
            &[("IRIS_NAME", policy_name(app))],
        )
    }

    pub fn clear() -> anyhow::Result<()> {
        run(
            "Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction SilentlyContinue | \
             Where-Object Name -like 'iris-cap-*' | Remove-NetQosPolicy -Confirm:$false",
            &[],
        )
    }
}

#[cfg(not(windows))]
mod platform {
    use iris_core::{AppId, RateCap};

    pub fn apply(_cap: &RateCap) -> anyhow::Result<()> {
        anyhow::bail!("upload caps are only available on windows so far")
    }

    pub fn remove(_app: &AppId) -> anyhow::Result<()> {
        Ok(())
    }

    pub fn clear() -> anyhow::Result<()> {
        Ok(())
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
