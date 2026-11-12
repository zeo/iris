//! per-app throughput caps. on windows an upload cap is a policy-based qos
//! throttle in the active store, which does not survive a reboot, so the json
//! file beside the rules is the source of truth and the engine re-applies it at
//! start. qos only throttles what a host sends, so download caps pace inbound
//! packets through WinDivert instead (see `shaper`). on linux each upload cap is
//! an htb class keyed by a flow mark the verdict thread sets, so the store also
//! hands back the mark each capped app's flows must carry. a spent throttle
//! quota lays a lower cap over the saved one until its period ends; that
//! overlay lives only here and never reaches the file.

use iris_core::{AlertKind, AppId, AppSample, RateCap};
use std::collections::HashMap;
use std::path::PathBuf;

#[cfg(windows)]
pub(crate) use platform::run as powershell;

fn caps_path() -> PathBuf {
    crate::paths::rules_file().with_file_name("caps.json")
}

pub struct CapStore {
    caps: Vec<RateCap>,
    /// quota throttles in force, by app
    throttles: HashMap<AppId, u64>,
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
        CapStore { caps, throttles: HashMap::new(), backend }
    }

    /// no caps and an idle backend, for tests that must not touch the os shaper
    #[cfg(test)]
    pub fn empty() -> CapStore {
        CapStore { caps: Vec::new(), throttles: HashMap::new(), backend: platform::Backend::default() }
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

    /// keep download caps on the capped apps' live connections
    pub fn follow_flows(&mut self, apps: &[AppSample]) -> Option<AlertKind> {
        self.backend.follow_flows(apps)
    }

    #[cfg(windows)]
    pub fn release_downloads(&mut self) {
        self.backend.release_downloads();
    }

    /// cap an app's upload and download, lifting each with none. returns the
    /// mark its flows must now carry, if the platform uses one
    pub fn set(
        &mut self,
        app: AppId,
        up_bytes_per_sec: Option<u64>,
        down_bytes_per_sec: Option<u64>,
    ) -> anyhow::Result<Option<u32>> {
        if up_bytes_per_sec == Some(0) || down_bytes_per_sec == Some(0) {
            anyhow::bail!("a cap must be above zero; block the app instead");
        }
        let cap = RateCap { app: app.clone(), up_bytes_per_sec, down_bytes_per_sec };
        let capped = up_bytes_per_sec.is_some() || down_bytes_per_sec.is_some();
        let limits = effective(&app, capped.then_some(&cap), self.throttles.get(&app).copied());
        self.enforce(&app, limits)?;
        self.caps.retain(|existing| existing.app != app);
        if capped {
            self.caps.push(cap);
        }
        let tmp = caps_path().with_extension("json.tmp");
        if let Some(parent) = tmp.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&tmp, serde_json::to_vec_pretty(&self.caps)?)?;
        std::fs::rename(&tmp, caps_path())?;
        Ok(self.backend.mark(&app))
    }

    /// hold each app in `wanted` to its rate and give every app no longer in
    /// it back its saved cap. returns the apps whose limits changed, with the
    /// mark their flows must now carry
    pub fn throttle(&mut self, wanted: HashMap<AppId, u64>) -> Vec<(AppId, Option<u32>)> {
        let mut changed: Vec<AppId> = wanted
            .iter()
            .filter(|(app, rate)| self.throttles.get(*app) != Some(*rate))
            .map(|(app, _)| app.clone())
            .collect();
        changed.extend(self.throttles.keys().filter(|app| !wanted.contains_key(*app)).cloned());
        self.throttles = wanted;
        changed
            .into_iter()
            .map(|app| {
                let saved = self.caps.iter().find(|cap| cap.app == app);
                let limits = effective(&app, saved, self.throttles.get(&app).copied());
                if let Err(error) = self.enforce(&app, limits) {
                    tracing::warn!(app = app.as_str(), "could not change a quota throttle: {error}");
                }
                let mark = self.backend.mark(&app);
                (app, mark)
            })
            .collect()
    }

    fn enforce(&mut self, app: &AppId, limits: Option<RateCap>) -> anyhow::Result<()> {
        match limits {
            Some(cap) => self.backend.apply(&cap),
            None => self.backend.remove(app),
        }
    }
}

/// the limits in force for an app: the lower of its saved cap and a quota
/// throttle each way. linux shapes only uploads, so a throttle leaves its
/// downloads alone
fn effective(app: &AppId, saved: Option<&RateCap>, throttle: Option<u64>) -> Option<RateCap> {
    let lower = |cap: Option<u64>, throttle: Option<u64>| cap.into_iter().chain(throttle).min();
    let up = lower(saved.and_then(|cap| cap.up_bytes_per_sec), throttle);
    let down = lower(saved.and_then(|cap| cap.down_bytes_per_sec), throttle.filter(|_| cfg!(windows)));
    (up.is_some() || down.is_some()).then(|| RateCap { app: app.clone(), up_bytes_per_sec: up, down_bytes_per_sec: down })
}

/// lift every cap iris put in force without touching the saved list, for
/// uninstall and firewall recovery
#[cfg_attr(not(windows), allow(dead_code))]
pub fn clear_all() -> anyhow::Result<()> {
    platform::Backend::default().clear()
}

/// a stable policy name per app, so re-applying replaces rather than stacks
#[cfg(any(windows, test))]
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
    use crate::platform::divert;
    use crate::shaper::{is_anticheat, Shaper};
    use iris_core::{AlertKind, AppId, AppSample, RateCap, WatchReason};
    use std::collections::HashMap;
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    #[derive(Default)]
    pub struct Backend {
        downloads: HashMap<AppId, u64>,
        /// running only while a download cap is in force and no anti-cheat is
        shaper: Option<Shaper>,
        /// the anti-cheat image download caps stepped aside for
        paused_for: Option<String>,
        checked: Option<Instant>,
        notice: Option<AlertKind>,
    }

    /// how often to look for an anti-cheat while download caps are in force
    const GUARD_EVERY: Duration = Duration::from_secs(5);

    fn running_anticheat() -> Option<String> {
        divert::running_image_names().into_iter().find(|name| is_anticheat(name))
    }

    fn caps_notice(message: String) -> AlertKind {
        AlertKind::Watch { reason: WatchReason::CapsPaused, app: None, message }
    }

    /// a qos cmdlet normally answers in a second or two; past this the wmi
    /// provider is wedged while the caller holds the rule lock waiting on it
    const RUN_TIMEOUT: Duration = Duration::from_secs(20);

    /// run a powershell snippet whose inputs arrive as environment variables,
    /// so a path never needs quoting into the script text
    pub(crate) fn run(script: &str, env: &[(&str, String)]) -> anyhow::Result<()> {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let shell = format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe");
        let mut child = Command::new(shell)
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
            .envs(env.iter().map(|(key, value)| (*key, value.as_str())))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        // drain stderr beside the wait so a chatty failure cannot fill the pipe
        // and stall the child
        let mut stderr = child.stderr.take();
        let errors = std::thread::spawn(move || {
            let mut text = String::new();
            if let Some(stderr) = stderr.as_mut() {
                let _ = stderr.read_to_string(&mut text);
            }
            text
        });
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if started.elapsed() > RUN_TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!("powershell did not finish within {}s", RUN_TIMEOUT.as_secs());
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let errors = errors.join().unwrap_or_default();
        if status.success() {
            Ok(())
        } else {
            anyhow::bail!("{}", errors.trim())
        }
    }

    impl Backend {
        pub fn apply(&mut self, cap: &RateCap) -> anyhow::Result<()> {
            let before = self.downloads.clone();
            let mut downloads = before.clone();
            match cap.down_bytes_per_sec {
                Some(rate) => downloads.insert(cap.app.clone(), rate),
                None => downloads.remove(&cap.app),
            };
            self.shape(downloads)?;
            let upload = apply_upload(cap);
            if upload.is_err() {
                // the cap is not saved, so neither half of it may stay in force
                let _ = self.shape(before);
            }
            upload
        }

        pub fn remove(&mut self, app: &AppId) -> anyhow::Result<()> {
            let mut downloads = self.downloads.clone();
            downloads.remove(app);
            self.shape(downloads)?;
            remove_upload(app)
        }

        pub fn clear(&mut self) -> anyhow::Result<()> {
            self.shape(HashMap::new())?;
            // a driver left loaded by an earlier run has no handle here to drop
            divert::stop_driver();
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

        pub fn follow_flows(&mut self, apps: &[AppSample]) -> Option<AlertKind> {
            if self.downloads.is_empty() {
                return None;
            }
            if self.checked.is_none_or(|at| at.elapsed() >= GUARD_EVERY) {
                self.guard();
            }
            if let Some(shaper) = self.shaper.as_mut() {
                let owners = apps
                    .iter()
                    .filter(|sample| self.downloads.contains_key(&sample.app))
                    .flat_map(|sample| {
                        sample
                            .processes
                            .iter()
                            .flat_map(|process| &process.conns)
                            .map(|conn| ((conn.remote.protocol, conn.local_port), sample.app.clone()))
                    })
                    .collect();
                if let Err(error) = shaper.follow(owners) {
                    tracing::warn!("could not point download caps at new connections: {error}");
                }
            }
            self.notice.take()
        }

        /// put these download caps in force, loading the driver for the first
        /// and unloading it after the last
        fn shape(&mut self, downloads: HashMap<AppId, u64>) -> anyhow::Result<()> {
            if downloads.is_empty() {
                self.stop();
                self.paused_for = None;
            } else if let Some(shaper) = self.shaper.as_mut() {
                shaper.set_rates(&downloads);
            } else if self.paused_for.is_none() {
                self.checked = Some(Instant::now());
                match running_anticheat() {
                    Some(name) => self.pause(name),
                    None => self.shaper = Some(Shaper::start(&downloads)?),
                }
            }
            self.downloads = downloads;
            Ok(())
        }

        /// step aside while an anti-cheat runs, since it would refuse to start
        /// or flag the account beside a packet driver, and come back after
        fn guard(&mut self) {
            self.checked = Some(Instant::now());
            match (running_anticheat(), self.paused_for.take()) {
                (Some(_), Some(name)) => self.paused_for = Some(name),
                (Some(name), None) => {
                    self.stop();
                    self.pause(name);
                }
                (None, Some(name)) => match Shaper::start(&self.downloads) {
                    Ok(shaper) => {
                        self.shaper = Some(shaper);
                        self.notice = Some(caps_notice(format!("Download caps are back on now that {name} closed")));
                    }
                    Err(error) => {
                        tracing::warn!("could not resume download caps, retrying: {error}");
                        self.paused_for = Some(name);
                    }
                },
                (None, None) => {}
            }
        }

        fn pause(&mut self, name: String) {
            tracing::info!("download caps paused while {name} runs");
            self.notice = Some(caps_notice(format!("Download caps are paused while {name} runs")));
            self.paused_for = Some(name);
        }

        fn stop(&mut self) {
            if self.shaper.take().is_some() {
                divert::stop_driver();
            }
        }

        /// drop the download shaper so the driver unloads, keeping the saved caps
        pub fn release_downloads(&mut self) {
            self.stop();
        }
    }

    fn apply_upload(cap: &RateCap) -> anyhow::Result<()> {
        let Some(rate) = cap.up_bytes_per_sec else {
            return remove_upload(&cap.app);
        };
        run(
            "$ErrorActionPreference = 'Stop'; \
             Remove-NetQosPolicy -Name $env:IRIS_NAME -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue; \
             New-NetQosPolicy -Name $env:IRIS_NAME -AppPathNameMatchCondition $env:IRIS_APP \
               -ThrottleRateActionBitsPerSecond ([uint64]$env:IRIS_BITS) -PolicyStore ActiveStore | Out-Null",
            &[
                ("IRIS_NAME", policy_name(&cap.app)),
                ("IRIS_APP", cap.app.as_str().to_string()),
                ("IRIS_BITS", rate.saturating_mul(8).to_string()),
            ],
        )
    }

    fn remove_upload(app: &AppId) -> anyhow::Result<()> {
        run(
            "Remove-NetQosPolicy -Name $env:IRIS_NAME -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue",
            &[("IRIS_NAME", policy_name(app))],
        )
    }

    #[cfg(test)]
    #[test]
    fn run_reports_success_and_the_failure_text() {
        run("exit 0", &[]).unwrap();
        let error = run("[Console]::Error.Write($env:IRIS_MSG); exit 3", &[("IRIS_MSG", "qos said no".into())])
            .unwrap_err();
        assert_eq!(error.to_string(), "qos said no");
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use iris_core::{AlertKind, AppId, AppSample, RateCap};
    use std::collections::HashMap;

    #[derive(Default)]
    pub struct Backend {
        shaper: crate::platform::Shaper,
        ids: HashMap<AppId, u16>,
        routed: bool,
    }

    impl Backend {
        pub fn apply(&mut self, cap: &RateCap) -> anyhow::Result<()> {
            anyhow::ensure!(cap.down_bytes_per_sec.is_none(), "download caps are only available on Windows");
            let Some(rate) = cap.up_bytes_per_sec else {
                return self.remove(&cap.app);
            };
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
            if let Err(error) = self.shaper.set(id, rate) {
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

        pub fn follow_flows(&mut self, _apps: &[AppSample]) -> Option<AlertKind> {
            None
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
    use iris_core::{AlertKind, AppId, AppSample, RateCap};

    #[derive(Default)]
    pub struct Backend {}

    impl Backend {
        pub fn apply(&mut self, _cap: &RateCap) -> anyhow::Result<()> {
            anyhow::bail!("caps are not available on this platform")
        }

        pub fn follow_flows(&mut self, _apps: &[AppSample]) -> Option<AlertKind> {
            None
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
    use super::{effective, policy_name};
    use iris_core::{AppId, RateCap};

    #[test]
    fn a_throttle_lowers_each_way_and_lifting_it_restores_the_saved_cap() {
        let app = AppId::from_path(r"C:\Games\game.exe");
        let saved = RateCap { app: app.clone(), up_bytes_per_sec: Some(2048), down_bytes_per_sec: Some(100_000) };
        let slowed = effective(&app, Some(&saved), Some(8192)).unwrap();
        assert_eq!(slowed.up_bytes_per_sec, Some(2048));
        assert_eq!(slowed.down_bytes_per_sec, Some(if cfg!(windows) { 8192 } else { 100_000 }));
        let unsaved = effective(&app, None, Some(8192)).unwrap();
        assert_eq!((unsaved.up_bytes_per_sec, unsaved.down_bytes_per_sec), (Some(8192), cfg!(windows).then_some(8192)));
        assert_eq!(effective(&app, Some(&saved), None), Some(saved));
        assert_eq!(effective(&app, None, None), None);
    }

    #[test]
    fn policy_names_are_stable_and_distinct_per_app() {
        let game = AppId::from_path(r"C:\Games\game.exe");
        assert_eq!(policy_name(&game), policy_name(&game.clone()));
        assert_ne!(policy_name(&game), policy_name(&AppId::from_path(r"C:\Games\other.exe")));
        assert!(policy_name(&game).starts_with("iris-cap-"));
    }
}
