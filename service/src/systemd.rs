//! the Linux service lifecycle: install/uninstall a systemd unit and run the
//! engine under it. this is the counterpart to the Windows SCM integration in
//! `svc.rs`. running as a `Type=simple` unit, the engine's foreground process is
//! the service; systemd sends SIGTERM to stop it, which we catch so the monitor
//! and firewall run their cleanup (stop the threads, remove the nftables table)
//! before exit, the way a graceful SCM stop lets the Windows Drop paths run.

use crate::paths;
use std::process::Command;

const UNIT_NAME: &str = "iris-engine.service";
const UNIT_PATH: &str = "/etc/systemd/system/iris-engine.service";
const PLUGIN_USER: &str = "iris-plugin";
const POLKIT_POLICY: &str = "/usr/share/polkit-1/actions/com.iris.engine.policy";

/// run the engine under systemd until SIGTERM/SIGINT, then return so the Drop
/// paths clean up. must run as root: netlink sock_diag/conntrack, NFQUEUE,
/// nftables, and reading other processes' /proc/<pid>/exe all need it.
pub fn run() -> anyhow::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("iris-engine must run as root");
    }
    paths::ensure_runtime_dirs();
    tracing::info!("iris-engine starting (systemd)");
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate())?;
        let mut int = signal(SignalKind::interrupt())?;
        tokio::select! {
            r = crate::run_engine() => r,
            _ = term.recv() => {
                tracing::info!("SIGTERM received, shutting down");
                Ok(())
            }
            _ = int.recv() => {
                tracing::info!("SIGINT received, shutting down");
                Ok(())
            }
        }
    })
}

/// install and start the service: create the sandbox account, write the unit and
/// the polkit policy, then enable and start it. invoked elevated by the UI, the
/// same way the Windows installer path runs elevated.
pub fn install() -> anyhow::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("installing the service requires root");
    }
    let exe = std::env::current_exe()?;
    ensure_plugin_user()?;
    std::fs::create_dir_all(paths::data_dir())?;
    std::fs::create_dir_all(paths::plugins_dir())?;

    let unit = format!(
        "[Unit]
Description=Iris network engine
Documentation=https://github.com/lintowe/iris
After=network.target nftables.service

[Service]
Type=simple
ExecStart={exe}
Restart=on-failure
RestartSec=5
RuntimeDirectory=iris
RuntimeDirectoryMode=0755
StateDirectory=iris
StateDirectoryMode=0755
# the engine drops privilege only for plugin children; it needs root itself for
# netlink, NFQUEUE, nftables, and reading other processes' executables
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
",
        exe = exe.display()
    );
    std::fs::write(UNIT_PATH, unit)?;
    std::fs::write(POLKIT_POLICY, polkit_policy(&exe))?;

    run_ok(Command::new("systemctl").arg("daemon-reload"))?;
    run_ok(Command::new("systemctl").args(["enable", "--now", UNIT_NAME]))?;
    tracing::info!("iris-engine installed and started");
    Ok(())
}

/// stop, disable, and remove the unit; leaves persistent state in place
pub fn uninstall() -> anyhow::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("uninstalling the service requires root");
    }
    let _ = Command::new("systemctl")
        .args(["disable", "--now", UNIT_NAME])
        .status();
    let _ = std::fs::remove_file(UNIT_PATH);
    let _ = std::fs::remove_file(POLKIT_POLICY);
    let _ = Command::new("systemctl").arg("daemon-reload").status();
    tracing::info!("iris-engine uninstalled");
    Ok(())
}

/// create the unprivileged, no-login account plugins are sandboxed to, if it is
/// not already present
fn ensure_plugin_user() -> anyhow::Result<()> {
    let exists = unsafe {
        let name = std::ffi::CString::new(PLUGIN_USER).unwrap();
        !libc::getpwnam(name.as_ptr()).is_null()
    };
    if exists {
        return Ok(());
    }
    run_ok(Command::new("useradd").args([
        "--system",
        "--no-create-home",
        "--shell",
        "/usr/sbin/nologin",
        "--user-group",
        PLUGIN_USER,
    ]))?;
    Ok(())
}

/// the polkit action that lets the desktop user run the engine's elevated
/// one-shots (rule mutations) after authenticating, the Linux analogue of the
/// UAC prompt behind the admin pipe
fn polkit_policy(exe: &std::path::Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1.0/policyconfig.dtd">
<policyconfig>
  <action id="com.iris.engine.rule">
    <description>Change Iris firewall rules</description>
    <message>Authentication is required to change Iris firewall rules</message>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">{}</annotate>
    <annotate key="org.freedesktop.policykit.exec.allow_gui">true</annotate>
  </action>
</policyconfig>
"#,
        exe.display()
    )
}

fn run_ok(cmd: &mut Command) -> anyhow::Result<()> {
    let out = cmd.output()?;
    if !out.status.success() {
        anyhow::bail!(
            "{:?} failed: {}",
            cmd,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}
