//! self-install of the engine as an auto-start Windows service, so it runs in
//! the background with no console window and comes up on boot. invoked by the
//! installer (and available as `iris-engine --install` / `--uninstall`).

use std::ffi::{c_void, OsStr};
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use windows::core::{BOOL, PCWSTR, PWSTR};
use windows::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService,
    CreateServiceW, DeleteService, OpenSCManagerW, OpenServiceW, StartServiceW, SC_ACTION,
    SC_ACTION_RESTART, SC_HANDLE, SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS, SERVICE_AUTO_START,
    SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, SERVICE_CONTROL_STOP,
    SERVICE_ERROR_NORMAL, SERVICE_FAILURE_ACTIONSW, SERVICE_FAILURE_ACTIONS_FLAG, SERVICE_STATUS,
    SERVICE_WIN32_OWN_PROCESS,
};

pub const SERVICE_NAME: &str = "IrisEngine";
const DISPLAY_NAME: &str = "Iris Engine";

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(once(0)).collect()
}

pub fn install() -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let bin_path = wide(&format!("\"{}\"", exe.display()));
    let name = wide(SERVICE_NAME);
    unsafe {
        let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS)?;
        // reuse an existing registration (a reinstall or upgrade) by repointing
        // it at this binary; only create it fresh when it is not there yet, so
        // installing over a prior version does not fail with SERVICE_EXISTS
        let svc = match OpenServiceW(scm, PCWSTR(name.as_ptr()), SERVICE_ALL_ACCESS) {
            Ok(existing) => {
                ChangeServiceConfigW(
                    existing,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    PCWSTR(bin_path.as_ptr()),
                    PCWSTR::null(),
                    None,
                    PCWSTR::null(),
                    PCWSTR::null(),
                    PCWSTR::null(),
                    PCWSTR(wide(DISPLAY_NAME).as_ptr()),
                )?;
                existing
            }
            Err(_) => CreateServiceW(
                scm,
                PCWSTR(name.as_ptr()),
                PCWSTR(wide(DISPLAY_NAME).as_ptr()),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                PCWSTR(bin_path.as_ptr()),
                PCWSTR::null(),
                None,
                PCWSTR::null(),
                PCWSTR::null(),
                PCWSTR::null(),
            )?,
        };
        configure_recovery(svc);
        let _ = StartServiceW(svc, None);
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
    }
    tracing::info!("service '{SERVICE_NAME}' installed and started");
    Ok(())
}

/// tell the SCM to restart the engine on failure (5s, 10s, then 30s backoff,
/// counter reset after a day of health) and to treat our non-zero error exit as
/// a failure, not only a hard process crash. best effort: a monitor that will
/// not auto-restart is worse than one whose recovery config did not take, so a
/// failure here never blocks the install.
unsafe fn configure_recovery(svc: SC_HANDLE) {
    let mut actions = [
        SC_ACTION { Type: SC_ACTION_RESTART, Delay: 5_000 },
        SC_ACTION { Type: SC_ACTION_RESTART, Delay: 10_000 },
        SC_ACTION { Type: SC_ACTION_RESTART, Delay: 30_000 },
    ];
    let failure_actions = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: 86_400,
        lpRebootMsg: PWSTR::null(),
        lpCommand: PWSTR::null(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };
    let _ = ChangeServiceConfig2W(
        svc,
        SERVICE_CONFIG_FAILURE_ACTIONS,
        Some(&failure_actions as *const _ as *const c_void),
    );
    let flag = SERVICE_FAILURE_ACTIONS_FLAG {
        fFailureActionsOnNonCrashFailures: BOOL(1),
    };
    let _ = ChangeServiceConfig2W(
        svc,
        SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
        Some(&flag as *const _ as *const c_void),
    );
}

pub fn uninstall() -> anyhow::Result<()> {
    unsafe {
        let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS)?;
        let svc = OpenServiceW(scm, PCWSTR(wide(SERVICE_NAME).as_ptr()), SERVICE_ALL_ACCESS)?;
        let mut status = SERVICE_STATUS::default();
        let _ = ControlService(svc, SERVICE_CONTROL_STOP, &mut status);
        DeleteService(svc)?;
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
    }
    tracing::info!("service '{SERVICE_NAME}' removed");
    Ok(())
}
