//! self-install of the engine as an auto-start Windows service, so it runs in
//! the background with no console window and comes up on boot. invoked by the
//! installer (and available as `iris-engine --install` / `--uninstall`).

use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use windows::core::PCWSTR;
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, CreateServiceW, DeleteService, OpenSCManagerW,
    OpenServiceW, StartServiceW, SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS, SERVICE_AUTO_START,
    SERVICE_CONTROL_STOP, SERVICE_ERROR_NORMAL, SERVICE_STATUS, SERVICE_WIN32_OWN_PROCESS,
};

pub const SERVICE_NAME: &str = "IrisEngine";
const DISPLAY_NAME: &str = "Iris Engine";

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(once(0)).collect()
}

pub fn install() -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let bin_path = wide(&format!("\"{}\"", exe.display()));
    unsafe {
        let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS)?;
        let svc = CreateServiceW(
            scm,
            PCWSTR(wide(SERVICE_NAME).as_ptr()),
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
        )?;
        let _ = StartServiceW(svc, None);
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
    }
    tracing::info!("service '{SERVICE_NAME}' installed and started");
    Ok(())
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
