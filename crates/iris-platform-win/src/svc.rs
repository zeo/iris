use std::collections::HashMap;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW,
    SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_ACTIVE, SERVICE_WIN32,
};

/// maps process ids to the Windows service(s) hosted inside them, so a shared
/// host like svchost.exe shows the service it is actually running instead of a
/// bare pid. rebuilt on a slow cadence since pid to service bindings are stable
/// for the life of a service.
pub struct ServiceMap {
    by_pid: HashMap<u32, Vec<String>>,
}

impl ServiceMap {
    pub fn new() -> Self {
        ServiceMap {
            by_pid: HashMap::new(),
        }
    }

    /// the display names of services running in `pid`, if any
    pub fn get(&self, pid: u32) -> Option<&[String]> {
        self.by_pid.get(&pid).map(Vec::as_slice)
    }

    /// re-enumerate running services; keeps the last good map on failure
    pub fn refresh(&mut self) {
        if let Some(map) = enumerate() {
            self.by_pid = map;
        }
    }
}

impl Default for ServiceMap {
    fn default() -> Self {
        Self::new()
    }
}

fn enumerate() -> Option<HashMap<u32, Vec<String>>> {
    unsafe {
        let scm =
            OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE).ok()?;
        let mut needed = 0u32;
        let mut count = 0u32;
        let mut resume = 0u32;
        // size probe: fails with ERROR_MORE_DATA and reports the required bytes
        let _ = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_ACTIVE,
            None,
            &mut needed,
            &mut count,
            Some(&mut resume),
            PCWSTR::null(),
        );
        if needed == 0 {
            let _ = CloseServiceHandle(scm);
            return Some(HashMap::new());
        }

        let mut buf = vec![0u8; needed as usize];
        resume = 0;
        let res = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_ACTIVE,
            Some(buf.as_mut_slice()),
            &mut needed,
            &mut count,
            Some(&mut resume),
            PCWSTR::null(),
        );
        let _ = CloseServiceHandle(scm);
        res.ok()?;

        let mut map: HashMap<u32, Vec<String>> = HashMap::new();
        let entries = buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW;
        for i in 0..count as usize {
            let e = &*entries.add(i);
            let pid = e.ServiceStatusProcess.dwProcessId;
            if pid == 0 {
                continue;
            }
            let name = pwstr_to_string(e.lpDisplayName);
            if !name.is_empty() {
                map.entry(pid).or_default().push(name);
            }
        }
        Some(map)
    }
}

unsafe fn pwstr_to_string(p: PWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    p.to_string().unwrap_or_default()
}
