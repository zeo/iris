use std::collections::HashMap;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// resolves a PID to its executable image path, caching results so the hot ETW
/// callback does not open a process handle per event. the cache is cleared
/// periodically by the monitor to bound the window in which PID reuse could
/// misattribute traffic to the wrong app.
pub struct PidCache {
    map: HashMap<u32, Option<String>>,
}

impl PidCache {
    pub fn new() -> Self {
        PidCache {
            map: HashMap::new(),
        }
    }

    pub fn resolve(&mut self, pid: u32) -> Option<String> {
        if let Some(hit) = self.map.get(&pid) {
            return hit.clone();
        }
        let path = query_image_path(pid);
        self.map.insert(pid, path.clone());
        path
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }
}

impl Default for PidCache {
    fn default() -> Self {
        Self::new()
    }
}

fn query_image_path(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let path = image_path_of(handle);
        let _ = CloseHandle(handle);
        path
    }
}

/// most image paths fit in 512 UTF-16 units, but long-path-enabled systems allow
/// far longer; grow to the NTFS maximum once on failure rather than returning
/// None (which the cache would then remember, leaving the pid unattributed)
unsafe fn image_path_of(handle: HANDLE) -> Option<String> {
    for cap in [512usize, 32768] {
        let mut buf = vec![0u16; cap];
        let mut len = buf.len() as u32;
        let res =
            QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len);
        if res.is_ok() && len > 0 {
            return Some(String::from_utf16_lossy(&buf[..len as usize]));
        }
    }
    None
}
