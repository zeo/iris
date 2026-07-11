use std::collections::HashMap;
use windows::core::PWSTR;
use windows::Win32::Foundation::CloseHandle;
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
        let mut buf = [0u16; 512];
        let mut len = buf.len() as u32;
        let res =
            QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len);
        let _ = CloseHandle(handle);
        res.ok()?;
        if len == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}
