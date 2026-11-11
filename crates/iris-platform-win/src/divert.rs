//! a thin binding to the WinDivert 2.2 user library, which ships beside the
//! engine and is only loaded while a download cap needs it. the library
//! installs and starts its own kernel driver on the first open

use std::ffi::{c_void, CString};
use std::io;
use std::path::Path;
use std::sync::Arc;
use windows::core::{BOOL, HSTRING, PCSTR, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, FreeLibrary, HANDLE, HMODULE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_WITH_ALTERED_SEARCH_PATH,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT,
    SERVICE_CONTROL_STOP, SERVICE_STATUS, SERVICE_STOP,
};

/// the largest packet the driver hands back, per windivert.h
pub const MTU_MAX: usize = 40 + 0xffff;

const LAYER_NETWORK: u32 = 0;
const SHUTDOWN_RECV: u32 = 1;
const ERROR_NO_DATA: i32 = 232;

/// the driver's per-packet metadata, opaque here and handed back on send
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Address {
    timestamp: i64,
    flags: u32,
    reserved: u32,
    data: [u8; 64],
}

impl Default for Address {
    fn default() -> Self {
        Address {
            timestamp: 0,
            flags: 0,
            reserved: 0,
            data: [0; 64],
        }
    }
}

type OpenFn = unsafe extern "C" fn(*const i8, u32, i16, u64) -> HANDLE;
type RecvFn = unsafe extern "C" fn(HANDLE, *mut c_void, u32, *mut u32, *mut Address) -> BOOL;
type SendFn = unsafe extern "C" fn(HANDLE, *const c_void, u32, *mut u32, *const Address) -> BOOL;
type ShutdownFn = unsafe extern "C" fn(HANDLE, u32) -> BOOL;
type CloseFn = unsafe extern "C" fn(HANDLE) -> BOOL;
/// what `GetProcAddress` hands back before the cast to the real signature
type Proc = unsafe extern "system" fn() -> isize;
type CompileFn =
    unsafe extern "C" fn(*const i8, u32, *mut i8, u32, *mut *const i8, *mut u32) -> BOOL;

struct Library {
    module: HMODULE,
    open: OpenFn,
    recv: RecvFn,
    send: SendFn,
    shutdown: ShutdownFn,
    close: CloseFn,
    compile: CompileFn,
}

// the module handle and function pointers are process-wide and immutable
unsafe impl Send for Library {}
unsafe impl Sync for Library {}

impl Drop for Library {
    fn drop(&mut self) {
        let _ = unsafe { FreeLibrary(self.module) };
    }
}

impl Library {
    fn load(path: &Path) -> io::Result<Library> {
        unsafe {
            let module = LoadLibraryExW(&HSTRING::from(path), None, LOAD_WITH_ALTERED_SEARCH_PATH)
                .map_err(|error| {
                    io::Error::other(format!("could not load {}: {error}", path.display()))
                })?;
            let symbol = |name: &[u8]| {
                GetProcAddress(module, PCSTR(name.as_ptr())).ok_or_else(|| {
                    io::Error::other("WinDivert.dll is missing an export iris needs")
                })
            };
            let resolved = (|| {
                Ok::<_, io::Error>(Library {
                    module,
                    open: std::mem::transmute::<Proc, OpenFn>(symbol(b"WinDivertOpen\0")?),
                    recv: std::mem::transmute::<Proc, RecvFn>(symbol(b"WinDivertRecv\0")?),
                    send: std::mem::transmute::<Proc, SendFn>(symbol(b"WinDivertSend\0")?),
                    shutdown: std::mem::transmute::<Proc, ShutdownFn>(symbol(b"WinDivertShutdown\0")?),
                    close: std::mem::transmute::<Proc, CloseFn>(symbol(b"WinDivertClose\0")?),
                    compile: std::mem::transmute::<Proc, CompileFn>(symbol(
                        b"WinDivertHelperCompileFilter\0",
                    )?),
                })
            })();
            if resolved.is_err() {
                let _ = FreeLibrary(module);
            }
            resolved
        }
    }
}

/// one open divert handle at the network layer
pub struct Divert {
    library: Arc<Library>,
    handle: HANDLE,
}

// windivert handles may be received on and sent through from several threads
unsafe impl Send for Divert {}
unsafe impl Sync for Divert {}

impl Divert {
    /// divert the packets `filter` matches, loading the library at `dll`
    pub fn open(dll: &Path, filter: &str) -> io::Result<Divert> {
        Divert::open_with(Arc::new(Library::load(dll)?), filter)
    }

    /// another handle on the library this one loaded, for swapping filters
    pub fn reopen(&self, filter: &str) -> io::Result<Divert> {
        Divert::open_with(self.library.clone(), filter)
    }

    fn open_with(library: Arc<Library>, filter: &str) -> io::Result<Divert> {
        let filter = CString::new(filter).map_err(io::Error::other)?;
        let handle = unsafe { (library.open)(filter.as_ptr(), LAYER_NETWORK, 0, 0) };
        if handle.is_invalid() {
            return Err(describe(io::Error::last_os_error()));
        }
        Ok(Divert { library, handle })
    }

    /// block for the next packet. fails with [`io::ErrorKind::BrokenPipe`]
    /// once [`Divert::shutdown`] has drained the queue
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Address)> {
        let mut len = 0u32;
        let mut address = Address::default();
        let ok = unsafe {
            (self.library.recv)(
                self.handle,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                &mut len,
                &mut address,
            )
        };
        if ok.as_bool() {
            return Ok((len as usize, address));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_NO_DATA) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "divert handle shut down",
            ));
        }
        Err(error)
    }

    pub fn send(&self, packet: &[u8], address: &Address) -> io::Result<()> {
        let ok = unsafe {
            (self.library.send)(
                self.handle,
                packet.as_ptr().cast(),
                packet.len() as u32,
                std::ptr::null_mut(),
                address,
            )
        };
        if ok.as_bool() {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// stop taking new packets; a blocked [`Divert::recv`] drains what is
    /// queued and then fails
    pub fn shutdown(&self) {
        let _ = unsafe { (self.library.shutdown)(self.handle, SHUTDOWN_RECV) };
    }
}

impl Drop for Divert {
    fn drop(&mut self) {
        let _ = unsafe { (self.library.close)(self.handle) };
    }
}

/// whether the driver would accept `filter`, checked in user mode without
/// loading the driver
pub fn check_filter(dll: &Path, filter: &str) -> io::Result<()> {
    let library = Library::load(dll)?;
    let filter = CString::new(filter).map_err(io::Error::other)?;
    let mut reason: *const i8 = std::ptr::null();
    let mut at = 0u32;
    let ok = unsafe {
        (library.compile)(
            filter.as_ptr(),
            LAYER_NETWORK,
            std::ptr::null_mut(),
            0,
            &mut reason,
            &mut at,
        )
    };
    if ok.as_bool() {
        return Ok(());
    }
    let reason = if reason.is_null() {
        "invalid filter".into()
    } else {
        unsafe { std::ffi::CStr::from_ptr(reason) }
            .to_string_lossy()
            .into_owned()
    };
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{reason} at {at}"),
    ))
}

fn describe(error: io::Error) -> io::Error {
    let reason = match error.raw_os_error() {
        Some(5) => "the engine needs administrator rights to load the WinDivert driver",
        Some(577) => "Windows rejected the WinDivert driver's signature",
        Some(654) => "another app has a different WinDivert version loaded",
        Some(1275) => "security software or the hypervisor blocked the WinDivert driver",
        Some(2) | Some(3) => "WinDivert64.sys is missing beside the engine",
        _ => return error,
    };
    io::Error::new(error.kind(), reason)
}

/// stop the WinDivert driver so it unloads; a no-op while another process
/// still holds a handle or when it is not loaded
pub fn stop_driver() {
    unsafe {
        let Ok(scm) = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) else {
            return;
        };
        if let Ok(service) = OpenServiceW(scm, &HSTRING::from("WinDivert"), SERVICE_STOP) {
            let mut status = SERVICE_STATUS::default();
            let _ = ControlService(service, SERVICE_CONTROL_STOP, &mut status);
            let _ = CloseServiceHandle(service);
        }
        let _ = CloseServiceHandle(scm);
    }
}

/// the image names of every running process, such as `vgc.exe`
pub fn running_image_names() -> Vec<String> {
    let mut names = Vec::new();
    unsafe {
        let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return names;
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut more = Process32FirstW(snapshot, &mut entry).is_ok();
        while more {
            let len = entry
                .szExeFile
                .iter()
                .position(|&unit| unit == 0)
                .unwrap_or(entry.szExeFile.len());
            names.push(String::from_utf16_lossy(&entry.szExeFile[..len]));
            more = Process32NextW(snapshot, &mut entry).is_ok();
        }
        let _ = CloseHandle(snapshot);
    }
    names
}

#[cfg(test)]
mod tests {
    #[test]
    fn address_matches_the_c_layout() {
        assert_eq!(size_of::<super::Address>(), 80);
        assert_eq!(align_of::<super::Address>(), 8);
    }

    #[test]
    fn lists_this_process() {
        let me = std::env::current_exe().unwrap();
        let me = me.file_name().unwrap().to_string_lossy().to_lowercase();
        assert!(super::running_image_names()
            .iter()
            .any(|name| name.to_lowercase() == me));
    }
}
