//! launch a child process under a restricted, low-integrity token. iris uses
//! this to run out-of-process plugins: the service is LocalSystem, but a plugin
//! must never be. the child keeps the SYSTEM user (so it can open the plugin
//! pipe by its SDDL) yet has every privilege stripped, the Administrators SID
//! demoted to deny-only, and its integrity dropped to Low, so it holds no power
//! to touch the system, other processes, or iris's own handles.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows::core::PCWSTR;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::Security::{
    CreateRestrictedToken, CreateWellKnownSid, GetLengthSid, SetTokenInformation,
    TokenIntegrityLevel, WinBuiltinAdministratorsSid, WinLowLabelSid, DISABLE_MAX_PRIVILEGE,
    LUA_TOKEN, PSID, SID_AND_ATTRIBUTES, TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows::Win32::System::SystemServices::{SE_GROUP_INTEGRITY, SE_GROUP_USE_FOR_DENY_ONLY};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, ResumeThread,
    TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
};

/// a running restricted child. the child is confined to a job object whose only
/// handle this struct owns, so dropping it (or the service exiting) closes the
/// job and terminates the child, leaving no orphaned SYSTEM process. [`terminate`]
/// kills it early. all handles are closed on drop.
///
/// [`terminate`]: RestrictedChild::terminate
pub struct RestrictedChild {
    process: HANDLE,
    thread: HANDLE,
    job: HANDLE,
}

// the handles are owned by this struct and only touched behind the supervisor's
// per-plugin state, so a Send assertion is sound
unsafe impl Send for RestrictedChild {}

impl RestrictedChild {
    /// true while the process is still running
    pub fn is_alive(&self) -> bool {
        unsafe { WaitForSingleObject(self.process, 0) != WAIT_OBJECT_0 }
    }

    /// exit code once the process has exited, else None
    pub fn exit_code(&self) -> Option<u32> {
        unsafe {
            if self.is_alive() {
                return None;
            }
            let mut code = 0u32;
            GetExitCodeProcess(self.process, &mut code).ok()?;
            Some(code)
        }
    }

    /// force the child to exit
    pub fn terminate(&self) {
        unsafe {
            let _ = TerminateProcess(self.process, 1);
        }
    }
}

impl Drop for RestrictedChild {
    fn drop(&mut self) {
        unsafe {
            // close the job first: it is kill-on-close, so this terminates the
            // child before its process and thread handles go
            if !self.job.is_invalid() {
                let _ = CloseHandle(self.job);
            }
            let _ = CloseHandle(self.thread);
            let _ = CloseHandle(self.process);
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// a cryptographically-random hex token, used to authenticate a spawned plugin
/// back to the service. falls back to an empty string only if the OS RNG fails,
/// which the caller treats as a spawn failure.
pub fn random_token() -> String {
    use windows::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };
    let mut bytes = [0u8; 32];
    let status = unsafe { BCryptGenRandom(None, &mut bytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if status.0 != 0 {
        tracing::error!("BCryptGenRandom failed: {:#x}", status.0);
        return String::new();
    }
    let mut out = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// spawn `exe` under a restricted low-integrity token, injecting `extra_env`
/// (e.g. the plugin auth token) into the child environment. handles are not
/// inherited: the child reaches iris only by connecting to the named pipe.
pub fn spawn_restricted(exe: &Path, extra_env: &[(String, String)]) -> io::Result<RestrictedChild> {
    unsafe {
        // start from the service's own primary token. the restricted token
        // inherits this handle's access, and lowering its integrity later needs
        // TOKEN_ADJUST_DEFAULT, so request it here or SetTokenInformation fails
        // with access denied.
        let mut base = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
            &mut base,
        )
        .map_err(io::Error::other)?;

        // demote Administrators to deny-only, so even though the child keeps the
        // SYSTEM user it can never use admin-group access
        let mut admin_buf = vec![0u8; 68];
        let mut admin_len = admin_buf.len() as u32;
        let admin = PSID(admin_buf.as_mut_ptr() as *mut _);
        let create_admin = CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            None,
            Some(admin),
            &mut admin_len,
        );
        let deny = [SID_AND_ATTRIBUTES {
            Sid: admin,
            Attributes: SE_GROUP_USE_FOR_DENY_ONLY as u32,
        }];
        let sids_to_disable = if create_admin.is_ok() {
            Some(&deny[..])
        } else {
            None
        };

        // DISABLE_MAX_PRIVILEGE strips every privilege; LUA_TOKEN marks it a
        // limited-user token
        let mut restricted = HANDLE::default();
        let close_base = || {
            let _ = CloseHandle(base);
        };
        if let Err(e) = CreateRestrictedToken(
            base,
            DISABLE_MAX_PRIVILEGE | LUA_TOKEN,
            sids_to_disable,
            None,
            None,
            &mut restricted,
        ) {
            close_base();
            return Err(io::Error::other(e));
        }
        close_base();

        // drop the token's integrity to Low
        if let Err(e) = set_low_integrity(restricted) {
            let _ = CloseHandle(restricted);
            return Err(e);
        }

        let mut env = build_environment(extra_env);
        let mut cmdline = wide(&format!("\"{}\"", exe.to_string_lossy()));
        // run the child from its own directory so it finds sibling files
        let cwd: Vec<u16> = exe
            .parent()
            .map(|p| {
                p.as_os_str()
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect()
            })
            .unwrap_or_else(|| vec![0]);

        // a low-integrity token cannot open the process's window station and
        // desktop (medium-IL objects), so CreateProcessAsUserW would fail with
        // access denied. label both Low in place so the child, inheriting them,
        // can attach.
        allow_low_il_on_desktop();

        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        // start suspended so the child is placed in its job before it runs its
        // first instruction, closing the window where it could act unjobbed
        let result = CreateProcessAsUserW(
            Some(restricted),
            None,
            Some(PWSTR(cmdline.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
            Some(env.as_mut_ptr() as *const core::ffi::c_void),
            PCWSTR(cwd.as_ptr()),
            &si,
            &mut pi,
        );
        let _ = CloseHandle(restricted);
        result.map_err(io::Error::other)?;

        // confine the child to a kill-on-close job, then let it run. resuming
        // happens even if the job could not be set up, so a jobless child still
        // starts (restricted by its token) rather than hanging suspended.
        let job = confine_to_job(pi.hProcess);
        ResumeThread(pi.hThread);

        Ok(RestrictedChild {
            process: pi.hProcess,
            thread: pi.hThread,
            job,
        })
    }
}

/// place `process` in a job object that kills its members when the last handle
/// closes and on an unhandled exception. returns the job handle to keep alive
/// for the child's lifetime, or an invalid handle if the job could not be built
/// or assigned (the child then runs jobless, still restricted by its token).
unsafe fn confine_to_job(process: HANDLE) -> HANDLE {
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
        JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    let job = match CreateJobObjectW(None, PCWSTR::null()) {
        Ok(job) => job,
        Err(e) => {
            tracing::warn!("could not create the plugin job object: {e}");
            return HANDLE::default();
        }
    };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    if let Err(e) = SetInformationJobObject(
        job,
        JobObjectExtendedLimitInformation,
        &limits as *const _ as *const core::ffi::c_void,
        std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
    ) {
        tracing::warn!("could not set plugin job limits: {e}");
        let _ = CloseHandle(job);
        return HANDLE::default();
    }
    if let Err(e) = AssignProcessToJobObject(job, process) {
        tracing::warn!("could not assign the plugin to its job: {e}");
        let _ = CloseHandle(job);
        return HANDLE::default();
    }
    job
}

/// label the process's own window station and desktop Low so a low-integrity
/// child that inherits them can attach. without this CreateProcessAsUserW fails
/// with access denied against the medium-labeled default desktop. best-effort
/// and idempotent: the objects are the service's own, and the label only ever
/// lets a lower-IL process in, never a higher one.
unsafe fn allow_low_il_on_desktop() {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows::Win32::Security::{
        SetUserObjectSecurity, LABEL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };
    use windows::Win32::System::StationsAndDesktops::{GetProcessWindowStation, GetThreadDesktop};
    use windows::Win32::System::Threading::GetCurrentThreadId;

    let (Ok(station), Ok(desktop)) = (
        GetProcessWindowStation(),
        GetThreadDesktop(GetCurrentThreadId()),
    ) else {
        tracing::warn!("no window station/desktop to label for the plugin child");
        return;
    };

    // a security descriptor carrying only a Low mandatory label; applying it
    // with LABEL_SECURITY_INFORMATION leaves the DACL untouched
    let sddl = wide("S:(ML;;NW;;;LW)");
    let mut psd = PSECURITY_DESCRIPTOR::default();
    if let Err(e) = ConvertStringSecurityDescriptorToSecurityDescriptorW(
        PCWSTR(sddl.as_ptr()),
        1, // SDDL_REVISION_1
        &mut psd,
        None,
    ) {
        tracing::warn!("could not build the low integrity label: {e}");
        return;
    }

    let info = LABEL_SECURITY_INFORMATION;
    if let Err(e) = SetUserObjectSecurity(HANDLE(station.0), &info, psd) {
        tracing::warn!("could not label window station low: {e}");
    }
    if let Err(e) = SetUserObjectSecurity(HANDLE(desktop.0), &info, psd) {
        tracing::warn!("could not label desktop low: {e}");
    }
    let _ = LocalFree(Some(HLOCAL(psd.0)));
}

/// stamp the token's mandatory integrity level down to Low
unsafe fn set_low_integrity(token: HANDLE) -> io::Result<()> {
    let mut sid_buf = vec![0u8; 68];
    let mut sid_len = sid_buf.len() as u32;
    let low = PSID(sid_buf.as_mut_ptr() as *mut _);
    CreateWellKnownSid(WinLowLabelSid, None, Some(low), &mut sid_len).map_err(io::Error::other)?;

    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: low,
            Attributes: SE_GROUP_INTEGRITY as u32,
        },
    };
    let size = std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(low);
    SetTokenInformation(
        token,
        TokenIntegrityLevel,
        &label as *const _ as *const core::ffi::c_void,
        size,
    )
    .map_err(io::Error::other)
}

// the standard Windows system variables a process needs to load and run,
// case-insensitive. the plugin child gets only these plus its injected token,
// so nothing non-standard the service inherited (secrets, parent-set values)
// leaks into an out-of-process plugin.
const KEEP_ENV: &[&str] = &[
    "SystemRoot",
    "SystemDrive",
    "windir",
    "ComSpec",
    "PATH",
    "PATHEXT",
    "OS",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "PROCESSOR_LEVEL",
    "PROCESSOR_REVISION",
    "COMPUTERNAME",
    "TEMP",
    "TMP",
    "ALLUSERSPROFILE",
    "ProgramData",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "CommonProgramFiles",
    "CommonProgramFiles(x86)",
    "CommonProgramW6432",
];

/// a UTF-16, double-null-terminated environment block: the standard system
/// variables plus `extra` merged in (extras win on a name clash)
fn build_environment(extra: &[(String, String)]) -> Vec<u16> {
    use std::collections::BTreeMap;
    let keep: std::collections::HashSet<String> =
        KEEP_ENV.iter().map(|name| name.to_ascii_lowercase()).collect();
    let mut vars: BTreeMap<String, String> = std::env::vars()
        .filter(|(name, _)| keep.contains(&name.to_ascii_lowercase()))
        .collect();
    for (k, v) in extra {
        vars.insert(k.clone(), v.clone());
    }
    let mut block = Vec::new();
    for (k, v) in vars {
        for u in format!("{k}={v}").encode_utf16() {
            block.push(u);
        }
        block.push(0);
    }
    block.push(0);
    block
}
