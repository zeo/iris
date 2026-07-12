//! launch a child process under a restricted, low-integrity token. iris uses
//! this to run out-of-process plugins: the service is LocalSystem, but a plugin
//! must never be. the child keeps the SYSTEM user (so it can open the plugin
//! pipe by its SDDL) yet has every privilege stripped, the Administrators SID
//! demoted to deny-only, and its integrity dropped to Low, so it holds no power
//! to touch the system, other processes, or iris's own handles.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::core::PCWSTR;
use windows::Win32::Security::{
    CreateRestrictedToken, CreateWellKnownSid, GetLengthSid, SetTokenInformation, TokenIntegrityLevel,
    DISABLE_MAX_PRIVILEGE, LUA_TOKEN, PSID, SID_AND_ATTRIBUTES, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, WinBuiltinAdministratorsSid, WinLowLabelSid,
};
use windows::Win32::System::SystemServices::{SE_GROUP_INTEGRITY, SE_GROUP_USE_FOR_DENY_ONLY};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken,
    TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT,
    PROCESS_INFORMATION, STARTUPINFOW,
};

/// a running restricted child. dropping it does not kill the child; call
/// [`RestrictedChild::terminate`] for that. the process handle is closed on drop.
pub struct RestrictedChild {
    process: HANDLE,
    thread: HANDLE,
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
    use windows::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
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
pub fn spawn_restricted(
    exe: &Path,
    extra_env: &[(String, String)],
) -> io::Result<RestrictedChild> {
    unsafe {
        // start from the service's own primary token
        let mut base = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
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
            .map(|p| p.as_os_str().encode_wide().chain(std::iter::once(0)).collect())
            .unwrap_or_else(|| vec![0]);

        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        let result = CreateProcessAsUserW(
            Some(restricted),
            None,
            Some(PWSTR(cmdline.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            Some(env.as_mut_ptr() as *const core::ffi::c_void),
            PCWSTR(cwd.as_ptr()),
            &si,
            &mut pi,
        );
        let _ = CloseHandle(restricted);
        result.map_err(io::Error::other)?;

        Ok(RestrictedChild {
            process: pi.hProcess,
            thread: pi.hThread,
        })
    }
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
    let size =
        std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(low);
    SetTokenInformation(
        token,
        TokenIntegrityLevel,
        &label as *const _ as *const core::ffi::c_void,
        size,
    )
    .map_err(io::Error::other)
}

/// a UTF-16, double-null-terminated environment block: the current environment
/// with `extra` merged in (extras win on a name clash)
fn build_environment(extra: &[(String, String)]) -> Vec<u16> {
    use std::collections::BTreeMap;
    let mut vars: BTreeMap<String, String> = std::env::vars().collect();
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
