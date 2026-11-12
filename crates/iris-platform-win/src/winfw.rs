//! what windows firewall itself does with outbound traffic. a profile that
//! blocks outbound by default overrides iris's allows, because a block in any
//! wfp sublayer beats a permit in another

use windows::core::HSTRING;
use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD};

const POLICY: &str = r"SOFTWARE\Policies\Microsoft\WindowsFirewall";
const LOCAL: &str = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
// group policy names the private profile PrivateProfile; the local store and
// older policy templates name it StandardProfile
const PROFILES: [(&[&str], &str, &str); 3] = [
    (&["DomainProfile"], "DomainProfile", "domain"),
    (&["PrivateProfile", "StandardProfile"], "StandardProfile", "private"),
    (&["PublicProfile"], "PublicProfile", "public"),
];

fn dword(key: &str, value: &str) -> Option<u32> {
    let mut data = 0u32;
    let mut size = size_of::<u32>() as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            &HSTRING::from(key),
            &HSTRING::from(value),
            RRF_RT_REG_DWORD,
            None,
            Some((&raw mut data).cast()),
            Some(&mut size),
        )
    };
    status.is_ok().then_some(data)
}

/// a group policy value wins over the local one, as the firewall applies them
fn setting(policy: &[&str], local: &str, value: &str) -> Option<u32> {
    policy
        .iter()
        .find_map(|key| dword(&format!(r"{POLICY}\{key}"), value))
        .or_else(|| dword(&format!(r"{LOCAL}\{local}"), value))
}

/// the firewall profiles that are on and block outbound connections by default
pub fn outbound_blocked_profiles() -> Vec<String> {
    PROFILES
        .iter()
        .filter(|(policy, local, _)| setting(policy, local, "EnableFirewall").unwrap_or(1) != 0)
        .filter(|(policy, local, _)| setting(policy, local, "DefaultOutboundAction") == Some(1))
        .map(|(_, _, name)| name.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn reads_the_firewall_profiles_without_failing() {
        let blocked = super::outbound_blocked_profiles();
        assert!(blocked.iter().all(|name| ["domain", "private", "public"].contains(&name.as_str())));
        assert!(super::dword(r"SYSTEM\CurrentControlSet\Control\Windows", "CSDVersion").is_some());
    }
}
