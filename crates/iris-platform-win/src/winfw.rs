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

/// a firewall profile that is on and blocks outbound connections by default
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundBlock {
    /// domain, private, or public
    pub profile: &'static str,
    /// group policy sets the block, so a local change would not take
    pub by_policy: bool,
}

/// the firewall profiles that are on and block outbound connections by default
pub fn outbound_blocks() -> Vec<OutboundBlock> {
    blocks(PROFILES.iter().map(|(policy, local, profile)| Settings {
        profile,
        enabled: setting(policy, local, "EnableFirewall"),
        policy_outbound: policy.iter().find_map(|key| dword(&format!(r"{POLICY}\{key}"), "DefaultOutboundAction")),
        local_outbound: dword(&format!(r"{LOCAL}\{local}"), "DefaultOutboundAction"),
    }))
}

/// one profile's registry values
struct Settings {
    profile: &'static str,
    enabled: Option<u32>,
    policy_outbound: Option<u32>,
    local_outbound: Option<u32>,
}

/// a missing EnableFirewall means on; a default outbound action of 1 blocks
fn blocks(profiles: impl Iterator<Item = Settings>) -> Vec<OutboundBlock> {
    profiles
        .filter(|settings| settings.enabled.unwrap_or(1) != 0)
        .filter(|settings| settings.policy_outbound.or(settings.local_outbound) == Some(1))
        .map(|settings| OutboundBlock { profile: settings.profile, by_policy: settings.policy_outbound.is_some() })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{blocks, OutboundBlock, Settings};

    #[test]
    fn picks_the_profiles_that_block_and_whether_policy_set_it() {
        let profile = |profile, enabled, policy_outbound, local_outbound| Settings {
            profile,
            enabled,
            policy_outbound,
            local_outbound,
        };
        let found = blocks(
            [
                profile("domain", Some(1), Some(1), Some(0)),
                profile("private", None, None, Some(1)),
                profile("public", Some(0), None, Some(1)),
            ]
            .into_iter(),
        );
        assert_eq!(
            found,
            [OutboundBlock { profile: "domain", by_policy: true }, OutboundBlock { profile: "private", by_policy: false }]
        );
        // a policy allow overrides a local block
        assert!(blocks([profile("public", Some(1), Some(0), Some(1))].into_iter()).is_empty());
    }

    #[test]
    fn reads_the_firewall_profiles_without_failing() {
        let blocked = super::outbound_blocks();
        assert!(blocked.iter().all(|block| ["domain", "private", "public"].contains(&block.profile)));
        assert!(super::dword(r"SYSTEM\CurrentControlSet\Control\Windows", "CSDVersion").is_some());
    }
}
