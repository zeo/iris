//! per-app upload caps on linux. the verdict thread tags the first packet of
//! a capped app's flow with a mark, the iris nft table copies it into the
//! connection's conntrack mark and back onto every later packet, and an htb
//! qdisc on the default-route interface sends each mark through its own
//! rate-limited class. processes stay in their own cgroups, so nothing about
//! the user's session moves.

use iris_core::{EngineError, EngineResult};
use std::collections::BTreeMap;
use std::process::Command;

/// the high half of every iris cap mark; the low half is the cap's id
pub const MARK_BASE: u32 = 0x1a15_0000;
pub const MARK_MASK: u32 = 0xffff_0000;
const HANDLE: &str = "1a15";
/// the class unmarked traffic takes: effectively unlimited
const DEFAULT_CLASS: u16 = 0xffff;
const LINE_RATE: &str = "100gbit";

pub fn mark_for(id: u16) -> u32 {
    MARK_BASE | u32::from(id)
}

/// the shaping state on one interface: cap id to bytes per second
#[derive(Default)]
pub struct Shaper {
    device: Option<String>,
    caps: BTreeMap<u16, u64>,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl Shaper {
    /// put a cap in force, building the root qdisc on first use
    pub fn set(&mut self, id: u16, bytes_per_sec: u64) -> EngineResult<()> {
        if id == 0 || id == DEFAULT_CLASS {
            return Err(EngineError::Os(format!("cap id {id} is reserved")));
        }
        self.caps.insert(id, bytes_per_sec);
        self.apply()
    }

    pub fn remove(&mut self, id: u16) -> EngineResult<()> {
        self.caps.remove(&id);
        self.apply()
    }

    /// follow the default route to `device`, moving every cap with it
    pub fn retarget(&mut self, device: Option<String>) -> EngineResult<()> {
        if device == self.device {
            return Ok(());
        }
        if let Some(old) = self.device.take() {
            run_tc(&teardown(&old));
        }
        self.device = device;
        self.apply()
    }

    /// rebuild the qdisc from scratch; a handful of classes makes this cheap,
    /// and it never leaves a half-edited tree behind
    fn apply(&mut self) -> EngineResult<()> {
        let Some(device) = self.device.clone() else {
            return Ok(());
        };
        run_tc(&teardown(&device));
        if self.caps.is_empty() {
            return Ok(());
        }
        for args in build(&device, &self.caps) {
            if !run_tc(&args) {
                run_tc(&teardown(&device));
                return Err(EngineError::Os(format!("tc {} failed", args.join(" "))));
            }
        }
        Ok(())
    }
}

impl Drop for Shaper {
    fn drop(&mut self) {
        if let Some(device) = &self.device {
            run_tc(&teardown(device));
        }
    }
}

/// remove iris's root qdisc from a device, leaving anything else alone. a
/// failure here only means the root was not ours or was already gone
fn teardown(device: &str) -> Vec<String> {
    words(&format!("qdisc del dev {device} root handle {HANDLE}:"))
}

/// the tc calls that build the whole tree for `caps` on `device`
fn build(device: &str, caps: &BTreeMap<u16, u64>) -> Vec<Vec<String>> {
    let mut calls = vec![
        words(&format!(
            "qdisc add dev {device} root handle {HANDLE}: htb default {DEFAULT_CLASS:x}"
        )),
        words(&format!(
            "class add dev {device} parent {HANDLE}: classid {HANDLE}:{DEFAULT_CLASS:x} htb rate {LINE_RATE}"
        )),
        words(&format!(
            "qdisc add dev {device} parent {HANDLE}:{DEFAULT_CLASS:x} fq_codel"
        )),
    ];
    for (id, rate) in caps {
        // tc reads "bps" as bytes per second
        calls.push(words(&format!(
            "class add dev {device} parent {HANDLE}: classid {HANDLE}:{id:x} htb rate {rate}bps ceil {rate}bps"
        )));
        calls.push(words(&format!(
            "qdisc add dev {device} parent {HANDLE}:{id:x} fq_codel"
        )));
        calls.push(words(&format!(
            "filter add dev {device} parent {HANDLE}: protocol all prio 1 handle {mark:#x} fw flowid {HANDLE}:{id:x}",
            mark = mark_for(*id)
        )));
    }
    calls
}

fn words(line: &str) -> Vec<String> {
    line.split_whitespace().map(str::to_string).collect()
}

fn run_tc(args: &[String]) -> bool {
    Command::new("tc")
        .args(args)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// the nft chains that carry a cap mark from the queued first packet to the
/// rest of its flow. they sit after the verdict chains, which accept the
/// queued packet into the next base chain
pub fn mark_chains() -> String {
    format!(
        "    chain cap_out {{
        type filter hook output priority -5; policy accept;
        meta mark & {MARK_MASK:#x} == {MARK_BASE:#x} ct mark set meta mark
        ct mark & {MARK_MASK:#x} == {MARK_BASE:#x} meta mark set ct mark
    }}
    chain cap_in {{
        type filter hook input priority -5; policy accept;
        meta mark & {MARK_MASK:#x} == {MARK_BASE:#x} ct mark set meta mark
    }}
"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_carry_the_cap_id_under_the_iris_prefix() {
        assert_eq!(mark_for(7), 0x1a15_0007);
        assert_eq!(mark_for(7) & MARK_MASK, MARK_BASE);
    }

    #[test]
    fn builds_a_default_class_and_one_class_and_filter_per_cap() {
        let caps = BTreeMap::from([(1, 65_536), (10, 1_000_000)]);
        let calls: Vec<String> = build("eth0", &caps).iter().map(|args| args.join(" ")).collect();
        assert_eq!(calls[0], "qdisc add dev eth0 root handle 1a15: htb default ffff");
        assert!(calls.contains(&"class add dev eth0 parent 1a15: classid 1a15:ffff htb rate 100gbit".to_string()));
        assert!(calls.contains(
            &"class add dev eth0 parent 1a15: classid 1a15:1 htb rate 65536bps ceil 65536bps".to_string()
        ));
        assert!(calls.contains(
            &"filter add dev eth0 parent 1a15: protocol all prio 1 handle 0x1a15000a fw flowid 1a15:a".to_string()
        ));
        assert_eq!(calls.len(), 3 + 2 * 3);
    }

    #[test]
    fn teardown_only_touches_the_iris_root() {
        assert_eq!(teardown("wlan0").join(" "), "qdisc del dev wlan0 root handle 1a15:");
    }

    #[test]
    fn mark_chains_restore_the_flow_mark_on_egress() {
        let chains = mark_chains();
        assert!(chains.contains("hook output priority -5"));
        assert!(chains.contains("ct mark & 0xffff0000 == 0x1a150000 meta mark set ct mark"));
        assert!(chains.contains("hook input priority -5"));
    }

    #[test]
    fn reserved_ids_are_refused() {
        let mut shaper = Shaper::default();
        assert!(shaper.set(0, 1).is_err());
        assert!(shaper.set(0xffff, 1).is_err());
    }
}
