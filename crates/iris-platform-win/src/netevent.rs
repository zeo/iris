//! ask-before-connect needs to know *which* application the ask-mode catch-all
//! just denied, the moment it happens. WFP publishes that as a classify-drop net
//! event carrying the filter id that dropped the packet plus the app id of the
//! process behind it, so iris subscribes to the event stream and reports only
//! the drops attributable to its own ask-mode filters.
//!
//! the subscription callback runs on a BFE-owned thread and must not block, so
//! it does nothing but decode the event and push it down a channel. collecting
//! net events is an engine-wide option that stays on for the life of the
//! subscription.

use iris_core::{AppId, Direction, Endpoint, Protocol};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Mutex, OnceLock};
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineSetOption0, FwpmNetEventSubscribe4, FwpmNetEventUnsubscribe0, FWPM_ENGINE_OPTION,
    FWPM_NET_EVENT5, FWPM_NET_EVENT_FLAG_APP_ID_SET, FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET,
    FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET, FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET,
    FWPM_NET_EVENT_SUBSCRIPTION0, FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, FWP_IP_VERSION_V6, FWP_UINT32,
    FWP_VALUE0,
};

// the engine option index for net event collection; FWPM_ENGINE_COLLECT_NET_EVENTS
const COLLECT_NET_EVENTS: FWPM_ENGINE_OPTION = FWPM_ENGINE_OPTION(0);

/// one connection the ask-mode filter denied, ready to become a prompt
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeniedConnection {
    pub app: AppId,
    pub remote: Endpoint,
    pub direction: Direction,
}

/// the callback has no safe way to carry a Rust closure across the FFI boundary
/// with a lifetime BFE respects, so the sink and the set of ask-mode filter ids
/// live in process-wide state that outlives any single subscription
struct Sink {
    tx: SyncSender<DeniedConnection>,
    /// which of iris's own ask-mode filters dropped it, and the direction that
    /// filter's layer represents. taking the direction from our own bookkeeping
    /// avoids depending on the undocumented numeric values of msFwpDirection.
    ask_filters: HashMap<u64, Direction>,
}

fn sink() -> &'static Mutex<Option<Sink>> {
    static SINK: OnceLock<Mutex<Option<Sink>>> = OnceLock::new();
    SINK.get_or_init(|| Mutex::new(None))
}

/// tell the subscriber which filter ids belong to ask mode. a drop by any other
/// filter is an explicit user block and must not raise a prompt.
pub fn set_ask_filters(ids: &[(u64, Direction)]) {
    if let Ok(mut guard) = sink().lock() {
        if let Some(sink) = guard.as_mut() {
            sink.ask_filters = ids.iter().copied().collect();
        }
    }
}

/// a live net-event subscription. dropping it unsubscribes.
pub struct NetEvents {
    handle: HANDLE,
    engine: HANDLE,
}

unsafe impl Send for NetEvents {}

impl NetEvents {
    /// subscribe to classify-drop events on `engine`, pushing ask-mode denials
    /// to `tx`. `ask_filters` seeds the id set the callback matches against.
    pub fn subscribe(
        engine: HANDLE,
        ask_filters: &[(u64, Direction)],
        tx: SyncSender<DeniedConnection>,
    ) -> Result<NetEvents, String> {
        if let Ok(mut guard) = sink().lock() {
            *guard = Some(Sink {
                tx,
                ask_filters: ask_filters.iter().copied().collect(),
            });
        }
        unsafe {
            let on = FWP_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous:
                    windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0 {
                        uint32: 1,
                    },
            };
            let rc = FwpmEngineSetOption0(engine, COLLECT_NET_EVENTS, &on);
            if rc != ERROR_SUCCESS.0 {
                return Err(format!("could not enable net events: {rc:#x}"));
            }

            let subscription: FWPM_NET_EVENT_SUBSCRIPTION0 = std::mem::zeroed();
            let mut handle = HANDLE::default();
            let rc = FwpmNetEventSubscribe4(
                engine,
                &subscription,
                Some(on_net_event),
                None,
                &mut handle,
            );
            if rc != ERROR_SUCCESS.0 {
                return Err(format!("could not subscribe to net events: {rc:#x}"));
            }
            Ok(NetEvents { handle, engine })
        }
    }
}

impl Drop for NetEvents {
    fn drop(&mut self) {
        unsafe {
            let _ = FwpmNetEventUnsubscribe0(self.engine, self.handle);
        }
        if let Ok(mut guard) = sink().lock() {
            *guard = None;
        }
    }
}

/// BFE calls this on its own thread for every collected event. it must return
/// promptly, so the only work here is decoding and a non-blocking send.
unsafe extern "system" fn on_net_event(
    _context: *mut core::ffi::c_void,
    event: *const FWPM_NET_EVENT5,
) {
    if event.is_null() {
        return;
    }
    let event = unsafe { &*event };
    if event.r#type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
        return;
    }
    let drop = unsafe { event.Anonymous.classifyDrop };
    if drop.is_null() {
        return;
    }
    let drop = unsafe { &*drop };
    let header = &event.header;

    let Ok(mut guard) = sink().lock() else { return };
    let Some(sink) = guard.as_mut() else { return };
    // only our own default-deny raises a prompt; a drop from a user's block rule
    // is already the answer to this question
    let Some(direction) = sink.ask_filters.get(&drop.filterId).copied() else {
        return;
    };

    let flags = header.flags;
    let has = |flag: u32| flags & flag != 0;
    if !has(FWPM_NET_EVENT_FLAG_APP_ID_SET) {
        return;
    }
    let Some(path) = app_id_path(&header.appId) else {
        return;
    };
    let is_v6 = header.ipVersion == FWP_IP_VERSION_V6;
    let addr = if !has(FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET) {
        if is_v6 {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        }
    } else if !is_v6 {
        IpAddr::V4(Ipv4Addr::from(unsafe { header.Anonymous2.remoteAddrV4 }))
    } else {
        IpAddr::V6(Ipv6Addr::from(unsafe {
            header.Anonymous2.remoteAddrV6.byteArray16
        }))
    };
    let protocol = if has(FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET) && header.ipProtocol == 17 {
        Protocol::Udp
    } else {
        Protocol::Tcp
    };
    let port = if has(FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET) {
        header.remotePort
    } else {
        0
    };
    let denied = DeniedConnection {
        app: AppId::from_path(&path),
        remote: Endpoint {
            addr,
            port,
            protocol,
        },
        direction,
    };
    // never block BFE's callback thread on a stalled consumer: a full queue
    // means a retry storm the consumer already has prompts for
    if let Err(TrySendError::Full(_)) = sink.tx.try_send(denied) {
        static DROPPED: AtomicU64 = AtomicU64::new(0);
        let dropped = DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
        if dropped.is_power_of_two() {
            tracing::warn!(dropped, "ask-mode denial queue full, dropping events");
        }
    }
}

/// a WFP app id is the image path as a NT device path in UTF-16, terminated.
/// convert it back to something that matches what the monitor records.
fn app_id_path(
    blob: &windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB,
) -> Option<String> {
    if blob.data.is_null() || blob.size < 2 {
        return None;
    }
    let units = (blob.size / 2) as usize;
    let wide = unsafe { std::slice::from_raw_parts(blob.data as *const u16, units) };
    let end = wide.iter().position(|c| *c == 0).unwrap_or(units);
    let path = String::from_utf16_lossy(&wide[..end]);
    if path.is_empty() {
        return None;
    }
    Some(to_drive_path(&path))
}

/// a WFP app id is an NT device path (`\device\harddiskvolume3\...`), while
/// everything else in iris keys apps by the drive-letter path the monitor reads
/// from a process handle. rewrite the device prefix so the two agree, or the
/// same executable would be two different apps.
use std::sync::Arc;

/// the drive-letter form of an NT device path, using the longest device
/// prefix that ends at a path separator
fn map_device_path(path: &str, map: &[(String, String)]) -> Option<String> {
    map.iter()
        .filter(|(device, _)| {
            path.get(..device.len()).is_some_and(|head| head.eq_ignore_ascii_case(device))
                && path.as_bytes().get(device.len()) == Some(&b'\\')
        })
        .max_by_key(|(device, _)| device.len())
        .map(|(device, letter)| format!("{letter}{}", &path[device.len()..]))
}

fn to_drive_path(path: &str) -> String {
    if !path.starts_with("\\device\\") && !path.starts_with("\\Device\\") {
        return path.to_string();
    }
    map_device_path(path, &cached_device_map()).unwrap_or_else(|| path.to_string())
}

type DeviceMapCache = (Option<std::time::Instant>, Arc<Vec<(String, String)>>);

fn cached_device_map() -> Arc<Vec<(String, String)>> {
    static CACHE: OnceLock<Mutex<DeviceMapCache>> = OnceLock::new();
    let lock = CACHE.get_or_init(|| Mutex::new((None, Arc::new(Vec::new()))));
    if let Ok(mut guard) = lock.lock() {
        let needs_refresh = match guard.0 {
            Some(last) => {
                last.elapsed() >= std::time::Duration::from_secs(30) || guard.1.is_empty()
            }
            None => true,
        };
        if needs_refresh {
            guard.1 = Arc::new(device_map());
            guard.0 = Some(std::time::Instant::now());
        }
        return guard.1.clone();
    }
    Arc::new(device_map())
}

/// each drive letter and the NT device path it resolves to.
fn device_map() -> Vec<(String, String)> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

    let mut map = Vec::new();
    for letter in b'a'..=b'z' {
        let drive = format!("{}:", letter as char);
        let wide: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
        let mut target = vec![0u16; 512];
        let len = unsafe { QueryDosDeviceW(PCWSTR(wide.as_ptr()), Some(&mut target)) };
        if len == 0 {
            continue;
        }
        let end = target.iter().position(|c| *c == 0).unwrap_or(0);
        if end == 0 {
            continue;
        }
        map.push((String::from_utf16_lossy(&target[..end]), drive));
    }
    map
}

#[cfg(test)]
mod tests {
    use super::{map_device_path, to_drive_path};

    #[test]
    fn leaves_a_drive_letter_path_alone() {
        assert_eq!(
            to_drive_path("c:\\windows\\system32\\svchost.exe"),
            "c:\\windows\\system32\\svchost.exe"
        );
    }

    #[test]
    fn leaves_an_unmapped_device_path_intact_rather_than_mangling_it() {
        let path = "\\device\\nothingmapped\\app.exe";
        assert_eq!(to_drive_path(path), path);
    }

    fn volumes() -> Vec<(String, String)> {
        vec![
            ("\\Device\\HarddiskVolume1".to_string(), "c:".to_string()),
            ("\\Device\\HarddiskVolume10".to_string(), "d:".to_string()),
        ]
    }

    #[test]
    fn device_volume_one_does_not_capture_volume_ten() {
        assert_eq!(
            map_device_path("\\device\\harddiskvolume10\\games\\x.exe", &volumes()).as_deref(),
            Some("d:\\games\\x.exe")
        );
    }

    #[test]
    fn device_prefix_matches_case_insensitively() {
        assert_eq!(
            map_device_path("\\DEVICE\\HARDDISKVOLUME1\\Tools\\X.EXE", &volumes()).as_deref(),
            Some("c:\\Tools\\X.EXE")
        );
    }

    #[test]
    fn device_path_with_a_multibyte_char_at_the_cut_does_not_panic() {
        let path = "\\device\\harddiskvolume\u{e9}\\x.exe";
        assert!(!path.is_char_boundary("\\Device\\HarddiskVolume1".len()));
        assert_eq!(map_device_path(path, &volumes()), None);
    }

    #[test]
    fn device_name_alone_is_not_a_path() {
        assert_eq!(map_device_path("\\device\\harddiskvolume1", &volumes()), None);
    }

    #[test]
    fn device_longest_prefix_wins() {
        let map = vec![
            ("\\Device\\Mup".to_string(), "x:".to_string()),
            ("\\Device\\Mup\\server\\share".to_string(), "z:".to_string()),
        ];
        assert_eq!(
            map_device_path("\\device\\mup\\server\\share\\app.exe", &map).as_deref(),
            Some("z:\\app.exe")
        );
    }
}
