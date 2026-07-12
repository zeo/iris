//! network pinning for out-of-process plugin children. every plugin binary is
//! default-blocked at the four ALE connect / recv-accept layers, then granted
//! narrow permits for exactly the remote address:port pairs the user consented
//! to, plus remote port 53 when the grant names hosts the child must resolve
//! itself. the filters live in a dynamic WFP session, so they vanish with the
//! service process and can never outlive a crash, and in their own sublayer so
//! the rules sublayer's startup reset never touches them.

use iris_core::{EngineError, EngineResult};
use std::net::SocketAddr;
use std::path::Path;
use std::ptr;
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmFreeMemory0,
    FwpmGetAppIdFromFileName0, FwpmProviderAdd0, FwpmSubLayerAdd0, FWPM_ACTION0,
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_PROVIDER0, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC,
    FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_ACTION_TYPE, FWP_BYTE_ARRAY16,
    FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_UINT16, FWP_UINT32, FWP_UINT8, FWP_VALUE0,
    FWP_VALUE0_0,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

// distinct from the rules provider + sublayer: wfp.rs::reset enumerates its own
// objects on startup and must never sweep plugin pins with them
const PIN_PROVIDER: GUID = GUID::from_values(
    0x6b1a3e12,
    0x9f2c,
    0x4d5b,
    [0xa1, 0x77, 0x3c, 0x88, 0x12, 0x44, 0x9e, 0x03],
);
const PIN_SUBLAYER: GUID = GUID::from_values(
    0x6b1a3e13,
    0x9f2c,
    0x4d5b,
    [0xa1, 0x77, 0x3c, 0x88, 0x12, 0x44, 0x9e, 0x04],
);

const CONNECT_LAYERS: [GUID; 2] = [
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
];
const ALL_LAYERS: [GUID; 4] = [
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
];

// within the pin sublayer the permits must always outrank the block-all
const WEIGHT_BLOCK: u8 = 0;
const WEIGHT_PERMIT: u8 = 15;

/// the dynamic WFP session holding every plugin's pin filters
pub struct PluginNet {
    engine: HANDLE,
}

// a WFP engine handle is safe to use from any thread; the service guards all
// access behind a mutex
unsafe impl Send for PluginNet {}

/// the permit filters currently backing one plugin's grant. the block filters
/// are not tracked: they never change for the life of the session.
pub struct AppPin {
    permit_ids: Vec<u64>,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn ok(rc: u32) -> bool {
    rc == ERROR_SUCCESS.0
}

impl PluginNet {
    /// open the dynamic session and provision the pin provider + sublayer. the
    /// sublayer outweighs the rules sublayer so a pin verdict is arbitrated
    /// first; a block from either still wins overall.
    pub fn open() -> EngineResult<PluginNet> {
        unsafe {
            let mut name = wide("Iris Plugins");
            let mut session: FWPM_SESSION0 = std::mem::zeroed();
            session.displayData = FWPM_DISPLAY_DATA0 {
                name: PWSTR(name.as_mut_ptr()),
                description: PWSTR(name.as_mut_ptr()),
            };
            session.flags = FWPM_SESSION_FLAG_DYNAMIC;

            let mut engine = HANDLE::default();
            let rc = FwpmEngineOpen0(None, RPC_C_AUTHN_WINNT, None, Some(&session), &mut engine);
            if !ok(rc) {
                return Err(EngineError::Os(format!("FwpmEngineOpen0 failed: {rc:#x}")));
            }
            let net = PluginNet { engine };

            let mut provider: FWPM_PROVIDER0 = std::mem::zeroed();
            provider.providerKey = PIN_PROVIDER;
            provider.displayData = FWPM_DISPLAY_DATA0 {
                name: PWSTR(name.as_mut_ptr()),
                description: PWSTR(name.as_mut_ptr()),
            };
            let rc = FwpmProviderAdd0(net.engine, &provider, None);
            if !ok(rc) {
                return Err(EngineError::Os(format!("FwpmProviderAdd0 failed: {rc:#x}")));
            }

            let mut sublayer: FWPM_SUBLAYER0 = std::mem::zeroed();
            sublayer.subLayerKey = PIN_SUBLAYER;
            sublayer.displayData = FWPM_DISPLAY_DATA0 {
                name: PWSTR(name.as_mut_ptr()),
                description: PWSTR(name.as_mut_ptr()),
            };
            sublayer.providerKey = &PIN_PROVIDER as *const _ as *mut _;
            sublayer.weight = 0xF000;
            let rc = FwpmSubLayerAdd0(net.engine, &sublayer, None);
            if !ok(rc) {
                return Err(EngineError::Os(format!("FwpmSubLayerAdd0 failed: {rc:#x}")));
            }
            Ok(net)
        }
    }

    /// pin one plugin binary: block everything in and out, then permit the
    /// allowed remote endpoints (and port 53 when the plugin resolves names).
    /// an empty `allowed` with no dns is a total network cut.
    pub fn pin(
        &mut self,
        exe: &Path,
        allowed: &[SocketAddr],
        allow_dns: bool,
    ) -> EngineResult<AppPin> {
        unsafe {
            let app_id = app_id(exe)?;
            let result = self.pin_blob(app_id, allowed, allow_dns);
            FwpmFreeMemory0(&mut (app_id as *mut core::ffi::c_void));
            result
        }
    }

    /// swap a pinned plugin's permits for a re-resolved endpoint set. the new
    /// permits go in before the old come out, so the child never sees a window
    /// where a still-granted endpoint is blocked.
    pub fn repin(
        &mut self,
        exe: &Path,
        pin: &mut AppPin,
        allowed: &[SocketAddr],
        allow_dns: bool,
    ) -> EngineResult<()> {
        unsafe {
            let app_id = app_id(exe)?;
            let fresh = self.add_permits(app_id, allowed, allow_dns);
            FwpmFreeMemory0(&mut (app_id as *mut core::ffi::c_void));
            let fresh = fresh?;
            for id in &pin.permit_ids {
                let _ = FwpmFilterDeleteById0(self.engine, *id);
            }
            pin.permit_ids = fresh;
            Ok(())
        }
    }

    unsafe fn pin_blob(
        &mut self,
        app_id: *mut FWP_BYTE_BLOB,
        allowed: &[SocketAddr],
        allow_dns: bool,
    ) -> EngineResult<AppPin> {
        let mut block_ids = Vec::with_capacity(ALL_LAYERS.len());
        for layer in ALL_LAYERS {
            let mut conds = [cond_app(app_id)];
            match self.add_filter(layer, &mut conds, FWP_ACTION_BLOCK, WEIGHT_BLOCK) {
                Ok(id) => block_ids.push(id),
                Err(e) => {
                    self.delete_all(&block_ids);
                    return Err(e);
                }
            }
        }
        match self.add_permits(app_id, allowed, allow_dns) {
            Ok(permit_ids) => Ok(AppPin { permit_ids }),
            Err(e) => {
                self.delete_all(&block_ids);
                Err(e)
            }
        }
    }

    /// add the permit set for a grant; on any failure the partial set is
    /// removed so the caller keeps a consistent view
    unsafe fn add_permits(
        &mut self,
        app_id: *mut FWP_BYTE_BLOB,
        allowed: &[SocketAddr],
        allow_dns: bool,
    ) -> EngineResult<Vec<u64>> {
        let mut ids = Vec::new();
        for addr in allowed {
            let added = match addr {
                SocketAddr::V4(v4) => {
                    let mut conds = [
                        cond_app(app_id),
                        cond_addr_v4(u32::from(*v4.ip())),
                        cond_port(v4.port()),
                    ];
                    self.add_filter(
                        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                        &mut conds,
                        FWP_ACTION_PERMIT,
                        WEIGHT_PERMIT,
                    )
                }
                SocketAddr::V6(v6) => {
                    let mut bytes = FWP_BYTE_ARRAY16 {
                        byteArray16: v6.ip().octets(),
                    };
                    let mut conds = [
                        cond_app(app_id),
                        cond_addr_v6(&mut bytes),
                        cond_port(v6.port()),
                    ];
                    self.add_filter(
                        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                        &mut conds,
                        FWP_ACTION_PERMIT,
                        WEIGHT_PERMIT,
                    )
                }
            };
            match added {
                Ok(id) => ids.push(id),
                Err(e) => {
                    self.delete_all(&ids);
                    return Err(e);
                }
            }
        }
        if allow_dns {
            for layer in CONNECT_LAYERS {
                let mut conds = [cond_app(app_id), cond_port(53)];
                match self.add_filter(layer, &mut conds, FWP_ACTION_PERMIT, WEIGHT_PERMIT) {
                    Ok(id) => ids.push(id),
                    Err(e) => {
                        self.delete_all(&ids);
                        return Err(e);
                    }
                }
            }
        }
        Ok(ids)
    }

    unsafe fn add_filter(
        &mut self,
        layer: GUID,
        conds: &mut [FWPM_FILTER_CONDITION0],
        action: FWP_ACTION_TYPE,
        weight: u8,
    ) -> EngineResult<u64> {
        let mut name = wide("Iris plugin pin");
        let mut filter: FWPM_FILTER0 = std::mem::zeroed();
        filter.displayData = FWPM_DISPLAY_DATA0 {
            name: PWSTR(name.as_mut_ptr()),
            description: PWSTR(name.as_mut_ptr()),
        };
        filter.providerKey = &PIN_PROVIDER as *const _ as *mut _;
        filter.layerKey = layer;
        filter.subLayerKey = PIN_SUBLAYER;
        filter.weight = FWP_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_VALUE0_0 { uint8: weight },
        };
        filter.numFilterConditions = conds.len() as u32;
        filter.filterCondition = conds.as_mut_ptr();
        filter.action = FWPM_ACTION0 {
            r#type: action,
            Anonymous: std::mem::zeroed(),
        };

        let mut id: u64 = 0;
        let rc = FwpmFilterAdd0(self.engine, &filter, None, Some(&mut id));
        if !ok(rc) {
            return Err(EngineError::Os(format!("FwpmFilterAdd0 failed: {rc:#x}")));
        }
        Ok(id)
    }

    unsafe fn delete_all(&mut self, ids: &[u64]) {
        for id in ids {
            let _ = FwpmFilterDeleteById0(self.engine, *id);
        }
    }
}

impl Drop for PluginNet {
    fn drop(&mut self) {
        unsafe {
            // the session is dynamic: closing it deletes every pin filter
            let _ = FwpmEngineClose0(self.engine);
        }
    }
}

unsafe fn app_id(exe: &Path) -> EngineResult<*mut FWP_BYTE_BLOB> {
    let file = wide(&exe.to_string_lossy());
    let mut blob: *mut FWP_BYTE_BLOB = ptr::null_mut();
    let rc = FwpmGetAppIdFromFileName0(PCWSTR(file.as_ptr()), &mut blob);
    if !ok(rc) || blob.is_null() {
        return Err(EngineError::NotFound(format!(
            "app id for {}: {rc:#x}",
            exe.display()
        )));
    }
    Ok(blob)
}

fn cond_app(app_id: *mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_ALE_APP_ID,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_BYTE_BLOB_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app_id },
        },
    }
}

fn cond_port(port: u16) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT16,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port },
        },
    }
}

// v4 remote addresses match as host-order integers at the ALE layers
fn cond_addr_v4(addr: u32) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT32,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint32: addr },
        },
    }
}

fn cond_addr_v6(bytes: &mut FWP_BYTE_ARRAY16) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_BYTE_ARRAY16_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 { byteArray16: bytes },
        },
    }
}
