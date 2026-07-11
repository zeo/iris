//! per-app allow/block enforcement via the Windows Filtering Platform. iris owns
//! a provider and a sublayer, and adds one filter per (app, direction, ip
//! family) that matches the app's image path at the ALE connect / recv-accept
//! layer. filters are keyed by the app-id blob WFP derives from the exe path.
//!
//! the byte-blob lifetime is the classic hazard here: the blob returned by
//! FwpmGetAppIdFromFileName0 must stay alive across FwpmFilterAdd0, so it is
//! freed only after the add returns.

use iris_core::{Direction, EngineError, EngineResult, RuleAction};
use std::ptr;
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmFreeMemory0,
    FwpmGetAppIdFromFileName0, FwpmProviderAdd0, FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0,
    FWPM_ACTION0, FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_PROVIDER0,
    FWPM_SUBLAYER0, FWPM_CONDITION_ALE_APP_ID, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB,
    FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0, FWP_EMPTY, FWP_MATCH_EQUAL, FWP_VALUE0,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

// iris's own provider + sublayer, so our filters are enumerable and removable as
// a group and invisible to the Windows Defender Firewall UI.
const IRIS_PROVIDER: GUID = GUID::from_values(
    0x6b1a3e10,
    0x9f2c,
    0x4d5b,
    [0xa1, 0x77, 0x3c, 0x88, 0x12, 0x44, 0x9e, 0x01],
);
const IRIS_SUBLAYER: GUID = GUID::from_values(
    0x6b1a3e11,
    0x9f2c,
    0x4d5b,
    [0xa1, 0x77, 0x3c, 0x88, 0x12, 0x44, 0x9e, 0x02],
);

/// an open WFP engine session with iris's provider + sublayer provisioned
pub struct Wfp {
    engine: HANDLE,
}

// a WFP engine handle is safe to use from any thread; the rule store guards all
// access behind a mutex, so a single Send assertion is enough
unsafe impl Send for Wfp {}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn ok(rc: u32) -> bool {
    rc == ERROR_SUCCESS.0
}

impl Wfp {
    /// open the engine and ensure iris's provider + sublayer exist
    pub fn open() -> EngineResult<Wfp> {
        unsafe {
            let mut engine = HANDLE::default();
            let rc = FwpmEngineOpen0(
                None,
                RPC_C_AUTHN_WINNT,
                None,
                None,
                &mut engine,
            );
            if !ok(rc) {
                return Err(EngineError::Os(format!("FwpmEngineOpen0 failed: {rc:#x}")));
            }
            let mut wfp = Wfp { engine };
            wfp.ensure_objects()?;
            Ok(wfp)
        }
    }

    unsafe fn ensure_objects(&mut self) -> EngineResult<()> {
        let mut name = wide("Iris");
        let mut provider: FWPM_PROVIDER0 = std::mem::zeroed();
        provider.providerKey = IRIS_PROVIDER;
        provider.displayData = FWPM_DISPLAY_DATA0 {
            name: PWSTR(name.as_mut_ptr()),
            description: PWSTR(name.as_mut_ptr()),
        };
        // FWPM_E_ALREADY_EXISTS is fine on a warm start
        let _ = FwpmProviderAdd0(self.engine, &provider, None);

        let mut sublayer: FWPM_SUBLAYER0 = std::mem::zeroed();
        sublayer.subLayerKey = IRIS_SUBLAYER;
        sublayer.displayData = FWPM_DISPLAY_DATA0 {
            name: PWSTR(name.as_mut_ptr()),
            description: PWSTR(name.as_mut_ptr()),
        };
        sublayer.providerKey = &IRIS_PROVIDER as *const _ as *mut _;
        sublayer.weight = 0x8000;
        let _ = FwpmSubLayerAdd0(self.engine, &sublayer, None);
        Ok(())
    }

    /// wipe every iris filter by dropping and recreating the sublayer, then
    /// leave a clean sublayer in place. called on startup before rules re-apply.
    pub fn reset(&mut self) -> EngineResult<()> {
        unsafe {
            let _ = FwpmSubLayerDeleteByKey0(self.engine, &IRIS_SUBLAYER);
            self.ensure_objects()
        }
    }

    fn layers(direction: Direction) -> [GUID; 2] {
        match direction {
            Direction::Outbound => [
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            ],
            Direction::Inbound => [
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            ],
        }
    }

    /// enforce a rule for one app; returns the backing filter ids (one per ip
    /// family) to store for later removal
    pub fn apply(
        &mut self,
        path: &str,
        direction: Direction,
        action: RuleAction,
    ) -> EngineResult<Vec<u64>> {
        unsafe {
            let file = wide(path);
            let mut app_id: *mut FWP_BYTE_BLOB = ptr::null_mut();
            let rc = FwpmGetAppIdFromFileName0(PCWSTR(file.as_ptr()), &mut app_id);
            if !ok(rc) || app_id.is_null() {
                return Err(EngineError::NotFound(format!(
                    "app id for {path}: {rc:#x}"
                )));
            }

            let action_type = match action {
                RuleAction::Block => FWP_ACTION_BLOCK,
                RuleAction::Allow => FWP_ACTION_PERMIT,
            };

            let mut ids = Vec::with_capacity(2);
            let mut result = Ok(());
            for layer in Self::layers(direction) {
                let mut cond: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
                cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                cond.matchType = FWP_MATCH_EQUAL;
                cond.conditionValue = FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE,
                    Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                        byteBlob: app_id,
                    },
                };

                let mut name = wide("Iris rule");
                let mut filter: FWPM_FILTER0 = std::mem::zeroed();
                filter.displayData = FWPM_DISPLAY_DATA0 {
                    name: PWSTR(name.as_mut_ptr()),
                    description: PWSTR(name.as_mut_ptr()),
                };
                filter.providerKey = &IRIS_PROVIDER as *const _ as *mut _;
                filter.layerKey = layer;
                filter.subLayerKey = IRIS_SUBLAYER;
                filter.weight = FWP_VALUE0 {
                    r#type: FWP_EMPTY,
                    Anonymous: std::mem::zeroed(),
                };
                filter.numFilterConditions = 1;
                filter.filterCondition = &mut cond;
                filter.action = FWPM_ACTION0 {
                    r#type: action_type,
                    Anonymous: std::mem::zeroed(),
                };

                let mut id: u64 = 0;
                let rc = FwpmFilterAdd0(self.engine, &filter, None, Some(&mut id));
                if ok(rc) {
                    ids.push(id);
                } else {
                    result = Err(EngineError::Os(format!("FwpmFilterAdd0 failed: {rc:#x}")));
                    break;
                }
            }

            // free the blob only after every add that referenced it has returned
            FwpmFreeMemory0(&mut (app_id as *mut core::ffi::c_void));

            if result.is_err() {
                for id in &ids {
                    let _ = FwpmFilterDeleteById0(self.engine, *id);
                }
                return result.map(|_| Vec::new());
            }
            Ok(ids)
        }
    }

    /// remove the filters backing a rule
    pub fn remove(&mut self, filter_ids: &[u64]) -> EngineResult<()> {
        unsafe {
            for id in filter_ids {
                let _ = FwpmFilterDeleteById0(self.engine, *id);
            }
        }
        Ok(())
    }
}

impl Drop for Wfp {
    fn drop(&mut self) {
        unsafe {
            let _ = FwpmEngineClose0(self.engine);
        }
    }
}
