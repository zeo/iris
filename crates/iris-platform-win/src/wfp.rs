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
use windows::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, HANDLE,
};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterCreateEnumHandle0,
    FwpmFilterDeleteById0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0,
    FwpmGetAppIdFromFileName0, FwpmProviderAdd0, FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0,
    FWPM_ACTION0, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_FLAGS, FWPM_DISPLAY_DATA0,
    FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_FILTER_ENUM_TEMPLATE0, FWPM_FILTER_FLAG_PERSISTENT,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_PROVIDER0,
    FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE,
    FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_CONDITION_VALUE0, FWP_FILTER_ENUM_OVERLAPPING,
    FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_NONE_SET, FWP_UINT32, FWP_UINT64, FWP_VALUE0,
    FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_SUBLAYER_FLAG_PERSISTENT,
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

/// filter weights inside iris's sublayer. WFP evaluates the highest weight
/// first and stops at the first permit or block, so a per-app decision must
/// outrank the ask-mode catch-all that sits underneath everything.
/// see: Filter Arbitration, learn.microsoft.com/windows/win32/fwp/filter-arbitration
/// an explicit decision the user made, which must win over everything below
const WEIGHT_APP_RULE: u64 = 0x2000;
/// a permit seeded for an app the user had already accepted before ask mode
/// existed. it has to beat the catch-all deny but lose to a real block rule, or
/// a block could be shadowed by the app's own grandfathered permit.
const WEIGHT_SEEDED_TRUST: u64 = 0x1000;
/// the ask-mode catch-all, underneath every decision
const WEIGHT_ASK_FALLBACK: u64 = 0x0100;

/// an open WFP engine session with iris's provider + sublayer provisioned
pub struct Wfp {
    engine: HANDLE,
    /// the catch-all filters backing ask mode, empty when ask mode is off, each
    /// paired with the direction its layer represents
    ask_filters: Vec<(u64, Direction)>,
    /// the live classify-drop subscription that turns ask-mode denials into
    /// prompts; present only while ask mode is on
    events: Option<crate::netevent::NetEvents>,
    /// the receiving end of that subscription, handed to the service once
    denied: Option<std::sync::mpsc::Receiver<crate::netevent::DeniedConnection>>,
    /// permits seeded for apps accepted before ask mode existed, so turning it
    /// on does not retroactively cut off the whole machine
    trusted_filters: Vec<u64>,
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
            let rc = FwpmEngineOpen0(None, RPC_C_AUTHN_WINNT, None, None, &mut engine);
            if !ok(rc) {
                return Err(EngineError::Os(format!("FwpmEngineOpen0 failed: {rc:#x}")));
            }
            let mut wfp = Wfp {
                engine,
                ask_filters: Vec::new(),
                events: None,
                denied: None,
                trusted_filters: Vec::new(),
            };
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
        provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
        let _ = FwpmProviderAdd0(self.engine, &provider, None);

        let mut sublayer: FWPM_SUBLAYER0 = std::mem::zeroed();
        sublayer.subLayerKey = IRIS_SUBLAYER;
        sublayer.displayData = FWPM_DISPLAY_DATA0 {
            name: PWSTR(name.as_mut_ptr()),
            description: PWSTR(name.as_mut_ptr()),
        };
        sublayer.providerKey = &IRIS_PROVIDER as *const _ as *mut _;
        sublayer.weight = 0x8000;
        // persistent like the filters: a non-persistent sublayer rejects
        // persistent filter adds with FWP_E_LIFETIME_MISMATCH
        sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
        let _ = FwpmSubLayerAdd0(self.engine, &sublayer, None);
        Ok(())
    }

    /// wipe every iris filter, then leave a clean provider + sublayer in place.
    /// called on startup before rules re-apply. the filters must be deleted
    /// first: our objects are non-dynamic and persist in the base filtering
    /// engine across a service-process restart, and deleting a sublayer that
    /// still holds filters fails with FWP_E_IN_USE, so a bare delete leaves the
    /// old run's filters enforcing and piles up duplicates on every restart.
    pub fn reset(&mut self) -> EngineResult<()> {
        unsafe {
            self.clear_filters();
            self.ask_filters.clear();
            // now that the sublayer is empty this succeeds; a fresh install
            // reports FWP_E_SUBLAYER_NOT_FOUND, which ensure_objects then fixes
            let _ = FwpmSubLayerDeleteByKey0(self.engine, &IRIS_SUBLAYER);
            self.ensure_objects()
        }
    }

    /// enumerate and delete every filter iris owns. we only ever add at the four
    /// ALE connect / recv-accept layers, so enumerating those by our provider key
    /// covers all of them.
    ///
    /// persistent filters from a previous run are included by default; the enum
    /// template's flags field stays zero for that reason.
    unsafe fn clear_filters(&self) {
        const LAYERS: [GUID; 4] = [
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        ];
        for layer in LAYERS {
            let mut provider_key = IRIS_PROVIDER;
            let mut template: FWPM_FILTER_ENUM_TEMPLATE0 = std::mem::zeroed();
            template.providerKey = &mut provider_key;
            template.layerKey = layer;
            template.enumType = FWP_FILTER_ENUM_OVERLAPPING;
            template.actionMask = 0xFFFF_FFFF;

            let mut enum_handle = HANDLE::default();
            if !ok(FwpmFilterCreateEnumHandle0(
                self.engine,
                Some(&template),
                &mut enum_handle,
            )) {
                continue;
            }
            loop {
                let mut entries: *mut *mut FWPM_FILTER0 = ptr::null_mut();
                let mut returned: u32 = 0;
                let rc = FwpmFilterEnum0(self.engine, enum_handle, 64, &mut entries, &mut returned);
                if !ok(rc) || returned == 0 || entries.is_null() {
                    break;
                }
                let slice = std::slice::from_raw_parts(entries, returned as usize);
                for &f in slice {
                    if !f.is_null() {
                        let _ = FwpmFilterDeleteById0(self.engine, (*f).filterId);
                    }
                }
                FwpmFreeMemory0(&mut (entries as *mut core::ffi::c_void));
                if returned < 64 {
                    break;
                }
            }
            let _ = FwpmFilterDestroyEnumHandle0(self.engine, enum_handle);
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
        self.apply_weighted(path, direction, action, &WEIGHT_APP_RULE)
    }

    fn apply_weighted(
        &mut self,
        path: &str,
        direction: Direction,
        action: RuleAction,
        rule_weight: &u64,
    ) -> EngineResult<Vec<u64>> {
        unsafe {
            let file = wide(path);
            let mut app_id: *mut FWP_BYTE_BLOB = ptr::null_mut();
            let rc = FwpmGetAppIdFromFileName0(PCWSTR(file.as_ptr()), &mut app_id);
            if !ok(rc) || app_id.is_null() {
                return Err(app_id_error(path, rc));
            }

            let action_type = match action {
                RuleAction::Block => FWP_ACTION_BLOCK,
                RuleAction::Allow => FWP_ACTION_PERMIT,
            };

            let mut ids = Vec::with_capacity(2);
            let mut result = Ok(());
            for layer in Self::layers(direction) {
                let mut conditions = vec![app_condition(app_id)];
                if action == RuleAction::Block {
                    conditions.push(non_loopback_condition());
                }

                let mut name = wide("Iris rule");
                let mut filter: FWPM_FILTER0 = std::mem::zeroed();
                filter.displayData = FWPM_DISPLAY_DATA0 {
                    name: PWSTR(name.as_mut_ptr()),
                    description: PWSTR(name.as_mut_ptr()),
                };
                filter.providerKey = &IRIS_PROVIDER as *const _ as *mut _;
                filter.layerKey = layer;
                filter.subLayerKey = IRIS_SUBLAYER;
                filter.weight = weight(rule_weight);
                // survive an ungraceful engine exit; the next startup wipes and
                // re-applies from the rules file either way
                filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
                filter.numFilterConditions = conditions.len() as u32;
                filter.filterCondition = conditions.as_mut_ptr();
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

    pub fn ask_mode_active(&self) -> bool {
        !self.ask_filters.is_empty()
    }

    /// permit the applications the user has already decided about, so switching
    /// ask mode on does not retroactively deny everything that was working.
    ///
    /// without this the catch-all would deny every app that predates ask mode,
    /// and the user would face a prompt for their whole machine at once. these
    /// filters are not stored rules: they are re-seeded from the app inventory
    /// on every start, and an explicit block rule still outranks them because
    /// WFP takes the first block within a sublayer at equal weight.
    pub fn trust_apps(&mut self, paths: &[String]) {
        let mut seeded = 0usize;
        for path in paths {
            for direction in [Direction::Outbound, Direction::Inbound] {
                match self.apply_weighted(path, direction, RuleAction::Allow, &WEIGHT_SEEDED_TRUST)
                {
                    Ok(ids) => {
                        seeded += 1;
                        self.trusted_filters.extend(ids);
                    }
                    // an app that has been uninstalled has nothing to permit
                    Err(EngineError::NotFound(_)) => {}
                    Err(error) => tracing::debug!(app = %path, "could not pre-trust: {error}"),
                }
            }
        }
        tracing::info!(
            seeded,
            offered = paths.len(),
            "pre-trusted already-accepted applications"
        );
    }

    /// switch ask-before-connect on or off.
    ///
    /// on: a catch-all block filter goes in underneath every per-app rule, so an
    /// application iris has no decision for is denied at the ALE layer instead of
    /// connecting first and being noticed after. loopback is exempt, and the
    /// per-app permit filters added by `apply` carry a heavier weight, so an
    /// allowed app still wins inside the sublayer.
    ///
    /// this is the piece that makes a decision arrive before the connection
    /// rather than after it.
    pub fn set_ask_mode(&mut self, enabled: bool) -> EngineResult<()> {
        if enabled == self.ask_mode_active() {
            return Ok(());
        }
        if !enabled {
            self.events = None;
            let ids: Vec<u64> = std::mem::take(&mut self.ask_filters)
                .into_iter()
                .map(|(id, _)| id)
                .collect();
            return self.remove(&ids);
        }
        unsafe {
            const LAYERS: [(GUID, Direction); 4] = [
                (FWPM_LAYER_ALE_AUTH_CONNECT_V4, Direction::Outbound),
                (FWPM_LAYER_ALE_AUTH_CONNECT_V6, Direction::Outbound),
                (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, Direction::Inbound),
                (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, Direction::Inbound),
            ];
            let mut ids = Vec::with_capacity(LAYERS.len());
            for (layer, direction) in LAYERS {
                let mut conditions = vec![non_loopback_condition()];
                let mut name = wide("Iris ask mode");
                let mut filter: FWPM_FILTER0 = std::mem::zeroed();
                filter.displayData = FWPM_DISPLAY_DATA0 {
                    name: PWSTR(name.as_mut_ptr()),
                    description: PWSTR(name.as_mut_ptr()),
                };
                filter.providerKey = &IRIS_PROVIDER as *const _ as *mut _;
                filter.layerKey = layer;
                filter.subLayerKey = IRIS_SUBLAYER;
                filter.weight = weight(&WEIGHT_ASK_FALLBACK);
                filter.numFilterConditions = conditions.len() as u32;
                filter.filterCondition = conditions.as_mut_ptr();
                filter.action = FWPM_ACTION0 {
                    r#type: FWP_ACTION_BLOCK,
                    Anonymous: std::mem::zeroed(),
                };
                let mut id: u64 = 0;
                let rc = FwpmFilterAdd0(self.engine, &filter, None, Some(&mut id));
                if !ok(rc) {
                    // never leave a half-installed default-deny in place: it would
                    // block one address family and not the other
                    for (id, _) in &ids {
                        let _ = FwpmFilterDeleteById0(self.engine, *id);
                    }
                    return Err(EngineError::Os(format!(
                        "could not install ask mode: {rc:#x}"
                    )));
                }
                ids.push((id, direction));
            }

            // the prompt source has to be live before the deny takes effect, or
            // the first denied connection is silent
            match self.events.as_ref() {
                Some(_) => crate::netevent::set_ask_filters(&ids),
                None => {
                    let (tx, rx) = std::sync::mpsc::channel();
                    match crate::netevent::NetEvents::subscribe(self.engine, &ids, tx) {
                        Ok(events) => {
                            self.events = Some(events);
                            self.denied = Some(rx);
                        }
                        Err(error) => {
                            for (id, _) in &ids {
                                let _ = FwpmFilterDeleteById0(self.engine, *id);
                            }
                            return Err(EngineError::Os(error));
                        }
                    }
                }
            }
            self.ask_filters = ids;
        }
        Ok(())
    }

    /// the stream of connections ask mode denied, taken once by the service
    pub fn take_denied_receiver(
        &mut self,
    ) -> Option<std::sync::mpsc::Receiver<crate::netevent::DeniedConnection>> {
        self.denied.take()
    }
}

/// an explicit filter weight. BFE takes a UINT64 as-is, which is what lets a
/// per-app decision outrank the ask-mode catch-all in the same sublayer. the
/// value is passed by pointer, so `value` must outlive the FwpmFilterAdd0 call.
fn weight(value: &u64) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_UINT64,
        Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0 {
            uint64: value as *const u64 as *mut u64,
        },
    }
}

fn app_id_error(path: &str, code: u32) -> EngineError {
    let message = format!("app id for {path}: {code:#x}");
    if code == ERROR_FILE_NOT_FOUND.0 || code == ERROR_PATH_NOT_FOUND.0 {
        EngineError::NotFound(message)
    } else {
        EngineError::Os(message)
    }
}

fn app_condition(app_id: *mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_ALE_APP_ID,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_BYTE_BLOB_TYPE,
            Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                byteBlob: app_id,
            },
        },
    }
}

fn non_loopback_condition() -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_FLAGS,
        matchType: FWP_MATCH_FLAGS_NONE_SET,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT32,
            Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
            },
        },
    }
}

impl Drop for Wfp {
    fn drop(&mut self) {
        // unsubscribe while the engine handle is still valid
        self.events.take();
        unsafe {
            let _ = FwpmEngineClose0(self.engine);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_exception_matches_only_non_loopback_traffic() {
        let condition = non_loopback_condition();
        assert_eq!(condition.fieldKey, FWPM_CONDITION_FLAGS);
        assert_eq!(condition.matchType, FWP_MATCH_FLAGS_NONE_SET);
        assert_eq!(condition.conditionValue.r#type, FWP_UINT32);
        unsafe {
            assert_eq!(
                condition.conditionValue.Anonymous.uint32,
                FWP_CONDITION_FLAG_IS_LOOPBACK
            );
        }
    }

    /// read a weight back out the way BFE would, so the test checks the value
    /// actually handed to WFP rather than the constant next to it
    fn weight_value(value: &FWP_VALUE0) -> u64 {
        assert_eq!(value.r#type, FWP_UINT64);
        unsafe { *value.Anonymous.uint64 }
    }

    #[test]
    fn a_block_rule_outranks_a_grandfathered_permit_which_outranks_the_deny() {
        // the ordering that keeps ask mode safe to switch on: apps the user had
        // already accepted keep working, but an explicit block still wins, and
        // anything with no decision at all falls through to the catch-all
        let rule = weight_value(&weight(&WEIGHT_APP_RULE));
        let seeded = weight_value(&weight(&WEIGHT_SEEDED_TRUST));
        let fallback = weight_value(&weight(&WEIGHT_ASK_FALLBACK));
        assert!(
            rule > seeded,
            "a user rule {rule} must outweigh seeded trust {seeded}"
        );
        assert!(
            seeded > fallback,
            "seeded trust {seeded} must outweigh the catch-all {fallback}"
        );
    }

    #[test]
    fn a_per_app_decision_outranks_the_ask_mode_catch_all() {
        // WFP evaluates a sublayer's filters from heaviest to lightest and stops
        // at the first permit or block, so an allowed app only survives ask mode
        // if its own filter is heavier than the default deny
        let app = weight_value(&weight(&WEIGHT_APP_RULE));
        let fallback = weight_value(&weight(&WEIGHT_ASK_FALLBACK));
        assert!(
            app > fallback,
            "app rule {app} must outweigh ask mode {fallback}"
        );
    }

    #[test]
    fn the_ask_mode_weight_survives_the_round_trip_into_wfp() {
        assert_eq!(
            weight_value(&weight(&WEIGHT_ASK_FALLBACK)),
            WEIGHT_ASK_FALLBACK
        );
    }

    #[test]
    fn defers_only_missing_application_paths() {
        assert!(matches!(
            app_id_error("c:\\gone.exe", ERROR_FILE_NOT_FOUND.0),
            EngineError::NotFound(_)
        ));
        assert!(matches!(
            app_id_error("c:\\gone\\app.exe", ERROR_PATH_NOT_FOUND.0),
            EngineError::NotFound(_)
        ));
        assert!(matches!(
            app_id_error("c:\\private\\app.exe", 5),
            EngineError::Os(_)
        ));
    }
}
