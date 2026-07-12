//! SQLite-backed persistence for iris: the first-seen app registry (for "new
//! app" alerts), per-minute usage rollups (for the Usage tab), and the durable
//! alert log. one connection guarded by the service behind a mutex; the workload
//! is a handful of writes per second and the occasional query.

use iris_core::{
    AdapterKind, Alert, AlertKind, AppId, Granularity, ProposalState, Rule, RuleProposal,
    UsageBucket, UsageQuery,
};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS apps (
    path TEXT PRIMARY KEY,
    first_seen INTEGER NOT NULL,
    name TEXT
);
CREATE TABLE IF NOT EXISTS usage (
    path TEXT NOT NULL,
    bucket INTEGER NOT NULL,
    sent INTEGER NOT NULL DEFAULT 0,
    recv INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (path, bucket)
);
CREATE INDEX IF NOT EXISTS usage_bucket ON usage(bucket);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at_ms INTEGER NOT NULL,
    kind TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0
);
";

/// v2: traffic split by adapter kind, alongside (not inside) the per-app usage
const SCHEMA_V2_ADAPTER_USAGE: &str = "
CREATE TABLE IF NOT EXISTS adapter_usage (
    kind TEXT NOT NULL,
    bucket INTEGER NOT NULL,
    sent INTEGER NOT NULL DEFAULT 0,
    recv INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (kind, bucket)
);
CREATE INDEX IF NOT EXISTS adapter_usage_bucket ON adapter_usage(bucket);
";

/// v3: per-plugin consent grants. `caps` and `egress` are JSON string arrays;
/// nothing runs out-of-process before a row here says the user allowed it.
const SCHEMA_V3_PLUGIN_GRANTS: &str = "
CREATE TABLE IF NOT EXISTS plugin_grants (
    id TEXT PRIMARY KEY,
    caps TEXT NOT NULL,
    egress TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    granted_at INTEGER NOT NULL
);
";

/// v4: rules plugins have proposed, awaiting the user's verdict. `rule` is the
/// JSON of the proposed [`iris_core::Rule`]; enforcement only ever happens when
/// an elevated caller accepts.
const SCHEMA_V4_RULE_PROPOSALS: &str = "
CREATE TABLE IF NOT EXISTS rule_proposals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    rule TEXT NOT NULL,
    reason TEXT NOT NULL,
    at_ms INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending'
);
CREATE INDEX IF NOT EXISTS rule_proposals_state ON rule_proposals(state);
";

/// bump when the schema changes; drives the migration ladder in [`Store::migrate`]
const SCHEMA_VERSION: i64 = 4;

pub struct Store {
    conn: Connection,
}

/// the user's persisted consent for one plugin: the capability and egress sets
/// approved on first enable, and whether it is currently switched on
#[derive(Debug, Clone, PartialEq)]
pub struct PluginGrant {
    pub id: String,
    pub caps: Vec<String>,
    pub egress: Vec<String>,
    pub enabled: bool,
    pub granted_at: u64,
}

fn grant_row(r: &rusqlite::Row) -> rusqlite::Result<PluginGrant> {
    let id: String = r.get(0)?;
    let caps: String = r.get(1)?;
    let egress: String = r.get(2)?;
    let enabled: i64 = r.get(3)?;
    let granted_at: i64 = r.get(4)?;
    Ok(PluginGrant {
        id,
        caps: serde_json::from_str(&caps).unwrap_or_default(),
        egress: serde_json::from_str(&egress).unwrap_or_default(),
        enabled: enabled != 0,
        granted_at: granted_at as u64,
    })
}

impl Store {
    pub fn open(path: &Path) -> rusqlite::Result<Store> {
        let conn = Self::open_checked(path)?;
        conn.pragma_update(None, "journal_mode", "WAL").ok();
        let store = Store { conn };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_in_memory() -> rusqlite::Result<Store> {
        let store = Store {
            conn: Connection::open_in_memory()?,
        };
        store.migrate()?;
        Ok(store)
    }

    /// open the db, and if it fails an integrity check (a torn write on power
    /// loss leaves SQLITE_CORRUPT) set the bad file aside and start fresh, so a
    /// corrupt history never degrades every read and write to a silent no-op.
    fn open_checked(path: &Path) -> rusqlite::Result<Connection> {
        let conn = Connection::open(path)?;
        let ok = conn
            .query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0))
            .map(|s| s == "ok")
            .unwrap_or(false);
        if ok {
            return Ok(conn);
        }
        tracing::error!(
            "history db {} failed its integrity check, recreating it",
            path.display()
        );
        drop(conn);
        let corrupt = path.with_extension("db.corrupt");
        let _ = std::fs::remove_file(&corrupt);
        let _ = std::fs::rename(path, &corrupt);
        // clear the WAL/SHM siblings so the fresh db does not inherit them
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
        Connection::open(path)
    }

    /// apply schema migrations in order, stamping PRAGMA user_version so an
    /// upgraded install evolves the existing db in place rather than silently
    /// running against the old shape.
    fn migrate(&self) -> rusqlite::Result<()> {
        let version: i64 = self.conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version < 1 {
            self.conn.execute_batch(SCHEMA)?;
        }
        if version < 2 {
            self.conn.execute_batch(SCHEMA_V2_ADAPTER_USAGE)?;
        }
        if version < 3 {
            self.conn.execute_batch(SCHEMA_V3_PLUGIN_GRANTS)?;
        }
        if version < 4 {
            self.conn.execute_batch(SCHEMA_V4_RULE_PROPOSALS)?;
        }
        if version < SCHEMA_VERSION {
            self.conn
                .pragma_update(None, "user_version", SCHEMA_VERSION)?;
        }
        Ok(())
    }

    /// record an app in the first-seen registry; returns true the first time an
    /// app is ever seen, which drives the "new app connected" alert
    pub fn ensure_app(&self, path: &str, name: Option<&str>, at_ms: u64) -> bool {
        match self.conn.execute(
            "INSERT OR IGNORE INTO apps(path, first_seen, name) VALUES (?1, ?2, ?3)",
            params![path, at_ms as i64, name],
        ) {
            Ok(rows) => rows > 0,
            Err(e) => {
                tracing::warn!("could not register app {path}: {e}");
                false
            }
        }
    }

    /// add bytes to an app's current-minute usage bucket
    pub fn add_usage(&self, path: &str, at_ms: u64, sent: u64, recv: u64) {
        if sent == 0 && recv == 0 {
            return;
        }
        let bucket = Granularity::Minute.bucket_start(at_ms) as i64;
        if let Err(e) = self.conn.execute(
            "INSERT INTO usage(path, bucket, sent, recv) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(path, bucket) DO UPDATE SET sent = sent + ?3, recv = recv + ?4",
            params![path, bucket, sent as i64, recv as i64],
        ) {
            tracing::warn!("could not record usage for {path}: {e}");
        }
    }

    /// add bytes to an adapter kind's current-minute usage bucket
    pub fn add_adapter_usage(&self, kind: AdapterKind, at_ms: u64, sent: u64, recv: u64) {
        if sent == 0 && recv == 0 {
            return;
        }
        let bucket = Granularity::Minute.bucket_start(at_ms) as i64;
        if let Err(e) = self.conn.execute(
            "INSERT INTO adapter_usage(kind, bucket, sent, recv) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(kind, bucket) DO UPDATE SET sent = sent + ?3, recv = recv + ?4",
            params![kind.as_str(), bucket, sent as i64, recv as i64],
        ) {
            tracing::warn!("could not record adapter usage: {e}");
        }
    }

    /// total bytes per adapter kind over a window, biggest first
    pub fn adapter_usage_totals(
        &self,
        from_ms: u64,
        to_ms: u64,
    ) -> Vec<(AdapterKind, iris_core::ByteCounts)> {
        let mut stmt = match self.conn.prepare(
            "SELECT kind, SUM(sent), SUM(recv) FROM adapter_usage
             WHERE bucket >= ?1 AND bucket < ?2 GROUP BY kind
             ORDER BY SUM(sent) + SUM(recv) DESC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map(params![from_ms as i64, to_ms as i64], |r| {
            let kind: String = r.get(0)?;
            let sent: i64 = r.get(1)?;
            let recv: i64 = r.get(2)?;
            Ok((kind, sent, recv))
        });
        match rows {
            Ok(rows) => rows
                .flatten()
                .filter_map(|(kind, sent, recv)| {
                    AdapterKind::parse(&kind).map(|k| {
                        (
                            k,
                            iris_core::ByteCounts {
                                sent: sent as u64,
                                recv: recv as u64,
                            },
                        )
                    })
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// per-app usage aggregated into the requested granularity over a window
    pub fn query_usage(&self, q: &UsageQuery) -> Vec<UsageBucket> {
        let width = q.granularity.width_ms().max(1) as i64;
        let from = q.from_ms as i64;
        let to = q.to_ms as i64;

        let mut out = Vec::new();
        let run = |sql: &str, extra: &[&dyn rusqlite::ToSql]| -> rusqlite::Result<Vec<UsageBucket>> {
            let mut stmt = self.conn.prepare(sql)?;
            let rows = stmt.query_map(extra, |r| {
                let path: String = r.get(0)?;
                let bucket: i64 = r.get(1)?;
                let sent: i64 = r.get(2)?;
                let recv: i64 = r.get(3)?;
                Ok(UsageBucket {
                    app: AppId(path),
                    bucket_start_ms: bucket as u64,
                    bytes: iris_core::ByteCounts {
                        sent: sent as u64,
                        recv: recv as u64,
                    },
                })
            })?;
            rows.collect()
        };

        // cap the number of returned rows so a wide query cannot dump the whole
        // history into memory / the pipe at once
        const MAX_ROWS: i64 = 200_000;
        let result = if let Some(app) = &q.app {
            run(
                "SELECT path, (bucket / ?1) * ?1 AS b, SUM(sent), SUM(recv)
                 FROM usage WHERE bucket >= ?2 AND bucket < ?3 AND path = ?4
                 GROUP BY path, b ORDER BY b LIMIT ?5",
                params![width, from, to, app.as_str(), MAX_ROWS],
            )
        } else {
            run(
                "SELECT path, (bucket / ?1) * ?1 AS b, SUM(sent), SUM(recv)
                 FROM usage WHERE bucket >= ?2 AND bucket < ?3
                 GROUP BY path, b ORDER BY b LIMIT ?4",
                params![width, from, to, MAX_ROWS],
            )
        };
        if let Ok(rows) = result {
            out = rows;
        }
        out
    }

    /// total bytes per app over a window, biggest first (for the Usage table)
    pub fn usage_totals(&self, from_ms: u64, to_ms: u64) -> Vec<(AppId, iris_core::ByteCounts)> {
        let mut stmt = match self.conn.prepare(
            "SELECT path, SUM(sent), SUM(recv) FROM usage
             WHERE bucket >= ?1 AND bucket < ?2 GROUP BY path
             ORDER BY SUM(sent) + SUM(recv) DESC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map(params![from_ms as i64, to_ms as i64], |r| {
            let path: String = r.get(0)?;
            let sent: i64 = r.get(1)?;
            let recv: i64 = r.get(2)?;
            Ok((
                AppId(path),
                iris_core::ByteCounts {
                    sent: sent as u64,
                    recv: recv as u64,
                },
            ))
        });
        rows.map(|r| r.flatten().collect()).unwrap_or_default()
    }

    pub fn insert_alert(&self, kind: &AlertKind, at_ms: u64) -> Alert {
        let kind_json = serde_json::to_string(kind).unwrap_or_default();
        // only trust last_insert_rowid when the insert actually wrote a row;
        // otherwise the returned Alert would carry a stale id for a row that was
        // never persisted
        let id = match self.conn.execute(
            "INSERT INTO alerts(at_ms, kind, acknowledged) VALUES (?1, ?2, 0)",
            params![at_ms as i64, kind_json],
        ) {
            Ok(rows) if rows > 0 => self.conn.last_insert_rowid(),
            Ok(_) => {
                tracing::warn!("alert insert wrote no rows");
                0
            }
            Err(e) => {
                tracing::warn!("could not persist alert: {e}");
                0
            }
        };
        Alert {
            id,
            at_ms,
            kind: kind.clone(),
            acknowledged: false,
        }
    }

    pub fn list_alerts(&self, unacked_only: bool) -> Vec<Alert> {
        let sql = if unacked_only {
            "SELECT id, at_ms, kind, acknowledged FROM alerts WHERE acknowledged = 0 ORDER BY id DESC LIMIT 500"
        } else {
            "SELECT id, at_ms, kind, acknowledged FROM alerts ORDER BY id DESC LIMIT 500"
        };
        let mut stmt = match self.conn.prepare(sql) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map([], |r| {
            let id: i64 = r.get(0)?;
            let at_ms: i64 = r.get(1)?;
            let kind_json: String = r.get(2)?;
            let acknowledged: i64 = r.get(3)?;
            Ok((id, at_ms, kind_json, acknowledged))
        });
        let mut out = Vec::new();
        if let Ok(rows) = rows {
            for row in rows.flatten() {
                if let Ok(kind) = serde_json::from_str::<AlertKind>(&row.2) {
                    out.push(Alert {
                        id: row.0,
                        at_ms: row.1 as u64,
                        kind,
                        acknowledged: row.3 != 0,
                    });
                }
            }
        }
        out
    }

    pub fn ack_alert(&self, id: i64) {
        if let Err(e) = self
            .conn
            .execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?1", params![id])
        {
            tracing::warn!("could not ack alert {id}: {e}");
        }
    }

    pub fn ack_all_alerts(&self) {
        if let Err(e) = self.conn.execute("UPDATE alerts SET acknowledged = 1", []) {
            tracing::warn!("could not ack alerts: {e}");
        }
    }

    /// drop usage buckets older than the cutoff to bound the file
    pub fn prune_usage(&self, older_than_ms: u64) {
        if let Err(e) = self.conn.execute(
            "DELETE FROM usage WHERE bucket < ?1",
            params![older_than_ms as i64],
        ) {
            tracing::warn!("could not prune usage: {e}");
        }
        if let Err(e) = self.conn.execute(
            "DELETE FROM adapter_usage WHERE bucket < ?1",
            params![older_than_ms as i64],
        ) {
            tracing::warn!("could not prune adapter usage: {e}");
        }
    }

    /// record (or replace) the user's consent for a plugin
    pub fn set_plugin_grant(
        &self,
        id: &str,
        caps: &[String],
        egress: &[String],
        enabled: bool,
        at_ms: u64,
    ) {
        let caps_json = serde_json::to_string(caps).unwrap_or_else(|_| "[]".into());
        let egress_json = serde_json::to_string(egress).unwrap_or_else(|_| "[]".into());
        if let Err(e) = self.conn.execute(
            "INSERT INTO plugin_grants(id, caps, egress, enabled, granted_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET
               caps = ?2, egress = ?3, enabled = ?4, granted_at = ?5",
            params![id, caps_json, egress_json, enabled as i64, at_ms as i64],
        ) {
            tracing::warn!("could not record plugin grant for {id}: {e}");
        }
    }

    /// flip a granted plugin on or off; false when no grant exists
    pub fn set_plugin_enabled(&self, id: &str, enabled: bool) -> bool {
        match self.conn.execute(
            "UPDATE plugin_grants SET enabled = ?2 WHERE id = ?1",
            params![id, enabled as i64],
        ) {
            Ok(rows) => rows > 0,
            Err(e) => {
                tracing::warn!("could not update plugin grant for {id}: {e}");
                false
            }
        }
    }

    pub fn plugin_grant(&self, id: &str) -> Option<PluginGrant> {
        self.conn
            .query_row(
                "SELECT id, caps, egress, enabled, granted_at FROM plugin_grants WHERE id = ?1",
                params![id],
                grant_row,
            )
            .optional()
            .ok()
            .flatten()
    }

    pub fn list_plugin_grants(&self) -> Vec<PluginGrant> {
        let mut stmt = match self
            .conn
            .prepare("SELECT id, caps, egress, enabled, granted_at FROM plugin_grants ORDER BY id")
        {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map([], grant_row)
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default()
    }

    /// record a plugin's rule proposal. an identical pending proposal is
    /// returned rather than duplicated, and each source is capped to a bounded
    /// pending backlog, so a chatty plugin can neither flood the review UI nor
    /// grow the db without limit. None when the cap refused it.
    pub fn insert_proposal(
        &self,
        source: &str,
        rule: &Rule,
        reason: &str,
        at_ms: u64,
    ) -> Option<RuleProposal> {
        const MAX_PENDING_PER_SOURCE: i64 = 50;
        let rule_json = serde_json::to_string(rule).ok()?;
        let existing = self
            .conn
            .query_row(
                "SELECT id, reason, at_ms FROM rule_proposals
                 WHERE source = ?1 AND rule = ?2 AND state = 'pending'",
                params![source, rule_json],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?)),
            )
            .optional()
            .ok()
            .flatten();
        if let Some((id, reason, at_ms)) = existing {
            return Some(RuleProposal {
                id,
                source: source.to_string(),
                rule: rule.clone(),
                reason,
                at_ms: at_ms as u64,
                state: ProposalState::Pending,
            });
        }
        let pending: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM rule_proposals WHERE source = ?1 AND state = 'pending'",
                params![source],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if pending >= MAX_PENDING_PER_SOURCE {
            tracing::warn!("proposal backlog for {source} is full, refusing another");
            return None;
        }
        match self.conn.execute(
            "INSERT INTO rule_proposals(source, rule, reason, at_ms, state)
             VALUES (?1, ?2, ?3, ?4, 'pending')",
            params![source, rule_json, reason, at_ms as i64],
        ) {
            Ok(rows) if rows > 0 => Some(RuleProposal {
                id: self.conn.last_insert_rowid(),
                source: source.to_string(),
                rule: rule.clone(),
                reason: reason.to_string(),
                at_ms,
                state: ProposalState::Pending,
            }),
            Ok(_) => None,
            Err(e) => {
                tracing::warn!("could not persist proposal from {source}: {e}");
                None
            }
        }
    }

    /// recent proposals, newest first, pending and resolved alike so the review
    /// UI can show a short history
    pub fn list_proposals(&self) -> Vec<RuleProposal> {
        let mut stmt = match self.conn.prepare(
            "SELECT id, source, rule, reason, at_ms, state FROM rule_proposals
             ORDER BY id DESC LIMIT 200",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map([], |r| {
            let id: i64 = r.get(0)?;
            let source: String = r.get(1)?;
            let rule_json: String = r.get(2)?;
            let reason: String = r.get(3)?;
            let at_ms: i64 = r.get(4)?;
            let state: String = r.get(5)?;
            Ok((id, source, rule_json, reason, at_ms, state))
        });
        let mut out = Vec::new();
        if let Ok(rows) = rows {
            for (id, source, rule_json, reason, at_ms, state) in rows.flatten() {
                let (Ok(rule), Some(state)) = (
                    serde_json::from_str::<Rule>(&rule_json),
                    ProposalState::parse(&state),
                ) else {
                    continue;
                };
                out.push(RuleProposal { id, source, rule, reason, at_ms: at_ms as u64, state });
            }
        }
        out
    }

    /// settle a pending proposal; returns it (with the new state) so an
    /// accepting caller has the rule to apply. None when it does not exist or
    /// was already settled, so a race between two reviewers resolves once.
    pub fn resolve_proposal(&self, id: i64, accept: bool) -> Option<RuleProposal> {
        let state = if accept { ProposalState::Accepted } else { ProposalState::Rejected };
        let updated = self
            .conn
            .execute(
                "UPDATE rule_proposals SET state = ?2 WHERE id = ?1 AND state = 'pending'",
                params![id, state.as_str()],
            )
            .unwrap_or(0);
        if updated == 0 {
            return None;
        }
        self.conn
            .query_row(
                "SELECT source, rule, reason, at_ms FROM rule_proposals WHERE id = ?1",
                params![id],
                |r| {
                    let source: String = r.get(0)?;
                    let rule_json: String = r.get(1)?;
                    let reason: String = r.get(2)?;
                    let at_ms: i64 = r.get(3)?;
                    Ok((source, rule_json, reason, at_ms))
                },
            )
            .optional()
            .ok()
            .flatten()
            .and_then(|(source, rule_json, reason, at_ms)| {
                serde_json::from_str::<Rule>(&rule_json).ok().map(|rule| RuleProposal {
                    id,
                    source,
                    rule,
                    reason,
                    at_ms: at_ms as u64,
                    state,
                })
            })
    }

    pub fn first_seen(&self, path: &str) -> Option<u64> {
        self.conn
            .query_row(
                "SELECT first_seen FROM apps WHERE path = ?1",
                params![path],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .ok()
            .flatten()
            .map(|v| v as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_seen_fires_once() {
        let s = Store::open_in_memory().unwrap();
        assert!(s.ensure_app("c:/x.exe", None, 100));
        assert!(!s.ensure_app("c:/x.exe", None, 200));
        assert_eq!(s.first_seen("c:/x.exe"), Some(100));
    }

    #[test]
    fn usage_accumulates_into_minute_buckets() {
        let s = Store::open_in_memory().unwrap();
        s.add_usage("c:/x.exe", 1_000, 100, 200);
        s.add_usage("c:/x.exe", 2_000, 50, 0); // same minute
        let totals = s.usage_totals(0, 120_000);
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[0].1.sent, 150);
        assert_eq!(totals[0].1.recv, 200);
    }

    #[test]
    fn adapter_usage_accumulates_and_totals() {
        let s = Store::open_in_memory().unwrap();
        s.add_adapter_usage(AdapterKind::Wifi, 1_000, 100, 200);
        s.add_adapter_usage(AdapterKind::Wifi, 2_000, 50, 0); // same minute
        s.add_adapter_usage(AdapterKind::Vpn, 1_000, 10, 10);
        let totals = s.adapter_usage_totals(0, 120_000);
        assert_eq!(totals.len(), 2);
        assert_eq!(totals[0].0, AdapterKind::Wifi);
        assert_eq!(totals[0].1.sent, 150);
        assert_eq!(totals[0].1.recv, 200);
        assert_eq!(totals[1].0, AdapterKind::Vpn);
        // outside the window
        assert!(s.adapter_usage_totals(120_000, 240_000).is_empty());
    }

    #[test]
    fn plugin_grants_roundtrip_and_toggle() {
        let s = Store::open_in_memory().unwrap();
        assert!(s.plugin_grant("com.example.rep").is_none());
        assert!(!s.set_plugin_enabled("com.example.rep", true));
        s.set_plugin_grant(
            "com.example.rep",
            &["observe:ticks".into(), "enrich:endpoint".into()],
            &["api.example.com:443".into()],
            true,
            1_000,
        );
        let g = s.plugin_grant("com.example.rep").unwrap();
        assert!(g.enabled);
        assert_eq!(g.caps.len(), 2);
        assert_eq!(g.egress, vec!["api.example.com:443".to_string()]);
        assert!(s.set_plugin_enabled("com.example.rep", false));
        assert!(!s.plugin_grant("com.example.rep").unwrap().enabled);
        assert_eq!(s.list_plugin_grants().len(), 1);
    }

    #[test]
    fn proposals_dedupe_cap_and_resolve_once() {
        let s = Store::open_in_memory().unwrap();
        let rule = iris_core::Rule::block_outbound(AppId("c:/evil.exe".into()));

        let p = s.insert_proposal("Rep", &rule, "known bad", 1_000).unwrap();
        assert_eq!(p.state, ProposalState::Pending);
        // the identical pending proposal comes back instead of stacking
        let again = s.insert_proposal("Rep", &rule, "still bad", 2_000).unwrap();
        assert_eq!(again.id, p.id);
        assert_eq!(s.list_proposals().len(), 1);

        // resolving settles it exactly once and hands back the rule to apply
        let accepted = s.resolve_proposal(p.id, true).unwrap();
        assert_eq!(accepted.state, ProposalState::Accepted);
        assert_eq!(accepted.rule, rule);
        assert!(s.resolve_proposal(p.id, false).is_none());

        // once settled, the same rule may be proposed afresh
        let fresh = s.insert_proposal("Rep", &rule, "back again", 3_000).unwrap();
        assert_ne!(fresh.id, p.id);
        assert!(s.resolve_proposal(fresh.id, false).is_some());

        // a source's pending backlog is bounded
        for n in 0..60 {
            let r = iris_core::Rule::block_outbound(AppId(format!("c:/{n}.exe")));
            s.insert_proposal("Flood", &r, "x", 1);
        }
        let pending = s
            .list_proposals()
            .into_iter()
            .filter(|p| p.source == "Flood" && p.state == ProposalState::Pending)
            .count();
        assert_eq!(pending, 50);
    }

    #[test]
    fn alerts_roundtrip_and_ack() {
        let s = Store::open_in_memory().unwrap();
        let a = s.insert_alert(&AlertKind::NewApp { app: AppId("c:/x.exe".into()) }, 500);
        assert_eq!(s.list_alerts(true).len(), 1);
        s.ack_alert(a.id);
        assert_eq!(s.list_alerts(true).len(), 0);
        assert_eq!(s.list_alerts(false).len(), 1);
    }
}
