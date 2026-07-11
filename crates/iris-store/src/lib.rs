//! SQLite-backed persistence for iris: the first-seen app registry (for "new
//! app" alerts), per-minute usage rollups (for the Usage tab), and the durable
//! alert log. one connection guarded by the service behind a mutex; the workload
//! is a handful of writes per second and the occasional query.

use iris_core::{Alert, AlertKind, AppId, Granularity, UsageBucket, UsageQuery};
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

/// bump when the schema changes; drives the migration ladder in [`Store::migrate`]
const SCHEMA_VERSION: i64 = 1;

pub struct Store {
    conn: Connection,
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
        // future steps append here: `if version < 2 { ...alter... }`
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
    fn alerts_roundtrip_and_ack() {
        let s = Store::open_in_memory().unwrap();
        let a = s.insert_alert(&AlertKind::NewApp { app: AppId("c:/x.exe".into()) }, 500);
        assert_eq!(s.list_alerts(true).len(), 1);
        s.ack_alert(a.id);
        assert_eq!(s.list_alerts(true).len(), 0);
        assert_eq!(s.list_alerts(false).len(), 1);
    }
}
