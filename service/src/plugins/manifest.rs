//! plugin manifests. each installed plugin lives in its own directory under
//! `%ProgramData%\Iris\plugins\<id>\` with a `plugin.json` manifest and its
//! entry binary. that root's ACL restricts writes to SYSTEM and Administrators,
//! so an unprivileged user cannot drop a plugin there; the manifest only ever
//! widens what a plugin *may* ask for, never what it is granted (that is the
//! user's consent, stored separately).

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// the plugin root, alongside the db and rules file
pub fn plugins_dir() -> PathBuf {
    crate::paths::plugins_dir()
}

/// the declared shape of a plugin, parsed from its `plugin.json`. this is the
/// ceiling: the effective grant is this intersected with the user's consent.
#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
    /// the entry binary, resolved relative to the plugin directory
    pub entry: String,
    /// requested capabilities, e.g. `observe:ticks`, `enrich:endpoint`,
    /// `emit:alerts`. anything the plugin registers with must be a subset.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// declared egress, `host:port` per entry. the service pins the child to
    /// exactly these with WFP; an empty list means no network.
    #[serde(default)]
    pub egress: Vec<String>,
}

/// the capabilities Iris understands; a manifest asking for anything else is
/// rejected rather than silently ignored
const KNOWN_CAPS: &[&str] = &[
    "observe:ticks",
    "observe:alerts",
    "enrich:endpoint",
    "enrich:app",
    "emit:alerts",
    "emit:rule-proposals",
    "ui:panel",
];

impl Manifest {
    /// parse and validate a manifest's JSON. rejects unknown capabilities,
    /// malformed egress, and an id that would escape the plugins directory.
    pub fn parse(json: &str) -> Result<Manifest, String> {
        let m: Manifest =
            serde_json::from_str(json).map_err(|e| format!("invalid plugin manifest: {e}"))?;
        if m.id.trim().is_empty() {
            return Err("plugin manifest has no id".into());
        }
        // the id names the on-disk directory, so it must be a single safe path
        // segment; a traversal here would let a manifest point entry elsewhere
        if !m
            .id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        {
            return Err(format!("plugin id has unsafe characters: {}", m.id));
        }
        if m.entry.trim().is_empty() {
            return Err("plugin manifest has no entry binary".into());
        }
        // the entry binary must stay inside the plugin directory
        if m.entry.contains('/') || m.entry.contains('\\') || m.entry.contains("..") {
            return Err(format!(
                "plugin entry must be a bare file name: {}",
                m.entry
            ));
        }
        for cap in &m.capabilities {
            if !KNOWN_CAPS.contains(&cap.as_str()) {
                return Err(format!("plugin requests unknown capability: {cap}"));
            }
        }
        for host in &m.egress {
            validate_egress(host)?;
        }
        Ok(m)
    }

    /// load and validate the manifest in a plugin directory
    pub fn load(dir: &Path) -> Result<Manifest, String> {
        let path = dir.join("plugin.json");
        let json = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let m = Manifest::parse(&json)?;
        // the directory name must match the id, so a manifest cannot masquerade
        // as a different plugin than the folder it was installed into
        if let Some(folder) = dir.file_name().and_then(|s| s.to_str()) {
            if folder != m.id {
                return Err(format!(
                    "plugin directory {folder} does not match manifest id {}",
                    m.id
                ));
            }
        }
        Ok(m)
    }

    /// absolute path to the entry binary
    pub fn entry_path(&self, dir: &Path) -> PathBuf {
        dir.join(&self.entry)
    }

    /// whether this manifest declares a given capability
    pub fn declares(&self, cap: &str) -> bool {
        self.capabilities.iter().any(|c| c == cap)
    }
}

/// enumerate every installed plugin's manifest, skipping (with a log) any that
/// fail to parse rather than failing the whole scan
pub fn discover() -> Vec<(PathBuf, Manifest)> {
    let root = plugins_dir();
    let entries = match std::fs::read_dir(&root) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        match Manifest::load(&dir) {
            Ok(m) => out.push((dir, m)),
            Err(e) => tracing::warn!("skipping plugin at {}: {e}", dir.display()),
        }
    }
    out
}

/// a declared egress entry must be `host:port` with a real port and a non-empty
/// host, so the WFP pin has something concrete to permit
fn validate_egress(entry: &str) -> Result<(), String> {
    let (host, port) = entry
        .rsplit_once(':')
        .ok_or_else(|| format!("egress must be host:port: {entry}"))?;
    if host.trim().is_empty() {
        return Err(format!("egress has an empty host: {entry}"));
    }
    port.parse::<u16>()
        .map(|_| ())
        .map_err(|_| format!("egress has an invalid port: {entry}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(extra: &str) -> String {
        format!(r#"{{"id":"com.example.rep","name":"Rep","entry":"rep.exe"{extra}}}"#)
    }

    #[test]
    fn parses_a_valid_manifest() {
        let m = Manifest::parse(&manifest(
            r#","capabilities":["enrich:endpoint","emit:alerts"],"egress":["api.example.com:443"]"#,
        ))
        .expect("valid");
        assert_eq!(m.id, "com.example.rep");
        assert!(m.declares("emit:alerts"));
        assert_eq!(m.egress, vec!["api.example.com:443".to_string()]);
    }

    #[test]
    fn rejects_unknown_capability() {
        let err =
            Manifest::parse(&manifest(r#","capabilities":["firewall:enforce"]"#)).unwrap_err();
        assert!(err.contains("unknown capability"));
    }

    #[test]
    fn rejects_path_traversal_in_id_and_entry() {
        assert!(Manifest::parse(r#"{"id":"../evil","name":"x","entry":"x.exe"}"#).is_err());
        assert!(Manifest::parse(r#"{"id":"ok","name":"x","entry":"..\\evil.exe"}"#).is_err());
        assert!(Manifest::parse(r#"{"id":"ok","name":"x","entry":"sub/x.exe"}"#).is_err());
    }

    #[test]
    fn rejects_malformed_egress() {
        assert!(Manifest::parse(&manifest(r#","egress":["api.example.com"]"#)).is_err());
        assert!(Manifest::parse(&manifest(r#","egress":["api.example.com:notaport"]"#)).is_err());
        assert!(Manifest::parse(&manifest(r#","egress":[":443"]"#)).is_err());
    }
}
