use crate::model::{AppId, Direction, Endpoint};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// why an alert was raised
#[derive(Debug, Clone, PartialEq)]
pub enum AlertKind {
    /// an application connected to the network for the first time ever
    NewApp {
        app: AppId,
        remote: Option<Endpoint>,
        direction: Option<Direction>,
    },
    /// a rule blocked an application's connection attempt
    Blocked { app: AppId, remote: Endpoint },
    /// an enricher or plugin flagged activity it considers noteworthy; `source`
    /// is its human-readable name and `message` is the full sentence to show
    Plugin { source: String, message: String },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum HumanAlertKind {
    NewApp {
        app: AppId,
        #[serde(default)]
        remote: Option<Endpoint>,
        #[serde(default)]
        direction: Option<Direction>,
    },
    Blocked {
        app: AppId,
        remote: Endpoint,
    },
    Plugin {
        source: String,
        message: String,
    },
}

#[derive(Serialize, Deserialize)]
enum BinaryAlertKind {
    NewApp {
        app: AppId,
        remote: Option<Endpoint>,
        direction: Option<Direction>,
    },
    Blocked {
        app: AppId,
        remote: Endpoint,
    },
    Plugin {
        source: String,
        message: String,
    },
}

macro_rules! convert_alert_kind {
    ($value:expr, $target:ident) => {
        match $value {
            AlertKind::NewApp {
                app,
                remote,
                direction,
            } => $target::NewApp {
                app,
                remote,
                direction,
            },
            AlertKind::Blocked { app, remote } => $target::Blocked { app, remote },
            AlertKind::Plugin { source, message } => $target::Plugin { source, message },
        }
    };
}

impl Serialize for AlertKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            convert_alert_kind!(self.clone(), HumanAlertKind).serialize(serializer)
        } else {
            convert_alert_kind!(self.clone(), BinaryAlertKind).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for AlertKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            Ok(match HumanAlertKind::deserialize(deserializer)? {
                HumanAlertKind::NewApp {
                    app,
                    remote,
                    direction,
                } => AlertKind::NewApp {
                    app,
                    remote,
                    direction,
                },
                HumanAlertKind::Blocked { app, remote } => AlertKind::Blocked { app, remote },
                HumanAlertKind::Plugin { source, message } => AlertKind::Plugin { source, message },
            })
        } else {
            Ok(match BinaryAlertKind::deserialize(deserializer)? {
                BinaryAlertKind::NewApp {
                    app,
                    remote,
                    direction,
                } => AlertKind::NewApp {
                    app,
                    remote,
                    direction,
                },
                BinaryAlertKind::Blocked { app, remote } => AlertKind::Blocked { app, remote },
                BinaryAlertKind::Plugin { source, message } => {
                    AlertKind::Plugin { source, message }
                }
            })
        }
    }
}

/// a durable alert. persisted so it survives a UI that is closed when the event
/// fires, then surfaced (and toasted) on next UI launch if still unacknowledged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Alert {
    pub id: i64,
    /// milliseconds since unix epoch
    pub at_ms: u64,
    pub kind: AlertKind,
    pub acknowledged: bool,
}
