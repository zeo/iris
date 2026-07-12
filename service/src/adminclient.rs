//! the elevated one-shot that performs rule mutations over the admin pipe, then
//! exits with 0 on success or non-zero on failure. the UI launches it with a
//! UAC prompt; the admin pipe's DACL means only an elevated process can reach
//! the engine here, so changing a firewall rule requires elevation.

use anyhow::{bail, Context};
use iris_core::{AppId, BackupRule, Direction, Rule, RuleAction, BACKUP_MAX_BYTES};
use iris_ipc::message::{ClientMessage, Reply, ServerMessage, PROTOCOL_VERSION};
use iris_ipc::transport;
use std::path::Path;

/// what one elevated run performs: a single mutation, or a whole backup file
enum Op {
    Single(ClientMessage),
    Import(Vec<BackupRule>),
}

/// `args` begins with the rule flag (e.g. `--rule-add`) and its operands.
pub fn run(args: &[String]) -> anyhow::Result<()> {
    let op = build_op(args)?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(exec(op))
}

fn build_op(args: &[String]) -> anyhow::Result<Op> {
    match args.first().map(String::as_str) {
        Some("--rule-add") => {
            let path = args.get(1).context("rule-add: missing app path")?;
            let direction = parse_direction(args.get(2).map(String::as_str))?;
            let action = parse_action(args.get(3).map(String::as_str))?;
            Ok(Op::Single(ClientMessage::AddRule {
                req: 1,
                rule: Rule {
                    app: AppId::from_path(path),
                    direction,
                    action,
                    label: None,
                },
            }))
        }
        Some("--rule-remove") => {
            let id = parse_id(args.get(1))?;
            Ok(Op::Single(ClientMessage::RemoveRule { req: 1, id }))
        }
        Some("--rule-enable") => {
            let id = parse_id(args.get(1))?;
            let enabled = matches!(args.get(2).map(String::as_str), Some("true") | Some("1"));
            Ok(Op::Single(ClientMessage::SetRuleEnabled { req: 1, id, enabled }))
        }
        Some("--rule-import") => {
            let path = args.get(1).context("rule-import: missing file path")?;
            Ok(Op::Import(read_backup(Path::new(path))?))
        }
        Some("--proposal-accept") => {
            let id = parse_id(args.get(1))?;
            Ok(Op::Single(ClientMessage::ResolveProposal { req: 1, id, accept: true }))
        }
        _ => bail!("unknown rule command"),
    }
}

fn read_backup(path: &Path) -> anyhow::Result<Vec<BackupRule>> {
    let meta =
        std::fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
    if meta.len() > BACKUP_MAX_BYTES {
        bail!("{} is too large to be a rules backup", path.display());
    }
    let json =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    iris_core::parse_backup(&json).map_err(anyhow::Error::msg)
}

fn parse_id(s: Option<&String>) -> anyhow::Result<i64> {
    s.and_then(|s| s.parse().ok()).context("expected a numeric rule id")
}

fn parse_direction(s: Option<&str>) -> anyhow::Result<Direction> {
    match s {
        Some("inbound") => Ok(Direction::Inbound),
        Some("outbound") => Ok(Direction::Outbound),
        _ => bail!("direction must be inbound or outbound"),
    }
}

fn parse_action(s: Option<&str>) -> anyhow::Result<RuleAction> {
    match s {
        Some("allow") => Ok(RuleAction::Allow),
        Some("block") => Ok(RuleAction::Block),
        _ => bail!("action must be allow or block"),
    }
}

async fn exec(op: Op) -> anyhow::Result<()> {
    let stream = transport::connect_admin()
        .await
        .context("could not open the admin channel (is the engine running?)")?;
    let (mut recv, mut send) = transport::split(stream);

    transport::write_frame(&mut send, &ClientMessage::Hello { protocol: PROTOCOL_VERSION }).await?;
    match transport::read_frame::<_, ServerMessage>(&mut recv).await? {
        Some(ServerMessage::Welcome { protocol, .. }) if protocol == PROTOCOL_VERSION => {}
        _ => bail!("engine protocol mismatch"),
    }

    match op {
        Op::Single(command) => match request(&mut recv, &mut send, command).await? {
            Reply::Error(e) => bail!("{e}"),
            _ => Ok(()),
        },
        Op::Import(entries) => {
            // the store replaces an existing rule for the same app + direction,
            // so re-importing a backup converges instead of piling up duplicates
            for entry in entries {
                let rule = entry.to_rule();
                let added =
                    request(&mut recv, &mut send, ClientMessage::AddRule { req: 1, rule }).await?;
                let stored = match added {
                    Reply::RuleAdded(stored) => stored,
                    Reply::Error(e) => bail!("{}: {e}", entry.app),
                    _ => bail!("{}: unexpected engine reply", entry.app),
                };
                if !entry.enabled {
                    let paused = ClientMessage::SetRuleEnabled {
                        req: 1,
                        id: stored.id,
                        enabled: false,
                    };
                    if let Reply::Error(e) = request(&mut recv, &mut send, paused).await? {
                        bail!("{}: {e}", entry.app);
                    }
                }
            }
            Ok(())
        }
    }
}

async fn request(
    recv: &mut transport::RecvHalf,
    send: &mut transport::SendHalf,
    command: ClientMessage,
) -> anyhow::Result<Reply> {
    transport::write_frame(send, &command).await?;
    loop {
        match transport::read_frame::<_, ServerMessage>(recv).await? {
            Some(ServerMessage::Reply { result, .. }) => return Ok(result),
            Some(_) => continue,
            None => bail!("the engine closed the connection"),
        }
    }
}
