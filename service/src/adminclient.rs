//! the elevated one-shot that performs a single rule mutation over the admin
//! pipe, then exits with 0 on success or non-zero on failure. the UI launches it
//! with a UAC prompt; the admin pipe's DACL means only an elevated process can
//! reach the engine here, so changing a firewall rule requires elevation.

use anyhow::{bail, Context};
use iris_core::{AppId, Direction, Rule, RuleAction};
use iris_ipc::message::{ClientMessage, Reply, ServerMessage, PROTOCOL_VERSION};
use iris_ipc::transport;

/// `args` begins with the rule flag (e.g. `--rule-add`) and its operands.
pub fn run(args: &[String]) -> anyhow::Result<()> {
    let command = build_command(args)?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(exec(command))
}

fn build_command(args: &[String]) -> anyhow::Result<ClientMessage> {
    match args.first().map(String::as_str) {
        Some("--rule-add") => {
            let path = args.get(1).context("rule-add: missing app path")?;
            let direction = parse_direction(args.get(2).map(String::as_str))?;
            let action = parse_action(args.get(3).map(String::as_str))?;
            Ok(ClientMessage::AddRule {
                req: 1,
                rule: Rule {
                    app: AppId::from_path(path),
                    direction,
                    action,
                    label: None,
                },
            })
        }
        Some("--rule-remove") => {
            let id = parse_id(args.get(1))?;
            Ok(ClientMessage::RemoveRule { req: 1, id })
        }
        Some("--rule-enable") => {
            let id = parse_id(args.get(1))?;
            let enabled = matches!(args.get(2).map(String::as_str), Some("true") | Some("1"));
            Ok(ClientMessage::SetRuleEnabled { req: 1, id, enabled })
        }
        _ => bail!("unknown rule command"),
    }
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

async fn exec(command: ClientMessage) -> anyhow::Result<()> {
    let stream = transport::connect_admin()
        .await
        .context("could not open the admin channel (is the engine running?)")?;
    let (mut recv, mut send) = transport::split(stream);

    transport::write_frame(&mut send, &ClientMessage::Hello { protocol: PROTOCOL_VERSION }).await?;
    match transport::read_frame::<_, ServerMessage>(&mut recv).await? {
        Some(ServerMessage::Welcome { protocol, .. }) if protocol == PROTOCOL_VERSION => {}
        _ => bail!("engine protocol mismatch"),
    }

    transport::write_frame(&mut send, &command).await?;
    loop {
        match transport::read_frame::<_, ServerMessage>(&mut recv).await? {
            Some(ServerMessage::Reply { result, .. }) => {
                return match result {
                    Reply::Error(e) => bail!("{e}"),
                    _ => Ok(()),
                };
            }
            Some(_) => continue,
            None => bail!("the engine closed the connection"),
        }
    }
}
