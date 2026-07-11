use crate::engine::Engine;
use iris_ipc::message::{ClientMessage, Reply, ServerMessage, PROTOCOL_VERSION};
use iris_ipc::transport;
use std::io;
use tokio::select;
use tokio::sync::broadcast::error::RecvError;

/// accept clients on the iris pipe until the runtime is cancelled. each
/// connection is served on its own task.
pub async fn serve(engine: Engine) -> anyhow::Result<()> {
    let listener = transport::listen()?;
    tracing::info!(pipe = iris_ipc::PIPE_NAME, "engine listening");
    loop {
        let conn = transport::accept(&listener).await?;
        let engine = engine.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(conn, engine).await {
                tracing::debug!("client disconnected: {e}");
            }
        });
    }
}

/// one client session: negotiate, then multiplex inbound commands against the
/// outbound tick/alert stream on a single duplex connection.
async fn handle(stream: transport::Stream, engine: Engine) -> io::Result<()> {
    let (mut recv, mut send) = transport::split(stream);

    // the first frame must be Hello; anything else is a protocol violation
    match transport::read_frame::<_, ClientMessage>(&mut recv).await? {
        Some(ClientMessage::Hello { protocol }) => {
            transport::write_frame(
                &mut send,
                &ServerMessage::Welcome {
                    protocol: PROTOCOL_VERSION,
                    engine_version: env!("CARGO_PKG_VERSION").to_string(),
                },
            )
            .await?;
            if protocol != PROTOCOL_VERSION {
                tracing::warn!(client = protocol, ours = PROTOCOL_VERSION, "protocol mismatch");
                return Ok(());
            }
        }
        _ => return Ok(()),
    }

    let mut subscribed = false;
    let mut events = engine.subscribe();

    loop {
        select! {
            inbound = transport::read_frame::<_, ClientMessage>(&mut recv) => {
                let Some(msg) = inbound? else { break };
                match msg {
                    ClientMessage::Hello { .. } => {}
                    ClientMessage::Subscribe => subscribed = true,
                    ClientMessage::Unsubscribe => subscribed = false,
                    ClientMessage::Ping { req } => {
                        reply(&mut send, req, Reply::Pong).await?;
                    }
                    // commands whose engine support arrives in later slices: answer
                    // rather than leave the UI awaiting a reply that never comes
                    other => {
                        if let Some(req) = req_of(&other) {
                            reply(&mut send, req, Reply::Error("not yet supported".into())).await?;
                        }
                    }
                }
            }
            outbound = events.recv() => {
                match outbound {
                    // ticks only go to subscribers; alerts always go out
                    Ok(msg) => {
                        let deliver = subscribed || matches!(msg, ServerMessage::Alert(_));
                        if deliver {
                            transport::write_frame(&mut send, &msg).await?;
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        tracing::trace!(dropped = n, "client fell behind on ticks");
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        }
    }
    Ok(())
}

async fn reply(
    send: &mut transport::SendHalf,
    req: u64,
    result: Reply,
) -> io::Result<()> {
    transport::write_frame(send, &ServerMessage::Reply { req, result }).await
}

fn req_of(m: &ClientMessage) -> Option<u64> {
    match m {
        ClientMessage::ListConnections { req }
        | ClientMessage::ListRules { req }
        | ClientMessage::AddRule { req, .. }
        | ClientMessage::RemoveRule { req, .. }
        | ClientMessage::SetRuleEnabled { req, .. }
        | ClientMessage::GetUsage { req, .. }
        | ClientMessage::ListAlerts { req, .. }
        | ClientMessage::AckAlert { req, .. }
        | ClientMessage::Ping { req } => Some(*req),
        ClientMessage::Hello { .. } | ClientMessage::Subscribe | ClientMessage::Unsubscribe => None,
    }
}
