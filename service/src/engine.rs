use iris_ipc::ServerMessage;
use tokio::sync::broadcast;

/// shared engine state. the fan-out channel every subscribed client reads ticks
/// and alerts from: the monitor publishes samples here, connected UIs subscribe.
/// cheap to clone (the sender is an `Arc` internally).
#[derive(Clone)]
pub struct Engine {
    events: broadcast::Sender<ServerMessage>,
}

impl Engine {
    pub fn new() -> Self {
        // a generous buffer so a briefly-busy client that falls behind drops old
        // ticks (Lagged) rather than stalling the publisher
        let (events, _) = broadcast::channel(512);
        Engine { events }
    }

    /// a receiver for a newly connected client
    pub fn subscribe(&self) -> broadcast::Receiver<ServerMessage> {
        self.events.subscribe()
    }

    /// publish a sample tick or alert to every subscriber. drops silently when
    /// nobody is listening.
    pub fn publish(&self, msg: ServerMessage) {
        let _ = self.events.send(msg);
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}
