//! download caps. inbound packets to a capped app's local ports are diverted
//! through WinDivert, held in a per-app token bucket, and reinjected at the
//! capped rate. a packet that would wait past the queue limit is dropped so
//! tcp backs off instead of buffering. the filter follows the live connection
//! table as the app opens new ports, so a brand new flow runs uncapped until
//! the next tick picks it up

use crate::platform::divert::{Address, Divert, MTU_MAX};
use iris_core::{AppId, Protocol};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::io;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub type Port = (Protocol, u16);

/// the driver compiles a filter into at most 256 tests and a span costs two,
/// so past this many spans the narrowest gaps between them are closed
const MAX_SPANS: usize = 100;

/// how long a packet may wait for its turn before it is dropped instead
const MAX_WAIT: Duration = Duration::from_millis(250);
const MIN_QUEUE: usize = 16 * 1024;

/// processes whose anti-cheat refuses to run beside a packet driver, matched
/// on the lowercase image name: exact names, then prefixes
const ANTICHEAT_NAMES: [&str; 2] = ["vgc.exe", "cod.exe"];
const ANTICHEAT_PREFIXES: [&str; 3] = ["easyanticheat", "beservice", "faceit"];

pub fn is_anticheat(image: &str) -> bool {
    let image = image.to_ascii_lowercase();
    ANTICHEAT_NAMES.contains(&image.as_str())
        || ANTICHEAT_PREFIXES
            .iter()
            .any(|prefix| image.starts_with(prefix))
}

/// contiguous port spans covering `ports`, at most [`MAX_SPANS`] of them
fn spans(ports: &BTreeSet<Port>) -> Vec<(Protocol, u16, u16)> {
    let mut spans: Vec<(Protocol, u16, u16)> = Vec::new();
    for &(protocol, port) in ports {
        match spans.last_mut() {
            Some((last, _, end)) if *last == protocol && end.checked_add(1) == Some(port) => {
                *end = port
            }
            _ => spans.push((protocol, port, port)),
        }
    }
    if spans.len() <= MAX_SPANS {
        return spans;
    }
    let mut gaps: Vec<(u16, usize)> = spans
        .windows(2)
        .enumerate()
        .filter(|(_, pair)| pair[0].0 == pair[1].0)
        .map(|(index, pair)| (pair[1].1 - pair[0].2, index))
        .collect();
    gaps.sort_unstable();
    let mut close = vec![false; spans.len()];
    for &(_, index) in gaps.iter().take(spans.len() - MAX_SPANS) {
        close[index] = true;
    }
    let mut merged: Vec<(Protocol, u16, u16)> = Vec::with_capacity(MAX_SPANS);
    for (index, span) in spans.into_iter().enumerate() {
        match merged.last_mut() {
            Some(last) if close[index - 1] => last.2 = span.2,
            _ => merged.push(span),
        }
    }
    merged
}

/// a WinDivert filter for inbound packets to these local ports
pub fn filter_for(ports: &BTreeSet<Port>) -> String {
    if ports.is_empty() {
        return "false".into();
    }
    let tests: Vec<String> = spans(ports)
        .into_iter()
        .map(|(protocol, start, end)| {
            let field = match protocol {
                Protocol::Tcp => "tcp.DstPort",
                Protocol::Udp => "udp.DstPort",
            };
            if start == end {
                format!("{field} == {start}")
            } else {
                format!("({field} >= {start} and {field} <= {end})")
            }
        })
        .collect();
    format!("inbound and !loopback and ({})", tests.join(" or "))
}

/// the transport and local port an inbound ip packet is addressed to
pub fn destination(packet: &[u8]) -> Option<Port> {
    let (protocol, header) = match packet.first()? >> 4 {
        4 => {
            // a later fragment carries no transport header
            let fragment = u16::from_be_bytes([*packet.get(6)?, *packet.get(7)?]) & 0x1fff;
            if fragment != 0 {
                return None;
            }
            (*packet.get(9)?, usize::from(packet[0] & 0x0f) * 4)
        }
        6 => (*packet.get(6)?, 40),
        _ => return None,
    };
    let protocol = match protocol {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        _ => return None,
    };
    let port = packet.get(header + 2..header + 4)?;
    Some((protocol, u16::from_be_bytes([port[0], port[1]])))
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// within the rate: reinject now
    Pass,
    /// queued for the pacer
    Hold,
    /// the queue is full; dropping tells tcp to slow down
    Drop,
}

/// one capped app's token bucket and the packets waiting on it. tokens may go
/// negative so a packet larger than the bucket still passes, and the deficit
/// holds the long-run rate
pub struct Lane<P> {
    rate: u64,
    tokens: f64,
    refilled: Instant,
    held: VecDeque<(usize, P)>,
    queued: usize,
}

impl<P> Lane<P> {
    pub fn new(rate: u64, now: Instant) -> Lane<P> {
        Lane {
            rate,
            tokens: burst(rate),
            refilled: now,
            held: VecDeque::new(),
            queued: 0,
        }
    }

    pub fn set_rate(&mut self, rate: u64) {
        self.rate = rate;
        self.tokens = self.tokens.min(burst(rate));
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.refilled).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate as f64).min(burst(self.rate));
        self.refilled = now;
    }

    fn limit(&self) -> usize {
        ((self.rate as f64 * MAX_WAIT.as_secs_f64()) as usize).max(MIN_QUEUE)
    }

    /// decide a packet of `len` bytes; `packet` is only built when it is held
    pub fn offer(&mut self, len: usize, packet: impl FnOnce() -> P, now: Instant) -> Verdict {
        self.refill(now);
        if self.held.is_empty() && self.tokens > 0.0 {
            self.tokens -= len as f64;
            return Verdict::Pass;
        }
        if self.queued + len > self.limit() {
            return Verdict::Drop;
        }
        self.queued += len;
        self.held.push_back((len, packet()));
        Verdict::Hold
    }

    /// move the held packets whose turn has come into `out`
    pub fn release(&mut self, now: Instant, out: &mut Vec<P>) {
        self.refill(now);
        while self.tokens > 0.0 {
            let Some((len, packet)) = self.held.pop_front() else {
                break;
            };
            self.tokens -= len as f64;
            self.queued -= len;
            out.push(packet);
        }
    }

    /// how long until the next held packet may go
    pub fn next_due(&self) -> Option<Duration> {
        (!self.held.is_empty())
            .then(|| Duration::from_secs_f64((-self.tokens).max(0.0) / self.rate as f64))
    }

    pub fn drain(&mut self) -> impl Iterator<Item = P> + '_ {
        self.queued = 0;
        self.held.drain(..).map(|(_, packet)| packet)
    }
}

/// a twentieth of a second at the rate, so a cap does not admit a long burst
fn burst(rate: u64) -> f64 {
    (rate as f64 / 20.0).max(1500.0)
}

/// a narrower port set is fine to keep diverting for a while: the extra
/// packets pass straight through, and every reopen risks a dropped packet
const SHRINK_AFTER: Duration = Duration::from_secs(30);

type Held = (Vec<u8>, Address);

struct State {
    lanes: HashMap<AppId, Lane<Held>>,
    owners: HashMap<Port, AppId>,
    divert: Arc<Divert>,
    stop: bool,
}

struct Shared {
    state: Mutex<State>,
    wake: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

pub struct Shaper {
    shared: Arc<Shared>,
    divert: Arc<Divert>,
    receiver: Option<JoinHandle<()>>,
    pacer: Option<JoinHandle<()>>,
    covered: BTreeSet<Port>,
    rebuilt: Instant,
}

impl Shaper {
    /// load the driver and start shaping at these per-app rates
    pub fn start(rates: &HashMap<AppId, u64>) -> anyhow::Result<Shaper> {
        let dll = std::env::current_exe()?.with_file_name("WinDivert.dll");
        let divert = Arc::new(Divert::open(&dll, "false")?);
        let now = Instant::now();
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                lanes: rates
                    .iter()
                    .map(|(app, rate)| (app.clone(), Lane::new(*rate, now)))
                    .collect(),
                owners: HashMap::new(),
                divert: divert.clone(),
                stop: false,
            }),
            wake: Condvar::new(),
        });
        let receiver = spawn_receiver(shared.clone(), divert.clone())?;
        let pacer = {
            let shared = shared.clone();
            std::thread::Builder::new()
                .name("download-pacer".into())
                .spawn(move || pace(&shared))?
        };
        tracing::info!("download shaper started");
        Ok(Shaper {
            shared,
            divert,
            receiver: Some(receiver),
            pacer: Some(pacer),
            covered: BTreeSet::new(),
            rebuilt: now,
        })
    }

    pub fn set_rates(&mut self, rates: &HashMap<AppId, u64>) {
        let mut state = self.shared.lock();
        let now = Instant::now();
        let mut freed = Vec::new();
        state.lanes.retain(|app, lane| {
            let keep = rates.contains_key(app);
            if !keep {
                freed.extend(lane.drain());
            }
            keep
        });
        for (app, rate) in rates {
            state
                .lanes
                .entry(app.clone())
                .and_modify(|lane| lane.set_rate(*rate))
                .or_insert_with(|| Lane::new(*rate, now));
        }
        let divert = state.divert.clone();
        drop(state);
        for (packet, address) in freed {
            let _ = divert.send(&packet, &address);
        }
    }

    /// point the filter at the capped apps' current local ports
    pub fn follow(&mut self, owners: HashMap<Port, AppId>) -> anyhow::Result<()> {
        let ports: BTreeSet<Port> = owners.keys().copied().collect();
        self.shared.lock().owners = owners;
        let grew = !ports.is_subset(&self.covered);
        let shrank = ports != self.covered && self.rebuilt.elapsed() > SHRINK_AFTER;
        let receiving = self
            .receiver
            .as_ref()
            .is_some_and(|thread| !thread.is_finished());
        if receiving && !grew && !shrank {
            return Ok(());
        }
        let fresh = Arc::new(self.divert.reopen(&filter_for(&ports))?);
        let thread = spawn_receiver(self.shared.clone(), fresh.clone())?;
        self.shared.lock().divert = fresh.clone();
        let old = std::mem::replace(&mut self.divert, fresh);
        old.shutdown();
        if let Some(old_thread) = self.receiver.replace(thread) {
            let _ = old_thread.join();
        }
        self.covered = ports;
        self.rebuilt = Instant::now();
        Ok(())
    }
}

impl Drop for Shaper {
    fn drop(&mut self) {
        // release what is held so lifting the last cap loses no packets
        self.set_rates(&HashMap::new());
        self.shared.lock().stop = true;
        self.shared.wake.notify_all();
        self.divert.shutdown();
        // both threads hold a handle, and the driver only stops once all close
        for thread in [self.receiver.take(), self.pacer.take()]
            .into_iter()
            .flatten()
        {
            let _ = thread.join();
        }
        tracing::info!("download shaper stopped");
    }
}

fn spawn_receiver(shared: Arc<Shared>, divert: Arc<Divert>) -> io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("download-divert".into())
        .spawn(move || receive(&shared, &divert))
}

fn receive(shared: &Shared, divert: &Divert) {
    let mut buf = vec![0u8; MTU_MAX];
    loop {
        let (len, address) = match divert.recv(&mut buf) {
            Ok(received) => received,
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => return,
            Err(error) => {
                // the next follow sees this thread gone and reopens
                tracing::warn!("download shaper stopped receiving: {error}");
                return;
            }
        };
        let packet = &buf[..len];
        let mut guard = shared.lock();
        let state = &mut *guard;
        let lane = destination(packet)
            .and_then(|port| state.owners.get(&port))
            .and_then(|app| state.lanes.get_mut(app));
        let verdict = match lane {
            Some(lane) => lane.offer(len, || (packet.to_vec(), address), Instant::now()),
            None => Verdict::Pass,
        };
        drop(guard);
        match verdict {
            Verdict::Pass => {
                let _ = divert.send(packet, &address);
            }
            Verdict::Hold => shared.wake.notify_one(),
            Verdict::Drop => {}
        }
    }
}

fn pace(shared: &Shared) {
    let mut ready: Vec<Held> = Vec::new();
    let mut state = shared.lock();
    loop {
        if state.stop {
            return;
        }
        let now = Instant::now();
        let mut due: Option<Duration> = None;
        for lane in state.lanes.values_mut() {
            lane.release(now, &mut ready);
            due = match (due, lane.next_due()) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
        if !ready.is_empty() {
            let divert = state.divert.clone();
            drop(state);
            for (packet, address) in ready.drain(..) {
                let _ = divert.send(&packet, &address);
            }
            state = shared.lock();
            continue;
        }
        state = match due {
            Some(due) => {
                shared
                    .wake
                    .wait_timeout(state, due.max(Duration::from_millis(1)))
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .0
            }
            None => shared
                .wake
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ports(list: &[(Protocol, u16)]) -> BTreeSet<Port> {
        list.iter().copied().collect()
    }

    #[test]
    fn filters_name_each_port_and_join_neighbours() {
        assert_eq!(filter_for(&BTreeSet::new()), "false");
        assert_eq!(
            filter_for(&ports(&[(Protocol::Tcp, 80), (Protocol::Tcp, 81), (Protocol::Udp, 53)])),
            "inbound and !loopback and ((tcp.DstPort >= 80 and tcp.DstPort <= 81) or udp.DstPort == 53)"
        );
    }

    #[test]
    fn many_ports_merge_into_few_spans_that_still_cover_them() {
        let many: BTreeSet<Port> = (0..2000u16)
            .map(|i| {
                (
                    if i % 3 == 0 {
                        Protocol::Udp
                    } else {
                        Protocol::Tcp
                    },
                    1024 + i * 7 + i % 5,
                )
            })
            .collect();
        let spans = spans(&many);
        assert_eq!(spans.len(), MAX_SPANS);
        for (protocol, port) in &many {
            assert!(spans
                .iter()
                .any(|(p, start, end)| p == protocol && start <= port && port <= end));
        }
    }

    #[test]
    fn the_driver_accepts_the_largest_filter() {
        let dll = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../vendor/windivert/WinDivert.dll");
        let wide: BTreeSet<Port> = (0..1000u16)
            .flat_map(|i| [(Protocol::Tcp, i * 60), (Protocol::Udp, i * 60 + 1)])
            .collect();
        assert_eq!(spans(&wide).len(), MAX_SPANS);
        crate::platform::divert::check_filter(&dll, &filter_for(&wide)).unwrap();
    }

    #[test]
    fn reads_the_destination_port() {
        let mut v4 = vec![0u8; 28];
        v4[0] = 0x45;
        v4[9] = 17;
        v4[22..24].copy_from_slice(&5353u16.to_be_bytes());
        assert_eq!(destination(&v4), Some((Protocol::Udp, 5353)));
        v4[6] = 0x00;
        v4[7] = 0x10;
        assert_eq!(destination(&v4), None, "a later fragment has no port");

        let mut v6 = vec![0u8; 60];
        v6[0] = 0x60;
        v6[6] = 6;
        v6[42..44].copy_from_slice(&443u16.to_be_bytes());
        assert_eq!(destination(&v6), Some((Protocol::Tcp, 443)));
        assert_eq!(destination(&v6[..41]), None);
    }

    #[test]
    fn a_lane_passes_its_burst_then_paces_at_the_rate() {
        let start = Instant::now();
        let mut lane: Lane<u32> = Lane::new(100_000, start);
        let verdicts: Vec<Verdict> = (0..5).map(|i| lane.offer(1500, || i, start)).collect();
        assert_eq!(
            verdicts[..4],
            [Verdict::Pass, Verdict::Pass, Verdict::Pass, Verdict::Pass]
        );
        assert_eq!(verdicts[4], Verdict::Hold);
        assert_eq!(lane.next_due(), Some(Duration::from_millis(10)));
        let mut out = Vec::new();
        lane.release(start + Duration::from_millis(5), &mut out);
        assert!(out.is_empty());
        lane.release(start + Duration::from_millis(11), &mut out);
        assert_eq!(out, [4]);
    }

    #[test]
    fn a_lane_holds_its_rate_and_drops_past_the_queue() {
        let start = Instant::now();
        let mut lane: Lane<()> = Lane::new(200_000, start);
        let (mut sent, mut dropped) = (0usize, 0usize);
        let mut out = Vec::new();
        for ms in 0..1000u64 {
            let now = start + Duration::from_millis(ms);
            // offer ten times the cap
            for _ in 0..2 {
                match lane.offer(1000, || (), now) {
                    Verdict::Pass => sent += 1000,
                    Verdict::Drop => dropped += 1,
                    Verdict::Hold => {}
                }
            }
            lane.release(now, &mut out);
            sent += out.len() * 1000;
            out.clear();
        }
        assert!((200_000..=212_000).contains(&sent), "sent {sent}");
        assert!(dropped > 0);
        assert!(lane.queued <= lane.limit());
    }

    #[test]
    fn spots_anticheat_by_image_name() {
        assert!(is_anticheat("vgc.exe"));
        assert!(is_anticheat("EasyAntiCheat_EOS.exe"));
        assert!(is_anticheat("BEService_x64.exe"));
        assert!(is_anticheat("FACEIT.exe"));
        assert!(!is_anticheat("code.exe"));
        assert!(!is_anticheat("svchost.exe"));
    }
}
