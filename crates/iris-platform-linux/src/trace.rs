//! process ownership for short TCP flows from the kernel's
//! `sock:inet_sock_set_state` tracepoint

use crate::proc;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::{fence, Ordering};

const PERF_TYPE_TRACEPOINT: u32 = 2;
const PERF_RECORD_SAMPLE: u32 = 9;
const PERF_SAMPLE_TID: u64 = 1 << 1;
const PERF_SAMPLE_RAW: u64 = 1 << 10;
const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 1 << 3;
const DATA_PAGES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub local: (IpAddr, u16),
    pub remote: (IpAddr, u16),
}

pub struct FlowOwner {
    pub key: FlowKey,
    pub pid: u32,
    pub path: String,
}

pub struct OwnerListener {
    rings: Vec<PerfRing>,
    fields: Fields,
    polls: Vec<libc::pollfd>,
}

impl OwnerListener {
    pub fn open() -> io::Result<Self> {
        let root = trace_root().ok_or_else(|| io::Error::other("tracefs is unavailable"))?;
        let event = root.join("events/sock/inet_sock_set_state");
        let id = std::fs::read_to_string(event.join("id"))?
            .trim()
            .parse::<u64>()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let fields = Fields::parse(&std::fs::read_to_string(event.join("format"))?)?;
        let cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_CONF) }.max(1) as i32;
        let mut rings = Vec::new();
        for cpu in 0..cpus {
            if let Ok(ring) = PerfRing::open(id, cpu) {
                rings.push(ring);
            }
        }
        if rings.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "cannot open the TCP state tracepoint on any CPU",
            ));
        }
        let polls = rings
            .iter()
            .map(|ring| libc::pollfd {
                fd: ring.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        Ok(Self {
            rings,
            fields,
            polls,
        })
    }

    pub fn receive(&mut self, timeout_ms: i32, owners: &mut Vec<FlowOwner>) -> io::Result<()> {
        let result = unsafe {
            libc::poll(
                self.polls.as_mut_ptr(),
                self.polls.len() as libc::nfds_t,
                timeout_ms,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if result == 0 {
            return Ok(());
        }
        for ring in &mut self.rings {
            ring.drain(|sample| {
                let Some((pid, raw)) = parse_sample(sample) else {
                    return;
                };
                let Some(key) = self.fields.flow(raw) else {
                    return;
                };
                let Some(path) = proc::image_path_of(pid) else {
                    return;
                };
                owners.push(FlowOwner { key, pid, path });
            });
        }
        Ok(())
    }
}

fn trace_root() -> Option<&'static Path> {
    [
        Path::new("/sys/kernel/tracing"),
        Path::new("/sys/kernel/debug/tracing"),
    ]
    .into_iter()
    .find(|root| root.join("events/sock/inet_sock_set_state/id").is_file())
}

#[repr(C)]
#[derive(Default)]
struct PerfEventAttr {
    kind: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    config1: u64,
}

struct PerfRing {
    fd: OwnedFd,
    mapping: *mut u8,
    mapping_len: usize,
    data_offset: usize,
    data_size: usize,
    scratch: Vec<u8>,
}

impl PerfRing {
    fn open(event_id: u64, cpu: i32) -> io::Result<Self> {
        let attr = PerfEventAttr {
            kind: PERF_TYPE_TRACEPOINT,
            size: 64,
            config: event_id,
            sample_period: 1,
            sample_type: PERF_SAMPLE_TID | PERF_SAMPLE_RAW,
            wakeup_events: 1,
            ..PerfEventAttr::default()
        };
        let raw = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &attr as *const PerfEventAttr,
                -1i32,
                cpu,
                -1i32,
                PERF_FLAG_FD_CLOEXEC,
            ) as i32
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let mapping_len = page * (1 + DATA_PAGES);
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mapping_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let mapping = mapping.cast::<u8>();
        let data_offset = unsafe { read_u64(mapping.add(1040)) as usize };
        let data_size = unsafe { read_u64(mapping.add(1048)) as usize };
        if data_offset == 0
            || !data_size.is_power_of_two()
            || data_offset.saturating_add(data_size) > mapping_len
        {
            unsafe { libc::munmap(mapping.cast(), mapping_len) };
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid perf ring metadata",
            ));
        }
        Ok(Self {
            fd,
            mapping,
            mapping_len,
            data_offset,
            data_size,
            scratch: Vec::new(),
        })
    }

    fn drain(&mut self, mut visit: impl FnMut(&[u8])) {
        let head = unsafe { read_u64(self.mapping.add(1024)) };
        fence(Ordering::Acquire);
        let mut tail = unsafe { read_u64(self.mapping.add(1032)) };
        while tail < head {
            let mut header = [0u8; 8];
            self.copy_from_ring(tail as usize, &mut header);
            let kind = u32::from_ne_bytes(header[0..4].try_into().unwrap());
            let size = u16::from_ne_bytes(header[6..8].try_into().unwrap()) as usize;
            if size < 8 || size > self.data_size || size as u64 > head - tail {
                tail = head;
                break;
            }
            self.scratch.resize(size, 0);
            let mut record = std::mem::take(&mut self.scratch);
            self.copy_from_ring(tail as usize, &mut record);
            if kind == PERF_RECORD_SAMPLE {
                visit(&record[8..]);
            }
            self.scratch = record;
            tail += size as u64;
        }
        fence(Ordering::Release);
        unsafe { write_u64(self.mapping.add(1032), tail) };
    }

    fn copy_from_ring(&self, absolute: usize, destination: &mut [u8]) {
        let offset = absolute & (self.data_size - 1);
        let first = destination.len().min(self.data_size - offset);
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.mapping.add(self.data_offset + offset),
                destination.as_mut_ptr(),
                first,
            );
            if first < destination.len() {
                std::ptr::copy_nonoverlapping(
                    self.mapping.add(self.data_offset),
                    destination.as_mut_ptr().add(first),
                    destination.len() - first,
                );
            }
        }
    }
}

impl Drop for PerfRing {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.mapping.cast(), self.mapping_len) };
    }
}

// the mapping and fd move together into one listener thread and are never shared
unsafe impl Send for PerfRing {}

unsafe fn read_u64(pointer: *const u8) -> u64 {
    std::ptr::read_volatile(pointer.cast::<u64>())
}

unsafe fn write_u64(pointer: *mut u8, value: u64) {
    std::ptr::write_volatile(pointer.cast::<u64>(), value)
}

fn parse_sample(sample: &[u8]) -> Option<(u32, &[u8])> {
    if sample.len() < 12 {
        return None;
    }
    let pid = u32::from_ne_bytes(sample[0..4].try_into().ok()?);
    let raw_len = u32::from_ne_bytes(sample[8..12].try_into().ok()?) as usize;
    let raw = sample.get(12..12 + raw_len)?;
    (pid != 0).then_some((pid, raw))
}

#[derive(Clone, Copy)]
struct Field {
    offset: usize,
    size: usize,
}

struct Fields {
    sport: Field,
    dport: Field,
    family: Field,
    protocol: Field,
    saddr: Field,
    daddr: Field,
    saddr_v6: Field,
    daddr_v6: Field,
}

impl Fields {
    fn parse(format: &str) -> io::Result<Self> {
        let find = |name| {
            format
                .lines()
                .find_map(|line| parse_field(line, name))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("tracepoint field {name} is missing"),
                    )
                })
        };
        Ok(Self {
            sport: find("sport")?,
            dport: find("dport")?,
            family: find("family")?,
            protocol: find("protocol")?,
            saddr: find("saddr")?,
            daddr: find("daddr")?,
            saddr_v6: find("saddr_v6")?,
            daddr_v6: find("daddr_v6")?,
        })
    }

    fn flow(&self, raw: &[u8]) -> Option<FlowKey> {
        if read_u16(raw, self.protocol)? != libc::IPPROTO_TCP as u16 {
            return None;
        }
        let sport = read_u16(raw, self.sport)?;
        let dport = read_u16(raw, self.dport)?;
        if sport == 0 || dport == 0 {
            return None;
        }
        let (local, remote) = match read_u16(raw, self.family)? as i32 {
            libc::AF_INET => (
                IpAddr::V4(Ipv4Addr::from(read_array::<4>(raw, self.saddr)?)),
                IpAddr::V4(Ipv4Addr::from(read_array::<4>(raw, self.daddr)?)),
            ),
            libc::AF_INET6 => (
                IpAddr::V6(Ipv6Addr::from(read_array::<16>(raw, self.saddr_v6)?)),
                IpAddr::V6(Ipv6Addr::from(read_array::<16>(raw, self.daddr_v6)?)),
            ),
            _ => return None,
        };
        Some(FlowKey {
            local: (local, sport),
            remote: (remote, dport),
        })
    }
}

fn parse_field(line: &str, name: &str) -> Option<Field> {
    let declaration = line.trim().strip_prefix("field:")?.split(';').next()?;
    let field_name = declaration
        .split_whitespace()
        .last()?
        .trim_start_matches('*')
        .split('[')
        .next()?;
    if field_name != name {
        return None;
    }
    let number = |label: &str| {
        line.split(';')
            .find_map(|part| part.trim().strip_prefix(label))?
            .trim()
            .parse::<usize>()
            .ok()
    };
    Some(Field {
        offset: number("offset:")?,
        size: number("size:")?,
    })
}

fn read_u16(raw: &[u8], field: Field) -> Option<u16> {
    (field.size == 2).then_some(u16::from_ne_bytes(
        raw.get(field.offset..field.offset + 2)?.try_into().ok()?,
    ))
}

fn read_array<const N: usize>(raw: &[u8], field: Field) -> Option<[u8; N]> {
    (field.size == N).then_some(raw.get(field.offset..field.offset + N)?.try_into().ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tracepoint_fields_and_ipv4_flow() {
        let format = "\
field:__u16 sport; offset:24; size:2; signed:0;\n\
field:__u16 dport; offset:26; size:2; signed:0;\n\
field:__u16 family; offset:28; size:2; signed:0;\n\
field:__u16 protocol; offset:30; size:2; signed:0;\n\
field:__u8 saddr[4]; offset:32; size:4; signed:0;\n\
field:__u8 daddr[4]; offset:36; size:4; signed:0;\n\
field:__u8 saddr_v6[16]; offset:40; size:16; signed:0;\n\
field:__u8 daddr_v6[16]; offset:56; size:16; signed:0;";
        let fields = Fields::parse(format).unwrap();
        let mut raw = [0u8; 72];
        raw[24..26].copy_from_slice(&40000u16.to_ne_bytes());
        raw[26..28].copy_from_slice(&443u16.to_ne_bytes());
        raw[28..30].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        raw[30..32].copy_from_slice(&(libc::IPPROTO_TCP as u16).to_ne_bytes());
        raw[32..36].copy_from_slice(&[192, 0, 2, 3]);
        raw[36..40].copy_from_slice(&[198, 51, 100, 8]);

        let flow = fields.flow(&raw).unwrap();
        assert_eq!(flow.local, (IpAddr::from([192, 0, 2, 3]), 40000));
        assert_eq!(flow.remote, (IpAddr::from([198, 51, 100, 8]), 443));
    }
}
