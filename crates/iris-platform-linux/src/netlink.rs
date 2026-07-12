//! a minimal raw netlink transport used by the sock_diag and conntrack layers.
//! it opens a netlink socket of a given protocol, sends one request, and reads
//! the multipart reply, handing each message header and payload to a visitor
//! until NLMSG_DONE. keeping this tiny and allocation-light matters: the byte
//! monitor runs it every second.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

pub const NLMSG_NOOP: u16 = 1;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;

pub const NLM_F_REQUEST: u16 = 0x001;
pub const NLM_F_ACK: u16 = 0x004;
pub const NLM_F_DUMP: u16 = 0x300;

/// round a length up to the netlink 4-byte alignment
pub const fn align4(len: usize) -> usize {
    (len + 3) & !3
}

pub struct NlSocket {
    fd: OwnedFd,
}

impl NlSocket {
    pub fn open(protocol: libc::c_int) -> io::Result<NlSocket> {
        let raw: RawFd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                protocol,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // own the fd immediately so an early return still closes it
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        let rc = unsafe {
            libc::bind(
                raw,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(NlSocket { fd })
    }

    pub fn send(&self, buf: &[u8]) -> io::Result<()> {
        let mut off = 0;
        while off < buf.len() {
            let n = unsafe {
                libc::send(
                    self.raw(),
                    buf[off..].as_ptr() as *const libc::c_void,
                    buf.len() - off,
                    0,
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            off += n as usize;
        }
        Ok(())
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe {
            libc::recv(
                self.raw(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// read the multipart reply, calling `visit(msg_type, payload)` for each
    /// data message. stops at NLMSG_DONE; surfaces an NLMSG_ERROR as an Err.
    pub fn recv_dump<F: FnMut(u16, &[u8])>(&self, mut visit: F) -> io::Result<()> {
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            let len = self.recv(&mut buf)?;
            if len == 0 {
                return Ok(());
            }
            let mut off = 0;
            while off + 16 <= len {
                let msg_len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
                let msg_type = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
                if msg_len < 16 || off + msg_len > len {
                    break;
                }
                match msg_type {
                    NLMSG_DONE => return Ok(()),
                    NLMSG_NOOP => {}
                    NLMSG_ERROR => {
                        // the error code is the first i32 of the payload; 0 is an
                        // ACK, anything else a real failure
                        let code = i32::from_ne_bytes(buf[off + 16..off + 20].try_into().unwrap());
                        if code != 0 {
                            return Err(io::Error::from_raw_os_error(-code));
                        }
                        return Ok(());
                    }
                    _ => visit(msg_type, &buf[off + 16..off + msg_len]),
                }
                off += align4(msg_len);
            }
        }
    }
}

/// iterate the rtattr TLVs in a netlink payload, calling `visit(nla_type, value)`
pub fn for_each_attr<F: FnMut(u16, &[u8])>(mut data: &[u8], mut visit: F) {
    while data.len() >= 4 {
        let nla_len = u16::from_ne_bytes(data[0..2].try_into().unwrap()) as usize;
        let nla_type = u16::from_ne_bytes(data[2..4].try_into().unwrap());
        if nla_len < 4 || nla_len > data.len() {
            break;
        }
        visit(nla_type, &data[4..nla_len]);
        let advance = align4(nla_len);
        if advance >= data.len() {
            break;
        }
        data = &data[advance..];
    }
}
