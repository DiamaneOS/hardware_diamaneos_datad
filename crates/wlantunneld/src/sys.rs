// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The kernel calls of the daemon: one netlink socket each for routes, XFRM and generic netlink, and the UDP and
//! TCP sockets that hold ports. The bytes come from the builders of `dataos-netcfg`. A message and a receive
//! buffer that may have held a key are zeroed, and an error answer of XFRM does not echo the request.
#![allow(unsafe_code)]
use dataos_netcfg::genl::{self, WlanRequest};
use dataos_netcfg::ops::RmnetFlags;
use dataos_netcfg::rtnl::{self, Ack, RmnetFlagsRaw};
use dataos_netcfg::rtnl_tunnel::{self, DumpStep, IfAddr, Rule};
use dataos_netcfg::xfrm::{self, Dir, NewState, SaId, Selector, Tmpl};
use dataos_qmi::dfs::PortKind;
use dataos_qmi::secret::wipe;
use dataos_wlan_tunnel::kernel::{Ip, Kernel, KernelResult, SockHandle};
use dataos_wlan_tunnel::state::MAX_FILE;
use dataos_wlan_tunnel::KernelError;
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

const ACK_TIMEOUT_SECS: libc::time_t = 2;
const NETLINK_XFRM: libc::c_int = 6;
const NETLINK_GENERIC: libc::c_int = 16;
const SOL_NETLINK: libc::c_int = 270;
const NETLINK_CAP_ACK: libc::c_int = 10;
const PR_SET_DUMPABLE: libc::c_int = 4;
const SIOCGIFINDEX: u32 = 0x8933;
const SIOCGIFNAME: u32 = 0x8910;
const SOL_UDP: libc::c_int = 17;
const UDP_ENCAP: libc::c_int = 100;
const UDP_ENCAP_ESPINUDP: libc::c_int = 2;
const NATT_PORT: u16 = 4500;
const MAX_ADDRS: usize = 64;
/// The signals the crash handler of the platform catches. It turns dumpable back on and lets `crash_dump` read the
/// memory of the process, which holds the keys.
const CRASH_SIGNALS: [libc::c_int; 8] = [
    libc::SIGABRT,
    libc::SIGBUS,
    libc::SIGFPE,
    libc::SIGILL,
    libc::SIGSEGV,
    libc::SIGSTKFLT,
    libc::SIGSYS,
    libc::SIGTRAP,
];
/// The signal of the platform's debugger request, which that handler also serves. Its default would end the daemon.
const DEBUGGER_SIGNAL: libc::c_int = 35;
/// The smallest receive buffer the kernel gives. The sockets that hold ports are never read.
const UNREAD_RCVBUF: libc::c_int = 1;
/// Datagrams of other sequence numbers read while waiting for an answer.
const MAX_READS: usize = 32;

/// No core dump of this process, and no access by a peer of the same user.
pub fn not_dumpable() -> io::Result<()> {
    // SAFETY: prctl with this option takes integers only.
    if unsafe { libc::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A crash ends the process with no tombstone and no core, so the keys stay in it. Call with dumpable off.
pub fn no_crash_handler() -> io::Result<()> {
    let wanted = CRASH_SIGNALS
        .iter()
        .map(|s| (*s, libc::SIG_DFL))
        .chain([(DEBUGGER_SIGNAL, libc::SIG_IGN)]);
    for (signal, action) in wanted {
        // SAFETY: both actions are constants of the kernel, no handler of this process runs.
        if unsafe { libc::signal(signal, action) } == libc::SIG_ERR {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn errno_of(e: i32) -> KernelError {
    match e {
        libc::ENODEV | libc::ENOENT | libc::EADDRNOTAVAIL | libc::ESRCH => KernelError::NotFound,
        libc::EEXIST => KernelError::Exists,
        other => KernelError::Failed(other),
    }
}

fn last_error() -> KernelError {
    errno_of(
        io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO),
    )
}

fn io_error(e: io::Error) -> KernelError {
    errno_of(e.raw_os_error().unwrap_or(libc::EIO))
}

fn built<T, E>(r: Result<T, E>) -> KernelResult<T> {
    r.map_err(|_| KernelError::Failed(libc::EINVAL))
}

fn set_option<T>(fd: RawFd, level: libc::c_int, name: libc::c_int, value: &T) -> io::Result<()> {
    // SAFETY: the pointer and the size are those of `value`, which lives through the call, and the kernel only
    // reads it.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (value as *const T).cast(),
            std::mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn open_netlink(protocol: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: socket() takes integers only and returns a new descriptor or -1.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            protocol,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is a valid descriptor that nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: a zeroed sockaddr_nl is "any port, no groups".
    let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;
    // SAFETY: sa is a valid sockaddr_nl of the size passed.
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&sa as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let tv = libc::timeval {
        tv_sec: ACK_TIMEOUT_SECS,
        tv_usec: 0,
    };
    set_option(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv)?;
    Ok(fd)
}

fn send_all(fd: RawFd, msg: &[u8]) -> KernelResult<()> {
    // SAFETY: msg is a valid buffer, and the kernel is the implicit destination of a netlink socket.
    let n = unsafe { libc::send(fd, msg.as_ptr().cast(), msg.len(), 0) };
    if n < 0 || n as usize != msg.len() {
        return Err(last_error());
    }
    Ok(())
}

/// One datagram into `buf`. A signal is no failure.
fn recv_one(fd: RawFd, buf: &mut [u8]) -> KernelResult<usize> {
    loop {
        // SAFETY: buf is valid for its length, and the kernel writes at most that.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(io_error(e));
        }
    }
}

/// Send a request and wait for its acknowledgement. The buffer of the answer is zeroed in every case.
fn transact(fd: RawFd, msg: &[u8], seq: u32) -> KernelResult<()> {
    send_all(fd, msg)?;
    let mut buf = [0u8; 4096];
    let mut result = Err(KernelError::Failed(libc::ETIMEDOUT));
    for _ in 0..MAX_READS {
        let n = match recv_one(fd, &mut buf) {
            Ok(n) => n,
            Err(e) => {
                result = Err(e);
                break;
            }
        };
        match rtnl::parse_ack(buf.get(..n).unwrap_or(&[]), seq) {
            Some(Ack::Ok) => {
                result = Ok(());
                break;
            }
            Some(Ack::Errno(e)) => {
                result = Err(errno_of(e));
                break;
            }
            None => {}
        }
    }
    wipe(&mut buf);
    result
}

pub struct LinuxKernel {
    route: OwnedFd,
    xfrm: OwnedFd,
    genl: OwnedFd,
    seq: u32,
    wlan_family: Option<u16>,
    state_dir: PathBuf,
    sockets: BTreeMap<SockHandle, OwnedFd>,
    next_socket: SockHandle,
}

impl LinuxKernel {
    pub fn open(state_dir: PathBuf) -> io::Result<Self> {
        let route = open_netlink(libc::NETLINK_ROUTE)?;
        let xfrm = open_netlink(NETLINK_XFRM)?;
        // a refused NEWSA must not come back with the request, and its keys, in the error
        set_option(
            xfrm.as_raw_fd(),
            SOL_NETLINK,
            NETLINK_CAP_ACK,
            &(1 as libc::c_int),
        )?;
        let genl = open_netlink(NETLINK_GENERIC)?;
        Ok(LinuxKernel {
            route,
            xfrm,
            genl,
            seq: 0,
            wlan_family: None,
            state_dir,
            sockets: BTreeMap::new(),
            next_socket: 1,
        })
    }

    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    fn ifreq(name: &str) -> KernelResult<libc::ifreq> {
        if name.is_empty() || name.len() > rtnl::IFNAME_MAX {
            return Err(KernelError::Failed(libc::EINVAL));
        }
        // SAFETY: an all-zero ifreq is valid.
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        for (dst, src) in ifr.ifr_name.iter_mut().zip(name.bytes()) {
            *dst = src as libc::c_char;
        }
        Ok(ifr)
    }

    fn index(&self, name: &str) -> KernelResult<i32> {
        let mut ifr = Self::ifreq(name)?;
        // SAFETY: ifr is a valid ifreq for the whole call.
        let rc = unsafe { libc::ioctl(self.route.as_raw_fd(), SIOCGIFINDEX as _, &mut ifr) };
        if rc < 0 {
            return Err(last_error());
        }
        // SAFETY: the kernel wrote ifru_ifindex for SIOCGIFINDEX.
        let i = unsafe { ifr.ifr_ifru.ifru_ifindex };
        if i <= 0 {
            return Err(KernelError::NotFound);
        }
        Ok(i)
    }

    /// The number of a generic netlink family.
    fn family_id(&mut self, name: &str) -> KernelResult<u16> {
        let seq = self.next_seq();
        let fd = self.genl.as_raw_fd();
        send_all(fd, &genl::get_family(seq, name))?;
        let mut buf = [0u8; 4096];
        for _ in 0..MAX_READS {
            let n = recv_one(fd, &mut buf)?;
            match genl::parse_family(buf.get(..n).unwrap_or(&[]), seq) {
                Some(Ok(id)) => return Ok(id),
                Some(Err(e)) => return Err(errno_of(e)),
                None => {}
            }
        }
        Err(KernelError::Failed(libc::ETIMEDOUT))
    }
}

/// `sockaddr_in` or `sockaddr_in6` of an address and port, as bytes of the right size.
enum SockAddr {
    V4(libc::sockaddr_in),
    V6(libc::sockaddr_in6),
}

impl SockAddr {
    fn of(addr: IpAddr, port: u16) -> SockAddr {
        match addr {
            IpAddr::V4(a) => {
                // SAFETY: an all-zero sockaddr_in is valid.
                let mut s: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                s.sin_family = libc::AF_INET as libc::sa_family_t;
                s.sin_port = port.to_be();
                s.sin_addr.s_addr = u32::from_ne_bytes(a.octets());
                SockAddr::V4(s)
            }
            IpAddr::V6(a) => {
                // SAFETY: an all-zero sockaddr_in6 is valid.
                let mut s: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
                s.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                s.sin6_port = port.to_be();
                s.sin6_addr.s6_addr = a.octets();
                SockAddr::V6(s)
            }
        }
    }

    fn parts(&self) -> (*const libc::sockaddr, libc::socklen_t) {
        match self {
            SockAddr::V4(s) => (
                (s as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ),
            SockAddr::V6(s) => (
                (s as *const libc::sockaddr_in6).cast(),
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            ),
        }
    }
}

fn new_socket(family: libc::c_int, kind: libc::c_int) -> KernelResult<OwnedFd> {
    // SAFETY: socket() takes integers only and returns a new descriptor or -1.
    let raw = unsafe { libc::socket(family, kind | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(last_error());
    }
    // SAFETY: raw is a valid descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn bind_to(fd: RawFd, addr: &SockAddr) -> KernelResult<()> {
    let (ptr, len) = addr.parts();
    // SAFETY: ptr and len describe the address in `addr`, which lives through the call.
    if unsafe { libc::bind(fd, ptr, len) } < 0 {
        return Err(last_error());
    }
    Ok(())
}

fn bound_port(fd: RawFd) -> KernelResult<u16> {
    // SAFETY: an all-zero sockaddr_storage is valid.
    let mut s: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: the buffer is the size that `len` says, and both live through the call.
    let rc =
        unsafe { libc::getsockname(fd, (&mut s as *mut libc::sockaddr_storage).cast(), &mut len) };
    if rc < 0 {
        return Err(last_error());
    }
    // SAFETY: the port is at the same place in sockaddr_in and sockaddr_in6, and the kernel filled one of them.
    let port =
        unsafe { (*(&s as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>()).sin_port };
    Ok(u16::from_be(port))
}

impl Kernel for LinuxKernel {
    fn ifindex(&mut self, name: &str) -> KernelResult<i32> {
        self.index(name)
    }

    fn if_name(&mut self, index: i32) -> KernelResult<String> {
        // SAFETY: an all-zero ifreq is valid.
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        ifr.ifr_ifru.ifru_ifindex = index;
        // SAFETY: ifr is a valid ifreq for the whole call.
        let rc = unsafe { libc::ioctl(self.route.as_raw_fd(), SIOCGIFNAME as _, &mut ifr) };
        if rc < 0 {
            return Err(last_error());
        }
        // c_char is u8 on arm64 and i8 on the build host.
        #[allow(clippy::unnecessary_cast)]
        let bytes: Vec<u8> = ifr
            .ifr_name
            .iter()
            .take_while(|c| **c != 0)
            .map(|c| *c as u8)
            .collect();
        String::from_utf8(bytes).map_err(|_| KernelError::Failed(libc::EINVAL))
    }

    fn create_link(
        &mut self,
        parent: &str,
        name: &str,
        mux: u8,
        flags: RmnetFlags,
    ) -> KernelResult<()> {
        let parent_index = self.index(parent)?;
        let seq = self.next_seq();
        let msg = built(rtnl::new_rmnet_link(
            seq,
            parent_index,
            name,
            u16::from(mux),
            RmnetFlagsRaw {
                flags: flags.flags,
                mask: flags.mask,
            },
        ))?;
        transact(self.route.as_raw_fd(), &msg, seq)
    }

    fn set_link(&mut self, name: &str, up: bool) -> KernelResult<()> {
        let index = self.index(name)?;
        let seq = self.next_seq();
        transact(
            self.route.as_raw_fd(),
            &rtnl::set_link(seq, index, up, None),
            seq,
        )
    }

    fn set_reverse_sysctls(&mut self, name: &str) -> KernelResult<()> {
        if !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
            return Err(KernelError::Failed(libc::EINVAL));
        }
        let mut result = Ok(());
        for knob in ["dad_transmits", "autoconf", "accept_ra"] {
            let path = format!("/proc/sys/net/ipv6/conf/{name}/{knob}");
            let written = std::fs::OpenOptions::new()
                .write(true)
                .open(path)
                .and_then(|mut f| f.write_all(b"0"));
            if let Err(e) = written {
                result = Err(io_error(e));
            }
        }
        result
    }

    fn add_state(&mut self, state: &NewState<'_>) -> KernelResult<()> {
        let seq = self.next_seq();
        let mut msg = built(xfrm::new_state(seq, state))?;
        let result = transact(self.xfrm.as_raw_fd(), &msg, seq);
        wipe(&mut msg);
        result
    }

    fn del_state(&mut self, id: &SaId) -> KernelResult<()> {
        let seq = self.next_seq();
        let msg = built(xfrm::del_state(seq, id))?;
        transact(self.xfrm.as_raw_fd(), &msg, seq)
    }

    fn add_policy(&mut self, sel: &Selector, dir: Dir, tmpl: &Tmpl) -> KernelResult<()> {
        let seq = self.next_seq();
        let msg = built(xfrm::new_policy(seq, sel, dir, tmpl))?;
        transact(self.xfrm.as_raw_fd(), &msg, seq)
    }

    fn del_policy(&mut self, sel: &Selector, dir: Dir) -> KernelResult<()> {
        let seq = self.next_seq();
        transact(self.xfrm.as_raw_fd(), &xfrm::del_policy(seq, sel, dir), seq)
    }

    fn wlan(&mut self, request: &WlanRequest) -> KernelResult<()> {
        let family = match self.wlan_family {
            Some(f) => f,
            None => {
                let f = self.family_id(genl::WLAN_FAMILY)?;
                self.wlan_family = Some(f);
                f
            }
        };
        let seq = self.next_seq();
        let msg = built(genl::wlan_message(seq, family, request))?;
        let result = transact(self.genl.as_raw_fd(), &msg, seq);
        // a module that was loaded again has another number
        if matches!(result, Err(KernelError::NotFound)) {
            self.wlan_family = None;
        }
        result
    }

    fn addresses(&mut self, ip: Ip) -> KernelResult<Vec<IfAddr>> {
        let seq = self.next_seq();
        let fd = self.route.as_raw_fd();
        send_all(fd, &rtnl_tunnel::get_addrs(seq, ip.af()))?;
        let mut out = Vec::new();
        let mut buf = vec![0u8; 16 * 1024];
        for _ in 0..MAX_READS {
            let n = recv_one(fd, &mut buf)?;
            let got = buf.get(..n).unwrap_or(&[]);
            match rtnl_tunnel::parse_addrs(got, seq, &mut out, MAX_ADDRS) {
                DumpStep::More => {}
                DumpStep::Done => return Ok(out),
                DumpStep::Failed(e) => return Err(errno_of(e)),
            }
        }
        Err(KernelError::Failed(libc::ETIMEDOUT))
    }

    fn add_rule(&mut self, rule: &Rule) -> KernelResult<()> {
        let seq = self.next_seq();
        let msg = built(rtnl_tunnel::new_rule(seq, rule))?;
        transact(self.route.as_raw_fd(), &msg, seq)
    }

    fn del_rule(&mut self, rule: &Rule) -> KernelResult<()> {
        let seq = self.next_seq();
        let msg = built(rtnl_tunnel::del_rule(seq, rule))?;
        transact(self.route.as_raw_fd(), &msg, seq)
    }

    fn reserve_port(&mut self, kind: PortKind, port: u16) -> KernelResult<(SockHandle, u16)> {
        let (family, wildcard): (libc::c_int, IpAddr) = match kind.ip() {
            4 => (libc::AF_INET, IpAddr::from([0u8; 4])),
            _ => (libc::AF_INET6, IpAddr::from([0u8; 16])),
        };
        let sock_type = if kind.is_udp() {
            libc::SOCK_DGRAM
        } else {
            libc::SOCK_STREAM
        };
        let fd = new_socket(family, sock_type)?;
        let raw = fd.as_raw_fd();
        if family == libc::AF_INET6 {
            set_option(
                raw,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                &(1 as libc::c_int),
            )
            .map_err(io_error)?;
        }
        // the UDP socket of a tunnel may need the same port: only this user can share it
        if kind.is_udp() {
            set_option(
                raw,
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                &(1 as libc::c_int),
            )
            .map_err(io_error)?;
            set_option(raw, libc::SOL_SOCKET, libc::SO_RCVBUF, &UNREAD_RCVBUF).map_err(io_error)?;
        }
        bind_to(raw, &SockAddr::of(wildcard, port))?;
        let got = if port == 0 { bound_port(raw)? } else { port };
        let handle = self.next_socket;
        self.next_socket = self.next_socket.wrapping_add(1);
        self.sockets.insert(handle, fd);
        Ok((handle, got))
    }

    fn open_encap(&mut self, local: IpAddr, remote: IpAddr, port: u16) -> KernelResult<SockHandle> {
        let family = match local {
            IpAddr::V4(_) => libc::AF_INET,
            IpAddr::V6(_) => libc::AF_INET6,
        };
        let fd = new_socket(family, libc::SOCK_DGRAM)?;
        let raw = fd.as_raw_fd();
        set_option(raw, SOL_UDP, UDP_ENCAP, &UDP_ENCAP_ESPINUDP).map_err(io_error)?;
        set_option(
            raw,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &(1 as libc::c_int),
        )
        .map_err(io_error)?;
        // the kernel takes ESP off before the queue of the socket, and nothing else is read
        set_option(raw, libc::SOL_SOCKET, libc::SO_RCVBUF, &UNREAD_RCVBUF).map_err(io_error)?;
        bind_to(raw, &SockAddr::of(local, port))?;
        let far = SockAddr::of(remote, NATT_PORT);
        let (ptr, len) = far.parts();
        // SAFETY: ptr and len describe the address in `far`, which lives through the call.
        if unsafe { libc::connect(raw, ptr, len) } < 0 {
            return Err(last_error());
        }
        let handle = self.next_socket;
        self.next_socket = self.next_socket.wrapping_add(1);
        self.sockets.insert(handle, fd);
        Ok(handle)
    }

    fn close_socket(&mut self, sock: SockHandle) {
        self.sockets.remove(&sock);
    }

    fn load_state(&mut self) -> Option<Vec<u8>> {
        let f = std::fs::File::open(self.state_dir.join("state")).ok()?;
        // one byte more than allowed, so a file that is too long is told from one that fits
        let mut bytes = Vec::new();
        f.take(MAX_FILE as u64 + 1).read_to_end(&mut bytes).ok()?;
        Some(bytes)
    }

    fn store_state(&mut self, bytes: &[u8]) -> KernelResult<()> {
        let tmp = self.state_dir.join("state.tmp");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(io_error)?;
        f.write_all(bytes).map_err(io_error)?;
        drop(f);
        std::fs::rename(&tmp, self.state_dir.join("state")).map_err(io_error)
    }

    fn random(&mut self) -> u32 {
        let mut b = [0u8; 4];
        // SAFETY: the buffer is valid for its length.
        let n = unsafe { libc::getrandom(b.as_mut_ptr().cast(), b.len(), 0) };
        if n == 4 {
            return u32::from_ne_bytes(b);
        }
        // a port number is no secret, and the tries that follow find a free one anyway
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel(name: &str) -> (LinuxKernel, PathBuf) {
        let dir = std::env::temp_dir().join(format!("wlantunneld-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        (LinuxKernel::open(dir.clone()).unwrap(), dir)
    }

    #[test]
    fn the_loopback_interface_is_found_through_the_dump_and_the_two_ioctls() {
        let (mut k, dir) = kernel("lo");
        let index = k.ifindex("lo").unwrap();
        assert_eq!(k.if_name(index).unwrap(), "lo");
        let addrs = k.addresses(Ip::V4).unwrap();
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(addrs.iter().any(|a| a.index == index && a.addr == lo));
        assert_eq!(k.ifindex("no-such-link"), Err(KernelError::NotFound));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_family_lookup_reads_the_answer_of_a_real_kernel() {
        let (mut k, dir) = kernel("family");
        // the control family has a fixed number
        assert_eq!(k.family_id("nlctrl"), Ok(genl::GENL_ID_CTRL));
        assert_eq!(k.family_id("NO_SUCH_FAMILY"), Err(KernelError::NotFound));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_crash_handler_is_gone_and_the_debugger_signal_is_ignored() {
        no_crash_handler().unwrap();
        let handler = |s| {
            // SAFETY: an all-zero sigaction is valid, and a null new action only reads the old one.
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { libc::sigaction(s, std::ptr::null(), &mut old) }, 0);
            old.sa_sigaction
        };
        for s in CRASH_SIGNALS {
            assert_eq!(handler(s), libc::SIG_DFL, "{s}");
        }
        assert_eq!(handler(DEBUGGER_SIGNAL), libc::SIG_IGN);
    }

    #[test]
    fn a_held_udp_port_has_the_smallest_queue() {
        let (mut k, dir) = kernel("rcvbuf");
        let (h, _) = k.reserve_port(PortKind::ALL[0], 0).unwrap();
        let raw = k.sockets[&h].as_raw_fd();
        let (mut value, mut len) = (0 as libc::c_int, 4 as libc::socklen_t);
        // SAFETY: value and len are valid for the call and have the size it says.
        let rc = unsafe {
            libc::getsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                std::ptr::addr_of_mut!(value).cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0);
        assert!(value <= 8192, "{value}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_held_port_keeps_others_out_until_it_is_closed() {
        let (mut k, dir) = kernel("ports");
        for kind in PortKind::ALL {
            let (h, port) = k.reserve_port(kind, 0).unwrap();
            assert_ne!(port, 0);
            // a socket that is not ours cannot share it
            let (family, sock_type) = (
                if kind.ip() == 4 {
                    libc::AF_INET
                } else {
                    libc::AF_INET6
                },
                if kind.is_udp() {
                    libc::SOCK_DGRAM
                } else {
                    libc::SOCK_STREAM
                },
            );
            let other = new_socket(family, sock_type).unwrap();
            let wildcard: IpAddr = if kind.ip() == 4 {
                IpAddr::from([0u8; 4])
            } else {
                IpAddr::from([0u8; 16])
            };
            let addr = SockAddr::of(wildcard, port);
            assert!(bind_to(other.as_raw_fd(), &addr).is_err(), "{kind:?}");
            k.close_socket(h);
            let again = new_socket(family, sock_type).unwrap();
            assert!(bind_to(again.as_raw_fd(), &addr).is_ok(), "{kind:?}");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn two_udp_holders_of_this_user_can_share_a_port() {
        let (mut k, dir) = kernel("share");
        let (_, port) = k.reserve_port(PortKind::V4Udp, 0).unwrap();
        assert!(k.reserve_port(PortKind::V4Udp, port).is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_state_file_is_written_whole_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let (mut k, dir) = kernel("state");
        assert_eq!(k.load_state(), None);
        k.store_state(b"one").unwrap();
        k.store_state(b"two").unwrap();
        assert_eq!(k.load_state().as_deref(), Some(&b"two"[..]));
        assert!(!dir.join("state.tmp").exists());
        let mode = std::fs::metadata(dir.join("state"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        // too long comes back too long, and the parser drops it
        std::fs::write(dir.join("state"), vec![b'x'; MAX_FILE + 10]).unwrap();
        assert_eq!(k.load_state().map(|b| b.len()), Some(MAX_FILE + 1));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn random_numbers_differ() {
        let (mut k, dir) = kernel("random");
        let first = k.random();
        assert!((0..8).any(|_| k.random() != first));
        let _ = std::fs::remove_dir_all(dir);
    }
}
