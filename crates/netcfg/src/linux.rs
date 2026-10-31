// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Linux backend: one NETLINK_ROUTE socket for everything. Link and address
//! requests go through it as messages. The interface ioctls (name to index and
//! the rmnet_ipa0 control) go through the same socket, because the kernel hands
//! `SIOCDEVPRIVATE` and unknown socket ioctls to the network device for any
//! socket type (`sock_ioctl` and `netlink_ioctl` in the 6.18 tree). So the
//! daemon needs no datagram socket. One request is in flight at a time, every
//! request is acknowledged and waiting for the acknowledgement has a deadline.
//!
//! Not exercised by host tests (needs CAP_NET_ADMIN and a real kernel, only
//! `cargo check --target aarch64-unknown-linux-gnu`). The message building it
//! relies on is tested in `rtnl` and `ipa`.
#![allow(unsafe_code)]
use crate::ethtool;
use crate::ipa;
use crate::ops::{
    AddrFlags, EgressPipe, Endpoint, IngressPipe, Ipv6Settings, NetError, NetOps, PipeStatus,
    RmnetFlags, SetupMarker,
};
use crate::rtnl::{self, Ack, BuildError, RmnetFlagsRaw};
use std::io;
use std::io::Write;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

/// How long to wait for the kernel's acknowledgement.
const ACK_TIMEOUT_SECS: libc::time_t = 2;
const SIOCGIFINDEX: u32 = 0x0000_8933;

/// Where the setup marker lives by default: a directory on tmpfs that init
/// creates for the daemon, so a reboot clears it by itself.
pub const DEFAULT_STATE_DIR: &str = "/dev/datad";
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

pub struct LinuxNet {
    fd: OwnedFd,
    seq: u32,
    state_dir: PathBuf,
}

fn map_build(e: BuildError) -> NetError {
    let _ = e;
    NetError::Invalid
}

fn map_errno(e: i32) -> NetError {
    match e {
        libc::ENODEV | libc::ENOENT | libc::EADDRNOTAVAIL => NetError::NotFound,
        libc::EEXIST => NetError::Exists,
        libc::EINVAL => NetError::Invalid,
        libc::EAGAIN => NetError::TimedOut,
        other => NetError::Os(other),
    }
}

fn last_errno() -> i32 {
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

impl LinuxNet {
    pub fn open() -> io::Result<Self> {
        Self::open_with_state_dir(DEFAULT_STATE_DIR.into())
    }

    pub fn open_with_state_dir(state_dir: PathBuf) -> io::Result<Self> {
        // SAFETY: socket() returns a new descriptor or -1.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a valid descriptor that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: zeroed sockaddr_nl is a valid "any port, no groups" address.
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
        // SAFETY: tv is a valid timeval of the size passed.
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&tv as *const libc::timeval).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(LinuxNet {
            fd,
            seq: 0,
            state_dir,
        })
    }

    fn ifreq(name: &str) -> Result<libc::ifreq, NetError> {
        if !valid_ifname(name) {
            return Err(NetError::Invalid);
        }
        // SAFETY: an all-zero ifreq is valid.
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        for (dst, src) in ifr.ifr_name.iter_mut().zip(name.bytes()) {
            *dst = src as libc::c_char;
        }
        Ok(ifr)
    }

    fn index(&self, name: &str) -> Result<i32, NetError> {
        let mut ifr = Self::ifreq(name)?;
        // SAFETY: ifr is a valid ifreq for the whole call.
        let rc = unsafe { libc::ioctl(self.fd.as_raw_fd(), SIOCGIFINDEX as _, &mut ifr) };
        if rc < 0 {
            return Err(map_errno(last_errno()));
        }
        // SAFETY: the kernel wrote ifru_ifindex for SIOCGIFINDEX.
        let i = unsafe { ifr.ifr_ifru.ifru_ifindex };
        if i <= 0 {
            Err(NetError::NotFound)
        } else {
            Ok(i)
        }
    }

    fn extended_ioctl(
        &self,
        device: &str,
        payload: &mut [u8; ipa::EXT_LEN],
    ) -> Result<(), NetError> {
        let mut ifr = Self::ifreq(device)?;
        ifr.ifr_ifru.ifru_data = payload.as_mut_ptr().cast();
        // SAFETY: ifr is valid for the call and ifru_data points to EXT_LEN
        // bytes that live until it returns. The driver reads that many.
        let rc = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                ipa::RMNET_IOCTL_EXTENDED as _,
                &mut ifr,
            )
        };
        if rc < 0 {
            return Err(map_errno(last_errno()));
        }
        Ok(())
    }

    /// `RMNET_IOCTL_EXTENDED_V2` for one format: the array of parameters is the driver's to read and to write the
    /// status of each endpoint back into, so it is a buffer of this call that lives until the ioctl returns.
    fn format_v2(
        &self,
        device: &str,
        kind: u32,
        params: &mut [u8],
        param_len: usize,
    ) -> Result<(), NetError> {
        let endpoints = u32::try_from(params.len() / param_len).map_err(|_| NetError::Invalid)?;
        let param_size = u32::try_from(param_len).map_err(|_| NetError::Invalid)?;
        let mut format = ipa::format_v2(params.as_mut_ptr() as u64, param_size, endpoints);
        let mut outer = ipa::extended_v2(format.as_mut_ptr() as u64, ipa::V2_LEN as u32, kind);
        let mut ifr = Self::ifreq(device)?;
        ifr.ifr_ifru.ifru_data = outer.as_mut_ptr().cast();
        // SAFETY: ifr is valid for the call. ifru_data points to the 16 bytes of `outer`, whose address field
        // holds `format`, whose address field holds `params`. All three live until the call returns, and the
        // driver reads them and writes the status words of `params`.
        let rc = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                ipa::RMNET_IOCTL_EXTENDED_V2 as _,
                &mut ifr,
            )
        };
        if rc < 0 {
            return Err(map_errno(last_errno()));
        }
        Ok(())
    }

    /// One `SIOCETHTOOL` request: `payload` is the request and gets the answer.
    fn ethtool_ioctl(&self, name: &str, payload: &mut [u8]) -> Result<(), NetError> {
        let mut ifr = Self::ifreq(name)?;
        ifr.ifr_ifru.ifru_data = payload.as_mut_ptr().cast();
        // SAFETY: ifr is valid for the call and ifru_data points to the bytes of `payload`, which live until
        // it returns. The kernel reads the request from them and writes the answer into them, and never more
        // than the sizes the request names, which `ethtool` made from the same lengths.
        let rc = unsafe { libc::ioctl(self.fd.as_raw_fd(), ethtool::SIOCETHTOOL as _, &mut ifr) };
        if rc < 0 {
            return Err(map_errno(last_errno()));
        }
        Ok(())
    }

    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    fn transact(&mut self, msg: &[u8], seq: u32) -> Result<(), NetError> {
        // SAFETY: msg is a valid buffer, the kernel address is implicit (port 0).
        let n = unsafe { libc::send(self.fd.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0) };
        if n < 0 || n as usize != msg.len() {
            return Err(map_errno(last_errno()));
        }
        let mut buf = [0u8; 4096];
        loop {
            // SAFETY: buf is valid for buf.len() bytes.
            let n =
                unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n < 0 {
                let e = last_errno();
                if e == libc::EINTR {
                    continue;
                }
                return Err(map_errno(e));
            }
            let got = buf.get(..n as usize).unwrap_or(&[]);
            match rtnl::parse_ack(got, seq) {
                Some(Ack::Ok) => return Ok(()),
                Some(Ack::Errno(e)) => return Err(map_errno(e)),
                None => continue, // unrelated or older reply
            }
        }
    }
}

fn valid_ifname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= rtnl::IFNAME_MAX
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

impl NetOps for LinuxNet {
    fn create_rmnet_link(
        &mut self,
        parent: &str,
        name: &str,
        mux_id: u8,
        flags: RmnetFlags,
    ) -> Result<(), NetError> {
        let parent_index = self.index(parent)?;
        let seq = self.next_seq();
        let msg = rtnl::new_rmnet_link(
            seq,
            parent_index,
            name,
            u16::from(mux_id),
            RmnetFlagsRaw {
                flags: flags.flags,
                mask: flags.mask,
            },
        )
        .map_err(map_build)?;
        self.transact(&msg, seq)
    }

    fn delete_link(&mut self, name: &str) -> Result<(), NetError> {
        // by name, so a name that does not exist costs no interface lookup
        // (which could make the kernel try to load a module for it)
        let seq = self.next_seq();
        let msg = rtnl::del_link_by_name(seq, name).map_err(map_build)?;
        self.transact(&msg, seq)
    }

    fn set_link(&mut self, name: &str, up: bool, mtu: Option<u32>) -> Result<(), NetError> {
        let idx = self.index(name)?;
        let seq = self.next_seq();
        self.transact(&rtnl::set_link(seq, idx, up, mtu), seq)
    }

    fn add_address(
        &mut self,
        name: &str,
        addr: IpAddr,
        prefix: u8,
        flags: AddrFlags,
    ) -> Result<(), NetError> {
        let idx = self.index(name)?;
        let seq = self.next_seq();
        let mut f = 0;
        if flags.no_dad {
            f |= rtnl::IFA_F_NODAD;
        }
        if flags.no_prefix_route {
            f |= rtnl::IFA_F_NOPREFIXROUTE;
        }
        let msg = rtnl::add_addr(seq, idx, addr, prefix, f).map_err(map_build)?;
        self.transact(&msg, seq)
    }

    fn del_address(&mut self, name: &str, addr: IpAddr, prefix: u8) -> Result<(), NetError> {
        let idx = self.index(name)?;
        let seq = self.next_seq();
        let msg = rtnl::del_addr(seq, idx, addr, prefix).map_err(map_build)?;
        self.transact(&msg, seq)
    }

    fn set_ipv6(&mut self, name: &str, cfg: Ipv6Settings) -> Result<(), NetError> {
        if !valid_ifname(name) {
            return Err(NetError::Invalid);
        }
        let path = format!("/proc/sys/net/ipv6/conf/{name}/disable_ipv6");
        let val: &[u8] = if cfg.disable_ipv6 { b"1" } else { b"0" };
        std::fs::write(path, val).map_err(|e| map_errno(e.raw_os_error().unwrap_or(libc::EIO)))
    }

    fn ifindex(&mut self, name: &str) -> Result<i32, NetError> {
        self.index(name)
    }

    fn boot_id(&mut self) -> Result<String, NetError> {
        let text = std::fs::read_to_string(BOOT_ID_PATH)
            .map_err(|e| map_errno(e.raw_os_error().unwrap_or(libc::EIO)))?;
        let id = text.trim();
        if id.is_empty() || id.len() > 64 || id.contains(char::is_whitespace) {
            return Err(NetError::Invalid);
        }
        Ok(id.to_string())
    }

    fn load_marker(&mut self) -> Option<SetupMarker> {
        let text = std::fs::read_to_string(self.state_dir.join("setup")).ok()?;
        SetupMarker::parse(&text)
    }

    fn store_marker(&mut self, marker: &SetupMarker) -> Result<(), NetError> {
        let tmp = self.state_dir.join("setup.tmp");
        let io_err = |e: io::Error| map_errno(e.raw_os_error().unwrap_or(libc::EIO));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(io_err)?;
        f.write_all(marker.to_text().as_bytes()).map_err(io_err)?;
        f.sync_all().map_err(io_err)?;
        std::fs::rename(&tmp, self.state_dir.join("setup")).map_err(io_err)
    }

    fn load_links(&mut self) -> Option<Vec<u8>> {
        use std::io::Read;
        let f = std::fs::File::open(self.state_dir.join("links")).ok()?;
        // one byte more than allowed, so a file that is too long is told from one that fits
        let mut bytes = Vec::new();
        f.take(crate::ops::MAX_LINKS_FILE as u64 + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        (bytes.len() <= crate::ops::MAX_LINKS_FILE).then_some(bytes)
    }

    fn store_links(&mut self, bytes: &[u8]) -> Result<(), NetError> {
        if bytes.len() > crate::ops::MAX_LINKS_FILE {
            return Err(NetError::Invalid);
        }
        let tmp = self.state_dir.join("links.tmp");
        let io_err = |e: io::Error| map_errno(e.raw_os_error().unwrap_or(libc::EIO));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(io_err)?;
        f.write_all(bytes).map_err(io_err)?;
        std::fs::rename(&tmp, self.state_dir.join("links")).map_err(io_err)
    }

    fn ipa_endpoint(&mut self, device: &str) -> Result<Endpoint, NetError> {
        let mut epid = ipa::get_epid();
        self.extended_ioctl(device, &mut epid)?;
        let mut pair = ipa::get_ep_pair();
        self.extended_ioctl(device, &mut pair)?;
        Ok(ipa::endpoint_of(&epid, &pair))
    }

    fn ipa_set_egress_format(
        &mut self,
        device: &str,
        pipes: &[EgressPipe],
    ) -> Result<PipeStatus, NetError> {
        let mut params: Vec<u8> = pipes.iter().flat_map(ipa::egress_param).collect();
        let rc = self.format_v2(device, ipa::V2_EGRESS, &mut params, ipa::EGRESS_PARAM_LEN);
        ipa::egress_result(rc, &params)
    }

    fn ipa_set_ingress_format(
        &mut self,
        device: &str,
        pipes: &[IngressPipe],
    ) -> Result<PipeStatus, NetError> {
        let mut params: Vec<u8> = pipes.iter().flat_map(ipa::ingress_param).collect();
        let rc = self.format_v2(device, ipa::V2_INGRESS, &mut params, ipa::INGRESS_PARAM_LEN);
        ipa::ingress_result(rc, &params)
    }

    fn ipa_add_mux_channel(
        &mut self,
        device: &str,
        mux_id: u8,
        link: &str,
    ) -> Result<(), NetError> {
        let mut payload = ipa::add_mux_channel(u32::from(mux_id), link).map_err(map_build)?;
        self.extended_ioctl(device, &mut payload)
    }

    fn set_features(&mut self, name: &str, wanted: &[&str]) -> Result<Vec<String>, NetError> {
        ethtool::enable(wanted, &mut |payload| self.ethtool_ioctl(name, payload))
    }
}
