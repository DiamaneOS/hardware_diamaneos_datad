// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! What the engine needs from the kernel, as a trait so that it runs in host tests.
use dataos_netcfg::genl::WlanRequest;
use dataos_netcfg::ops::RmnetFlags;
use dataos_netcfg::rtnl_tunnel::{IfAddr, Rule};
use dataos_netcfg::xfrm::{Dir, NewState, SaId, Selector, Tmpl};
use dataos_qmi::dfs::PortKind;
use dataos_qmi::wds::IpFamily;
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelError {
    NotFound,
    Exists,
    /// The kernel refused with this errno.
    Failed(i32),
}

impl KernelError {
    /// The number for a log line.
    pub fn errno(self) -> i32 {
        match self {
            KernelError::NotFound => 2,
            KernelError::Exists => 17,
            KernelError::Failed(e) => e,
        }
    }
}

pub type KernelResult<T> = Result<T, KernelError>;
pub type SockHandle = u32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ip {
    V4,
    V6,
}

impl Ip {
    pub fn of(a: IpAddr) -> Ip {
        match a {
            IpAddr::V4(_) => Ip::V4,
            IpAddr::V6(_) => Ip::V6,
        }
    }

    pub fn wds(self) -> IpFamily {
        match self {
            Ip::V4 => IpFamily::V4,
            Ip::V6 => IpFamily::V6,
        }
    }

    pub fn number(self) -> u8 {
        match self {
            Ip::V4 => 4,
            Ip::V6 => 6,
        }
    }

    pub fn af(self) -> u8 {
        match self {
            Ip::V4 => dataos_netcfg::rtnl::AF_INET,
            Ip::V6 => dataos_netcfg::rtnl::AF_INET6,
        }
    }

    /// The prefix of the selector of a tunnel's policies.
    pub fn selector_prefix(self) -> u8 {
        match self {
            Ip::V4 => 32,
            Ip::V6 => 64,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Ip::V4 => "v4",
            Ip::V6 => "v6",
        }
    }
}

pub trait Kernel {
    /// The index of an interface. `NotFound` when there is none.
    fn ifindex(&mut self, name: &str) -> KernelResult<i32>;
    fn if_name(&mut self, index: i32) -> KernelResult<String>;
    fn create_link(
        &mut self,
        parent: &str,
        name: &str,
        mux: u8,
        flags: RmnetFlags,
    ) -> KernelResult<()>;
    fn set_link(&mut self, name: &str, up: bool) -> KernelResult<()>;
    /// `dad_transmits`, `autoconf` and `accept_ra` of the link to 0.
    fn set_reverse_sysctls(&mut self, name: &str) -> KernelResult<()>;
    fn add_state(&mut self, state: &NewState<'_>) -> KernelResult<()>;
    fn del_state(&mut self, id: &SaId) -> KernelResult<()>;
    fn add_policy(&mut self, sel: &Selector, dir: Dir, tmpl: &Tmpl) -> KernelResult<()>;
    fn del_policy(&mut self, sel: &Selector, dir: Dir) -> KernelResult<()>;
    /// A command of `rmnet_wlan`.
    fn wlan(&mut self, request: &WlanRequest) -> KernelResult<()>;
    fn addresses(&mut self, ip: Ip) -> KernelResult<Vec<IfAddr>>;
    fn add_rule(&mut self, rule: &Rule) -> KernelResult<()>;
    fn del_rule(&mut self, rule: &Rule) -> KernelResult<()>;
    /// Hold a port with a bound socket, the port the kernel picks for 0. The answer has the port.
    fn reserve_port(&mut self, kind: PortKind, port: u16) -> KernelResult<(SockHandle, u16)>;
    /// The UDP socket that carries a tunnel's ESP: bound to the local address and port, connected to port 4500.
    fn open_encap(&mut self, local: IpAddr, remote: IpAddr, port: u16) -> KernelResult<SockHandle>;
    fn close_socket(&mut self, sock: SockHandle);
    fn load_state(&mut self) -> Option<Vec<u8>>;
    fn store_state(&mut self, bytes: &[u8]) -> KernelResult<()>;
    fn random(&mut self) -> u32;
}
