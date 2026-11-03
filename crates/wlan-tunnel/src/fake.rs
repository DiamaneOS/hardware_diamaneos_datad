// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! A simulated modem and a fake kernel for the tests. The modem answers every request with success unless a test
//! says otherwise, and sends what the test queues. The kernel holds what it is given and refuses what a
//! real one would, and every call is in a list so the order can be read.
use crate::kernel::{Ip, Kernel, KernelError, KernelResult, SockHandle};
use dataos_datacore::{ClientId, Qmi, QmiError};
use dataos_netcfg::genl::{Tuple, WlanRequest};
use dataos_netcfg::ops::RmnetFlags;
use dataos_netcfg::rtnl_tunnel::{IfAddr, Rule};
use dataos_netcfg::xfrm::{Dir, Encap, NewState, SaId, Selector, Tmpl};
use dataos_qmi::dfs::{self, PortKind};
use dataos_qmi::reverse;
use dataos_qmi::wds;
use dataos_qmi::{Builder, Frame, Kind};
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::rc::Rc;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClientInfo {
    pub service: u8,
    pub mux: u8,
    pub family: u8,
}

#[derive(Default)]
pub struct ModemState {
    next_client: ClientId,
    pub clients: BTreeMap<ClientId, ClientInfo>,
    pub closed: Vec<ClientId>,
    pub inbox: VecDeque<(ClientId, Vec<u8>)>,
    /// Every request: client, service, message ID, bytes.
    pub sent: Vec<(ClientId, u8, u16, Vec<u8>)>,
    /// Errors to answer with, per service and message ID, in turn.
    pub refuse: BTreeMap<(u8, u16), VecDeque<u16>>,
    /// Requests that get no answer.
    pub silent: Vec<(u8, u16)>,
    /// What follows the response to `0x11c`, and its request ID.
    pub sa_segments: Vec<Vec<u8>>,
    pub sa_id: u32,
    /// The value of TLV 0x10 in the answer to DFS `0x30`.
    pub filters: Option<Vec<u8>>,
    pub send_fails: bool,
}

#[derive(Clone, Default)]
pub struct SimModem(pub Rc<RefCell<ModemState>>);

fn byte_of(f: &Frame<'_>, tag: u8) -> u8 {
    f.tlv(tag).and_then(|v| v.first().copied()).unwrap_or(0)
}

impl ModemState {
    /// The WDS client of a mux and family.
    pub fn wds_client(&self, mux: u8, family: u8) -> Option<ClientId> {
        self.find(wds::SERVICE, mux, family)
    }

    pub fn dfs_client(&self, mux: u8, family: u8) -> Option<ClientId> {
        self.find(dfs::SERVICE, mux, family)
    }

    fn find(&self, service: u8, mux: u8, family: u8) -> Option<ClientId> {
        self.clients
            .iter()
            .find(|(_, c)| c.service == service && c.mux == mux && c.family == family)
            .map(|(id, _)| *id)
    }

    /// The requests with this message ID of a service.
    pub fn sent_of(&self, service: u8, id: u16) -> Vec<(ClientId, Vec<u8>)> {
        self.sent
            .iter()
            .filter(|(_, s, i, _)| *s == service && *i == id)
            .map(|(c, _, _, b)| (*c, b.clone()))
            .collect()
    }
}

impl Qmi for SimModem {
    fn open_client(&mut self, service: u8) -> Result<ClientId, QmiError> {
        let mut m = self.0.borrow_mut();
        m.next_client = m.next_client.saturating_add(1);
        let id = m.next_client;
        m.clients.insert(
            id,
            ClientInfo {
                service,
                ..ClientInfo::default()
            },
        );
        Ok(id)
    }

    fn close_client(&mut self, client: ClientId) {
        let mut m = self.0.borrow_mut();
        if m.clients.remove(&client).is_some() {
            m.closed.push(client);
        }
        m.inbox.retain(|(c, _)| *c != client);
    }

    fn send(&mut self, client: ClientId, datagram: &[u8]) -> Result<(), QmiError> {
        let mut m = self.0.borrow_mut();
        if m.send_fails {
            return Err(QmiError::Unavailable);
        }
        let Some(mut info) = m.clients.get(&client).copied() else {
            return Err(QmiError::Unavailable);
        };
        let Ok(f) = Frame::parse(datagram) else {
            return Err(QmiError::Unavailable);
        };
        if f.kind != Kind::Request {
            return Err(QmiError::Unavailable);
        }
        m.sent.push((client, info.service, f.id, datagram.to_vec()));
        if m.silent.contains(&(info.service, f.id)) {
            return Ok(());
        }
        let refusal = m
            .refuse
            .get_mut(&(info.service, f.id))
            .and_then(|q| q.pop_front());
        if refusal.is_none() {
            match (info.service, f.id) {
                (wds::SERVICE, reverse::id::BIND_CLIENT) => {
                    info.mux = byte_of(&f, 0x13);
                    info.family = byte_of(&f, 0x11);
                }
                (wds::SERVICE, wds::id::BIND_MUX_DATA_PORT) => info.mux = byte_of(&f, 0x11),
                (wds::SERVICE, wds::id::SET_IP_FAMILY) => info.family = byte_of(&f, 0x01),
                (dfs::SERVICE, dfs::id::BIND_CLIENT) => {
                    info.mux = byte_of(&f, 0x13);
                    info.family = byte_of(&f, 0x11);
                }
                _ => {}
            }
            m.clients.insert(client, info);
        }
        let b = Builder::response(f.txn, f.id);
        let b = match refusal {
            Some(e) => b.fail(e),
            None => b.ok(),
        };
        let mut b = b.map_err(|_| QmiError::Unavailable)?;
        if refusal.is_none() {
            if info.service == wds::SERVICE && f.id == reverse::id::IPSEC_SA {
                let id = m.sa_id;
                b = b.u32(0x10, id).map_err(|_| QmiError::Unavailable)?;
            }
            if info.service == dfs::SERVICE && f.id == dfs::id::GET_FILTERS {
                if let Some(list) = m.filters.clone() {
                    b = b.tlv(0x10, &list).map_err(|_| QmiError::Unavailable)?;
                }
            }
        }
        let bytes = b.build().map_err(|_| QmiError::Unavailable)?;
        m.inbox.push_back((client, bytes));
        if refusal.is_none() && info.service == wds::SERVICE && f.id == reverse::id::IPSEC_SA {
            let segments = m.sa_segments.clone();
            for s in segments {
                m.inbox.push_back((client, s));
            }
        }
        Ok(())
    }
}

/// A state as the kernel holds it. It keeps the keys, as a test must read them.
#[derive(Clone, PartialEq, Eq)]
pub struct HeldState {
    pub id: SaId,
    pub mode: u8,
    pub flags: u8,
    pub replay_window: u8,
    pub crypt_name: String,
    pub crypt_key: Vec<u8>,
    pub auth_name: String,
    pub auth_trunc_bits: u32,
    pub auth_key: Vec<u8>,
    pub encap: Option<Encap>,
    pub mark: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeldSocket {
    Port(PortKind, u16),
    Encap(u16),
}

#[derive(Default)]
pub struct KernelState {
    pub device_present: bool,
    /// Name, mux and flags, and whether it is up.
    pub links: BTreeMap<String, (u8, RmnetFlags, bool)>,
    pub sysctls: Vec<String>,
    pub states: Vec<HeldState>,
    pub policies: Vec<(Selector, Dir, Tmpl)>,
    pub rules: Vec<Rule>,
    /// `rmnet_wlan`: the device slot, the forwards and the tuples.
    pub device: Option<String>,
    pub forwards: Vec<(String, IpAddr)>,
    pub tuples: Vec<[u8; 8]>,
    pub encap_ports: Vec<[u8; 2]>,
    /// Every command number sent to the module.
    pub wlan_log: Vec<u8>,
    /// Every call, in order, in a short name.
    pub log: Vec<String>,
    pub addrs: Vec<(String, i32, IpAddr)>,
    pub sockets: BTreeMap<SockHandle, HeldSocket>,
    next_sock: SockHandle,
    pub busy_ports: Vec<u16>,
    pub state_file: Option<Vec<u8>>,
    pub state_writes: u32,
    pub random: u32,
    /// The call of this short name fails with this error, once each.
    pub fail: BTreeMap<String, KernelError>,
}

#[derive(Clone, Default)]
pub struct FakeKernel(pub Rc<RefCell<KernelState>>);

impl KernelState {
    fn call(&mut self, name: &str) -> KernelResult<()> {
        self.log.push(name.to_owned());
        match self.fail.remove(name) {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Nothing of a tunnel is left in the kernel.
    pub fn is_clean(&self) -> bool {
        self.states.is_empty()
            && self.policies.is_empty()
            && self.rules.is_empty()
            && self.forwards.is_empty()
            && self.device.is_none()
            && self.links.values().all(|(_, _, up)| !up)
    }
}

impl Kernel for FakeKernel {
    fn ifindex(&mut self, name: &str) -> KernelResult<i32> {
        let k = self.0.borrow();
        if (name == "rmnet_ipa0" || name == "rmnet_data0") && k.device_present {
            return Ok(1);
        }
        k.addrs
            .iter()
            .find(|(n, _, _)| n == name)
            .map(|(_, i, _)| *i)
            .ok_or(KernelError::NotFound)
    }

    fn if_name(&mut self, index: i32) -> KernelResult<String> {
        self.0
            .borrow()
            .addrs
            .iter()
            .find(|(_, i, _)| *i == index)
            .map(|(n, _, _)| n.clone())
            .ok_or(KernelError::NotFound)
    }

    fn create_link(
        &mut self,
        _parent: &str,
        name: &str,
        mux: u8,
        flags: RmnetFlags,
    ) -> KernelResult<()> {
        let mut k = self.0.borrow_mut();
        k.call(&format!("newlink {name}"))?;
        if k.links.contains_key(name) {
            return Err(KernelError::Exists);
        }
        k.links.insert(name.to_owned(), (mux, flags, false));
        Ok(())
    }

    fn set_link(&mut self, name: &str, up: bool) -> KernelResult<()> {
        let mut k = self.0.borrow_mut();
        k.call(if up { "link up" } else { "link down" })?;
        match k.links.get_mut(name) {
            Some(l) => {
                l.2 = up;
                Ok(())
            }
            None => Err(KernelError::NotFound),
        }
    }

    fn set_reverse_sysctls(&mut self, name: &str) -> KernelResult<()> {
        let mut k = self.0.borrow_mut();
        k.call("sysctls")?;
        k.sysctls.push(name.to_owned());
        Ok(())
    }

    fn add_state(&mut self, s: &NewState<'_>) -> KernelResult<()> {
        let mut k = self.0.borrow_mut();
        k.call("newsa")?;
        if k.states.iter().any(|h| h.id == s.id) {
            return Err(KernelError::Exists);
        }
        k.states.push(HeldState {
            id: s.id,
            mode: s.mode,
            flags: s.flags,
            replay_window: s.replay_window,
            crypt_name: s.crypt_name.to_owned(),
            crypt_key: s.crypt_key.to_vec(),
            auth_name: s.auth_name.to_owned(),
            auth_trunc_bits: s.auth_trunc_bits,
            auth_key: s.auth_key.to_vec(),
            encap: s.encap,
            mark: s.mark,
        });
        Ok(())
    }

    fn del_state(&mut self, id: &SaId) -> KernelResult<()> {
        let mut k = self.0.borrow_mut();
        k.call("delsa")?;
        let before = k.states.len();
        k.states.retain(|h| h.id != *id);
        if k.states.len() == before {
            return Err(KernelError::NotFound);
        }
        Ok(())
    }

    fn add_policy(&mut self, sel: &Selector, dir: Dir, tmpl: &Tmpl) -> KernelResult<()> {
        let mut k = self.0.borrow_mut();
        k.call(&format!("newpolicy {dir:?}"))?;
        if k.policies.iter().any(|(s, d, _)| s == sel && *d == dir) {
            return Err(KernelError::Exists);
        }
        k.policies.push((*sel, dir, *tmpl));
        Ok(())
    }

    fn del_policy(&mut self, sel: &Selector, dir: Dir) -> KernelResult<()> {
        let mut k = self.0.borrow_mut();
        k.call(&format!("delpolicy {dir:?}"))?;
        let before = k.policies.len();
        k.policies.retain(|(s, d, _)| !(s == sel && *d == dir));
        if k.policies.len() == before {
            return Err(KernelError::NotFound);
        }
        Ok(())
    }

    fn wlan(&mut self, r: &WlanRequest) -> KernelResult<()> {
        let mut k = self.0.borrow_mut();
        k.wlan_log.push(r.number());
        k.call(&format!("genl {}", r.number()))?;
        match r {
            WlanRequest::AddTuples(list) => {
                for t in list {
                    let b = t.bytes();
                    if !k.tuples.contains(&b) {
                        k.tuples.push(b);
                    }
                }
            }
            WlanRequest::DelTuples(list) => {
                let gone: Vec<[u8; 8]> = list.iter().map(Tuple::bytes).collect();
                k.tuples.retain(|t| !gone.contains(t));
            }
            WlanRequest::SetDevice { device, .. } => k.device = Some(device.clone()),
            WlanRequest::UnsetDevice { .. } => k.device = None,
            WlanRequest::AddForward { device, addr, .. } => {
                if k.forwards.iter().any(|(_, a)| a == addr) {
                    return Err(KernelError::Exists);
                }
                k.forwards.push((device.clone(), *addr));
            }
            WlanRequest::DelForward { device, addr, .. } => {
                let before = k.forwards.len();
                k.forwards.retain(|(d, a)| !(d == device && a == addr));
                if k.forwards.len() == before {
                    return Err(KernelError::NotFound);
                }
            }
            WlanRequest::SetEncapPort(p) => {
                if k.encap_ports.contains(p) {
                    return Err(KernelError::Exists);
                }
                k.encap_ports.push(*p);
            }
            WlanRequest::UnsetEncapPort(p) => k.encap_ports.retain(|e| e != p),
            WlanRequest::Flush => {
                k.device = None;
                k.forwards.clear();
                k.tuples.clear();
                k.encap_ports.clear();
            }
            WlanRequest::EncapPass(_) | WlanRequest::EncapDrop(_) => {}
        }
        Ok(())
    }

    fn addresses(&mut self, ip: Ip) -> KernelResult<Vec<IfAddr>> {
        let mut k = self.0.borrow_mut();
        k.call("getaddr")?;
        Ok(k.addrs
            .iter()
            .filter(|(_, _, a)| Ip::of(*a) == ip)
            .map(|(_, index, addr)| IfAddr {
                index: *index,
                addr: *addr,
            })
            .collect())
    }

    fn add_rule(&mut self, rule: &Rule) -> KernelResult<()> {
        let mut k = self.0.borrow_mut();
        k.call("newrule")?;
        if k.rules.contains(rule) {
            return Err(KernelError::Exists);
        }
        k.rules.push(*rule);
        Ok(())
    }

    fn del_rule(&mut self, rule: &Rule) -> KernelResult<()> {
        let mut k = self.0.borrow_mut();
        k.call("delrule")?;
        let before = k.rules.len();
        k.rules.retain(|r| r != rule);
        if k.rules.len() == before {
            return Err(KernelError::NotFound);
        }
        Ok(())
    }

    fn reserve_port(&mut self, kind: PortKind, port: u16) -> KernelResult<(SockHandle, u16)> {
        let mut k = self.0.borrow_mut();
        let chosen = if port == 0 {
            40_000 + k.next_sock as u16
        } else {
            port
        };
        if k.busy_ports.contains(&chosen) {
            return Err(KernelError::Failed(98));
        }
        k.next_sock = k.next_sock.saturating_add(1);
        let h = k.next_sock;
        k.sockets.insert(h, HeldSocket::Port(kind, chosen));
        Ok((h, chosen))
    }

    fn open_encap(&mut self, _l: IpAddr, _r: IpAddr, port: u16) -> KernelResult<SockHandle> {
        let mut k = self.0.borrow_mut();
        k.call("encap socket")?;
        k.next_sock = k.next_sock.saturating_add(1);
        let h = k.next_sock;
        k.sockets.insert(h, HeldSocket::Encap(port));
        Ok(h)
    }

    fn close_socket(&mut self, sock: SockHandle) {
        self.0.borrow_mut().sockets.remove(&sock);
    }

    fn load_state(&mut self) -> Option<Vec<u8>> {
        self.0.borrow().state_file.clone()
    }

    fn store_state(&mut self, bytes: &[u8]) -> KernelResult<()> {
        let mut k = self.0.borrow_mut();
        k.call("store state")?;
        k.state_writes = k.state_writes.saturating_add(1);
        k.state_file = Some(bytes.to_vec());
        Ok(())
    }

    fn random(&mut self) -> u32 {
        let mut k = self.0.borrow_mut();
        k.random = k.random.wrapping_add(1);
        k.random
    }
}
