// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The engine. It is synchronous and never blocks on the modem. Its inputs are datagrams, service events and timer
//! ticks, and its outputs are QMI requests, kernel calls and lines for the log. A line has no address, SPI, key or
//! any other identifier in it: only link names, families, step names, counts and error numbers.
use crate::kernel::{Ip, Kernel, KernelError, SockHandle};
use crate::ports::{self, tuple_of, Store};
use crate::sa::{usable_address, Added, Assembly, IpsecSa};
use crate::state::Ledger;
use dataos_datacore::{ClientId, Qmi, ServiceEvent};
use dataos_netcfg::genl::{NetType, Tuple, TupleKey, WlanRequest, PROTO_ESP};
use dataos_netcfg::ops::RmnetFlags;
use dataos_netcfg::rtnl_tunnel::Rule;
use dataos_netcfg::xfrm::{Dir, SaId, Selector, Side, Tmpl};
use dataos_qmi::dfs::{self, EspFilter, PortAnswer, PortKind, PortsWanted};
use dataos_qmi::reverse::{self, tech, ReverseInd, STATUS_CONNECTED, STATUS_DISCONNECTED};
use dataos_qmi::secret::wipe;
use dataos_qmi::wds;
use dataos_qmi::{Error as QmiParseError, Frame, Kind, QmiStatus};
use std::collections::VecDeque;
use std::net::IpAddr;

/// The services that make the modem up for this daemon.
pub const WANTED: [u8; 2] = [wds::SERVICE, dfs::SERVICE];
/// Two clients per link and family, one for the ports, and a little room.
pub const MAX_CLIENTS: usize = 20;
/// The largest datagram to read, a full filter list.
pub const MAX_DATAGRAM: usize = dfs::MAX_MESSAGE;

const ERR_NO_REVERSE_BIND: u16 = 0x47;
const S2B_TX_MARK: u32 = 0x20000;
const RULE_MASK: u32 = 0xfffff;
const RULE_TABLE_BASE: i32 = 1000;
/// Tries to find a free port in the range the modem gave.
const PICK_TRIES: u32 = 100;
const MAX_ENCAP: usize = 8;
const MAX_LINES: usize = 256;
const PROPERTY_SYMMETRIC: u32 = dfs::PROPERTY_SYMMETRIC;
/// A tunnel runs over Wi-Fi only.
const TRANSPORT_PREFIX: &str = "wlan";
/// The only interfaces that may hold the inner address of a tunnel: the forward links of the data daemon.
const INNER_ADDRESS_PREFIX: &str = "rmnet_data";
/// Failed deletions kept for a retry. With what the links can hold, this fits the state file.
const MAX_LEFT: usize = 20;
/// Ports of one request named in the log. They say nothing about the user.
const MAX_PORTS_SAID: usize = 8;

#[derive(Clone, Debug)]
pub struct Config {
    pub parent: String,
    /// The first forward link. The data daemon makes it after the data format of the device, and a reverse link
    /// made earlier would set up the rmnet port before that.
    pub forward_link: String,
    pub link_prefix: String,
    /// The reverse links. The links of the data daemon end at mux 17.
    pub links: u8,
    pub first_mux: u8,
    /// Endpoint type and number of the data port on this device.
    pub endpoint: (u32, u32),
    /// The mux of the client that hears about ports.
    pub ports_mux: u8,
    pub request_timeout_ms: u64,
    /// How long a tunnel waits for its ESP states.
    pub sa_wait_ms: u64,
    pub bind_tries: u8,
    pub bind_retry_ms: u64,
    pub retry_ms: u64,
    pub retry_max_ms: u64,
    pub rmnet_flags: RmnetFlags,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            parent: "rmnet_ipa0".into(),
            forward_link: "rmnet_data0".into(),
            link_prefix: "r_rmnet_data".into(),
            links: 4,
            first_mux: 18,
            endpoint: (wds::EP_EMBEDDED, 1),
            ports_mux: 1,
            request_timeout_ms: 5_000,
            sa_wait_ms: 5_000,
            bind_tries: 3,
            bind_retry_ms: 100,
            retry_ms: 1_000,
            retry_max_ms: 60_000,
            rmnet_flags: RmnetFlags::qmap_default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Idle,
    Bind,
    LegacyBind,
    SetFamily,
    Register,
    DfsBind,
    DfsRegister,
    Ready,
    Failed,
}

impl Step {
    fn answers(self) -> Option<u16> {
        match self {
            Step::Bind => Some(reverse::id::BIND_CLIENT),
            Step::LegacyBind => Some(wds::id::BIND_MUX_DATA_PORT),
            Step::SetFamily => Some(wds::id::SET_IP_FAMILY),
            Step::Register => Some(reverse::id::REGISTER),
            Step::DfsBind => Some(dfs::id::BIND_CLIENT),
            Step::DfsRegister => Some(dfs::id::INDICATION_REGISTER),
            Step::Idle | Step::Ready | Step::Failed => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Step::Idle => "idle",
            Step::Bind => "bind 0x118",
            Step::LegacyBind => "bind 0xa2",
            Step::SetFamily => "family 0x4d",
            Step::Register => "register 0x8d",
            Step::DfsBind => "dfs bind 0x21",
            Step::DfsRegister => "dfs register 0x03",
            Step::Ready => "ready",
            Step::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    WaitSa,
    WaitFilters,
}

/// A connect of an S2B tunnel that waits for the modem.
struct Pending {
    tid: u32,
    tech: u16,
    addr: IpAddr,
    phase: Phase,
    txn: u16,
    deadline: u64,
    assembly: Assembly,
    sa: Option<IpsecSa>,
}

/// What one family of a link has installed.
#[derive(Clone)]
struct Installed {
    tech: u16,
    net: NetType,
    addr: IpAddr,
    transport: String,
    /// OUT, IN, FWD, as they went in.
    policies: Vec<(Selector, Dir)>,
    rule: Option<Rule>,
}

struct Leg {
    link: usize,
    ip: Ip,
    wds: Option<ClientId>,
    dfs: Option<ClientId>,
    step: Step,
    txn: u16,
    deadline: Option<u64>,
    tries: u8,
    retry_at: Option<u64>,
    backoff: u64,
    pending: Option<Box<Pending>>,
    installed: Option<Installed>,
}

struct LinkState {
    name: String,
    mux: u8,
    /// TX and RX, for all the families of the link.
    states: Option<[SaId; 2]>,
}

struct PortsLeg {
    client: Option<ClientId>,
    step: Step,
    txn: u16,
    deadline: Option<u64>,
    retry_at: Option<u64>,
    backoff: u64,
}

struct EncapSock {
    port: u16,
    local: IpAddr,
    remote: IpAddr,
    sock: SockHandle,
}

enum Undo {
    LinkDown(usize),
    States(usize),
    State(SaId),
    Policy(Selector, Dir),
    Forward(WlanRequest),
    Device(WlanRequest),
}

enum Owner {
    Wds(usize),
    Dfs(usize),
    Ports,
}

pub struct Engine<Q: Qmi, K: Kernel> {
    cfg: Config,
    qmi: Q,
    kernel: K,
    now: u64,
    modem_up: bool,
    started_clients: bool,
    links_retry_at: Option<u64>,
    said_waiting: bool,
    links: Vec<LinkState>,
    legs: Vec<Leg>,
    ports_leg: PortsLeg,
    store: Store,
    encaps: Vec<EncapSock>,
    txn: u16,
    lines: VecDeque<String>,
    stored_state: Vec<u8>,
    state_write_failed: bool,
    said_stale: bool,
    /// What the kernel refused to delete. It stays in the state file and is tried again.
    left: Ledger,
    /// Commands of the module that failed. While there are any, no policy goes and no tunnel comes.
    left_wlan: Vec<WlanRequest>,
    left_retry_at: Option<u64>,
}

fn net_type(t: u16) -> NetType {
    match t {
        tech::IWLAN_S2B => NetType::S2b,
        tech::CIWLAN => NetType::Ciwlan,
        _ => NetType::LocalBreakout,
    }
}

fn dup_ok(r: Result<(), KernelError>) -> Result<(), KernelError> {
    match r {
        Err(KernelError::Exists) => Ok(()),
        other => other,
    }
}

fn gone_ok(r: Result<(), KernelError>) -> Result<(), KernelError> {
    match r {
        Err(KernelError::NotFound) => Ok(()),
        other => other,
    }
}

/// A local address belongs to an interface when the whole IPv4 address matches, or the first 8 bytes of an IPv6
/// one (all 16 for a link local address).
fn same_interface(ours: IpAddr, theirs: IpAddr) -> bool {
    match (ours, theirs) {
        (IpAddr::V4(a), IpAddr::V4(b)) => a == b,
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let (x, y) = (a.octets(), b.octets());
            if a.segments().first() == Some(&0xfe80) {
                x == y
            } else {
                x.get(..8) == y.get(..8)
            }
        }
        _ => false,
    }
}

fn kinds_of(ip: u8, proto: u32) -> Vec<PortKind> {
    PortKind::ALL
        .into_iter()
        .filter(|k| ip == dfs::IP_BOTH || ip == k.ip())
        .filter(|k| proto == dfs::PROTO_BOTH || proto == u32::from(k.proto()))
        .collect()
}

fn esp_tuples(filters: &[EspFilter]) -> Vec<Tuple> {
    filters
        .iter()
        .map(|f| Tuple {
            key: TupleKey::Spi(f.spi),
            version: f.version,
            proto: PROTO_ESP,
        })
        .collect()
}

impl<Q: Qmi, K: Kernel> Engine<Q, K> {
    pub fn new(cfg: Config, qmi: Q, kernel: K) -> Self {
        let mut links = Vec::new();
        let mut legs = Vec::new();
        for i in 0..cfg.links {
            links.push(LinkState {
                name: format!("{}{i}", cfg.link_prefix),
                mux: cfg.first_mux.saturating_add(i),
                states: None,
            });
            for ip in [Ip::V4, Ip::V6] {
                legs.push(Leg {
                    link: usize::from(i),
                    ip,
                    wds: None,
                    dfs: None,
                    step: Step::Idle,
                    txn: 0,
                    deadline: None,
                    tries: 0,
                    retry_at: None,
                    backoff: cfg.retry_ms,
                    pending: None,
                    installed: None,
                });
            }
        }
        let ports_leg = PortsLeg {
            client: None,
            step: Step::Idle,
            txn: 0,
            deadline: None,
            retry_at: None,
            backoff: cfg.retry_ms,
        };
        Engine {
            cfg,
            qmi,
            kernel,
            now: 0,
            modem_up: false,
            started_clients: false,
            links_retry_at: None,
            said_waiting: false,
            links,
            legs,
            ports_leg,
            store: Store::default(),
            encaps: Vec::new(),
            txn: 0,
            lines: VecDeque::new(),
            stored_state: Ledger::default().encode(),
            state_write_failed: false,
            said_stale: false,
            left: Ledger::default(),
            left_wlan: Vec::new(),
            left_retry_at: None,
        }
    }

    pub fn qmi_mut(&mut self) -> &mut Q {
        &mut self.qmi
    }

    pub fn kernel_mut(&mut self) -> &mut K {
        &mut self.kernel
    }

    pub fn take_lines(&mut self) -> Vec<String> {
        self.lines.drain(..).collect()
    }

    fn say(&mut self, line: String) {
        if self.lines.len() >= MAX_LINES {
            self.lines.pop_front();
        }
        self.lines.push_back(line);
    }

    fn who(&self, i: usize) -> String {
        let leg = &self.legs[i];
        format!("{} {}", self.links[leg.link].name, leg.ip.name())
    }

    fn next_txn(&mut self) -> u16 {
        self.txn = self.txn.wrapping_add(1);
        if self.txn == 0 {
            self.txn = 1;
        }
        self.txn
    }

    /// What the process does first: remove what an earlier instance left and hold the two ports of IMS.
    pub fn start(&mut self, now: u64) {
        self.now = now;
        self.stop_carrying();
        match self.kernel.load_state() {
            None => {}
            Some(bytes) => match Ledger::parse(&bytes) {
                None => self.say("state file: corrupt, dropped".into()),
                Some(old) => self.remove_ledger(&old),
            },
        }
        self.persist_force();
        self.reserve_well_known();
    }

    /// The reverse links go down and the module forgets its forwards before any policy goes. The module sends a
    /// packet of a reverse link out through the route and the policies of the moment and has no check of its own, so
    /// with a forward left and no policy, an inner packet would leave on Wi-Fi in the clear.
    fn stop_carrying(&mut self) {
        for i in 0..self.links.len() {
            let name = self.links[i].name.clone();
            let _ = self.kernel.set_link(&name, false);
        }
        match gone_ok(self.kernel.wlan(&WlanRequest::Flush)) {
            Ok(()) => self.left_wlan.clear(),
            Err(e) => {
                self.say(format!("rmnet_wlan flush failed, errno {}", e.errno()));
                self.left_wlan.clear();
                self.left_wlan.push(WlanRequest::Flush);
                self.retry_later();
            }
        }
    }

    fn retry_later(&mut self) {
        if self.left_retry_at.is_none() {
            self.left_retry_at = Some(self.now.saturating_add(self.cfg.retry_max_ms));
        }
    }

    fn left_has_room(&mut self) -> bool {
        let used = self.left.states.len() + self.left.policies.len() + self.left.rules.len();
        if used >= MAX_LEFT {
            self.say("the list of failed deletions is full, an entry is forgotten".into());
            return false;
        }
        self.retry_later();
        true
    }

    /// True: it is gone. Otherwise it is kept for a retry. It waits while a forward may be left in the module.
    fn remove_policy(&mut self, sel: &Selector, dir: Dir) -> bool {
        if self.left_wlan.is_empty() {
            match gone_ok(self.kernel.del_policy(sel, dir)) {
                Ok(()) => return true,
                Err(e) => self.say(format!("DELPOLICY {dir:?} failed, errno {}", e.errno())),
            }
        }
        if self.left_has_room() {
            self.left.policies.push((*sel, dir));
        }
        false
    }

    fn remove_state(&mut self, id: &SaId) -> bool {
        if self.left_wlan.is_empty() {
            match gone_ok(self.kernel.del_state(id)) {
                Ok(()) => return true,
                Err(e) => self.say(format!("DELSA failed, errno {}", e.errno())),
            }
        }
        if self.left_has_room() {
            self.left.states.push(*id);
        }
        false
    }

    fn remove_rule(&mut self, rule: &Rule) -> bool {
        match gone_ok(self.kernel.del_rule(rule)) {
            Ok(()) => true,
            Err(e) => {
                self.say(format!("rule delete failed, errno {}", e.errno()));
                if self.left_has_room() {
                    self.left.rules.push(*rule);
                }
                false
            }
        }
    }

    /// Try again what the kernel refused: the module first, then policies, states and rules.
    fn retry_left(&mut self) {
        self.left_retry_at = None;
        for req in std::mem::take(&mut self.left_wlan) {
            if gone_ok(self.kernel.wlan(&req)).is_err() {
                self.left_wlan.push(req);
            }
        }
        if !self.left_wlan.is_empty() {
            self.retry_later();
        }
        let old = std::mem::take(&mut self.left);
        for (sel, dir) in &old.policies {
            self.remove_policy(sel, *dir);
        }
        for id in &old.states {
            self.remove_state(id);
        }
        for rule in &old.rules {
            self.remove_rule(rule);
        }
        self.persist();
    }

    fn remove_ledger(&mut self, old: &Ledger) {
        let mut failed = 0u32;
        for (sel, dir) in &old.policies {
            failed += u32::from(!self.remove_policy(sel, *dir));
        }
        for id in &old.states {
            failed += u32::from(!self.remove_state(id));
        }
        for rule in &old.rules {
            failed += u32::from(!self.remove_rule(rule));
        }
        self.say(format!(
            "state file: removed {} policies, {} states, {} rules of an earlier instance, {failed} failed",
            old.policies.len(),
            old.states.len(),
            old.rules.len()
        ));
    }

    fn ledger(&self) -> Ledger {
        let mut l = Ledger::default();
        for link in &self.links {
            if let Some(ids) = &link.states {
                l.states.extend(ids.iter().copied());
            }
        }
        for leg in &self.legs {
            if let Some(inst) = &leg.installed {
                l.policies.extend(inst.policies.iter().copied());
                l.rules.extend(inst.rule);
            }
        }
        l.states.extend(self.left.states.iter().copied());
        l.policies.extend(self.left.policies.iter().copied());
        l.rules.extend(self.left.rules.iter().copied());
        l.rules.dedup();
        l
    }

    fn persist(&mut self) {
        let bytes = self.ledger().encode();
        if bytes != self.stored_state {
            self.write_state(bytes);
        }
    }

    fn persist_force(&mut self) {
        let bytes = self.ledger().encode();
        self.write_state(bytes);
    }

    fn write_state(&mut self, bytes: Vec<u8>) {
        match self.kernel.store_state(&bytes) {
            Ok(()) => {
                self.state_write_failed = false;
                self.stored_state = bytes;
            }
            Err(e) => {
                if !self.state_write_failed {
                    self.say(format!("state file: write failed, errno {}", e.errno()));
                }
                self.state_write_failed = true;
            }
        }
    }

    fn reserve_well_known(&mut self) {
        for port in ports::WELL_KNOWN {
            for kind in PortKind::ALL {
                if self
                    .store
                    .find(port, kind)
                    .is_some_and(|e| e.sock.is_some())
                {
                    continue;
                }
                match self.kernel.reserve_port(kind, port) {
                    Ok((sock, _)) => self.store.put(port, kind, Some(sock)),
                    Err(e) => {
                        self.say(format!(
                            "port {port} {kind:?}: bind failed, errno {}, the tuple stays",
                            e.errno()
                        ));
                        self.store.put(port, kind, None);
                    }
                }
            }
        }
        self.say(format!("ports: {} in the store", self.store.len()));
    }

    pub fn on_service(&mut self, now: u64, ev: ServiceEvent) {
        self.now = now;
        match ev {
            ServiceEvent::ModemDown => self.modem_down(),
            ServiceEvent::ModemUp => self.modem_up(),
        }
    }

    fn modem_down(&mut self) {
        self.say("modem services gone".into());
        self.modem_up = false;
        self.started_clients = false;
        self.links_retry_at = None;
        self.said_waiting = false;
        self.close_clients();
    }

    fn close_clients(&mut self) {
        for leg in &mut self.legs {
            for c in [leg.wds.take(), leg.dfs.take()].into_iter().flatten() {
                self.qmi.close_client(c);
            }
            leg.step = Step::Idle;
            leg.deadline = None;
            leg.retry_at = None;
            leg.tries = 0;
            leg.backoff = self.cfg.retry_ms;
            // the keys that waited here are zeroed with it
            leg.pending = None;
        }
        if let Some(c) = self.ports_leg.client.take() {
            self.qmi.close_client(c);
        }
        self.ports_leg.step = Step::Idle;
        self.ports_leg.deadline = None;
        self.ports_leg.retry_at = None;
        self.ports_leg.backoff = self.cfg.retry_ms;
    }

    fn modem_up(&mut self) {
        self.say("modem services up".into());
        self.modem_up = true;
        self.close_clients();
        self.remove_everything();
        self.bring_up();
    }

    /// A new modem knows nothing of what is installed: it all goes, by exact identifier, then the module is flushed
    /// and the sockets are closed. The two ports of IMS stay held.
    fn remove_everything(&mut self) {
        self.stop_carrying();
        let mut tunnels = 0u32;
        for i in 0..self.legs.len() {
            if self.legs[i].installed.is_some() {
                tunnels = tunnels.saturating_add(1);
                self.remove_family(i, false);
            }
        }
        self.say(format!("removed {tunnels} tunnels"));
        for e in std::mem::take(&mut self.encaps) {
            self.kernel.close_socket(e.sock);
        }
        for e in self.store.take_asked() {
            if let Some(s) = e.sock {
                self.kernel.close_socket(s);
            }
        }
        self.reserve_well_known();
        self.persist();
    }

    /// The device, the endpoint and the links, then the clients. Run again later while the device is not there.
    fn bring_up(&mut self) {
        self.links_retry_at = None;
        if !self.modem_up || self.started_clients {
            return;
        }
        let parent = self.cfg.parent.clone();
        let forward = self.cfg.forward_link.clone();
        let present = self
            .kernel
            .ifindex(&parent)
            .and_then(|_| self.kernel.ifindex(&forward));
        if let Err(e) = present {
            if !self.said_waiting {
                self.say(format!(
                    "waiting for {parent}, errno {}, the data daemon brings it up",
                    e.errno()
                ));
                self.said_waiting = true;
            }
            self.links_retry_at = Some(self.now.saturating_add(self.cfg.retry_ms));
            return;
        }
        let flags = self.cfg.rmnet_flags;
        for i in 0..self.links.len() {
            let (name, mux) = (self.links[i].name.clone(), self.links[i].mux);
            match dup_ok(self.kernel.create_link(&parent, &name, mux, flags)) {
                Ok(()) => self.say(format!("link {name}: mux {mux} present")),
                Err(e) => {
                    self.say(format!("link {name}: create failed, errno {}", e.errno()));
                    self.links_retry_at = Some(self.now.saturating_add(self.cfg.retry_ms));
                    return;
                }
            }
        }
        self.started_clients = true;
        for i in 0..self.legs.len() {
            self.start_leg(i);
        }
        self.start_ports();
    }

    fn start_leg(&mut self, i: usize) {
        self.legs[i].tries = 1;
        self.legs[i].retry_at = None;
        match self.qmi.open_client(wds::SERVICE) {
            Ok(c) => {
                self.legs[i].wds = Some(c);
                self.send_bind(i);
            }
            Err(_) => self.leg_failed(i, "no WDS client"),
        }
    }

    fn send_bind(&mut self, i: usize) {
        let (ip, mux) = (self.legs[i].ip, self.links[self.legs[i].link].mux);
        let ep = self.cfg.endpoint;
        self.send_step(i, Step::Bind, |t| {
            reverse::bind_client(t, ip.wds(), ep, mux)
        });
    }

    /// Send a request of the bring-up on the client its step belongs to.
    fn send_step(
        &mut self,
        i: usize,
        step: Step,
        build: impl FnOnce(u16) -> Result<Vec<u8>, QmiParseError>,
    ) {
        let txn = self.next_txn();
        let client = match step {
            Step::DfsBind | Step::DfsRegister => self.legs[i].dfs,
            _ => self.legs[i].wds,
        };
        let sent = client.is_some_and(|c| {
            build(txn)
                .ok()
                .is_some_and(|b| self.qmi.send(c, &b).is_ok())
        });
        if !sent {
            return self.leg_failed(i, step.name());
        }
        let leg = &mut self.legs[i];
        leg.step = step;
        leg.txn = txn;
        leg.deadline = Some(self.now.saturating_add(self.cfg.request_timeout_ms));
        leg.retry_at = None;
    }

    fn leg_failed(&mut self, i: usize, why: &str) {
        let who = self.who(i);
        let backoff = self.legs[i].backoff;
        self.say(format!(
            "{who}: bring-up failed at {why}, again in {backoff} ms"
        ));
        let leg = &mut self.legs[i];
        for c in [leg.wds.take(), leg.dfs.take()].into_iter().flatten() {
            self.qmi.close_client(c);
        }
        leg.step = Step::Failed;
        leg.deadline = None;
        leg.retry_at = Some(self.now.saturating_add(backoff));
        leg.backoff = backoff.saturating_mul(2).min(self.cfg.retry_max_ms);
    }

    fn start_ports(&mut self) {
        self.ports_leg.retry_at = None;
        match self.qmi.open_client(dfs::SERVICE) {
            Ok(c) => {
                self.ports_leg.client = Some(c);
                let (ep, mux) = (self.cfg.endpoint, self.cfg.ports_mux);
                self.send_ports(Step::DfsBind, |t| {
                    dfs::bind_client(t, Ip::V4.number(), ep, mux)
                });
            }
            Err(_) => self.ports_failed("no DFS client"),
        }
    }

    fn send_ports(
        &mut self,
        step: Step,
        build: impl FnOnce(u16) -> Result<Vec<u8>, QmiParseError>,
    ) {
        let txn = self.next_txn();
        let sent = self.ports_leg.client.is_some_and(|c| {
            build(txn)
                .ok()
                .is_some_and(|b| self.qmi.send(c, &b).is_ok())
        });
        if !sent {
            return self.ports_failed(step.name());
        }
        self.ports_leg.step = step;
        self.ports_leg.txn = txn;
        self.ports_leg.deadline = Some(self.now.saturating_add(self.cfg.request_timeout_ms));
    }

    fn ports_failed(&mut self, why: &str) {
        let backoff = self.ports_leg.backoff;
        self.say(format!(
            "ports client: failed at {why}, again in {backoff} ms"
        ));
        if let Some(c) = self.ports_leg.client.take() {
            self.qmi.close_client(c);
        }
        self.ports_leg.step = Step::Failed;
        self.ports_leg.deadline = None;
        self.ports_leg.retry_at = Some(self.now.saturating_add(backoff));
        self.ports_leg.backoff = backoff.saturating_mul(2).min(self.cfg.retry_max_ms);
    }

    fn owner(&self, client: ClientId) -> Option<Owner> {
        if self.ports_leg.client == Some(client) {
            return Some(Owner::Ports);
        }
        self.legs.iter().enumerate().find_map(|(i, l)| {
            if l.wds == Some(client) {
                Some(Owner::Wds(i))
            } else if l.dfs == Some(client) {
                Some(Owner::Dfs(i))
            } else {
                None
            }
        })
    }

    /// One datagram from the modem. It may hold keys, so it is zeroed whatever became of it.
    pub fn on_qmi(&mut self, now: u64, client: ClientId, bytes: &mut [u8]) {
        self.now = now;
        self.dispatch(client, bytes);
        wipe(bytes);
    }

    fn dispatch(&mut self, client: ClientId, bytes: &[u8]) {
        let Ok(f) = Frame::parse_bounded(bytes, MAX_DATAGRAM) else {
            self.say("modem: a datagram that is no QMI message".into());
            return;
        };
        let Some(owner) = self.owner(client) else {
            return;
        };
        match (owner, f.kind) {
            (Owner::Wds(i), Kind::Indication) => match f.id {
                reverse::id::REVERSE_IND => self.on_reverse(i, &f),
                reverse::id::IPSEC_SA => self.on_sa_segment(i, &f),
                _ => {}
            },
            (Owner::Wds(i), Kind::Response) => match f.id {
                reverse::id::REVERSE_ANSWER => self.on_answer_result(i, &f),
                reverse::id::IPSEC_SA => self.on_sa_response(i, &f),
                _ => self.on_leg_response(i, &f),
            },
            (Owner::Dfs(i), Kind::Response) => match f.id {
                dfs::id::GET_FILTERS => self.on_filters_response(i, &f),
                _ => self.on_leg_response(i, &f),
            },
            (Owner::Ports, Kind::Response) => self.on_ports_response(&f),
            (Owner::Dfs(_) | Owner::Ports, Kind::Indication) => self.on_dfs_indication(client, &f),
            (_, Kind::Request) => {}
        }
    }

    fn on_leg_response(&mut self, i: usize, f: &Frame<'_>) {
        let step = self.legs[i].step;
        if step.answers() != Some(f.id) || self.legs[i].txn != f.txn {
            if !self.said_stale {
                self.say("modem: an answer that nothing waits for".into());
                self.said_stale = true;
            }
            return;
        }
        let status = f.status().unwrap_or(QmiStatus {
            result: 1,
            error: 0,
        });
        self.legs[i].deadline = None;
        if status.is_ok() {
            self.step_done(i, step);
        } else if step == Step::Bind {
            self.bind_refused(i, Some(status.error));
        } else {
            let why = format!("{}, QMI error {:#x}", step.name(), status.error);
            self.leg_failed(i, &why);
        }
    }

    /// Bind refused or unanswered. It is tried again a few times, and the older bind comes after that or at once
    /// when the modem says it does not know the message.
    fn bind_refused(&mut self, i: usize, error: Option<u16>) {
        let who = self.who(i);
        let tries = self.legs[i].tries;
        match error {
            Some(e) => self.say(format!("{who}: bind 0x118 refused, QMI error {e:#x}")),
            None => self.say(format!("{who}: bind 0x118 not answered")),
        }
        if error == Some(ERR_NO_REVERSE_BIND) || tries >= self.cfg.bind_tries {
            let (ep, mux) = (self.cfg.endpoint, self.links[self.legs[i].link].mux);
            self.say(format!("{who}: using the older bind"));
            self.send_step(i, Step::LegacyBind, |t| {
                reverse::bind_mux_reverse(t, ep, mux)
            });
        } else {
            let leg = &mut self.legs[i];
            leg.tries = tries.saturating_add(1);
            leg.deadline = None;
            leg.retry_at = Some(self.now.saturating_add(self.cfg.bind_retry_ms));
        }
    }

    fn step_done(&mut self, i: usize, step: Step) {
        match step {
            Step::Bind | Step::SetFamily => self.send_step(i, Step::Register, reverse::register),
            Step::LegacyBind => {
                let ip = self.legs[i].ip;
                self.send_step(i, Step::SetFamily, |t| wds::set_ip_family(t, ip.wds()));
            }
            Step::Register => match self.qmi.open_client(dfs::SERVICE) {
                Ok(c) => {
                    self.legs[i].dfs = Some(c);
                    let (ip, ep) = (self.legs[i].ip, self.cfg.endpoint);
                    let mux = self.links[self.legs[i].link].mux;
                    self.send_step(i, Step::DfsBind, |t| {
                        dfs::bind_client(t, ip.number(), ep, mux)
                    });
                }
                Err(_) => self.leg_failed(i, "no DFS client"),
            },
            Step::DfsBind => self.send_step(i, Step::DfsRegister, dfs::register_link),
            Step::DfsRegister => {
                let leg = &mut self.legs[i];
                leg.step = Step::Ready;
                leg.deadline = None;
                leg.backoff = self.cfg.retry_ms;
                let who = self.who(i);
                self.say(format!("{who}: ready"));
            }
            Step::Idle | Step::Ready | Step::Failed => {}
        }
    }

    fn on_ports_response(&mut self, f: &Frame<'_>) {
        let ok = f.status().is_ok_and(|s| s.is_ok());
        if f.id == dfs::id::PORTS_ANSWER {
            if !ok {
                self.say("ports: the modem refused the answer 0x33".into());
            }
            return;
        }
        let step = self.ports_leg.step;
        if step.answers() != Some(f.id) || self.ports_leg.txn != f.txn {
            return;
        }
        self.ports_leg.deadline = None;
        if !ok {
            return self.ports_failed(step.name());
        }
        match step {
            Step::DfsBind => self.send_ports(Step::DfsRegister, dfs::register_ports),
            _ => {
                self.ports_leg.step = Step::Ready;
                self.ports_leg.backoff = self.cfg.retry_ms;
                self.say("ports client: ready".into());
            }
        }
    }

    fn answer(&mut self, i: usize, tid: u32, ok: bool) {
        let who = self.who(i);
        let txn = self.next_txn();
        let sent = self.legs[i].wds.is_some_and(|c| {
            reverse::reverse_answer(txn, ok, tid)
                .ok()
                .is_some_and(|b| self.qmi.send(c, &b).is_ok())
        });
        if sent {
            self.say(format!("{who}: answered 0x90 with {}", u8::from(ok)));
        } else {
            self.say(format!("{who}: the answer 0x90 could not be sent"));
        }
    }

    fn on_answer_result(&mut self, i: usize, f: &Frame<'_>) {
        if let Ok(s) = f.status() {
            if !s.is_ok() {
                let who = self.who(i);
                self.say(format!(
                    "{who}: the modem refused the answer 0x90, QMI error {:#x}",
                    s.error
                ));
            }
        }
    }

    fn on_reverse(&mut self, i: usize, f: &Frame<'_>) {
        let who = self.who(i);
        let ind = match reverse::parse_reverse_ind(f) {
            Ok(ind) => ind,
            Err(_) => {
                self.say(format!("{who}: 0x8e is malformed"));
                if let Some(tid) = reverse::reverse_tid(f) {
                    self.answer(i, tid, false);
                }
                return;
            }
        };
        match ind.status {
            STATUS_CONNECTED => self.on_connect(i, &ind),
            STATUS_DISCONNECTED => self.on_disconnect(i, &ind),
            other => {
                self.say(format!("{who}: 0x8e with status {other}"));
                self.answer(i, ind.tid, false);
            }
        }
    }

    fn refuse(&mut self, i: usize, tid: u32, why: &str) {
        let who = self.who(i);
        self.say(format!("{who}: connect refused: {why}"));
        self.answer(i, tid, false);
    }

    fn on_connect(&mut self, i: usize, ind: &ReverseInd) {
        let who = self.who(i);
        let Some(t) = ind.tech else {
            return self.refuse(i, ind.tid, "no technology");
        };
        self.say(format!("{who}: 0x8e connected, technology {t:#06x}"));
        match t {
            tech::LOCAL_BREAKOUT | tech::IWLAN_S2B => {}
            tech::CIWLAN => return self.refuse(i, ind.tid, "C-IWLAN is out of scope"),
            _ => return self.refuse(i, ind.tid, "unknown technology"),
        }
        let Some(addr) = ind.address().filter(|a| Ip::of(*a) == self.legs[i].ip) else {
            return self.refuse(i, ind.tid, "no inner address of this family");
        };
        if !usable_address(addr) {
            return self.refuse(
                i,
                ind.tid,
                "the inner address is not a usable unicast address",
            );
        }
        // the indication proves the registration, and local breakout does not use the DFS client
        let ready = match self.legs[i].step {
            Step::Ready => true,
            Step::Register | Step::DfsBind | Step::DfsRegister => t == tech::LOCAL_BREAKOUT,
            _ => false,
        };
        if !ready {
            return self.refuse(i, ind.tid, "the client is not ready");
        }
        self.fail_pending(i, "a new connect came first");
        if self.legs[i].installed.is_some() {
            self.say(format!(
                "{who}: connect over a live tunnel, the old one goes first"
            ));
            self.remove_family(i, true);
        }
        if t == tech::LOCAL_BREAKOUT {
            return self.finish_connect(i, ind.tid, t, addr, None, &[]);
        }
        let txn = self.next_txn();
        let sent = self.legs[i].wds.is_some_and(|c| {
            reverse::ipsec_sa_request(txn)
                .ok()
                .is_some_and(|b| self.qmi.send(c, &b).is_ok())
        });
        if !sent {
            return self.refuse(i, ind.tid, "0x11c could not be sent");
        }
        self.say(format!("{who}: asked for the ESP states, 0x11c"));
        self.legs[i].pending = Some(Box::new(Pending {
            tid: ind.tid,
            tech: t,
            addr,
            phase: Phase::WaitSa,
            txn,
            deadline: self.now.saturating_add(self.cfg.sa_wait_ms),
            assembly: Assembly::default(),
            sa: None,
        }));
    }

    fn fail_pending(&mut self, i: usize, why: &str) {
        if let Some(p) = self.legs[i].pending.take() {
            let who = self.who(i);
            self.say(format!("{who}: connect failed: {why}"));
            self.answer(i, p.tid, false);
        }
    }

    fn on_sa_response(&mut self, i: usize, f: &Frame<'_>) {
        let waiting = self.legs[i]
            .pending
            .as_ref()
            .is_some_and(|p| p.phase == Phase::WaitSa && p.txn == f.txn);
        if !waiting {
            return;
        }
        let Ok(id) = reverse::parse_ipsec_sa_response(f) else {
            let why = format!(
                "0x11c refused, QMI error {:#x}",
                f.status().map_or(0, |s| s.error)
            );
            return self.fail_pending(i, &why);
        };
        let done = self.legs[i].pending.as_mut().is_some_and(|p| {
            p.assembly.expect(id);
            p.assembly.is_complete()
        });
        if done {
            self.sa_complete(i);
        }
    }

    fn on_sa_segment(&mut self, i: usize, f: &Frame<'_>) {
        let who = self.who(i);
        let waiting = self.legs[i]
            .pending
            .as_ref()
            .is_some_and(|p| p.phase == Phase::WaitSa);
        if !waiting {
            self.say(format!(
                "{who}: 0x11c indication with no connect waiting, left alone"
            ));
            return;
        }
        let Ok(seg) = reverse::parse_sa_segment(f) else {
            self.say(format!("{who}: 0x11c indication is malformed"));
            return;
        };
        let added = self.legs[i]
            .pending
            .as_mut()
            .map_or(Added::Dropped, |p| p.assembly.add(seg));
        match added {
            Added::Waiting => self.say(format!("{who}: 0x11c segment taken")),
            Added::Dropped => self.say(format!(
                "{who}: 0x11c segment does not fit, the segments so far are dropped"
            )),
            Added::Complete => self.sa_complete(i),
        }
    }

    fn sa_complete(&mut self, i: usize) {
        let who = self.who(i);
        let Some(fields) = self.legs[i]
            .pending
            .as_mut()
            .map(|p| p.assembly.take_fields())
        else {
            return;
        };
        let sa = match IpsecSa::from_fields(fields) {
            Ok(sa) => sa,
            Err(what) => {
                let why = format!("the ESP states have a bad or missing {what}");
                return self.fail_pending(i, &why);
            }
        };
        self.say(format!(
            "{who}: ESP states complete with {} and {}, asking for the filters, DFS 0x30",
            sa.crypt_name, sa.auth_name
        ));
        let txn = self.next_txn();
        let sent = self.legs[i].dfs.is_some_and(|c| {
            dfs::get_filters(txn)
                .ok()
                .is_some_and(|b| self.qmi.send(c, &b).is_ok())
        });
        if !sent {
            return self.fail_pending(i, "DFS 0x30 could not be sent");
        }
        let deadline = self.now.saturating_add(self.cfg.request_timeout_ms);
        if let Some(p) = self.legs[i].pending.as_mut() {
            p.sa = Some(sa);
            p.phase = Phase::WaitFilters;
            p.txn = txn;
            p.deadline = deadline;
        }
    }

    fn on_filters_response(&mut self, i: usize, f: &Frame<'_>) {
        let waiting = self.legs[i]
            .pending
            .as_ref()
            .is_some_and(|p| p.phase == Phase::WaitFilters && p.txn == f.txn);
        if !waiting {
            return;
        }
        let filters = match dfs::parse_get_filters(f) {
            Ok(list) => list,
            Err(_) => return self.fail_pending(i, "DFS 0x30 refused"),
        };
        let Some(p) = self.legs[i].pending.take() else {
            return;
        };
        let Pending {
            tid,
            tech,
            addr,
            sa,
            ..
        } = *p;
        self.finish_connect(i, tid, tech, addr, sa.as_ref(), &filters);
    }

    fn finish_connect(
        &mut self,
        i: usize,
        tid: u32,
        t: u16,
        addr: IpAddr,
        sa: Option<&IpsecSa>,
        filters: &[EspFilter],
    ) {
        let who = self.who(i);
        match self.install(i, t, addr, sa, filters) {
            Ok(()) => {
                self.say(format!("{who}: tunnel up, technology {t:#06x}"));
                self.answer(i, tid, true);
            }
            Err(why) => {
                self.say(format!("{who}: connect failed at {why}, rolled back"));
                self.answer(i, tid, false);
            }
        }
    }

    fn find_transport(&mut self, local: IpAddr) -> Result<(String, i32), String> {
        let addrs = self
            .kernel
            .addresses(Ip::of(local))
            .map_err(|e| format!("the address dump, errno {}", e.errno()))?;
        for found in addrs.iter().filter(|a| same_interface(local, a.addr)) {
            let name = self
                .kernel
                .if_name(found.index)
                .map_err(|e| format!("the name of the transport, errno {}", e.errno()))?;
            if name.starts_with(TRANSPORT_PREFIX) {
                return Ok((name, found.index));
            }
        }
        Err(format!(
            "finding the transport, no Wi-Fi interface of {} has the local address",
            addrs.len()
        ))
    }

    /// The inner address of a tunnel may only be on a forward link. On the transport or anywhere else, the module
    /// and the policies would take packets of this phone for packets of the modem.
    fn check_inner(&mut self, inner: IpAddr) -> Result<(), String> {
        let addrs = self
            .kernel
            .addresses(Ip::of(inner))
            .map_err(|e| format!("the address dump, errno {}", e.errno()))?;
        for found in addrs.iter().filter(|a| same_interface(inner, a.addr)) {
            let name = self
                .kernel
                .if_name(found.index)
                .map_err(|e| format!("the name of an interface, errno {}", e.errno()))?;
            if !name.starts_with(INNER_ADDRESS_PREFIX) {
                return Err("the check of the inner address, it is on another interface".into());
            }
        }
        Ok(())
    }

    fn entries_on_link(&self, link: usize) -> usize {
        self.legs
            .iter()
            .filter(|l| l.link == link && l.installed.is_some())
            .count()
    }

    /// Tunnels of S2B and local breakout on this transport, which share the device slot of the module.
    fn transport_refs(&self, transport: &str) -> usize {
        self.legs
            .iter()
            .filter_map(|l| l.installed.as_ref())
            .filter(|t| {
                t.transport == transport && matches!(t.net, NetType::S2b | NetType::LocalBreakout)
            })
            .count()
    }

    fn install(
        &mut self,
        i: usize,
        t: u16,
        addr: IpAddr,
        sa: Option<&IpsecSa>,
        filters: &[EspFilter],
    ) -> Result<(), String> {
        if !self.left.is_empty() || !self.left_wlan.is_empty() {
            self.retry_left();
        }
        if !self.left_wlan.is_empty() {
            return Err("rmnet_wlan, it may still hold an old forward".into());
        }
        let local = sa.map_or(addr, |s| s.local);
        let (transport, index) = self.find_transport(local)?;
        if sa.is_some() {
            self.check_inner(addr)?;
        }
        let who = self.who(i);
        self.say(format!("{who}: transport {transport}"));
        let mut undo = Vec::new();
        let result = self.install_steps(i, t, addr, sa, filters, transport, index, &mut undo);
        if result.is_err() {
            let steps = undo.len();
            for u in undo.into_iter().rev() {
                self.run_undo(u);
            }
            self.legs[i].installed = None;
            self.say(format!("{who}: rollback of {steps} steps"));
        }
        self.persist();
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn install_steps(
        &mut self,
        i: usize,
        t: u16,
        addr: IpAddr,
        sa: Option<&IpsecSa>,
        filters: &[EspFilter],
        transport: String,
        index: i32,
        undo: &mut Vec<Undo>,
    ) -> Result<(), String> {
        let link = self.legs[i].link;
        let ip = self.legs[i].ip;
        let name = self.links[link].name.clone();
        let net = net_type(t);
        let policies = sa.map_or(Vec::new(), |_| {
            let source = Selector {
                addr,
                prefix: ip.selector_prefix(),
                side: Side::Source,
            };
            let destination = Selector {
                side: Side::Destination,
                ..source
            };
            vec![
                (source, Dir::Out),
                (destination, Dir::In),
                (destination, Dir::Fwd),
            ]
        });
        let rule = sa.map(|s| Rule {
            family: Ip::of(s.local).af(),
            mark: S2B_TX_MARK,
            mask: RULE_MASK,
            table: u32::try_from(index.saturating_add(RULE_TABLE_BASE)).unwrap_or(0),
        });
        // in the table before the first kernel call, and with a state of the first family in the file
        self.legs[i].installed = Some(Installed {
            tech: t,
            net,
            addr,
            transport: transport.clone(),
            policies: policies.clone(),
            rule,
        });
        let first_on_link = self.entries_on_link(link) == 1;
        if first_on_link {
            self.kernel
                .set_link(&name, true)
                .map_err(|e| format!("link up, errno {}", e.errno()))?;
            undo.push(Undo::LinkDown(link));
            if let Err(e) = self.kernel.set_reverse_sysctls(&name) {
                self.say(format!("{name}: sysctls failed, errno {}", e.errno()));
            }
        }
        if let Some(s) = sa {
            if self.links[link].states.is_none() {
                self.links[link].states = Some([s.tx_id(), s.rx_id()]);
                undo.push(Undo::States(link));
                self.persist();
                if self.state_write_failed {
                    return Err("the state file".into());
                }
                self.kernel
                    .add_state(&s.tx_state(Some(S2B_TX_MARK)))
                    .map_err(|e| format!("NEWSA TX, errno {}", e.errno()))?;
                undo.push(Undo::State(s.tx_id()));
                self.kernel
                    .add_state(&s.rx_state(None))
                    .map_err(|e| format!("NEWSA RX, errno {}", e.errno()))?;
                undo.push(Undo::State(s.rx_id()));
                self.say(format!("{name}: states in"));
            } else {
                self.persist();
                if self.state_write_failed {
                    return Err("the state file".into());
                }
                if self.links[link].states != Some([s.tx_id(), s.rx_id()]) {
                    return Err("the states, the other family of this link has others".into());
                }
                self.say(format!("{name}: states shared with the other family"));
            }
            for (sel, dir) in &policies {
                let tmpl = Tmpl {
                    id: match dir {
                        Dir::Out => s.tx_id(),
                        Dir::In | Dir::Fwd => s.rx_id(),
                    },
                    mode: s.mode,
                };
                self.kernel
                    .add_policy(sel, *dir, &tmpl)
                    .map_err(|e| format!("NEWPOLICY {dir:?}, errno {}", e.errno()))?;
                undo.push(Undo::Policy(*sel, *dir));
            }
            self.say(format!("{name} {}: policies in", ip.name()));
            if let Some(port) = s.encap_port {
                self.ensure_encap(s.local, s.remote, port)?;
            }
        }
        let tuples = self.store.tuples();
        if !tuples.is_empty() {
            dup_ok(self.kernel.wlan(&WlanRequest::AddTuples(tuples)))
                .map_err(|e| format!("genl 1, errno {}", e.errno()))?;
        }
        let forward_add = WlanRequest::AddForward {
            net,
            device: name.clone(),
            addr,
        };
        dup_ok(self.kernel.wlan(&forward_add))
            .map_err(|e| format!("genl 5, errno {}", e.errno()))?;
        undo.push(Undo::Forward(WlanRequest::DelForward {
            net,
            device: name.clone(),
            addr,
        }));
        if self.transport_refs(&transport) == 1 {
            self.kernel
                .wlan(&WlanRequest::SetDevice {
                    net,
                    device: transport.clone(),
                })
                .map_err(|e| format!("genl 3, errno {}", e.errno()))?;
            undo.push(Undo::Device(WlanRequest::UnsetDevice {
                net,
                device: transport.clone(),
            }));
        }
        self.say(format!("{name} {}: rmnet_wlan set", ip.name()));
        if let Some(r) = rule {
            if let Err(e) = dup_ok(self.kernel.add_rule(&r)) {
                self.say(format!(
                    "{name}: rule 9999 failed, errno {}, going on",
                    e.errno()
                ));
                if let Some(inst) = self.legs[i].installed.as_mut() {
                    inst.rule = None;
                }
            }
        }
        if !filters.is_empty() {
            let tuples = esp_tuples(filters);
            self.say(format!("{name}: {} ESP filters", tuples.len()));
            if let Err(e) = dup_ok(self.kernel.wlan(&WlanRequest::AddTuples(tuples))) {
                self.say(format!(
                    "{name}: ESP filter tuples failed, errno {}",
                    e.errno()
                ));
            }
        }
        Ok(())
    }

    fn run_undo(&mut self, u: Undo) {
        match u {
            Undo::LinkDown(link) => {
                let name = self.links[link].name.clone();
                let _ = self.kernel.set_link(&name, false);
            }
            Undo::States(link) => self.links[link].states = None,
            Undo::State(id) => {
                self.remove_state(&id);
            }
            Undo::Policy(sel, dir) => {
                self.remove_policy(&sel, dir);
            }
            Undo::Forward(req) | Undo::Device(req) => {
                self.teardown_wlan(&req);
            }
        }
    }

    fn ensure_encap(&mut self, local: IpAddr, remote: IpAddr, port: [u8; 2]) -> Result<(), String> {
        let number = u16::from_be_bytes(port);
        let known = self
            .encaps
            .iter()
            .any(|e| e.port == number && e.local == local && e.remote == remote);
        if !known {
            if self.encaps.len() >= MAX_ENCAP && !self.evict_encap() {
                return Err("the UDP socket, all are in use".into());
            }
            let sock = self
                .kernel
                .open_encap(local, remote, number)
                .map_err(|e| format!("the UDP socket, errno {}", e.errno()))?;
            self.encaps.push(EncapSock {
                port: number,
                local,
                remote,
                sock,
            });
            self.say(format!(
                "UDP encapsulation socket open, {} now",
                self.encaps.len()
            ));
        }
        // the module answers EEXIST for a port it has, which is fine, and anything else only costs a log line
        for req in [
            WlanRequest::SetEncapPort(port),
            WlanRequest::EncapPass(port),
        ] {
            if let Err(e) = dup_ok(self.kernel.wlan(&req)) {
                self.say(format!("genl {} failed, errno {}", req.number(), e.errno()));
            }
        }
        Ok(())
    }

    /// Close the oldest socket no tunnel uses. A socket stays after its tunnel, for a modem that comes back.
    fn evict_encap(&mut self) -> bool {
        let used = |e: &EncapSock, links: &[LinkState]| {
            links.iter().any(|l| {
                l.states
                    .is_some_and(|[tx, _]| tx.src == e.local && tx.dst == e.remote)
            })
        };
        let Some(at) = self.encaps.iter().position(|e| !used(e, &self.links)) else {
            return false;
        };
        let e = self.encaps.remove(at);
        self.kernel.close_socket(e.sock);
        true
    }

    fn on_disconnect(&mut self, i: usize, ind: &ReverseInd) {
        let who = self.who(i);
        self.say(format!("{who}: 0x8e disconnected"));
        self.fail_pending(i, "a disconnect came first");
        if self.legs[i].installed.is_some() {
            let ok = self.remove_family(i, true);
            self.say(format!("{who}: tunnel down, clean: {ok}"));
            self.answer(i, ind.tid, ok);
        } else {
            let known = ind.tech.is_some_and(|t| {
                matches!(t, tech::LOCAL_BREAKOUT | tech::IWLAN_S2B | tech::CIWLAN)
            });
            self.answer(i, ind.tid, known);
        }
    }

    /// Take one family of a link out of the kernel, in reverse order. True: every step worked or found it gone
    /// already. With `module` false, `rmnet_wlan` is left to the flush that follows.
    fn remove_family(&mut self, i: usize, module: bool) -> bool {
        let Some(inst) = self.legs[i].installed.clone() else {
            return true;
        };
        let link = self.legs[i].link;
        let name = self.links[link].name.clone();
        let mut ok = true;
        if let Some(rule) = inst.rule {
            let others = self
                .legs
                .iter()
                .enumerate()
                .filter(|(n, _)| *n != i)
                .filter_map(|(_, l)| l.installed.as_ref())
                .any(|o| o.rule == Some(rule));
            if !others {
                self.remove_rule(&rule);
            }
        }
        if module {
            if self.transport_refs(&inst.transport) == 1 {
                let req = WlanRequest::UnsetDevice {
                    net: inst.net,
                    device: inst.transport.clone(),
                };
                ok &= self.teardown_wlan(&req);
            }
            let req = WlanRequest::DelForward {
                net: inst.net,
                device: name.clone(),
                addr: inst.addr,
            };
            ok &= self.teardown_wlan(&req);
        }
        for wanted in [Dir::In, Dir::Fwd, Dir::Out] {
            for (sel, dir) in inst.policies.iter().filter(|(_, d)| *d == wanted) {
                ok &= self.remove_policy(sel, *dir);
            }
        }
        let last = self.entries_on_link(link) == 1;
        self.legs[i].installed = None;
        if last {
            if let Some(ids) = self.links[link].states.take() {
                for id in &ids {
                    ok &= self.remove_state(id);
                }
            }
            if let Err(e) = gone_ok(self.kernel.set_link(&name, false)) {
                self.say(format!("{name}: link down failed, errno {}", e.errno()));
                ok = false;
            }
        }
        self.persist();
        ok
    }

    fn teardown_wlan(&mut self, req: &WlanRequest) -> bool {
        match gone_ok(self.kernel.wlan(req)) {
            Ok(()) => true,
            Err(e) => {
                self.say(format!("genl {} failed, errno {}", req.number(), e.errno()));
                if self.left_wlan.len() < MAX_LEFT {
                    self.left_wlan.push(req.clone());
                }
                self.retry_later();
                false
            }
        }
    }

    fn on_dfs_indication(&mut self, client: ClientId, f: &Frame<'_>) {
        match f.id {
            dfs::id::FILTERS_CHANGED => self.on_filters_changed(f),
            dfs::id::PORTS_WANTED => match dfs::parse_ports_wanted(f) {
                Ok(p) => self.on_ports_wanted(client, &p),
                Err(_) => self.say("ports: 0x32 is malformed".into()),
            },
            dfs::id::PORTS_RELEASED => match dfs::parse_ports_released(f) {
                Ok(hashes) => self.on_ports_released(&hashes),
                Err(_) => self.say("ports: 0x34 is malformed".into()),
            },
            dfs::id::ENCAP_PORT => match dfs::parse_encap_port(f) {
                Ok((hash, value)) => self.on_encap_port(hash, value),
                Err(_) => self.say("ports: 0x35 is malformed".into()),
            },
            _ => {}
        }
    }

    fn on_filters_changed(&mut self, f: &Frame<'_>) {
        let (action, filters) = match dfs::parse_filters_changed(f) {
            Ok(v) => v,
            Err(_) => return self.say("filters: 0x31 is malformed".into()),
        };
        self.say(format!(
            "filters: 0x31 action {action}, {} ESP",
            filters.len()
        ));
        if filters.is_empty() {
            return;
        }
        let tuples = esp_tuples(&filters);
        let req = match action {
            dfs::FILTER_ADD => WlanRequest::AddTuples(tuples),
            dfs::FILTER_DELETE => WlanRequest::DelTuples(tuples),
            _ => return,
        };
        if let Err(e) = dup_ok(gone_ok(self.kernel.wlan(&req))) {
            self.say(format!("genl {} failed, errno {}", req.number(), e.errno()));
        }
    }

    /// Hold one port. The answer is the port, and whether it is new.
    fn reserve(
        &mut self,
        kind: PortKind,
        port: u16,
        range: Option<(u32, u16, u16)>,
    ) -> Option<(u16, bool)> {
        if port != 0 && self.store.find(port, kind).is_some() {
            return Some((port, false));
        }
        if !self.store.has_room() {
            return None;
        }
        let taken = match (port, range) {
            (0, Some((_, min, max))) => self.pick_in_range(kind, min, max),
            _ => match self.kernel.reserve_port(kind, port) {
                Ok(found) => Some(found),
                Err(e) => {
                    self.say(format!(
                        "ports: port {port} {kind:?}: bind failed, errno {}",
                        e.errno()
                    ));
                    None
                }
            },
        };
        let (sock, got) = taken?;
        self.store.put(got, kind, Some(sock));
        Some((got, true))
    }

    fn pick_in_range(&mut self, kind: PortKind, min: u16, max: u16) -> Option<(SockHandle, u16)> {
        let span = u32::from(max)
            .saturating_sub(u32::from(min))
            .saturating_add(1);
        for _ in 0..PICK_TRIES {
            let offset = self.kernel.random().checked_rem(span).unwrap_or(0);
            let port = u32::from(min).saturating_add(offset);
            let port = u16::try_from(port).ok()?;
            if self.store.find(port, kind).is_some() {
                continue;
            }
            if let Ok(found) = self.kernel.reserve_port(kind, port) {
                return Some(found);
            }
        }
        None
    }

    fn on_ports_wanted(&mut self, client: ClientId, p: &PortsWanted) {
        let bad_range = p.range.is_some_and(|(_, min, max)| min >= max);
        let symmetric = p
            .range
            .is_some_and(|(prop, _, _)| prop == PROPERTY_SYMMETRIC);
        let mut answers = Vec::new();
        let mut new_ports = Vec::new();
        // the answer ends at the first port that cannot be had, with no entry for it and no status
        let mut failed = bad_range;
        'wishes: for wish in p.wishes.iter().filter(|_| !bad_range) {
            let mut same_port = 0u16;
            for kind in kinds_of(wish.ip, wish.proto) {
                if answers.len() >= dfs::MAX_PORT_ANSWERS {
                    break 'wishes;
                }
                let ask = if wish.port != 0 { wish.port } else { same_port };
                let Some((port, new)) = self.reserve(kind, ask, p.range) else {
                    failed = true;
                    break 'wishes;
                };
                if new {
                    new_ports.push((port, kind));
                }
                if symmetric && wish.port == 0 {
                    same_port = port;
                }
                answers.push(PortAnswer {
                    status: 0,
                    kind,
                    port,
                    chosen: wish.port == 0,
                });
            }
        }
        let asked: Vec<u16> = p
            .wishes
            .iter()
            .map(|w| w.port)
            .filter(|n| *n != 0)
            .take(MAX_PORTS_SAID)
            .collect();
        self.say(format!(
            "ports: 0x32 with {} entries, {} answers, stopped: {failed}, {} in the store, first ports {asked:?}, range {:?}",
            p.wishes.len(),
            answers.len(),
            self.store.len(),
            p.range
        ));
        if !new_ports.is_empty() {
            let tuples = new_ports.iter().map(|(n, k)| tuple_of(*n, *k)).collect();
            if let Err(e) = dup_ok(self.kernel.wlan(&WlanRequest::AddTuples(tuples))) {
                self.say(format!("genl 1 failed, errno {}", e.errno()));
            }
        }
        let txn = self.next_txn();
        let sent = dfs::ports_answer(txn, &answers, p.transaction)
            .ok()
            .is_some_and(|b| self.qmi.send(client, &b).is_ok());
        if sent {
            return;
        }
        self.say("ports: the answer 0x33 could not be sent, the new ports go".into());
        let tuples: Vec<Tuple> = new_ports.iter().map(|(n, k)| tuple_of(*n, *k)).collect();
        for (n, k) in new_ports {
            if let Some(s) = self.store.remove(n, k).and_then(|e| e.sock) {
                self.kernel.close_socket(s);
            }
        }
        if !tuples.is_empty() {
            let _ = self.kernel.wlan(&WlanRequest::DelTuples(tuples));
        }
    }

    fn on_ports_released(&mut self, hashes: &[u32]) {
        let mut tuples = Vec::new();
        for hash in hashes {
            let Some((port, kind)) = dfs::port_of_hash(*hash) else {
                continue;
            };
            if let Some(e) = self.store.remove(port, kind) {
                if let Some(s) = e.sock {
                    self.kernel.close_socket(s);
                }
                tuples.push(tuple_of(port, kind));
            }
            if kind.is_udp() {
                let ip = kind.ip();
                let mut keep = Vec::new();
                for e in std::mem::take(&mut self.encaps) {
                    if e.port == port && Ip::of(e.local).number() == ip {
                        self.kernel.close_socket(e.sock);
                    } else {
                        keep.push(e);
                    }
                }
                self.encaps = keep;
            }
        }
        self.say(format!(
            "ports: 0x34 with {} entries, {} removed, {} in the store",
            hashes.len(),
            tuples.len(),
            self.store.len()
        ));
        if !tuples.is_empty() {
            if let Err(e) = gone_ok(self.kernel.wlan(&WlanRequest::DelTuples(tuples))) {
                self.say(format!("genl 2 failed, errno {}", e.errno()));
            }
        }
    }

    fn on_encap_port(&mut self, hash: u32, value: u8) {
        let Some((port, _)) = dfs::port_of_hash(hash) else {
            return self.say("ports: 0x35 with a hash that is no port".into());
        };
        let be = port.to_be_bytes();
        let requests = if value != 0 {
            [WlanRequest::SetEncapPort(be), WlanRequest::EncapDrop(be)]
        } else {
            [WlanRequest::UnsetEncapPort(be), WlanRequest::EncapPass(be)]
        };
        self.say(format!("ports: 0x35 with value {value}"));
        for req in &requests {
            if let Err(e) = dup_ok(gone_ok(self.kernel.wlan(req))) {
                self.say(format!("genl {} failed, errno {}", req.number(), e.errno()));
            }
        }
    }

    /// When the engine wants `tick`.
    pub fn next_deadline(&self) -> Option<u64> {
        let legs = self.legs.iter().flat_map(|l| {
            l.deadline
                .into_iter()
                .chain(l.retry_at)
                .chain(l.pending.as_ref().map(|p| p.deadline))
        });
        legs.chain(self.ports_leg.deadline)
            .chain(self.ports_leg.retry_at)
            .chain(self.links_retry_at)
            .chain(self.left_retry_at)
            .min()
    }

    pub fn tick(&mut self, now: u64) {
        self.now = now;
        if self.links_retry_at.is_some_and(|at| at <= now) {
            self.bring_up();
        }
        if self.left_retry_at.is_some_and(|at| at <= now) {
            self.retry_left();
        }
        for i in 0..self.legs.len() {
            if self.legs[i]
                .pending
                .as_ref()
                .is_some_and(|p| p.deadline <= now)
            {
                let why = match self.legs[i].pending.as_ref().map(|p| p.phase) {
                    Some(Phase::WaitFilters) => "no answer to DFS 0x30",
                    _ => "no whole answer to 0x11c in time",
                };
                self.fail_pending(i, why);
            }
            if self.legs[i].retry_at.is_some_and(|at| at <= now) {
                self.legs[i].retry_at = None;
                if self.legs[i].step == Step::Failed {
                    self.start_leg(i);
                } else {
                    self.send_bind(i);
                }
                continue;
            }
            if self.legs[i].deadline.is_some_and(|at| at <= now) {
                let step = self.legs[i].step;
                self.legs[i].deadline = None;
                if step == Step::Bind {
                    self.bind_refused(i, None);
                } else {
                    let why = format!("{}, no answer", step.name());
                    self.leg_failed(i, &why);
                }
            }
        }
        if self.ports_leg.retry_at.is_some_and(|at| at <= now) {
            self.start_ports();
        }
        if self.ports_leg.deadline.is_some_and(|at| at <= now) {
            let step = self.ports_leg.step;
            self.ports_failed(step.name());
        }
    }

    /// How many tunnels are up, for a test or a look from outside.
    pub fn tunnels_up(&self) -> usize {
        self.legs.iter().filter(|l| l.installed.is_some()).count()
    }

    /// The technologies of what is up. It is here so nothing has to read the private table.
    pub fn tunnel_technologies(&self) -> Vec<u16> {
        self.legs
            .iter()
            .filter_map(|l| l.installed.as_ref().map(|t| t.tech))
            .collect()
    }

    pub fn ready_clients(&self) -> usize {
        self.legs.iter().filter(|l| l.step == Step::Ready).count()
    }

    pub fn ports_in_store(&self) -> usize {
        self.store.len()
    }

    pub fn encap_sockets(&self) -> usize {
        self.encaps.len()
    }
}
