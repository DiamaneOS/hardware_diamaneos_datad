// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The data call engine. One `Call` owns one rmnet link while it runs and one
//! WDS client per IP family. All state changes happen inside the public
//! methods, which never block and never sleep. The time (`now`, in
//! milliseconds) must come from a clock that stops in suspend
//! (`CLOCK_MONOTONIC`), or local deadlines fire right after a resume.
use crate::model::*;
use dataos_netcfg::{
    AddrFlags, IpaFormat, Ipv6Settings, NetError, NetOps, PipeState, PipeStatus, RmnetFlags,
    SetupMarker, STOCK_FEATURES,
};
use dataos_qmi::wds::{self, ConnectionStatus, RuntimeSettings, StartOutcome};
use dataos_qmi::{dpm, wda, Frame, Kind};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

mod lookup;
pub use lookup::MAX_LOOKUPS;

/// Boot ID that stands for "could not be read" in the marker.
const UNKNOWN_BOOT: &str = "-";

/// Smallest MTU Linux keeps IPv6 enabled on.
const MIN_IPV6_MTU: u32 = 1280;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QmiError {
    /// The service or the modem is not there.
    Unavailable,
}

/// The modem side as the engine sees it. A client is one QRTR socket.
pub trait Qmi {
    fn open_client(&mut self, service: u8) -> Result<ClientId, QmiError>;
    fn close_client(&mut self, client: ClientId);
    fn send(&mut self, client: ClientId, datagram: &[u8]) -> Result<(), QmiError>;
}

/// Values marked "unverified" are placeholders until they are checked against a trace of the
/// stock stack. Wrong ones fail every call.
#[derive(Clone, Debug)]
pub struct Config {
    /// Physical data device the rmnet links sit on.
    pub parent: String,
    pub link_prefix: String,
    /// Links created at bring-up. The IPA driver registers at most 15 mux
    /// channels, so this is the most calls that can run at once.
    pub link_count: u8,
    /// Links only an emergency call may take.
    pub reserve_links: u8,
    /// Mux ID of the first link (mux ID = link number + 1, as in a stock trace).
    pub base_mux_id: u8,
    pub slots: u8,
    /// (endpoint type, interface number) of the data port. The type is libqmi's value for the embedded
    /// transport. The interface number is the driver's answer (`RMNET_IOCTL_GET_EPID`, 1 on the FP6) and this
    /// is what is used until the driver has been asked at the first bring-up.
    pub endpoint: (u32, u32),
    /// The downlink limits of the data format request: stock's own, 64844 bytes and 63 datagrams, which are also
    /// the aggregation limits of the ingress pipe (`IpaFormat`), so the modem does not send aggregates that the
    /// pipe would cut.
    pub dl_max_size: u32,
    pub dl_max_datagrams: u32,
    /// Timeout of the local QMI steps (not of Start Network).
    pub qmi_timeout_ms: u64,
    /// The deadline of the steps an emergency call passes over when they get no
    /// answer (subscription binding, IP family, indication register). Each one costs
    /// this much, so it is short. Every other step keeps `qmi_timeout_ms`, because a
    /// timeout there ends a leg.
    pub emergency_qmi_timeout_ms: u64,
    /// Delay before the first bring-up retry. It doubles up to `retry_max_ms`.
    pub retry_ms: u64,
    pub retry_max_ms: u64,
    pub rmnet_flags: RmnetFlags,
    /// Data format of the IPA pipes, as stock nicmd sends it.
    pub ipa: IpaFormat,
    /// Client type in Bind Mux Data Port (unverified).
    pub bind_client_type: u32,
    /// The most a lookup for an existing call may take from start to answer. The module waits for
    /// it on a thread of the radio daemon, so it is short, where the local steps of a call are not.
    pub lookup_timeout_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            parent: "rmnet_ipa0".into(),
            link_prefix: "rmnet_data".into(),
            link_count: 15,
            reserve_links: 2,
            base_mux_id: 1,
            slots: 2,
            endpoint: (wds::EP_EMBEDDED, 1),
            dl_max_size: 64844,
            dl_max_datagrams: 63,
            qmi_timeout_ms: 10_000,
            emergency_qmi_timeout_ms: 3_000,
            retry_ms: 2_000,
            retry_max_ms: 60_000,
            rmnet_flags: RmnetFlags::qmap_default(),
            ipa: IpaFormat::default(),
            bind_client_type: 0xff,
            lookup_timeout_ms: 2_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceEvent {
    ModemUp,
    ModemDown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub malformed: u32,
    pub stale: u32,
    pub unknown_client: u32,
    /// Optional runtime settings entries that were left out.
    pub dropped_optional: u32,
    /// Bind Subscription and Set IP Family refusals of emergency calls that were passed over.
    pub bind_refusals_passed: u32,
    /// Indication Register refusals or timeouts that were passed over.
    pub ind_register_refusals: u32,
    /// Links that could not be created or registered.
    pub link_errors: u32,
    /// Times the setup marker could not be written.
    pub marker_store_failures: u32,
    /// Pipes an earlier instance had started, that the driver reported as existing.
    pub pipes_found: u32,
    /// Settings refetches of a working call that got no answer. The call keeps what it had.
    pub refresh_timeouts: u32,
    /// Settings refetches of a working call whose answer was not usable. The call keeps what it had.
    pub refresh_bad: u32,
    /// Packet status indications that named the other IP family and were passed over.
    pub other_family_indications: u32,
    /// Bring-up steps (data format, port) that were refused or unanswered and passed
    /// over because the device was already set up by an earlier instance.
    pub bringup_refusals_passed: u32,
    /// Bring-ups that found the IPA pipes already set up and did not repeat them.
    pub pipes_skipped: u32,
    /// Times the physical device was found replaced without a modem-down event.
    pub device_changes: u32,
    /// Links on which not every offload feature of the stock set could be switched on. The link works
    /// without them, only slower.
    pub feature_gaps: u32,
    /// Lookups for an existing call that got no answer in time.
    pub lookup_timeouts: u32,
    /// Lookups the modem refused or answered with something unusable.
    pub lookup_bad: u32,
    /// Emergency calls moved to another link after their data port binding was refused.
    pub emergency_relinks: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    BindMux,
    BindSub,
    SetFamily,
    IndReg,
    Start,
    Wait,
    Settings,
    Up,
    Refresh,
    Stop,
    Dead,
}

impl Step {
    /// The message a response in this step must answer.
    fn answers(self) -> Option<u16> {
        match self {
            Step::BindMux => Some(wds::id::BIND_MUX_DATA_PORT),
            Step::BindSub => Some(wds::id::BIND_SUBSCRIPTION),
            Step::SetFamily => Some(wds::id::SET_IP_FAMILY),
            Step::IndReg => Some(wds::id::INDICATION_REGISTER),
            Step::Start => Some(wds::id::START_NETWORK),
            Step::Settings | Step::Refresh => Some(wds::id::GET_RUNTIME_SETTINGS),
            Step::Stop => Some(wds::id::STOP_NETWORK),
            Step::Wait | Step::Up | Step::Dead => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Pending,
    Up,
    Failed(EndReason),
    Down(EndReason),
}

/// How a follower's first look for the call of its module went (`Engine::call_look`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Look {
    Pending,
    Done,
    Failed,
}

struct Leg {
    family: Family,
    client: Option<ClientId>,
    step: Step,
    txn: u16,
    deadline: Option<u64>,
    handle: Option<u32>,
    early_connected: bool,
    /// The first settings request of an attached leg may find no call yet.
    probe: bool,
    /// The first look for the call: still under way, answered (found the call or was told there is none),
    /// or failed (no answer in time, or a failure of the request itself).
    look: Look,
    settings: Option<RuntimeSettings>,
    applied: Vec<(IpAddr, u8)>,
    outcome: Outcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CallState {
    WaitReady,
    Active,
    Stopping,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Announced {
    Nothing,
    Connected,
    Partial,
}

struct Call {
    id: CallId,
    params: CallParams,
    /// The link this call holds. Taken at start, given back when the call ends.
    link: Option<usize>,
    ifname: String,
    link_mtu: Option<u32>,
    state: CallState,
    legs: Vec<Leg>,
    announced: Announced,
    /// An emergency call whose data port binding was refused moves to another
    /// link once.
    relinked: bool,
    /// The follower saw the modem say the call is connected. nicmd keeps this flag in the data
    /// call of the interface (+0x28), sets it at the packet status "connected" (0x6985c) and clears it
    /// at a disconnect (0x69ae8, 0x6c128, 0x68e84), so it outlives a leg that could not get the
    /// settings. Only a disconnect, the end of the call and a modem restart clear it.
    seen_connected: bool,
    /// IPv6 was switched on on the link for this call. It is switched off when the call lets go of the link,
    /// as stock does: an idle link has `disable_ipv6` 1 and the kernel takes its addresses away.
    ipv6_on: bool,
}

impl Call {
    fn emergency(&self) -> bool {
        self.params.priority == Priority::Emergency
    }

    /// Remember that a leg is at a step that only a connected call reaches.
    fn note_connected(&mut self) {
        if self.state != CallState::Closed
            && self.legs.iter().any(|l| {
                l.outcome == Outcome::Up
                    || matches!(l.step, Step::Up | Step::Refresh)
                    || (l.step == Step::Settings && !l.probe)
            })
        {
            self.seen_connected = true;
        }
    }
}

struct LinkSlot {
    name: String,
    mux_id: u8,
    created: bool,
    mux_added: bool,
    /// The last attempt to create or register it failed. Such a link is not
    /// counted when the reserve is checked, and ordinary calls skip it.
    broken: bool,
    owner: Option<CallId>,
    /// The module may still name this link (it was freed by a modem restart), so it
    /// is not handed out before this time, unless nothing else is free.
    hold_until: u64,
}

/// What the engine knows about the setup of the physical device: the
/// interface index it saw and which pipes are set up on it. It comes from the
/// marker an earlier instance stored, when boot and interface index still match.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct IpaProgress {
    ifindex: Option<i32>,
    egress: Pipe,
    ingress: Pipe,
}

/// One pipe as this instance sees it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Pipe {
    #[default]
    Missing,
    /// An earlier instance was about to send the ioctl and left no word on how it
    /// went. A refusal that says "exists" then means it worked.
    Maybe,
    Done,
}

/// Unusual things the host should write down once. They carry no identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Note {
    /// The setup marker could not be written. A restarted daemon will not know what exists.
    MarkerStoreFailed(NetError),
    /// The boot ID could not be read, the marker is matched by interface index alone.
    BootIdUnreadable,
    /// The modem did not answer a question about a link that has not come up, or refused it. Written for
    /// the first and then for every sixteenth, because a modem that does not take the route lookup refuses
    /// every one.
    CheckUnanswered,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Owner {
    Leg(CallId, usize),
    Wda,
    Dpm,
    Lookup(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BStep {
    Idle,
    Wda,
    Dpm,
}

struct Bringup {
    step: BStep,
    wda: Option<ClientId>,
    dpm: Option<ClientId>,
    txn: u16,
    deadline: Option<u64>,
    retry_at: Option<u64>,
    attempts: u32,
}

pub struct Engine<Q: Qmi, N: NetOps> {
    cfg: Config,
    qmi: Q,
    net: N,
    links: Vec<LinkSlot>,
    calls: BTreeMap<CallId, Call>,
    next_call: CallId,
    clients: BTreeMap<ClientId, Owner>,
    ready: bool,
    modem_up: bool,
    ipa: IpaProgress,
    notes: Vec<Note>,
    bringup: Bringup,
    events: Vec<Event>,
    now: u64,
    txn: u16,
    stats: Stats,
    lookups: BTreeMap<u32, lookup::Lookup>,
    /// The links of an earlier instance of the daemon were kept at the last bring-up.
    adopted: bool,
    /// The data port as the driver reported it at the last bring-up: (endpoint type, interface number).
    endpoint: (u32, u32),
    /// The consumer and producer pipe numbers the driver reported.
    pipe_pair: (u32, u32),
}

impl<Q: Qmi, N: NetOps> Engine<Q, N> {
    pub fn new(cfg: Config, qmi: Q, net: N) -> Self {
        let links = (0..cfg.link_count)
            .map(|i| LinkSlot {
                name: format!("{}{}", cfg.link_prefix, i),
                mux_id: cfg.base_mux_id.saturating_add(i),
                created: false,
                mux_added: false,
                broken: false,
                owner: None,
                hold_until: 0,
            })
            .collect();
        Engine {
            endpoint: cfg.endpoint,
            pipe_pair: (0, 0),
            cfg,
            qmi,
            net,
            links,
            calls: BTreeMap::new(),
            next_call: 1,
            clients: BTreeMap::new(),
            ready: false,
            modem_up: false,
            ipa: IpaProgress::default(),
            notes: Vec::new(),
            bringup: Bringup {
                step: BStep::Idle,
                wda: None,
                dpm: None,
                txn: 0,
                deadline: None,
                retry_at: None,
                attempts: 0,
            },
            events: Vec::new(),
            now: 0,
            txn: 0,
            stats: Stats::default(),
            lookups: BTreeMap::new(),
            adopted: false,
        }
    }

    pub fn qmi_mut(&mut self) -> &mut Q {
        &mut self.qmi
    }

    pub fn net(&self) -> &N {
        &self.net
    }

    pub fn net_mut(&mut self) -> &mut N {
        &mut self.net
    }

    pub fn is_ready(&self) -> bool {
        self.ready
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Things to write down, each kind once.
    /// The host-facing server writes down something it saw (see `Note`).
    pub fn note(&mut self, n: Note) {
        self.notes.push(n);
    }

    pub fn take_notes(&mut self) -> Vec<Note> {
        std::mem::take(&mut self.notes)
    }

    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// Links no call holds.
    pub fn free_links(&self) -> usize {
        self.links.iter().filter(|l| l.owner.is_none()).count()
    }

    /// Free links that work or have not failed yet and are not on hold. The reserve is counted in
    /// these: a link on hold is the last fallback of an emergency call and no part of the reserve
    /// that keeps ordinary calls from taking the last good link.
    pub fn free_usable_links(&self) -> usize {
        self.links
            .iter()
            .filter(|l| l.owner.is_none() && !l.broken && l.hold_until <= self.now)
            .count()
    }

    /// The links of an earlier instance of the daemon were kept at the last bring-up, so the calls
    /// the module has on them may still run. False after a fresh setup of the device.
    pub fn links_adopted(&self) -> bool {
        self.adopted
    }

    /// The links of an earlier instance that were kept, which is every link of the pool when
    /// they were (see `links_adopted`): a call of the module may run on any of them.
    pub fn adopted_links(&self) -> Vec<usize> {
        if self.adopted {
            (0..self.links.len()).collect()
        } else {
            Vec::new()
        }
    }

    /// Until when this link is on hold (0: not at all).
    pub fn link_hold_until(&self, link: usize) -> u64 {
        self.links.get(link).map_or(0, |l| l.hold_until)
    }

    /// Links all together.
    pub fn link_total(&self) -> usize {
        self.links.len()
    }

    /// Links only emergency calls may take.
    pub fn reserved_links(&self) -> usize {
        usize::from(self.cfg.reserve_links)
    }

    /// Earliest time the host must call `tick`.
    pub fn next_deadline(&self) -> Option<u64> {
        let legs = self
            .calls
            .values()
            .flat_map(|c| c.legs.iter().filter_map(|l| l.deadline));
        legs.chain(self.bringup.retry_at)
            .chain(self.bringup.deadline)
            .chain(self.lookups.values().map(|l| l.deadline))
            .min()
    }

    fn next_txn(&mut self) -> u16 {
        self.txn = self.txn.wrapping_add(1);
        if self.txn == 0 {
            self.txn = 1;
        }
        self.txn
    }

    fn emit(&mut self, e: Event) {
        self.events.push(e);
    }

    // ---- modem availability and bring-up -------------------------------

    pub fn on_service_event(&mut self, now: u64, ev: ServiceEvent) {
        self.now = now;
        match ev {
            ServiceEvent::ModemUp => {
                // A repeated announcement must not redo the data format while
                // calls run, or interrupt a bring-up that is in progress.
                if self.modem_up && (self.ready || self.bringup.step != BStep::Idle) {
                    return;
                }
                self.modem_up = true;
                self.start_bringup();
            }
            ServiceEvent::ModemDown => {
                self.modem_up = false;
                self.ready = false;
                self.stop_bringup();
                self.bringup.attempts = 0;
                // The kernel frees `rmnet_ipa0` with the modem and deletes every
                // link on it. Bring-up forgets what it believed about the links
                // and makes them again (`reset_links`).
                self.ipa = IpaProgress::default();
                self.adopted = false;
                self.end_active_calls(EndReason::Local(LocalReason::ModemRestart));
                self.end_lookups();
            }
        }
    }

    /// Every call that runs or stops ends with this reason.
    fn end_active_calls(&mut self, r: EndReason) {
        let ids: Vec<CallId> = self.calls.keys().copied().collect();
        for id in ids {
            self.with_call(id, |s, c| {
                if matches!(c.state, CallState::Active | CallState::Stopping) {
                    for i in 0..c.legs.len() {
                        if c.legs[i].step != Step::Dead {
                            s.kill_leg(c, i, r);
                        }
                    }
                    s.finalize(c, r);
                }
            });
        }
    }

    /// The physical device was replaced without a modem-down event reaching us:
    /// its pipes, links and mux channels are gone. Treat it as a modem restart.
    fn device_lost(&mut self) {
        self.stats.device_changes = self.stats.device_changes.saturating_add(1);
        self.ready = false;
        self.ipa = IpaProgress::default();
        self.end_active_calls(EndReason::Local(LocalReason::ModemRestart));
        self.end_lookups();
        if self.modem_up {
            self.start_bringup();
        }
    }

    /// Is the device the one we set up? `NotFound` or another index says no, a
    /// failed lookup does not.
    fn device_changed(&mut self) -> bool {
        match self.net.ifindex(&self.cfg.parent) {
            Ok(i) => self.ipa.ifindex != Some(i),
            Err(NetError::NotFound) => true,
            Err(_) => false,
        }
    }

    fn stop_bringup(&mut self) {
        for c in [self.bringup.wda.take(), self.bringup.dpm.take()]
            .into_iter()
            .flatten()
        {
            self.clients.remove(&c);
            self.qmi.close_client(c);
        }
        self.bringup.step = BStep::Idle;
        self.bringup.deadline = None;
        self.bringup.retry_at = None;
    }

    /// What an earlier instance left: the marker counts only for the interface
    /// index the device has now, and for this boot when the boot ID can be read at
    /// both times (the directory is tmpfs, so a marker cannot outlive a boot).
    fn load_progress(&mut self) {
        let cur = self.net.ifindex(&self.cfg.parent).ok();
        let boot = self.read_boot_id();
        self.ipa = match (cur, self.net.load_marker()) {
            (Some(i), Some(m))
                if m.ifindex == i
                    && (boot == UNKNOWN_BOOT || m.boot_id == UNKNOWN_BOOT || m.boot_id == boot) =>
            {
                IpaProgress {
                    ifindex: Some(i),
                    egress: pipe_from(m.egress),
                    ingress: pipe_from(m.ingress),
                }
            }
            (Some(i), _) => IpaProgress {
                ifindex: Some(i),
                ..Default::default()
            },
            _ => IpaProgress::default(),
        };
    }

    /// The boot ID, or `-` when it cannot be read (noted once).
    fn read_boot_id(&mut self) -> String {
        match self.net.boot_id() {
            Ok(b) => b,
            Err(_) => {
                if !self.notes.contains(&Note::BootIdUnreadable) {
                    self.notes.push(Note::BootIdUnreadable);
                }
                UNKNOWN_BOOT.to_string()
            }
        }
    }

    /// The modem side of this device was set up already, by an earlier attempt or
    /// instance. A marker entry for a pipe exists only after the data format and the
    /// port request succeeded for this interface index, in the same modem lifetime.
    /// A second request for them may be refused or ignored.
    fn modem_set_up(&self) -> bool {
        self.ipa.egress != Pipe::Missing || self.ipa.ingress != Pipe::Missing
    }

    /// Both pipes exist, so there is nothing left to send to the driver.
    fn pipes_done(&self) -> bool {
        self.ipa.egress == Pipe::Done && self.ipa.ingress == Pipe::Done
    }

    fn start_bringup(&mut self) {
        self.stop_bringup();
        self.load_progress();
        // Ask the device which endpoint it is and which pipes it has, and bring it up, in the order stock nicmd
        // does after a modem restart. The numbers go to the modem and they are the driver's, not ours.
        match self.net.ipa_endpoint(&self.cfg.parent) {
            Ok(ep) => {
                self.endpoint.1 = ep.epid;
                self.pipe_pair = (ep.consumer, ep.producer);
            }
            Err(_) => return self.bringup_failed(),
        }
        if self.net.set_link(&self.cfg.parent, true, None).is_err() {
            return self.bringup_failed();
        }
        let client = match self.qmi.open_client(wda::SERVICE) {
            Ok(c) => c,
            Err(_) => return self.bringup_failed(),
        };
        self.clients.insert(client, Owner::Wda);
        self.bringup.wda = Some(client);
        let txn = self.next_txn();
        let req = wda::SetDataFormat::stock(
            self.endpoint,
            self.cfg.dl_max_size,
            self.cfg.dl_max_datagrams,
        )
        .encode(txn);
        match req {
            Ok(b) if self.qmi.send(client, &b).is_ok() => {
                self.bringup.step = BStep::Wda;
                self.bringup.txn = txn;
                self.bringup.deadline = Some(self.now.saturating_add(self.cfg.qmi_timeout_ms));
            }
            _ => self.bringup_failed(),
        }
    }

    /// Give up this attempt and try again later, with a growing delay.
    fn bringup_failed(&mut self) {
        self.stop_bringup();
        let shift = self.bringup.attempts.min(16);
        let delay = self
            .cfg
            .retry_ms
            .saturating_mul(1u64 << shift)
            .min(self.cfg.retry_max_ms);
        self.bringup.attempts = self.bringup.attempts.saturating_add(1);
        self.bringup.retry_at = Some(self.now.saturating_add(delay));
    }

    fn bringup_rx(&mut self, owner: Owner, bytes: &[u8]) {
        let f = match Frame::parse(bytes) {
            Ok(f) if f.kind == Kind::Response => f,
            Ok(_) => return,
            Err(_) => {
                self.stats.malformed = self.stats.malformed.saturating_add(1);
                return;
            }
        };
        let asked = match self.bringup.step {
            BStep::Wda => Some(wda::SET_DATA_FORMAT),
            BStep::Dpm => Some(dpm::OPEN_PORT),
            BStep::Idle => None,
        };
        if f.txn != self.bringup.txn || Some(f.id) != asked {
            self.stats.stale = self.stats.stale.saturating_add(1);
            return;
        }
        match (owner, self.bringup.step) {
            (Owner::Wda, BStep::Wda) => {
                if wda::parse_set_data_format_response(&f).is_err() {
                    if !self.modem_set_up() {
                        return self.bringup_failed();
                    }
                    self.stats.bringup_refusals_passed =
                        self.stats.bringup_refusals_passed.saturating_add(1);
                }
                self.bringup_open_port();
            }
            (Owner::Dpm, BStep::Dpm) => {
                if !f.status().map(|s| s.is_ok()).unwrap_or(false) {
                    if !self.modem_set_up() {
                        return self.bringup_failed();
                    }
                    self.stats.bringup_refusals_passed =
                        self.stats.bringup_refusals_passed.saturating_add(1);
                }
                self.finish_bringup();
            }
            _ => self.stats.stale = self.stats.stale.saturating_add(1),
        }
    }

    /// Second bring-up step: open the hardware data port.
    fn bringup_open_port(&mut self) {
        let client = match self.qmi.open_client(dpm::SERVICE) {
            Ok(c) => c,
            Err(_) => return self.bringup_failed(),
        };
        self.clients.insert(client, Owner::Dpm);
        self.bringup.dpm = Some(client);
        let txn = self.next_txn();
        let port = dpm::HardwarePort {
            ep_type: self.endpoint.0,
            iface: self.endpoint.1,
            consumer: self.pipe_pair.0,
            producer: self.pipe_pair.1,
        };
        match dpm::open_hardware_ports(txn, &[port]) {
            Ok(b) if self.qmi.send(client, &b).is_ok() => {
                self.bringup.step = BStep::Dpm;
                self.bringup.txn = txn;
                self.bringup.deadline = Some(self.now.saturating_add(self.cfg.qmi_timeout_ms));
            }
            _ => self.bringup_failed(),
        }
    }

    /// A bring-up step got no answer in time.
    fn bringup_deadline(&mut self) {
        if !self.modem_set_up() {
            return self.bringup_failed();
        }
        self.stats.bringup_refusals_passed = self.stats.bringup_refusals_passed.saturating_add(1);
        match self.bringup.step {
            BStep::Wda => self.bringup_open_port(),
            BStep::Dpm => self.finish_bringup(),
            BStep::Idle => {}
        }
    }

    /// The modem side is ready. Set up the physical device, then make the
    /// links, then let waiting calls start.
    fn finish_bringup(&mut self) {
        self.bringup.step = BStep::Idle;
        self.bringup.deadline = None;
        // The device was set up already (by an earlier instance, or an earlier attempt of this one):
        // its links may carry calls of the module that outlived the daemon. The stock daemon does not
        // touch those either, it flushes an address when the kernel reports the link down.
        let adopt = self.pipes_done();
        if self.setup_ipa().is_err() {
            return self.bringup_failed();
        }
        self.reset_links(adopt);
        self.adopted = adopt;
        self.ready = true;
        self.bringup.attempts = 0;
        let waiting: Vec<CallId> = self
            .calls
            .values()
            .filter(|c| c.state == CallState::WaitReady)
            .map(|c| c.id)
            .collect();
        for id in waiting {
            self.with_call(id, |s, c| s.begin_call(c));
        }
    }

    /// The offloads of `rmnet_ipa0`, on before any pipe is asked for. The driver puts them in `hw_features`
    /// after it registered the device, and the kernel does not switch those on, so a new `rmnet_ipa0` has
    /// none. Without `rx-gro-hw` the coalescing pipe is skipped with a status of failure while the ioctl returns
    /// 0, after the default pipe and the WAN routing tables are made, and every later request answers `EPERM`.
    /// Without a transmit checksum the uplink pipe gets no checksum header, which the v5 format of the links
    /// needs, and it is a ULSO pipe only with scatter-gather or a TSO feature on, while the links always offer
    /// segmentation. So the whole set of stock is needed: it is read back, and an attempt in which one feature is
    /// not on ends before the first request.
    fn set_ipa_features(&mut self) -> Result<(), NetError> {
        let missing = self.net.set_features(&self.cfg.parent, &STOCK_FEATURES)?;
        if !missing.is_empty() {
            return Err(NetError::Os(95));
        }
        Ok(())
    }

    /// Both pipes of `rmnet_ipa0`, each once. Without the ingress format the AP gets no downlink, without the
    /// egress format it cannot send. The driver reports a pipe that is up already (`PipeStatus::Existed`),
    /// also with the `EPERM` it answers a repeated ingress request with, and does not set it up again, so what
    /// an earlier instance or an earlier attempt of this one did is harmless to repeat, and the marker only
    /// saves the request. Before each ioctl the marker says `pending`, after it `done`. A failure of the
    /// driver, also one it reports in the status of a pipe while the ioctl itself works, ends the attempt.
    /// The features come first, on every new `rmnet_ipa0`.
    fn setup_ipa(&mut self) -> Result<(), NetError> {
        let cur = self.net.ifindex(&self.cfg.parent)?;
        if self.ipa.ifindex != Some(cur) {
            self.ipa = IpaProgress {
                ifindex: Some(cur),
                ..Default::default()
            };
        }
        if self.pipes_done() {
            self.stats.pipes_skipped = self.stats.pipes_skipped.saturating_add(1);
            return Ok(());
        }
        self.set_ipa_features()?;
        let f = self.cfg.ipa.clone();
        for egress in [true, false] {
            let before = if egress {
                self.ipa.egress
            } else {
                self.ipa.ingress
            };
            if before == Pipe::Done {
                continue;
            }
            self.store_progress(Some(egress));
            let r = if egress {
                self.net.ipa_set_egress_format(&self.cfg.parent, &f.egress)
            } else {
                self.net
                    .ipa_set_ingress_format(&self.cfg.parent, &f.ingress)
            };
            match r {
                Ok(PipeStatus::Existed) => {
                    self.stats.pipes_found = self.stats.pipes_found.saturating_add(1);
                }
                Ok(_) => {}
                Err(e) => {
                    // the driver said no, so the intent record must not stay as a doubt
                    self.store_progress(None);
                    return Err(e);
                }
            }
            if egress {
                self.ipa.egress = Pipe::Done;
            } else {
                self.ipa.ingress = Pipe::Done;
            }
            self.store_progress(None);
        }
        Ok(())
    }

    /// Write the marker. `pending` names the pipe whose ioctl is about to be sent.
    /// A failure is counted and noted once, it never stops the setup.
    fn store_progress(&mut self, pending: Option<bool>) {
        let Some(ifindex) = self.ipa.ifindex else {
            return;
        };
        let state = |p: Pipe, is_pending: bool| match (p, is_pending) {
            (Pipe::Done, _) => PipeState::Done,
            (_, true) | (Pipe::Maybe, _) => PipeState::Pending,
            _ => PipeState::Missing,
        };
        let marker = SetupMarker {
            boot_id: self.read_boot_id(),
            ifindex,
            egress: state(self.ipa.egress, pending == Some(true)),
            ingress: state(self.ipa.ingress, pending == Some(false)),
        };
        if let Err(e) = self.net.store_marker(&marker) {
            self.stats.marker_store_failures = self.stats.marker_store_failures.saturating_add(1);
            if !self
                .notes
                .iter()
                .any(|n| matches!(n, Note::MarkerStoreFailed(_)))
            {
                self.notes.push(Note::MarkerStoreFailed(e));
            }
        }
    }

    /// Make every link. Links of an earlier daemon instance survive with their addresses, and
    /// nothing is dumped to find them. When the device was set up by that instance (`adopt`) they are
    /// kept as they are and only the missing ones are made. Otherwise each name is deleted blindly
    /// first, because nothing says what state they are in.
    fn reset_links(&mut self, adopt: bool) {
        for i in 0..self.links.len() {
            if !adopt {
                let name = self.links[i].name.clone();
                let _ = self.net.delete_link(&name);
            }
            self.links[i].created = false;
            self.links[i].mux_added = false;
        }
        for i in 0..self.links.len() {
            let _ = self.ensure_link(i);
        }
    }

    /// The link exists and its mux channel is registered with the device.
    fn ensure_link(&mut self, i: usize) -> Result<(), NetError> {
        let r = self.try_ensure_link(i);
        self.links[i].broken = r.is_err();
        r
    }

    fn try_ensure_link(&mut self, i: usize) -> Result<(), NetError> {
        let (name, mux) = (self.links[i].name.clone(), self.links[i].mux_id);
        if !self.links[i].created {
            let r = self
                .net
                .create_rmnet_link(&self.cfg.parent, &name, mux, self.cfg.rmnet_flags);
            // a link that exists is the one an earlier instance made
            if let Err(e) = r.or_else(|e| {
                if e == NetError::Exists {
                    Ok(())
                } else {
                    Err(e)
                }
            }) {
                self.stats.link_errors = self.stats.link_errors.saturating_add(1);
                return Err(e);
            }
            self.links[i].created = true;
            // the same offloads as on rmnet_ipa0, as stock sets them. A link works without them.
            if !matches!(self.net.set_features(&name, &STOCK_FEATURES), Ok(m) if m.is_empty()) {
                self.stats.feature_gaps = self.stats.feature_gaps.saturating_add(1);
            }
        }
        if !self.links[i].mux_added {
            let r = self.net.ipa_add_mux_channel(&self.cfg.parent, mux, &name);
            if let Err(e) = r.or_else(|e| {
                if e == NetError::Exists {
                    Ok(())
                } else {
                    Err(e)
                }
            }) {
                self.stats.link_errors = self.stats.link_errors.saturating_add(1);
                return Err(e);
            }
            self.links[i].mux_added = true;
        }
        Ok(())
    }

    /// The first free link for this kind of call. An ordinary call takes only a
    /// link that works. An emergency call prefers one, and takes any free link
    /// if there is none, because creating a failed one again may work now.
    fn pick_link(&self, priority: Priority, not: Option<usize>) -> Option<usize> {
        let free = |i: &usize| self.links[*i].owner.is_none() && Some(*i) != not;
        let held = |i: &usize| self.links[*i].hold_until > self.now;
        let mut all = 0..self.links.len();
        let good = all
            .clone()
            .filter(free)
            .find(|i| !self.links[*i].broken && !held(i));
        match priority {
            Priority::Normal => good,
            // a link on hold is the last choice, but not out of reach
            Priority::Emergency => good
                .or_else(|| all.clone().filter(free).find(|i| !self.links[*i].broken))
                .or_else(|| all.find(free)),
        }
    }

    /// Is this link on hold right now (a modem restart freed it a moment ago)?
    pub fn link_on_hold(&self, link: usize) -> bool {
        self.links
            .get(link)
            .is_some_and(|l| l.hold_until > self.now)
    }

    /// Do not hand this link out before `until`, because the module may still name
    /// it (its call ended with a modem restart and it releases the link late).
    pub fn hold_link(&mut self, link: usize, until: u64) {
        if let Some(l) = self.links.get_mut(link) {
            l.hold_until = until;
        }
    }

    // ---- call API ------------------------------------------------------

    pub fn start_call(&mut self, now: u64, params: CallParams) -> Result<CallId, StartError> {
        self.start_call_on(now, params, None)
    }

    /// Start a call, on the link asked for if there is one (a call the module had before the
    /// daemon restarted, which has its link already) or on the first one that suits.
    fn start_call_on(
        &mut self,
        now: u64,
        params: CallParams,
        at: Option<usize>,
    ) -> Result<CallId, StartError> {
        self.now = now;
        params.validate(self.cfg.slots)?;
        // Ordinary calls leave the reserve alone, so an emergency call finds a link.
        // Links that failed to be made do not count as reserve.
        let link = match at {
            Some(l) => self
                .links
                .get(l)
                .is_some_and(|slot| slot.owner.is_none())
                .then_some(l)
                .ok_or(StartError::NoLink)?,
            None => {
                if params.priority == Priority::Normal
                    && self.free_usable_links() <= self.reserved_links()
                {
                    return Err(StartError::NoLink);
                }
                self.pick_link(params.priority, None)
                    .ok_or(StartError::NoLink)?
            }
        };
        let id = self.next_call;
        self.next_call = self.next_call.wrapping_add(1).max(1);
        self.links[link].owner = Some(id);
        let legs = params
            .ip_version
            .families()
            .iter()
            .map(|f| new_leg(*f))
            .collect();
        let call = Call {
            id,
            params,
            link: Some(link),
            ifname: self.links[link].name.clone(),
            link_mtu: None,
            state: CallState::WaitReady,
            legs,
            announced: Announced::Nothing,
            relinked: false,
            seen_connected: false,
            ipv6_on: false,
        };
        self.calls.insert(id, call);
        // The device is checked at every call start. If it was replaced
        // without a modem-down event, this call waits for a new bring-up.
        if self.ready && self.device_changed() {
            self.device_lost();
        }
        if self.ready {
            self.with_call(id, |s, c| s.begin_call(c));
        }
        Ok(id)
    }

    pub fn stop_call(&mut self, now: u64, id: CallId) -> Result<(), StartError> {
        self.now = now;
        if !self.calls.contains_key(&id) {
            return Err(StartError::NoSuchCall);
        }
        self.with_call(id, |s, c| s.begin_stop(c));
        Ok(())
    }

    /// Drop the call object. An active call is stopped without an event.
    pub fn release_call(&mut self, now: u64, id: CallId) -> Result<(), StartError> {
        self.now = now;
        let mut call = self.calls.remove(&id).ok_or(StartError::NoSuchCall)?;
        if call.state != CallState::Closed {
            let r = EndReason::Local(LocalReason::UserRequested);
            for i in 0..call.legs.len() {
                if call.legs[i].step != Step::Dead {
                    self.kill_leg(&mut call, i, r);
                }
            }
            self.close_link(&mut call);
        }
        self.free_link(&mut call);
        Ok(())
    }

    /// Follow a call the data module starts on a link of its own choice of the
    /// route lookup. The link is held until `release_call`.
    pub fn attach_call(
        &mut self,
        now: u64,
        subscription: u8,
        priority: Priority,
        family: Family,
    ) -> Result<CallId, StartError> {
        self.attach_call_on(now, subscription, priority, family, None)
    }

    /// The same on this link, which must be free: the call of a module that outlived the daemon.
    pub fn attach_call_at(
        &mut self,
        now: u64,
        link: usize,
        subscription: u8,
        priority: Priority,
        family: Family,
    ) -> Result<CallId, StartError> {
        self.attach_call_on(now, subscription, priority, family, Some(link))
    }

    fn attach_call_on(
        &mut self,
        now: u64,
        subscription: u8,
        priority: Priority,
        family: Family,
        at: Option<usize>,
    ) -> Result<CallId, StartError> {
        let ip_version = match family {
            Family::V4 => IpVersion::V4,
            Family::V6 => IpVersion::V6,
        };
        self.start_call_on(
            now,
            CallParams {
                // the module's value is bound as it is, the slot is only the bookkeeping, and
                // "don't care" belongs to the first
                slot: Slot(if u32::from(subscription) == wds::DONT_CARE_SUBS {
                    0
                } else {
                    subscription.saturating_sub(1)
                }),
                subscription: Some(subscription),
                priority,
                ip_version,
                attach: true,
                ..Default::default()
            },
            at,
        )
    }

    /// The other family of an attached call, on the same link. A family whose leg
    /// ended is followed again.
    pub fn attach_family(
        &mut self,
        now: u64,
        id: CallId,
        family: Family,
    ) -> Result<(), StartError> {
        self.now = now;
        self.with_call(id, |s, c| {
            if !c.params.attach || c.state == CallState::Closed {
                return Err(StartError::Invalid);
            }
            let at = c.legs.iter().position(|l| l.family == family);
            let i = match at {
                Some(i) if c.legs[i].step != Step::Dead => return Err(StartError::Invalid),
                Some(i) => {
                    c.legs[i] = new_leg(family);
                    i
                }
                None => {
                    c.legs.push(new_leg(family));
                    c.legs.len() - 1
                }
            };
            if c.state == CallState::Active {
                s.begin_leg(c, i);
                s.settle(c);
            }
            Ok(())
        })
        .unwrap_or(Err(StartError::NoSuchCall))
    }

    /// Position of the call's link in the pool, which is the link number of the data module.
    pub fn call_link(&self, id: CallId) -> Option<usize> {
        self.calls.get(&id)?.link
    }

    /// Has the follower of this call seen the modem say it is connected, and not seen it end since?
    /// nicmd keeps the flag in the data call of the interface (+0x28, set at the packet status
    /// "connected" and cleared at the disconnect), and never takes such an interface back as unused.
    /// It stays when the leg that saw it could not get the settings and ended.
    pub fn call_seen_connected(&self, id: CallId) -> bool {
        self.calls
            .get(&id)
            .is_some_and(|c| c.seen_connected && c.state != CallState::Closed)
    }

    /// How the follower's first look for the call went. `Done`: every leg that is alive bound, registered and
    /// got an answer to its question about the settings (the call, or that there is none). `Pending`: one is
    /// still on its way. `Failed`: no leg is alive, or one asked and got no answer in time or an answer that
    /// says the request failed. A call whose follower could not look has not looked, and its absence in the
    /// modem's answer proves nothing.
    pub fn call_look(&self, id: CallId) -> Look {
        let Some(c) = self.calls.get(&id) else {
            return Look::Failed;
        };
        let mut live = c.legs.iter().filter(|l| l.step != Step::Dead).peekable();
        if live.peek().is_none() {
            return Look::Failed;
        }
        let looks: Vec<Look> = live.map(|l| l.look).collect();
        if looks.contains(&Look::Pending) {
            Look::Pending
        } else if looks.contains(&Look::Failed) {
            Look::Failed
        } else {
            Look::Done
        }
    }

    /// The families of a call that are up now.
    pub fn call_up_families(&self, id: CallId) -> Vec<Family> {
        self.calls.get(&id).map_or_else(Vec::new, |c| {
            c.legs
                .iter()
                .filter(|l| l.outcome == Outcome::Up)
                .map(|l| l.family)
                .collect()
        })
    }

    /// The families an attached call follows with a live leg.
    pub fn call_families(&self, id: CallId) -> Vec<Family> {
        self.calls.get(&id).map_or_else(Vec::new, |c| {
            c.legs
                .iter()
                .filter(|l| l.step != Step::Dead)
                .map(|l| l.family)
                .collect()
        })
    }

    pub fn call_info(&self, id: CallId) -> Option<CallInfo> {
        let c = self.calls.get(&id)?;
        let mut info = CallInfo {
            ifname: c.ifname.clone(),
            link_mtu: c.link_mtu,
            v4: None,
            v6: None,
            end_v4: None,
            end_v6: None,
        };
        for l in &c.legs {
            let fam = l.settings.clone().map(|s| FamilyInfo {
                mtu: s.mtu,
                settings: s,
            });
            let end = match l.outcome {
                Outcome::Failed(r) | Outcome::Down(r) => Some(r),
                _ => None,
            };
            match l.family {
                Family::V4 => {
                    info.v4 = if l.outcome == Outcome::Up { fam } else { None };
                    info.end_v4 = end;
                }
                Family::V6 => {
                    info.v6 = if l.outcome == Outcome::Up { fam } else { None };
                    info.end_v6 = end;
                }
            }
        }
        Some(info)
    }

    pub fn call_is_active(&self, id: CallId) -> bool {
        self.calls
            .get(&id)
            .map(|c| matches!(c.state, CallState::Active | CallState::WaitReady))
            .unwrap_or(false)
    }

    /// The call ended (Disconnected was emitted) and only waits to be released.
    pub fn call_is_closed(&self, id: CallId) -> bool {
        self.calls
            .get(&id)
            .map(|c| c.state == CallState::Closed)
            .unwrap_or(false)
    }

    /// The call holds a link (it has not ended).
    pub fn call_holds_link(&self, id: CallId) -> bool {
        self.calls.get(&id).is_some_and(|c| c.link.is_some())
    }

    // ---- inputs from the modem ------------------------------------------

    pub fn tick(&mut self, now: u64) {
        self.now = now;
        self.lookup_deadlines();
        if self.bringup.deadline.is_some_and(|d| now >= d) {
            self.bringup_deadline();
        }
        if let Some(t) = self.bringup.retry_at {
            if now >= t && self.modem_up {
                self.bringup.retry_at = None;
                self.start_bringup();
            }
        }
        let ids: Vec<CallId> = self.calls.keys().copied().collect();
        for id in ids {
            self.with_call(id, |s, c| {
                for i in 0..c.legs.len() {
                    if c.legs[i].deadline.is_some_and(|d| now >= d) {
                        s.leg_deadline(c, i);
                    }
                }
                s.settle(c);
            });
        }
    }

    pub fn on_qmi(&mut self, now: u64, client: ClientId, bytes: &[u8]) {
        self.now = now;
        match self.clients.get(&client).copied() {
            Some(Owner::Leg(id, i)) => {
                self.with_call(id, |s, c| s.leg_rx(c, i, bytes));
            }
            Some(o @ (Owner::Wda | Owner::Dpm)) => self.bringup_rx(o, bytes),
            Some(Owner::Lookup(token)) => self.lookup_rx(token, bytes),
            None => self.stats.unknown_client += 1,
        }
    }

    // ---- helpers ---------------------------------------------------------

    fn with_call<R>(&mut self, id: CallId, f: impl FnOnce(&mut Self, &mut Call) -> R) -> Option<R> {
        let mut call = self.calls.remove(&id)?;
        let r = f(self, &mut call);
        call.note_connected();
        self.calls.insert(id, call);
        Some(r)
    }

    fn begin_call(&mut self, c: &mut Call) {
        if c.state != CallState::WaitReady {
            return;
        }
        c.state = CallState::Active;
        let link_ok = match c.link {
            Some(l) => self.ensure_link(l).is_ok(),
            None => false,
        };
        if !link_ok {
            self.finalize(c, EndReason::Local(LocalReason::LinkFailed));
            return;
        }
        for i in 0..c.legs.len() {
            self.begin_leg(c, i);
        }
        self.settle(c);
    }

    fn begin_leg(&mut self, c: &mut Call, i: usize) {
        match self.qmi.open_client(wds::SERVICE) {
            Ok(client) => {
                c.legs[i].client = Some(client);
                self.clients.insert(client, Owner::Leg(c.id, i));
                self.send_bind_mux(c, i);
            }
            Err(_) => self.fail_leg(c, i, EndReason::Local(LocalReason::NoQmiClient)),
        }
    }

    fn request(
        &mut self,
        c: &mut Call,
        i: usize,
        step: Step,
        timed: bool,
        build: impl FnOnce(u16) -> Result<Vec<u8>, dataos_qmi::Error>,
    ) {
        let txn = self.next_txn();
        let client = match c.legs[i].client {
            Some(cl) => cl,
            None => return self.fail_leg(c, i, EndReason::Local(LocalReason::NoQmiClient)),
        };
        let bytes = match build(txn) {
            Ok(b) => b,
            Err(_) => return self.fail_leg(c, i, EndReason::Local(LocalReason::Malformed)),
        };
        if self.qmi.send(client, &bytes).is_err() {
            return self.fail_leg(c, i, EndReason::Local(LocalReason::NoQmiClient));
        }
        let passed_over = matches!(step, Step::BindSub | Step::SetFamily | Step::IndReg);
        let timeout = if c.emergency() && passed_over {
            self.cfg.emergency_qmi_timeout_ms
        } else {
            self.cfg.qmi_timeout_ms
        };
        let leg = &mut c.legs[i];
        leg.step = step;
        leg.txn = txn;
        leg.deadline = timed.then_some(self.now.saturating_add(timeout));
    }

    fn send_bind_mux(&mut self, c: &mut Call, i: usize) {
        let mux = c
            .link
            .and_then(|l| self.links.get(l))
            .map_or(0, |l| l.mux_id);
        let (ep, iface) = self.endpoint;
        let client_type = self.cfg.bind_client_type;
        self.request(c, i, Step::BindMux, true, |t| {
            wds::bind_mux_data_port(t, ep, iface, mux, client_type)
        });
    }

    fn send_bind_sub(&mut self, c: &mut Call, i: usize) {
        let sub = c
            .params
            .subscription
            .map_or(u32::from(c.params.slot.0) + 1, u32::from);
        self.request(c, i, Step::BindSub, true, |t| {
            wds::bind_subscription(t, sub)
        });
    }

    fn send_set_family(&mut self, c: &mut Call, i: usize) {
        let fam = c.legs[i].family.wds();
        self.request(c, i, Step::SetFamily, true, |t| wds::set_ip_family(t, fam));
    }

    fn send_ind_register(&mut self, c: &mut Call, i: usize) {
        self.request(c, i, Step::IndReg, true, |t| {
            wds::indication_register(t, true)
        });
    }

    /// Everything is bound and registered. Our own call starts the network, an
    /// attached call looks for the call somebody else started, in case its
    /// packet status came before the registration.
    fn after_registration(&mut self, c: &mut Call, i: usize) {
        if c.params.attach {
            c.legs[i].probe = true;
            c.legs[i].step = Step::Wait;
            self.request_settings(c, i, Step::Settings);
        } else {
            self.send_start(c, i);
        }
    }

    fn send_start(&mut self, c: &mut Call, i: usize) {
        let p = &c.params;
        let req = wds::StartNetwork {
            apn: p.apn.clone(),
            username: p.username.clone(),
            password: p.password.clone(),
            auth: p.auth,
            ip_family: Some(c.legs[i].family.wds()),
            profile_3gpp: p.profile_index,
            technology_preference: p.technology_preference,
            extra: p
                .start_tlvs
                .iter()
                .map(|t| (t.tag, t.value.clone()))
                .collect(),
        };
        // No deadline: the modem owns the retry policy of a start.
        self.request(c, i, Step::Start, false, |t| req.encode(t));
    }

    /// The data port binding of an emergency call was refused: move it to another
    /// working link, once, and bind again on every leg that is still at the
    /// binding. False when it is not an emergency call, it already moved, a leg
    /// got further, or there is no other link.
    fn relink_emergency(&mut self, c: &mut Call) -> bool {
        // The data module was told the link already, so an attached call stays on it.
        if !c.emergency() || c.relinked || c.params.attach {
            return false;
        }
        if c.legs.iter().any(|l| {
            !(l.step == Step::BindMux
                || (l.step == Step::Dead
                    && l.outcome == Outcome::Failed(EndReason::Local(LocalReason::BindFailed))))
        }) {
            return false;
        }
        let Some(old) = c.link else { return false };
        let Some(new) = self.pick_link(Priority::Emergency, Some(old)) else {
            return false;
        };
        if self.ensure_link(new).is_err() {
            return false;
        }
        self.links[new].owner = Some(c.id);
        self.links[old].owner = None;
        c.link = Some(new);
        c.ifname = self.links[new].name.clone();
        c.relinked = true;
        self.stats.emergency_relinks = self.stats.emergency_relinks.saturating_add(1);
        for i in 0..c.legs.len() {
            if let Some(cl) = c.legs[i].client.take() {
                self.clients.remove(&cl);
                self.qmi.close_client(cl);
            }
            c.legs[i].outcome = Outcome::Pending;
            c.legs[i].step = Step::BindMux;
            c.legs[i].deadline = None;
            match self.qmi.open_client(wds::SERVICE) {
                Ok(client) => {
                    c.legs[i].client = Some(client);
                    self.clients.insert(client, Owner::Leg(c.id, i));
                    self.send_bind_mux(c, i);
                }
                Err(_) => self.fail_leg(c, i, EndReason::Local(LocalReason::NoQmiClient)),
            }
        }
        true
    }

    /// A local step got no answer in time. Steps whose failure must not stop
    /// the call are passed over, the others end the leg.
    fn leg_deadline(&mut self, c: &mut Call, i: usize) {
        match c.legs[i].step {
            Step::IndReg => {
                self.stats.ind_register_refusals =
                    self.stats.ind_register_refusals.saturating_add(1);
                self.after_registration(c, i);
            }
            Step::Settings if c.legs[i].probe => {
                // The first look for an attached call's call found no answer in time.
                c.legs[i].probe = false;
                c.legs[i].look = Look::Failed;
                c.legs[i].step = Step::Wait;
                c.legs[i].deadline = None;
            }
            Step::Refresh => {
                // A working call is never ended by a refetch that gets no answer.
                // It keeps its settings and the next indication asks again.
                self.stats.refresh_timeouts = self.stats.refresh_timeouts.saturating_add(1);
                c.legs[i].step = Step::Up;
                c.legs[i].deadline = None;
            }
            Step::BindSub if c.emergency() => {
                self.stats.bind_refusals_passed = self.stats.bind_refusals_passed.saturating_add(1);
                self.send_set_family(c, i);
            }
            Step::SetFamily if c.emergency() => {
                self.stats.bind_refusals_passed = self.stats.bind_refusals_passed.saturating_add(1);
                self.send_ind_register(c, i);
            }
            _ => self.fail_leg(c, i, EndReason::Local(LocalReason::Timeout)),
        }
    }

    /// End a leg that never came up (or fell over) and release its resources.
    fn fail_leg(&mut self, c: &mut Call, i: usize, reason: EndReason) {
        let was_up = matches!(c.legs[i].outcome, Outcome::Up);
        let was_dead = c.legs[i].step == Step::Dead;
        self.kill_leg(c, i, reason);
        if was_up {
            c.legs[i].outcome = Outcome::Down(reason);
        }
        if c.params.attach && !was_dead {
            self.emit(Event::LegFailed {
                call: c.id,
                family: c.legs[i].family,
                reason,
            });
        }
    }

    /// An attached leg lost its call. The leg stays bound and registered, so a
    /// later call on the same link is followed too. The addresses go, and the
    /// link goes down when no family is left.
    fn attach_down(&mut self, c: &mut Call, i: usize, reason: EndReason) {
        let leg = &mut c.legs[i];
        for (addr, prefix) in leg.applied.drain(..) {
            let _ = self.net.del_address(&c.ifname, addr, prefix);
        }
        leg.outcome = Outcome::Pending;
        leg.step = Step::Wait;
        leg.probe = false;
        leg.look = Look::Done;
        leg.deadline = None;
        leg.settings = None;
        let family = leg.family;
        if !c.legs.iter().any(|l| l.outcome == Outcome::Up) {
            self.link_idle(c);
        }
        // the modem said the call ended: what the follower saw is over
        c.seen_connected = false;
        self.emit(Event::LegDown {
            call: c.id,
            family,
            reason,
        });
    }

    fn kill_leg(&mut self, c: &mut Call, i: usize, reason: EndReason) {
        let leg = &mut c.legs[i];
        if matches!(leg.outcome, Outcome::Pending | Outcome::Up) {
            leg.outcome = if leg.outcome == Outcome::Up {
                Outcome::Down(reason)
            } else {
                Outcome::Failed(reason)
            };
        }
        leg.step = Step::Dead;
        leg.deadline = None;
        for (addr, prefix) in leg.applied.drain(..) {
            let _ = self.net.del_address(&c.ifname, addr, prefix);
        }
        if let Some(cl) = leg.client.take() {
            self.clients.remove(&cl);
            self.qmi.close_client(cl);
        }
    }

    fn close_link(&mut self, c: &mut Call) {
        let created = c
            .link
            .and_then(|l| self.links.get(l))
            .is_some_and(|l| l.created);
        if created {
            self.link_idle(c);
        }
    }

    /// The link goes down, and IPv6 goes off on it when this call had switched it on.
    fn link_idle(&mut self, c: &mut Call) {
        let _ = self.net.set_link(&c.ifname, false, None);
        if std::mem::take(&mut c.ipv6_on) {
            let _ = self
                .net
                .set_ipv6(&c.ifname, Ipv6Settings { disable_ipv6: true });
        }
    }

    /// Give the link back so another call can use it.
    fn free_link(&mut self, c: &mut Call) {
        if let Some(l) = c.link.take() {
            if let Some(slot) = self.links.get_mut(l) {
                if slot.owner == Some(c.id) {
                    slot.owner = None;
                }
            }
        }
    }

    /// Final step of a call: link down, link free, one Disconnected event.
    fn finalize(&mut self, c: &mut Call, reason: EndReason) {
        if c.state == CallState::Closed {
            return;
        }
        for i in 0..c.legs.len() {
            if c.legs[i].step != Step::Dead {
                self.kill_leg(c, i, reason);
            }
        }
        self.close_link(c);
        // An attached call keeps its link until the data module releases it.
        if !c.params.attach {
            self.free_link(c);
        }
        c.state = CallState::Closed;
        self.emit(Event::Disconnected { call: c.id, reason });
    }

    /// Decide whether the call-level state changed after a leg changed.
    fn settle(&mut self, c: &mut Call) {
        match c.state {
            // Legs of an attached call wait for their call for as long as the link is
            // held. The call is over when no leg is left that could follow one.
            CallState::Active
                if c.params.attach
                    && !c.legs.is_empty()
                    && c.legs.iter().all(|l| l.step == Step::Dead) =>
            {
                let r = first_reason(c);
                self.finalize(c, r);
            }
            CallState::Active if c.params.attach => {}
            CallState::Active => {
                let pending = c.legs.iter().any(|l| l.outcome == Outcome::Pending);
                let up = c.legs.iter().filter(|l| l.outcome == Outcome::Up).count();
                if c.announced == Announced::Nothing {
                    if pending {
                        return;
                    }
                    if up == c.legs.len() {
                        c.announced = Announced::Connected;
                        self.emit(Event::Connected { call: c.id });
                    } else if up > 0 {
                        c.announced = Announced::Partial;
                        self.emit(Event::PartiallyConnected { call: c.id });
                    } else {
                        let r = first_reason(c);
                        self.finalize(c, r);
                    }
                } else if up == 0 && !pending {
                    let r = first_reason(c);
                    self.finalize(c, r);
                }
            }
            CallState::Stopping if c.legs.iter().all(|l| l.step == Step::Dead) => {
                self.finalize(c, EndReason::Local(LocalReason::UserRequested));
            }
            _ => {}
        }
    }

    fn begin_stop(&mut self, c: &mut Call) {
        match c.state {
            CallState::Closed | CallState::Stopping => {}
            CallState::WaitReady => {
                self.finalize(c, EndReason::Local(LocalReason::UserRequested));
            }
            CallState::Active => {
                c.state = CallState::Stopping;
                for i in 0..c.legs.len() {
                    let can_stop = c.legs[i].handle.is_some()
                        && matches!(
                            c.legs[i].step,
                            Step::Wait | Step::Settings | Step::Up | Step::Refresh
                        );
                    if can_stop {
                        let h = c.legs[i].handle.unwrap_or(0);
                        self.request(c, i, Step::Stop, true, |t| wds::stop_network(t, h));
                    } else if c.legs[i].step != Step::Dead {
                        // Nothing to stop yet, or the start is still in flight:
                        // closing the client makes the modem release it.
                        self.kill_leg(c, i, EndReason::Local(LocalReason::UserRequested));
                    }
                }
                self.settle(c);
            }
        }
    }

    // ---- receive path of one leg ---------------------------------------

    fn leg_rx(&mut self, c: &mut Call, i: usize, bytes: &[u8]) {
        let f = match Frame::parse(bytes) {
            Ok(f) => f,
            Err(_) => {
                self.stats.malformed = self.stats.malformed.saturating_add(1);
                return;
            }
        };
        match f.kind {
            Kind::Response => {
                // The transaction and the message must both be the ones asked for.
                if f.txn != c.legs[i].txn || Some(f.id) != c.legs[i].step.answers() {
                    self.stats.stale = self.stats.stale.saturating_add(1);
                    return;
                }
                self.leg_response(c, i, &f);
            }
            Kind::Indication => self.leg_indication(c, i, &f),
            Kind::Request => {}
        }
        self.settle(c);
    }

    fn leg_response(&mut self, c: &mut Call, i: usize, f: &Frame<'_>) {
        let ok = f.status().map(|s| s.is_ok()).unwrap_or(false);
        c.legs[i].deadline = None;
        match c.legs[i].step {
            Step::BindMux => {
                if !ok {
                    // A stale binding of this mux ID from a crashed daemon is a
                    // plausible cause. An emergency call tries one other link.
                    if self.relink_emergency(c) {
                        return;
                    }
                    return self.fail_leg(c, i, EndReason::Local(LocalReason::BindFailed));
                }
                self.send_bind_sub(c, i);
            }
            Step::BindSub => {
                if !ok {
                    // Without a SIM there may be no subscription to bind to,
                    // and an emergency call must still try. Anyone else on the
                    // wrong subscription would use the wrong SIM, so it ends.
                    if !c.emergency() {
                        return self.fail_leg(c, i, EndReason::Local(LocalReason::BindFailed));
                    }
                    self.stats.bind_refusals_passed =
                        self.stats.bind_refusals_passed.saturating_add(1);
                }
                self.send_set_family(c, i);
            }
            Step::SetFamily => {
                if !ok {
                    if !c.emergency() {
                        return self.fail_leg(c, i, EndReason::Local(LocalReason::BindFailed));
                    }
                    self.stats.bind_refusals_passed =
                        self.stats.bind_refusals_passed.saturating_add(1);
                }
                self.send_ind_register(c, i);
            }
            Step::IndReg => {
                // Optional: without it only later configuration changes go unnoticed.
                if !ok {
                    self.stats.ind_register_refusals =
                        self.stats.ind_register_refusals.saturating_add(1);
                }
                self.after_registration(c, i);
            }
            Step::Start => match wds::parse_start_network_response(f) {
                Ok(StartOutcome::Started { handle }) => {
                    c.legs[i].handle = Some(handle);
                    c.legs[i].step = Step::Wait;
                    if c.legs[i].early_connected {
                        self.request_settings(c, i, Step::Settings);
                    }
                }
                Ok(StartOutcome::Failed {
                    qmi_error,
                    call_end_reason,
                    verbose,
                }) => {
                    let r = match (verbose, call_end_reason) {
                        (Some((kind, reason)), _) => EndReason::Network { kind, reason },
                        (None, Some(b)) => EndReason::NetworkBasic(b),
                        (None, None) => EndReason::Qmi(qmi_error),
                    };
                    self.fail_leg(c, i, r);
                }
                Err(_) => self.fail_leg(c, i, EndReason::Local(LocalReason::Malformed)),
            },
            Step::Settings | Step::Refresh => {
                let refresh = c.legs[i].step == Step::Refresh;
                let parsed = wds::parse_runtime_settings(f, c.legs[i].family.wds());
                if parsed.is_err() && c.legs[i].probe {
                    // No call yet: wait for its packet status. An answer that says the request failed is
                    // no answer about the call.
                    c.legs[i].probe = false;
                    c.legs[i].look = match f.status() {
                        Ok(status) if !status.is_stack_failure() => Look::Done,
                        _ => Look::Failed,
                    };
                    c.legs[i].step = Step::Wait;
                    return;
                }
                if parsed.is_err() && refresh {
                    // A working call is never ended by an answer that does not parse. It keeps
                    // its settings, like after a refetch without an answer.
                    return self.keep_after_bad_refresh(c, i);
                }
                match parsed {
                    Ok(s) => {
                        self.stats.dropped_optional = self
                            .stats
                            .dropped_optional
                            .saturating_add(u32::from(s.dropped));
                        match self.apply(c, i, s, refresh) {
                            Ok(()) => {
                                c.legs[i].outcome = Outcome::Up;
                                c.legs[i].step = Step::Up;
                                c.legs[i].probe = false;
                                c.legs[i].look = Look::Done;
                                if c.params.attach && !refresh {
                                    self.emit(Event::LegUp {
                                        call: c.id,
                                        family: c.legs[i].family,
                                    });
                                }
                            }
                            // an answer without a usable address changes nothing on a working call
                            Err(LocalReason::BadSettings) if refresh => {
                                self.keep_after_bad_refresh(c, i)
                            }
                            Err(r) => self.fail_leg(c, i, EndReason::Local(r)),
                        }
                    }
                    Err(_) => self.fail_leg(c, i, EndReason::Local(LocalReason::BadSettings)),
                }
            }
            Step::Stop => {
                c.legs[i].outcome = match c.legs[i].outcome {
                    Outcome::Up => Outcome::Down(EndReason::Local(LocalReason::UserRequested)),
                    o => o,
                };
                self.kill_leg(c, i, EndReason::Local(LocalReason::UserRequested));
            }
            Step::Wait | Step::Up | Step::Dead => self.stats.stale += 1,
        }
    }

    /// A refetch of the settings of a working leg got an answer that is no use.
    fn keep_after_bad_refresh(&mut self, c: &mut Call, i: usize) {
        self.stats.refresh_bad = self.stats.refresh_bad.saturating_add(1);
        c.legs[i].step = Step::Up;
        c.legs[i].deadline = None;
    }

    fn request_settings(&mut self, c: &mut Call, i: usize, step: Step) {
        self.request(c, i, step, true, |t| {
            wds::get_runtime_settings(t, wds::settings::IMS)
        });
    }

    fn leg_indication(&mut self, c: &mut Call, i: usize, f: &Frame<'_>) {
        match f.id {
            wds::id::PACKET_SERVICE_STATUS => {
                let p = match wds::parse_packet_service_status(f) {
                    Ok(p) => p,
                    Err(_) => {
                        self.stats.malformed = self.stats.malformed.saturating_add(1);
                        return;
                    }
                };
                // The modem may tell every client bound to a mux about a call on it. An
                // indication that names the other IP family is not about this leg.
                if matches!(p.ip_family, Some(f) if f != wds::IpFamily::Unspecified && f != c.legs[i].family.wds())
                {
                    self.stats.other_family_indications =
                        self.stats.other_family_indications.saturating_add(1);
                    return;
                }
                match (p.status, c.legs[i].step) {
                    (ConnectionStatus::Connected, Step::Start) => c.legs[i].early_connected = true,
                    (ConnectionStatus::Connected, Step::Wait) => {
                        c.legs[i].probe = false;
                        c.legs[i].look = Look::Done;
                        self.request_settings(c, i, Step::Settings)
                    }
                    (ConnectionStatus::Connected, Step::Up) if p.reconfiguration_required => {
                        self.request_settings(c, i, Step::Refresh)
                    }
                    (ConnectionStatus::Disconnected, Step::Stop | Step::Dead) => {}
                    (ConnectionStatus::Disconnected, step) => {
                        let r = match (p.verbose, p.call_end_reason) {
                            (Some((kind, reason)), _) => EndReason::Network { kind, reason },
                            (None, Some(b)) => EndReason::NetworkBasic(b),
                            (None, None) => EndReason::Qmi(0),
                        };
                        if c.params.attach {
                            // Somebody else owns the call. Only a call we configured matters.
                            if matches!(step, Step::Up | Step::Refresh) {
                                self.attach_down(c, i, r);
                            }
                            return;
                        }
                        let was_up = c.legs[i].outcome == Outcome::Up;
                        self.fail_leg(c, i, r);
                        if was_up
                            && c.state == CallState::Active
                            && c.announced != Announced::Nothing
                        {
                            let others = c.legs.iter().any(|l| l.outcome == Outcome::Up);
                            if others {
                                self.emit(Event::Reconfigured { call: c.id });
                            }
                        }
                    }
                    _ => {}
                }
            }
            wds::id::EXTENDED_IP_CONFIG => {
                if wds::parse_extended_ip_config(f).is_err() {
                    self.stats.malformed = self.stats.malformed.saturating_add(1);
                } else if c.legs[i].step == Step::Up {
                    self.request_settings(c, i, Step::Refresh);
                }
            }
            _ => {}
        }
    }

    // ---- interface configuration ---------------------------------------

    fn apply(
        &mut self,
        c: &mut Call,
        i: usize,
        s: RuntimeSettings,
        refresh: bool,
    ) -> Result<(), LocalReason> {
        let name = c.ifname.clone();
        let fam = c.legs[i].family;
        let mut wanted: Vec<(IpAddr, u8, AddrFlags)> = Vec::new();
        match fam {
            Family::V4 => {
                let a = s.ipv4.ok_or(LocalReason::BadSettings)?;
                if !usable_v4(a) {
                    return Err(LocalReason::BadSettings);
                }
                let prefix = match s.ipv4_mask {
                    Some(m) => prefix_from_mask(m).ok_or(LocalReason::BadSettings)?,
                    None => 32,
                };
                wanted.push((IpAddr::V4(a), prefix, AddrFlags::default()));
            }
            Family::V6 => {
                let (a, prefix) = s.ipv6.ok_or(LocalReason::BadSettings)?;
                if !usable_v6(a) || prefix == 0 {
                    return Err(LocalReason::BadSettings);
                }
                // The network assigns the interface identifier, so the link-local
                // address uses the same one.
                wanted.push((
                    IpAddr::V6(link_local_from(a)),
                    64,
                    AddrFlags {
                        no_dad: true,
                        no_prefix_route: false,
                    },
                ));
                wanted.push((
                    IpAddr::V6(a),
                    prefix,
                    AddrFlags {
                        no_dad: true,
                        no_prefix_route: true,
                    },
                ));
            }
        }
        // Link MTU: the smallest of what the connected families report, but
        // never below what IPv6 needs. Linux turns IPv6 off on a smaller link.
        let mut mtu = s.mtu.filter(|m| *m >= 576);
        // An IPv6 leg that has not failed counts even before it is up: the link
        // is brought up with the first family and must not start below 1280.
        let v6_active = c.legs.iter().any(|l| {
            l.family == Family::V6 && !matches!(l.outcome, Outcome::Failed(_) | Outcome::Down(_))
        });
        for (j, l) in c.legs.iter().enumerate() {
            if j != i && l.outcome == Outcome::Up {
                if let Some(m) = l.settings.as_ref().and_then(|x| x.mtu) {
                    mtu = Some(mtu.map_or(m, |cur| cur.min(m)));
                }
            }
        }
        if v6_active {
            mtu = mtu.map(|m| m.max(MIN_IPV6_MTU));
        }
        let old_mtu = c.legs[i].settings.as_ref().and_then(|x| x.mtu);

        if let Err(e) = self.configure(c, i, &name, fam, mtu, &wanted, refresh) {
            // The kernel does not know the link any more: make the next call create it again.
            if e == NetError::NotFound {
                if let Some(l) = c.link.and_then(|l| self.links.get_mut(l)) {
                    l.created = false;
                    l.mux_added = false;
                }
            }
            return Err(LocalReason::LinkFailed);
        }
        c.link_mtu = mtu;
        let leg = &mut c.legs[i];
        let new_mtu = s.mtu;
        leg.settings = Some(s);
        // A call the module started is followed and never announced, but its changes
        // are told all the same.
        if refresh && (c.params.attach || c.announced != Announced::Nothing) {
            if new_mtu != old_mtu {
                if let Some(m) = new_mtu {
                    self.emit(Event::MtuChanged {
                        call: c.id,
                        family: fam,
                        mtu: m,
                    });
                }
            }
            self.emit(Event::Reconfigured { call: c.id });
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn configure(
        &mut self,
        c: &mut Call,
        i: usize,
        name: &str,
        fam: Family,
        mtu: Option<u32>,
        wanted: &[(IpAddr, u8, AddrFlags)],
        refresh: bool,
    ) -> Result<(), NetError> {
        if fam == Family::V6 && !refresh {
            self.net.set_ipv6(
                name,
                Ipv6Settings {
                    disable_ipv6: false,
                },
            )?;
            c.ipv6_on = true;
        }
        self.net.set_link(name, true, mtu)?;

        // Remove addresses that are no longer wanted, then add the new ones.
        let leg = &mut c.legs[i];
        let keep: Vec<(IpAddr, u8)> = wanted.iter().map(|(a, p, _)| (*a, *p)).collect();
        let (stale, kept): (Vec<_>, Vec<_>) =
            leg.applied.drain(..).partition(|x| !keep.contains(x));
        for (a, p) in stale {
            let _ = self.net.del_address(name, a, p);
        }
        leg.applied = kept;
        for (a, p, flags) in wanted {
            if !leg.applied.contains(&(*a, *p)) {
                self.net.add_address(name, *a, *p, *flags)?;
                leg.applied.push((*a, *p));
            }
        }
        Ok(())
    }
}

fn pipe_from(s: PipeState) -> Pipe {
    match s {
        PipeState::Missing => Pipe::Missing,
        PipeState::Pending => Pipe::Maybe,
        PipeState::Done => Pipe::Done,
    }
}

fn new_leg(family: Family) -> Leg {
    Leg {
        family,
        client: None,
        step: Step::BindMux,
        txn: 0,
        deadline: None,
        handle: None,
        early_connected: false,
        probe: false,
        look: Look::Pending,
        settings: None,
        applied: Vec::new(),
        outcome: Outcome::Pending,
    }
}

fn first_reason(c: &Call) -> EndReason {
    c.legs
        .iter()
        .find_map(|l| match l.outcome {
            Outcome::Failed(r) | Outcome::Down(r) => Some(r),
            _ => None,
        })
        .unwrap_or(EndReason::Local(LocalReason::Malformed))
}

fn usable_v4(a: Ipv4Addr) -> bool {
    !(a.is_unspecified()
        || a.is_loopback()
        || a.is_multicast()
        || a.is_broadcast()
        || a.is_link_local())
}

fn usable_v6(a: Ipv6Addr) -> bool {
    !(a.is_unspecified() || a.is_loopback() || a.is_multicast())
        && (a.segments()[0] & 0xffc0) != 0xfe80
}

/// fe80::/64 address with the interface identifier (low 64 bits) of `a`.
pub fn link_local_from(a: Ipv6Addr) -> Ipv6Addr {
    let s = a.segments();
    Ipv6Addr::new(0xfe80, 0, 0, 0, s[4], s[5], s[6], s[7])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_local_uses_the_assigned_identifier() {
        let a: Ipv6Addr = "2001:db8:1:2:a:b:c:d".parse().unwrap();
        assert_eq!(
            link_local_from(a),
            "fe80::a:b:c:d".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn address_sanity() {
        assert!(usable_v4("192.0.2.1".parse().unwrap()));
        assert!(!usable_v4("0.0.0.0".parse().unwrap()));
        assert!(!usable_v4("169.254.1.1".parse().unwrap()));
        assert!(!usable_v4("224.0.0.1".parse().unwrap()));
        assert!(usable_v6("2001:db8::1".parse().unwrap()));
        assert!(!usable_v6("fe80::1".parse().unwrap()));
        assert!(!usable_v6("ff02::1".parse().unwrap()));
        assert!(!usable_v6("::".parse().unwrap()));
    }
}
