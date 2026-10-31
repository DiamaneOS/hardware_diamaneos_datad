// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Maps connections of the private protocol onto the engine. The closed data
//! module starts its network calls itself. The daemon answers its route lookup
//! with a link, follows the call on that link, configures the link and tells
//! the module with interface events, which is what the stock nicmd does.
//! Each connection has its own links and cannot touch those of another one. A
//! connection that goes away releases its links. Peers are admitted by UID and
//! by SELinux label, and an ordinary call may not take more than its
//! connection's share of the links, so one radio daemon instance cannot starve
//! the other or the emergency reserve.
use crate::convert;
use crate::table::{self, Dead, Proc, Row};
use dataos_datacore::engine::{Engine, Qmi, ServiceEvent};
use dataos_datacore::trace::{self, Trace};
use dataos_datacore::Look;
use dataos_datacore::{
    CallId, ClientId, Event, Family, LookupHint, LookupQuery, Priority, StartError,
};
use dataos_netcfg::NetOps;
use dataos_wire::{DecodeError, IfaceEvent, MatchHint, Notify, Request, ResultCode, RouteRequest};
use std::collections::BTreeMap;
use std::net::IpAddr;

pub type ConnId = u32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// The peer's UID is not in the allow list.
    Uid,
    /// The peer's SELinux label is not in the allow list.
    Label,
    TooManyConnections,
}

/// What a route lookup was for. A later lookup for the other family of the same
/// APN and type belongs on the same link.
#[derive(Clone, PartialEq, Eq)]
struct LinkKey {
    slot: u8,
    apn: Option<String>,
    apn_type: u32,
    apn_type_mask: u64,
}

struct LinkState {
    call: CallId,
    key: LinkKey,
    emergency: bool,
    /// Families the module asked a link for. The other one is followed too, because the
    /// module may start it without a lookup, but its failures are not the module's business.
    requested: [bool; 2],
    /// Address and MTU the module was told, per family (v4, v6).
    addr: [Option<(IpAddr, u8)>; 2],
    mtu: [Option<u32>; 2],
    /// The MTU triple (link, v4, v6) the module has, 0 for unknown. It starts at 0 like nicmd's.
    triple: [u32; 3],
    /// The module was told the link is up. Until then it hears nothing but up and down.
    announced: bool,
    /// The module was told the link is up and has not been told it is down, which includes what it was
    /// told before the daemon restarted. A restored link has this and not `announced` until its follower
    /// sees the call. Every way the link can end while this is set owes the module a Down.
    told: bool,
    /// The number was on restart hold when it was handed out (an emergency lookup, the last fallback of
    /// the pool), so a release the module sends for it until the hold ends is taken to be the late
    /// release of the call that held it before the restart. Each is answered "ok" and not carried out
    /// (0: no mark). The cost: a real release in that time is swallowed too, and the link stays for
    /// the reclaim to take back.
    swallow_until: u64,
    /// A release was swallowed already. The first is the late release of the old call, a second one is the
    /// module giving the new start up.
    swallowed: bool,
    /// The module released the link twice in the time of the mark, so it gave the start up. The link
    /// is no emergency start in progress any more.
    gave_up: bool,
    /// The hand-out (a repeated lookup is a new hand-out, nicmd stamps the same moment and takes an
    /// interface back that has not come up 30 s after it), or the last time the modem was asked
    /// whether a call is up on this link, which is a new start of the 30 s too.
    checked_at: u64,
    /// The token of that question while it is open.
    check: Option<u32>,
}

/// The MTU event nicmd would post after this family's MTU was set: none when the triple did not
/// change or when no part that was known (and not 0) changed.
fn mtu_event(st: &mut LinkState, family: Family) -> Option<IfaceEvent> {
    let v4 = st.mtu[0].unwrap_or(0);
    let v6 = st.mtu[1].unwrap_or(0);
    let new = [dataos_nicm_abi::link_mtu(v4, v6), v4, v6];
    let old = std::mem::replace(&mut st.triple, new);
    let moved = old.iter().zip(new.iter()).any(|(o, n)| *o != 0 && o != n);
    let mtu = st.mtu[slot_of(family)]?;
    moved.then_some(IfaceEvent::MtuUpdate {
        family: convert::family(family),
        mtu,
    })
}

/// What a module that takes a link over is told: the state of the link as the daemon has it. The
/// events that went to a connection that closed, or were in flight when it did, are not recovered
/// one by one. A module that heard some of them again has the same state.
fn replay(c: &mut Conn, link: u8, st: &mut LinkState) {
    if st.up_families() == 0 {
        return;
    }
    st.told = true;
    let slot = st.key.slot;
    let mut tell = |event| c.queue(Notify::Event { link, slot, event });
    tell(IfaceEvent::Up);
    for fam in [Family::V4, Family::V6] {
        let i = slot_of(fam);
        if let Some((addr, prefix)) = st.addr[i] {
            if let Some(mtu) = st.mtu[i] {
                tell(IfaceEvent::MtuUpdate {
                    family: convert::family(fam),
                    mtu,
                });
            }
            tell(IfaceEvent::NewAddr {
                family: convert::family(fam),
                addr,
                prefix,
            });
        }
    }
}

fn row_of(link: u8, proc: Proc, st: &LinkState) -> Row {
    Row {
        link,
        proc,
        slot: st.key.slot,
        apn: st.key.apn.clone(),
        apn_type: st.key.apn_type,
        apn_type_mask: st.key.apn_type_mask,
        emergency: st.emergency,
        told: st.told,
        requested: st.requested,
    }
}

fn slot_of(f: Family) -> usize {
    match f {
        Family::V4 => 0,
        Family::V6 => 1,
    }
}

impl LinkState {
    fn up_families(&self) -> usize {
        self.addr.iter().flatten().count()
    }
}

/// A question to the modem for a call the module could use again, and who asked it.
struct PendingMatch {
    conn: ConnId,
    txn: u32,
    slot: u8,
    apn: Option<String>,
    apn_type: u32,
    apn_type_mask: u64,
}

/// The owner of the links of a connection that closed.
const ORPHAN: ConnId = 0;

struct Orphan {
    st: LinkState,
    until: u64,
    /// The process that held it. Only a connection of the same process gets it back.
    proc: Proc,
}

/// A link whose call went down while its connection was closed. The number stays on hold until the
/// process has reconnected and been told, or the time is over.
struct Tombstone {
    proc: Proc,
    slot: u8,
    reason: dataos_wire::EndReason,
    until: u64,
    /// The connection the Down is queued to. The tombstone stays, in the table too, and the number stays on
    /// hold, until the daemon says the Down was written to the socket (`Server::written`), because a Down that
    /// is queued only is lost with the daemon, and with the connection that is closed before it is written.
    sent_to: Option<ConnId>,
}

/// A restored call the module was told is up, to be confirmed or lost.
#[derive(Clone, Copy, Default)]
struct Verify {
    /// The earliest time of the next question (0: when the follower has looked).
    next: u64,
    /// How many times the call was found unlooked: its follower could not look, and the modem did not name it.
    unlooked: u8,
}

/// How many questions about a restored call whose follower could not look are asked, one after the other,
/// before the call is left as it is. A call is never lost for the modem's answer to those.
const MAX_UNLOOKED: u8 = 3;

/// Who has a link.
enum Holder {
    Conn(ConnId),
    Orphan(Proc),
}

/// What a module is told when its call ended while it could not hear why: the link failed.
fn owed_reason() -> dataos_wire::EndReason {
    convert::reason(dataos_datacore::EndReason::Local(
        dataos_datacore::LocalReason::LinkFailed,
    ))
}

/// Notifications queued for one connection that the main loop has not taken. A client
/// that stops reading cannot make the daemon's memory grow: the rest is dropped and the
/// connection is marked, so the main loop closes it.
pub const MAX_QUEUED: usize = 256;

struct Conn {
    proc: Proc,
    links: BTreeMap<u8, LinkState>,
    out: Vec<Notify>,
    overflowed: bool,
    /// The module has been told what it missed: the library hands the module the events of the daemon
    /// only after INIT_DONE, and DSI drops every event but a few while it is not inited. So what a connection
    /// takes over (links of its process, Downs it is owed) is queued after the answer to its Hello that says
    /// the daemon is ready, or after the Ready message, and the events of its links wait until then. Every
    /// connection starts untold, and `deliver` is the only way to be told.
    told: bool,
}

impl Conn {
    fn queue(&mut self, n: Notify) {
        if self.out.len() >= MAX_QUEUED {
            self.overflowed = true;
        } else {
            self.out.push(n);
        }
    }
}

pub struct ServerConfig {
    /// UIDs allowed to connect (the radio UID).
    pub allowed_uids: Vec<u32>,
    /// SELinux contexts allowed to connect, compared as a whole (`SO_PEERSEC`).
    /// The policy is the real gate, this keeps a second process that shares
    /// the UID out even if the policy slips.
    pub allowed_labels: Vec<String>,
    pub max_connections: usize,
    /// Links an ordinary call may hold per connection. None: half of the
    /// links that are not reserved, rounded up.
    pub max_links_per_connection: Option<usize>,
    /// The bit of the APN type mask that marks an emergency call. 512 is
    /// `ApnSetting.TYPE_EMERGENCY` of Android **[I]**: the mask the module passes
    /// to its route lookup is taken for Android's. The stock logs settle it.
    pub emergency_mask: u64,
    /// The APN type value of an emergency call (the module's `apn_type`). The bit alone
    /// does not decide: a profile that lists emergency among its types is an ordinary call.
    /// Android's `TYPE_EMERGENCY` again **[I]**, the stock logs settle it.
    pub emergency_apn_type: u32,
    /// How long a link freed by a modem restart is kept out of the pool, so that the
    /// module's late release of the old call cannot hit a new one. Milliseconds.
    pub restart_hold_ms: u64,
    /// How long the links of a closed connection are kept, so that a module that
    /// reconnects finds its calls where it left them. Milliseconds. It is clearly longer than the
    /// longest pause of the library between two tries to reconnect (30 s), or a daemon that was away
    /// for a while would find its modules' calls gone the moment they came back.
    pub orphan_grace_ms: u64,
    /// How long a link that nothing has been up on stays with the module before a new call may
    /// take it back (nicmd: 30 s). Milliseconds.
    pub unused_release_ms: u64,
    /// How long to wait before asking again about a restored call when the modem did not answer.
    pub verify_retry_ms: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            allowed_uids: vec![1001],
            allowed_labels: vec!["u:r:rild:s0".into()],
            max_connections: 4,
            max_links_per_connection: None,
            emergency_mask: 512,
            emergency_apn_type: 512,
            restart_hold_ms: 30_000,
            orphan_grace_ms: 90_000,
            unused_release_ms: 30_000,
            verify_retry_ms: 5_000,
        }
    }
}

pub struct Server<Q: Qmi, N: NetOps> {
    cfg: ServerConfig,
    link_quota: usize,
    engine: Engine<Q, N>,
    conns: BTreeMap<ConnId, Conn>,
    owner: BTreeMap<CallId, (ConnId, u8)>,
    /// Links of connections that closed with a call up, and until when they are kept.
    orphans: BTreeMap<u8, Orphan>,
    next_conn: ConnId,
    last_ready: bool,
    screen_on: bool,
    /// Events held back because the module had not been told the link was up (nicmd's gate).
    dropped_before_up: u32,
    swallowed_releases: u32,
    kept_releases: u32,
    reclaimed_links: u32,
    /// Matching-call questions the modem has not answered, by the token of the engine's lookup.
    pending_matches: BTreeMap<u32, PendingMatch>,
    /// Questions about a link that has not come up, by token, with the link they are about.
    pending_checks: BTreeMap<u32, u8>,
    next_lookup: u32,
    /// Links that went down while their process was away, by number.
    tombstones: BTreeMap<u8, Tombstone>,
    /// Restored links the module had been told were up: the modem is asked whether the call is still there,
    /// once the follower has looked for it, and again later when the modem did not answer. The value is the
    /// earliest time of the next question (0: when the follower is ready).
    verify: BTreeMap<u8, Verify>,
    /// Restored calls found unlooked, counted without identifiers.
    unlooked_checks: u32,
    /// Until when each number is on the hold of a modem restart, apart from the hold of a tombstone.
    restart_holds: BTreeMap<u8, u64>,
    /// The time of the last call into the server, for the places that have none (`drain`).
    now: u64,
    /// Questions about unused links that got no usable answer: a modem that refuses the route lookup shows here.
    unanswered_checks: u32,
    /// The table of links of an earlier instance was looked at (once, when the engine became ready).
    restored: bool,
    restored_links: u32,
    last_saved: Vec<u8>,
    boot: String,
    save_failures: u32,
    /// Readiness questions answered so far, not ready and ready, and requests refused, by request and code.
    /// They only decide which lines go to the log.
    hello_answers: [u32; 2],
    refusals: BTreeMap<(&'static str, u8), u32>,
}

/// Questions about links that have not come up that may be open at once. The rest of the engine's
/// places are for the questions of matching calls, which a thread of the module waits for.
const MAX_CHECKS: usize = 4;

impl<Q: Qmi, N: NetOps> Server<Q, N> {
    pub fn new(cfg: ServerConfig, engine: Engine<Q, N>) -> Self {
        let normal = engine.link_total().saturating_sub(engine.reserved_links());
        let link_quota = cfg
            .max_links_per_connection
            .unwrap_or_else(|| normal.div_ceil(2));
        Server {
            cfg,
            link_quota,
            engine,
            conns: BTreeMap::new(),
            owner: BTreeMap::new(),
            orphans: BTreeMap::new(),
            next_conn: 1,
            last_ready: false,
            screen_on: true,
            dropped_before_up: 0,
            swallowed_releases: 0,
            kept_releases: 0,
            reclaimed_links: 0,
            pending_matches: BTreeMap::new(),
            pending_checks: BTreeMap::new(),
            next_lookup: 1,
            tombstones: BTreeMap::new(),
            verify: BTreeMap::new(),
            unlooked_checks: 0,
            restart_holds: BTreeMap::new(),
            now: 0,
            unanswered_checks: 0,
            restored: false,
            restored_links: 0,
            last_saved: Vec::new(),
            boot: String::new(),
            save_failures: 0,
            hello_answers: [0; 2],
            refusals: BTreeMap::new(),
        }
    }

    pub fn engine(&mut self) -> &mut Engine<Q, N> {
        &mut self.engine
    }

    /// Links an ordinary call of one connection may hold.
    pub fn link_quota(&self) -> usize {
        self.link_quota
    }

    /// Releases the module sent for a number that had been on hold when it was handed out, answered
    /// "ok" and not carried out (once per hand-out). The host writes the count, it names nobody.
    pub fn swallowed_releases(&self) -> u32 {
        self.swallowed_releases
    }

    /// Releases of a link with a call up on it, answered "ok" and not carried out (nicmd does the same
    /// when the modem reports the call). The host writes the count, it names nobody.
    pub fn kept_releases(&self) -> u32 {
        self.kept_releases
    }

    /// Links taken back from a connection that had left them unused. Counted without identifiers.
    pub fn reclaimed_links(&self) -> u32 {
        self.reclaimed_links
    }

    /// Matching-call questions that wait for the modem, for the host's status line.
    /// Links taken back from the table of an earlier instance.
    pub fn restored_links(&self) -> u32 {
        self.restored_links
    }

    /// Times the table of links could not be written.
    pub fn save_failures(&self) -> u32 {
        self.save_failures
    }

    pub fn open_questions(&self) -> usize {
        self.pending_matches.len()
    }

    /// Questions about links that have not come up that wait for the modem.
    pub fn open_checks(&self) -> usize {
        self.pending_checks.len()
    }

    /// Restored calls that are still to be confirmed or lost.
    pub fn verifying(&self) -> usize {
        self.verify.len()
    }

    /// Questions about unused links that the modem did not answer or refused. Counted without identifiers,
    /// so a modem that does not take the route lookup shows in the logs.
    pub fn unanswered_checks(&self) -> u32 {
        self.unanswered_checks
    }

    /// The time of the last call into the server, for a caller that has no time of its own at hand.
    pub fn last_now(&self) -> u64 {
        self.now
    }

    /// How many times a restored call was kept although its follower could not look for it and the modem did
    /// not name it. A call is never lost for that.
    pub fn unlooked_checks(&self) -> u32 {
        self.unlooked_checks
    }

    /// How the first look of the follower of the call on this link went, if the link has a call.
    pub fn look_of(&self, link: u8) -> Option<Look> {
        let call = self
            .conns
            .values()
            .find_map(|c| c.links.get(&link))
            .or_else(|| self.orphans.get(&link).map(|o| &o.st))?
            .call;
        Some(self.engine.call_look(call))
    }

    /// Downs that processes are owed, for the status line.
    pub fn owed_downs(&self) -> usize {
        self.tombstones.len()
    }

    /// How many events were held back because the link was not announced up yet.
    pub fn dropped_before_up(&self) -> u32 {
        self.dropped_before_up
    }

    /// The last screen state the module reported. Nothing depends on it.
    pub fn screen_on(&self) -> bool {
        self.screen_on
    }

    /// A peer connects. `peer_pid` is the process of the peer (`SO_PEERCRED`), whose start time is not known.
    pub fn accept(
        &mut self,
        peer_pid: u32,
        peer_uid: u32,
        peer_label: &str,
    ) -> Result<ConnId, Reject> {
        let proc = Proc {
            pid: peer_pid,
            ino: 0,
        };
        self.accept_proc(proc, peer_uid, peer_label)
    }

    /// A peer connects. The links an earlier connection of the same process left are this connection's
    /// now: the module keeps its calls across the loss of the connection and names nothing. They and the
    /// Downs the process is owed are queued after the answer to its Hello (see `Conn::told`).
    pub fn accept_proc(
        &mut self,
        proc: Proc,
        peer_uid: u32,
        peer_label: &str,
    ) -> Result<ConnId, Reject> {
        if !self.cfg.allowed_uids.contains(&peer_uid) {
            return Err(Reject::Uid);
        }
        if !self.cfg.allowed_labels.iter().any(|l| l == peer_label) {
            return Err(Reject::Label);
        }
        if self.conns.len() >= self.cfg.max_connections {
            return Err(Reject::TooManyConnections);
        }
        let id = self.next_conn;
        self.next_conn = self.next_conn.wrapping_add(1);
        let mine: Vec<u8> = self
            .orphans
            .iter()
            .filter(|(_, o)| o.proc == proc)
            .map(|(l, _)| *l)
            .collect();
        let mut links = BTreeMap::new();
        for link in mine {
            if let Some(o) = self.orphans.remove(&link) {
                self.owner.insert(o.st.call, (id, link));
                links.insert(link, o.st);
            }
        }
        self.conns.insert(
            id,
            Conn {
                proc,
                links,
                out: Vec::new(),
                overflowed: false,
                told: false,
            },
        );
        Ok(id)
    }

    /// Tell a connection what it missed, once, when the daemon is ready: the state of the links it took over
    /// and the Down of every call that ended while its process was away. The Down is queued here and stays
    /// owed, with its number on hold, until the daemon says it was written (`written`).
    fn deliver(&mut self, conn: ConnId) {
        let Some(c) = self.conns.get_mut(&conn) else {
            return;
        };
        if c.told {
            return;
        }
        c.told = true;
        let proc = c.proc;
        let mut kept = std::mem::take(&mut c.links);
        for (link, st) in &mut kept {
            replay(c, *link, st);
        }
        c.links = kept;
        let owed: Vec<u8> = self
            .tombstones
            .iter()
            .filter(|(_, t)| t.proc == proc && t.sent_to.is_none())
            .map(|(l, _)| *l)
            .collect();
        for link in owed {
            self.queue_down(conn, link);
        }
    }

    /// Queue the Down a tombstone owes to a connection of its process, which stays owed until it is written.
    fn queue_down(&mut self, conn: ConnId, link: u8) {
        let Some(t) = self.tombstones.get_mut(&link) else {
            return;
        };
        t.sent_to = Some(conn);
        let (slot, reason) = (t.slot, t.reason);
        if let Some(c) = self.conns.get_mut(&conn) {
            c.queue(Notify::Event {
                link,
                slot,
                event: IfaceEvent::Down(reason),
            });
        }
    }

    /// The daemon wrote the Down of this link to the socket of the connection: it is not owed any more and the
    /// number is free, except for the hold of a modem restart that is still running.
    pub fn written(&mut self, conn: ConnId, link: u8) {
        if self
            .tombstones
            .get(&link)
            .is_none_or(|t| t.sent_to != Some(conn))
        {
            return;
        }
        self.tombstones.remove(&link);
        self.release_hold(link);
        self.save_links();
    }

    /// Give the number back to the pool, apart from the hold of a modem restart that is still running.
    fn release_hold(&mut self, link: u8) {
        let restart = self
            .restart_holds
            .get(&link)
            .copied()
            .filter(|e| *e > self.now);
        if restart.is_none() {
            self.restart_holds.remove(&link);
        }
        self.engine
            .hold_link(usize::from(link), restart.unwrap_or(0));
    }

    /// The newest connection of this process that has been told what it missed, if one is open. The library
    /// connects again before it lets the old connection go, so the newest is the one that listens.
    fn told_conn_of(&self, proc: Proc) -> Option<ConnId> {
        self.conns
            .iter()
            .rev()
            .find(|(_, c)| c.told && c.proc == proc)
            .map(|(id, _)| *id)
    }

    /// The connection of this process, if one is open.
    fn conn_of(&self, proc: Proc) -> Option<ConnId> {
        self.conns
            .iter()
            .find(|(_, c)| c.proc == proc)
            .map(|(id, _)| *id)
    }

    /// Give a link to an open connection: its events go there from now on, and its state is replayed when the
    /// connection has been told what it missed (a connection that has not been will get it with the rest).
    fn hand_to(&mut self, conn: ConnId, link: u8, mut st: LinkState) {
        self.owner.insert(st.call, (conn, link));
        if let Some(c) = self.conns.get_mut(&conn) {
            if c.told {
                replay(c, link, &mut st);
            }
            c.links.insert(link, st);
        }
    }

    /// The connection closed. Its links stay for `orphan_grace_ms` for a connection of the same process,
    /// the calls that are up and the starts that are pending alike, and are freed when no one comes.
    pub fn close(&mut self, now: u64, conn: ConnId) {
        self.now = now;
        // nobody is left to hear the answer to its open questions
        let open: Vec<u32> = self
            .pending_matches
            .iter()
            .filter(|(_, p)| p.conn == conn)
            .map(|(t, _)| *t)
            .collect();
        for token in open {
            self.pending_matches.remove(&token);
            self.engine.cancel_lookup(token);
        }
        // what was queued for it and not written is still owed
        let mut given_back: Vec<(u8, Proc)> = Vec::new();
        for (link, t) in self
            .tombstones
            .iter_mut()
            .filter(|(_, t)| t.sent_to == Some(conn))
        {
            t.sent_to = None;
            given_back.push((*link, t.proc));
        }
        if let Some(c) = self.conns.remove(&conn) {
            let until = now.saturating_add(self.cfg.orphan_grace_ms);
            // A new connection of the same process may be open already: the library reconnects before
            // the old one is seen to close. The links are its.
            let mate = self.conn_of(c.proc);
            for (link, st) in c.links {
                if let Some(m) = mate {
                    self.hand_to(m, link, st);
                    continue;
                }
                self.owner.insert(st.call, (ORPHAN, link));
                self.orphans.insert(
                    link,
                    Orphan {
                        st,
                        until,
                        proc: c.proc,
                    },
                );
            }
        }
        // a connection of the process that has been told what it missed gets what the closed one did not take
        for (link, proc) in given_back {
            if let Some(m) = self.told_conn_of(proc) {
                self.queue_down(m, link);
            }
        }
        self.route_events(now);
    }

    /// Free the links of closed connections whose time is over. A connection of the process that is open
    /// by now gets the link instead. A link the module was told is up ends with a Down it gets when it comes back.
    fn expire_orphans(&mut self, now: u64) {
        self.tombstones.retain(|_, t| t.until > now);
        let due: Vec<u8> = self
            .orphans
            .iter()
            .filter(|(_, o)| o.until <= now)
            .map(|(l, _)| *l)
            .collect();
        for link in due {
            let Some(o) = self.orphans.remove(&link) else {
                continue;
            };
            if let Some(m) = self.conn_of(o.proc) {
                self.hand_to(m, link, o.st);
                continue;
            }
            let (proc, slot, told) = (o.proc, o.st.key.slot, o.st.told);
            self.drop_link(now, o.st);
            if told {
                let until = self.grace_end(now);
                self.owe(link, proc, slot, owed_reason(), until);
            }
        }
    }

    /// The end of the grace that starts now.
    fn grace_end(&self, now: u64) -> u64 {
        now.saturating_add(self.cfg.orphan_grace_ms)
    }

    /// The one place that makes a tombstone: the Down a process is owed for a link, and the number kept
    /// until the Down was written or `until`. A connection of the process that has been told what it missed
    /// gets the Down at once, otherwise the next one that is told gets it.
    fn owe(&mut self, link: u8, proc: Proc, slot: u8, reason: dataos_wire::EndReason, until: u64) {
        self.tombstones.insert(
            link,
            Tombstone {
                proc,
                slot,
                reason,
                until,
                sent_to: None,
            },
        );
        let held = self.engine.link_hold_until(usize::from(link));
        self.engine.hold_link(usize::from(link), until.max(held));
        if let Some(conn) = self.told_conn_of(proc) {
            self.queue_down(conn, link);
        }
    }

    /// Let go of a link: its questions to the modem, its owner entry and its call.
    fn drop_link(&mut self, now: u64, st: LinkState) {
        if let Some(t) = st.check {
            self.pending_checks.remove(&t);
            self.engine.cancel_lookup(t);
        }
        if let Some((_, link)) = self.owner.remove(&st.call) {
            self.verify.remove(&link);
        }
        let _ = self.engine.release_call(now, st.call);
    }

    /// Take a link out of whoever holds it.
    fn take_link(&mut self, link: u8) -> Option<LinkState> {
        self.take_holder(link).map(|(st, _)| st)
    }

    /// The same, and who held it.
    fn take_holder(&mut self, link: u8) -> Option<(LinkState, Holder)> {
        for (id, c) in &mut self.conns {
            if let Some(st) = c.links.remove(&link) {
                return Some((st, Holder::Conn(*id)));
            }
        }
        self.orphans
            .remove(&link)
            .map(|o| (o.st, Holder::Orphan(o.proc)))
    }

    /// End a link that the module has not asked to release. When the module was told the link is up, it is
    /// told it is down: now when its connection has been told what it missed, otherwise when it is.
    fn end_with_down(&mut self, now: u64, link: u8, reason: dataos_wire::EndReason) {
        let Some((st, holder)) = self.take_holder(link) else {
            return;
        };
        let (slot, told) = (st.key.slot, st.told);
        self.drop_link(now, st);
        if !told {
            return;
        }
        let proc = match holder {
            Holder::Conn(id) => match self.conns.get(&id) {
                Some(c) => c.proc,
                None => return,
            },
            Holder::Orphan(proc) => proc,
        };
        let until = self.grace_end(now);
        self.owe(link, proc, slot, reason, until);
    }

    fn link_state_mut(&mut self, link: u8) -> Option<&mut LinkState> {
        for c in self.conns.values_mut() {
            if c.links.contains_key(&link) {
                return c.links.get_mut(&link);
            }
        }
        self.orphans.get_mut(&link).map(|o| &mut o.st)
    }

    /// Take what is queued for a connection and take it as written: for a caller that is the transport, the
    /// tests. The daemon uses `drain_encoded` and tells `written` when the socket took each Down.
    pub fn drain(&mut self, conn: ConnId) -> Vec<Notify> {
        let taken = self
            .conns
            .get_mut(&conn)
            .map(|c| std::mem::take(&mut c.out))
            .unwrap_or_default();
        for n in &taken {
            if let Notify::Event {
                link,
                event: IfaceEvent::Down(_),
                ..
            } = n
            {
                self.written(conn, *link);
            }
        }
        taken
    }

    /// The connection did not take its notifications and some were dropped. The caller closes it.
    pub fn overflowed(&self, conn: ConnId) -> bool {
        self.conns.get(&conn).is_some_and(|c| c.overflowed)
    }

    /// Put notifications back at the front of a connection's queue (for tests that look at one kind).
    pub fn conns_requeue(&mut self, conn: ConnId, mut back: Vec<Notify>) {
        if let Some(c) = self.conns.get_mut(&conn) {
            back.append(&mut c.out);
            c.out = back;
        }
    }

    /// Queued notifications as datagrams. Every message fits the protocol by
    /// construction, one that does not encode is dropped.
    /// A Down in it stays owed until the caller says `written`.
    pub fn drain_encoded(&mut self, conn: ConnId) -> Vec<Vec<u8>> {
        self.conns
            .get_mut(&conn)
            .map(|c| std::mem::take(&mut c.out))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|n| n.encode().ok())
            .collect()
    }

    /// One datagram from a connection. A message that does not decode is a
    /// protocol violation and the caller closes the connection.
    pub fn on_datagram(&mut self, now: u64, conn: ConnId, bytes: &[u8]) -> Result<(), DecodeError> {
        let req = Request::decode(bytes)?;
        self.request(now, conn, req);
        Ok(())
    }

    pub fn on_qmi(&mut self, now: u64, client: ClientId, bytes: &[u8]) {
        self.now = now;
        self.engine.on_qmi(now, client, bytes);
        self.after_engine(now);
    }

    pub fn on_service_event(&mut self, now: u64, ev: ServiceEvent) {
        self.now = now;
        self.engine.on_service_event(now, ev);
        self.after_engine(now);
    }

    pub fn tick(&mut self, now: u64) {
        self.now = now;
        self.expire_orphans(now);
        self.engine.tick(now);
        self.after_engine(now);
    }

    fn after_engine(&mut self, now: u64) {
        self.restore_when_ready(now);
        self.route_events(now);
        let ready = self.engine.is_ready();
        if ready != self.last_ready {
            self.last_ready = ready;
            self.engine.trace(Trace::ReadyChanged(ready));
            for c in self.conns.values_mut() {
                c.queue(Notify::Ready { ready });
            }
            // the library says INIT_DONE at this message, so what the module missed comes after it
            if ready {
                let waiting: Vec<ConnId> = self
                    .conns
                    .iter()
                    .filter(|(_, c)| !c.told)
                    .map(|(id, _)| *id)
                    .collect();
                for id in waiting {
                    self.deliver(id);
                }
            }
        }
        self.start_verifies(now);
        self.save_links();
    }

    /// Queue an event for a connection that can hear it: one that has not been told what it missed gets the
    /// state of its links in one go when it is, and a Down it is owed as a tombstone.
    fn push(&mut self, conn: ConnId, link: u8, slot: u8, event: IfaceEvent) {
        if let Some(c) = self.conns.get_mut(&conn).filter(|c| c.told) {
            c.queue(Notify::Event { link, slot, event });
        }
    }

    fn route_events(&mut self, now: u64) {
        for ev in self.engine.take_events() {
            let call = match ev {
                Event::LookupDone {
                    token,
                    link,
                    companion,
                    answered,
                } => {
                    if self.pending_checks.contains_key(&token) {
                        self.check_done(now, token, link, answered);
                    } else {
                        self.lookup_done(token, link, companion);
                    }
                    continue;
                }
                Event::Connected { call }
                | Event::PartiallyConnected { call }
                | Event::Disconnected { call, .. }
                | Event::Reconfigured { call }
                | Event::MtuChanged { call, .. }
                | Event::LegUp { call, .. }
                | Event::LegDown { call, .. }
                | Event::LegFailed { call, .. } => call,
            };
            let Some((conn, link)) = self.owner.get(&call).copied() else {
                continue;
            };
            self.route_one(now, conn, link, call, ev);
        }
    }

    fn route_one(&mut self, now: u64, conn: ConnId, link: u8, call: CallId, ev: Event) {
        let info = self.engine.call_info(call);
        // The books are kept for the links of a closed connection too, the events go nowhere.
        let conn_told = self.conns.get(&conn).is_some_and(|c| c.told);
        let st = match self
            .conns
            .get_mut(&conn)
            .and_then(|c| c.links.get_mut(&link))
        {
            Some(st) => st,
            None => match self.orphans.get_mut(&link) {
                Some(o) if conn == ORPHAN => &mut o.st,
                _ => return,
            },
        };
        let slot = st.key.slot;
        let was_told = st.told;
        let mut out: Vec<IfaceEvent> = Vec::new();
        let mut dropped = 0u32;
        match ev {
            Event::LegUp { family, .. } => {
                if let Some(info) = &info {
                    let was_up = st.up_families() > 0;
                    let addr = convert::address(info, family);
                    st.addr[slot_of(family)] = addr;
                    st.mtu[slot_of(family)] = convert::family_mtu(info, family);
                    if !was_up && addr.is_some() {
                        out.push(IfaceEvent::Up);
                    }
                    // nicmd sets the MTU before it posts the address event, and posts an MTU event only
                    // when a part it knew changed, so a new call gets none
                    out.extend(mtu_event(st, family));
                    if let Some((addr, prefix)) = addr {
                        out.push(IfaceEvent::NewAddr {
                            family: convert::family(family),
                            addr,
                            prefix,
                        });
                    }
                }
            }
            Event::LegDown { family, reason, .. } => {
                if let Some((addr, prefix)) = st.addr[slot_of(family)].take() {
                    out.push(IfaceEvent::DelAddr {
                        family: convert::family(family),
                        addr,
                        prefix,
                    });
                    if st.up_families() == 0 {
                        out.push(IfaceEvent::Down(convert::reason(reason)));
                    }
                }
                st.mtu[slot_of(family)] = None;
            }
            // A family the module never asked for is followed on the chance that it starts
            // it without a lookup. That it cannot be followed is not the module's concern.
            Event::LegFailed { family, .. }
                if !st.requested[slot_of(family)] && st.addr[slot_of(family)].is_none() => {}
            Event::LegFailed { family, reason, .. } => {
                // A family that was up and can no longer be followed goes the way of one
                // that ended: its address is taken away, and the link goes down with the last.
                if let Some((addr, prefix)) = st.addr[slot_of(family)].take() {
                    out.push(IfaceEvent::DelAddr {
                        family: convert::family(family),
                        addr,
                        prefix,
                    });
                    if st.up_families() == 0 {
                        out.push(IfaceEvent::Down(convert::reason(reason)));
                    }
                } else {
                    out.push(IfaceEvent::OpFailed(convert::reason(reason)));
                }
                st.mtu[slot_of(family)] = None;
            }
            Event::MtuChanged { family, mtu, .. } => {
                st.mtu[slot_of(family)] = Some(mtu);
                out.extend(mtu_event(st, family));
            }
            Event::Reconfigured { .. } => {
                if let Some(info) = &info {
                    for fam in [Family::V4, Family::V6] {
                        let now_addr = convert::address(info, fam);
                        let old = st.addr[slot_of(fam)];
                        // only a family that was up can change its address
                        if old.is_some() && now_addr != old {
                            if let Some((addr, prefix)) = old {
                                out.push(IfaceEvent::DelAddr {
                                    family: convert::family(fam),
                                    addr,
                                    prefix,
                                });
                            }
                            st.addr[slot_of(fam)] = now_addr;
                            if let Some((addr, prefix)) = now_addr {
                                out.push(IfaceEvent::NewAddr {
                                    family: convert::family(fam),
                                    addr,
                                    prefix,
                                });
                            }
                        }
                    }
                }
                out.push(IfaceEvent::Reconfigured);
            }
            Event::Disconnected { reason, .. } => {
                let was_up = st.up_families() > 0;
                for fam in [Family::V4, Family::V6] {
                    if let Some((addr, prefix)) = st.addr[slot_of(fam)].take() {
                        out.push(IfaceEvent::DelAddr {
                            family: convert::family(fam),
                            addr,
                            prefix,
                        });
                    }
                }
                // a restored link has no address yet, and the module was told it is up
                if was_up || st.told {
                    out.push(IfaceEvent::Down(convert::reason(reason)));
                }
            }
            // a lookup belongs to no call, `route_events` took it out before
            Event::Connected { .. }
            | Event::PartiallyConnected { .. }
            | Event::LookupDone { .. } => {}
        }
        // nicmd's gate (`postEvent`): until the interface was announced up the module hears nothing
        // but up and down. A failed follow before that would make DSI abort its own start.
        let mut kept = Vec::new();
        let mut went_down = false;
        let mut down_reason = None;
        for e in out {
            match e {
                IfaceEvent::Up => {
                    st.announced = true;
                    if conn_told {
                        st.told = true;
                    }
                    kept.push(e);
                }
                IfaceEvent::Down(reason) => {
                    st.announced = false;
                    st.told = false;
                    went_down = true;
                    down_reason = Some(reason);
                    kept.push(e);
                }
                other if st.announced => kept.push(other),
                _ => dropped = dropped.saturating_add(1),
            }
        }
        self.dropped_before_up = self.dropped_before_up.saturating_add(dropped);
        // A Down the module was told to expect is owed until the daemon has written it, also to a connection
        // that has been told what it missed: a write that fails, a close or the end of the daemon would lose it,
        // and the number would go to another call while DSI still has the old one on it.
        let owe_it = was_told && down_reason.is_some();
        for e in kept {
            if owe_it && matches!(e, IfaceEvent::Down(_)) {
                continue;
            }
            self.push(conn, link, slot, e);
        }
        // If the module had been told the link is up, it is owed the Down: a tombstone keeps the number, and
        // `owe` queues the Down at once to a connection of the process that has been told what it missed.
        let grace_end = now.saturating_add(self.cfg.orphan_grace_ms);
        let away = if conn == ORPHAN {
            self.orphans.get(&link).map(|o| (o.proc, o.until))
        } else {
            self.conns.get(&conn).map(|c| (c.proc, grace_end))
        };
        let owed = away.filter(|_| was_told).zip(down_reason);
        // After a modem restart the module starts over, so its links go back to the pool, and the
        // module may release the old call late: that number is not handed out soon.
        let restart = matches!(ev, Event::Disconnected { reason, .. }
            if reason == dataos_datacore::EndReason::Local(dataos_datacore::LocalReason::ModemRestart));
        if restart {
            if let Some(st) = self.take_link(link) {
                self.drop_link(now, st);
            }
            let hold_end = now.saturating_add(self.cfg.restart_hold_ms);
            self.engine.hold_link(usize::from(link), hold_end);
            // kept apart from the hold of a tombstone: a Down that is written ends only that one
            self.restart_holds.insert(link, hold_end);
            if let Some(((proc, until), reason)) = owed {
                self.owe(link, proc, slot, reason, until);
            }
        } else if went_down {
            // nicmd takes an interface back when its call goes down (`stateDownHook`), and so do we
            if let Some(st) = self.take_link(link) {
                self.drop_link(now, st);
            }
            if let Some(((proc, until), reason)) = owed {
                self.owe(link, proc, slot, reason, until);
            }
        }
    }

    pub fn request(&mut self, now: u64, conn: ConnId, req: Request) {
        self.now = now;
        // the links of an earlier instance are taken back before the first lookup can take one
        self.restore_when_ready(now);
        let hello = matches!(req, Request::Hello);
        let request = request_name(&req);
        let reply = self.handle(now, conn, req);
        self.trace_reply(request, &reply);
        if let Some(c) = self.conns.get_mut(&conn) {
            for n in reply {
                c.queue(n);
            }
        }
        // the answer says the daemon is ready: the library says INIT_DONE, and the module is told what it missed
        if hello && self.engine.is_ready() {
            self.deliver(conn);
        }
        self.after_engine(now);
    }

    /// Write down the readiness answer, and every refusal, to the log. A question that repeats (the data module
    /// asks every hundred milliseconds until the daemon is ready) is written for the first eight and then for
    /// each power of two, with the count, so the log has every kind of answer and no flood.
    fn trace_reply(&mut self, request: &'static str, reply: &[Notify]) {
        for n in reply {
            match n {
                Notify::HelloAck { ready } => {
                    let slot = self.hello_answers.get_mut(usize::from(*ready));
                    if let Some(count) = slot {
                        *count = count.saturating_add(1);
                        if trace::due(*count) {
                            let t = Trace::HelloAnswered {
                                ready: *ready,
                                count: *count,
                            };
                            self.engine.trace(t);
                        }
                    }
                }
                Notify::Done { code, .. }
                | Notify::RouteReply { code, .. }
                | Notify::MtuReply { code, .. }
                    if *code != ResultCode::Ok =>
                {
                    let count = self.refusals.entry((request, code.code())).or_insert(0);
                    *count = count.saturating_add(1);
                    if trace::due(*count) {
                        let t = Trace::Refused {
                            request,
                            code: code_name(*code),
                            count: *count,
                        };
                        self.engine.trace(t);
                    }
                }
                _ => {}
            }
        }
    }

    fn handle(&mut self, now: u64, conn: ConnId, req: Request) -> Vec<Notify> {
        let ready = self.engine.is_ready();
        if !self.conns.contains_key(&conn) {
            return Vec::new();
        }
        let done = |txn, code| vec![Notify::Done { txn, code }];
        match req {
            Request::Hello => vec![Notify::HelloAck { ready }],
            Request::RouteLookup { txn, req } => vec![self.route_lookup(now, conn, txn, req)],
            Request::MatchingCall { txn, req, hint } => {
                self.matching_call(now, conn, txn, req, hint)
            }
            Request::LinkRelease { txn, link } => {
                if let Some(st) = self
                    .conns
                    .get_mut(&conn)
                    .and_then(|c| c.links.get_mut(&link))
                    .filter(|st| st.swallow_until > now)
                {
                    // The first is the late release of the call the number had before the restart. A second
                    // is the module giving up the start that has the number now.
                    st.gave_up = st.swallowed;
                    st.swallowed = true;
                    self.swallowed_releases = self.swallowed_releases.saturating_add(1);
                    return done(txn, ResultCode::Ok);
                }
                // A link with a call up on it is not given up: the module releases the link of a start
                // that failed, and the call may be another user's (nicmd answers "ok" and keeps it
                // while the modem reports the call).
                if self
                    .conns
                    .get(&conn)
                    .and_then(|c| c.links.get(&link))
                    .is_some_and(|st| st.announced)
                {
                    self.kept_releases = self.kept_releases.saturating_add(1);
                    return done(txn, ResultCode::Ok);
                }
                let st = self
                    .conns
                    .get_mut(&conn)
                    .and_then(|c| c.links.remove(&link));
                match st {
                    Some(st) => {
                        self.drop_link(now, st);
                        done(txn, ResultCode::Ok)
                    }
                    None => done(txn, ResultCode::NoSuchLink),
                }
            }
            Request::QueryMtu { txn, link } => {
                let st = self.conns.get(&conn).and_then(|c| c.links.get(&link));
                match st {
                    None => vec![mtu_reply(txn, ResultCode::NoSuchLink, 0, 0)],
                    Some(st) if st.up_families() == 0 => {
                        vec![mtu_reply(txn, ResultCode::BadState, 0, 0)]
                    }
                    Some(st) => {
                        let link_mtu = self
                            .engine
                            .call_info(st.call)
                            .and_then(|i| i.link_mtu)
                            .unwrap_or(0);
                        let of = |f: Family| st.mtu[slot_of(f)].unwrap_or(link_mtu);
                        vec![mtu_reply(
                            txn,
                            ResultCode::Ok,
                            of(Family::V4),
                            of(Family::V6),
                        )]
                    }
                }
            }
            Request::ScreenState { txn, on } => {
                self.screen_on = on;
                done(txn, ResultCode::Ok)
            }
        }
    }

    /// Take back the links that were handed out and have not come up `unused_release_ms` after it, as
    /// nicmd does (`releaseUnusedInterfaces`). Only a route lookup for a new link calls it there
    /// (0x83b4c), there is no timer, and so it is only here. For every such link the modem is asked,
    /// the closed follower included (nicmd asks before every release), and only an answer that is
    /// well formed and names no call frees the link. Not asked, and never taken back: a link whose
    /// follower saw the packet status "connected" (nicmd's flag at +0x28 of the data call, which it
    /// skips), a link the module was told is up (`told`, the flag again, which the table keeps over a
    /// restart of the daemon, so a restored call whose follower could not look is not lost to the modem's
    /// silence), and an emergency link while its follower is open, because an emergency start can take
    /// longer than the limit and its PDN would come up on a number that belongs to another call.
    fn reclaim_unused(&mut self, now: u64) {
        let limit = self.cfg.unused_release_ms;
        let mut ask: Vec<u8> = Vec::new();
        let all = self
            .conns
            .values()
            .flat_map(|c| c.links.iter())
            .chain(self.orphans.iter().map(|(l, o)| (l, &o.st)));
        for (link, st) in all {
            if st.announced
                || st.told
                || st.up_families() > 0
                || self.verify.contains_key(link)
                || now < st.checked_at.saturating_add(limit)
                || self.engine.call_seen_connected(st.call)
                || (st.emergency && !st.gave_up && !self.engine.call_is_closed(st.call))
            {
                continue;
            }
            ask.push(*link);
        }
        for link in ask {
            if self.pending_checks.len() >= MAX_CHECKS {
                break;
            }
            self.start_check(now, link);
        }
    }

    /// Ask the modem whether a call is up for the request this link was handed out for.
    fn start_check(&mut self, now: u64, link: u8) -> bool {
        let Some(st) = self.link_state_mut(link) else {
            return false;
        };
        let query = LookupQuery {
            subscription: st.key.slot,
            family: if st.requested[0] {
                Family::V4
            } else {
                Family::V6
            },
            apn: st.key.apn.clone(),
            apn_type: (st.key.apn_type != dataos_nicm_abi::APN_TYPE_NOT_SET)
                .then_some(st.key.apn_type),
            apn_type_mask: (st.key.apn_type_mask != 0).then_some(st.key.apn_type_mask),
            hint: LookupHint::default(),
        };
        let token = self.next_lookup;
        self.next_lookup = self.next_lookup.wrapping_add(1);
        if self.engine.start_lookup(now, token, query).is_err() {
            return false;
        }
        self.pending_checks.insert(token, link);
        if let Some(st) = self.link_state_mut(link) {
            st.check = Some(token);
            st.checked_at = now;
        }
        true
    }

    /// The modem answered a question about a link that has not come up, or its time was over. A call
    /// it names on this link keeps the link, and so does an answer that says nothing (a timeout, a
    /// refusal, an unusable message): only a well formed answer that names no call frees it. nicmd
    /// releases on an error too (0x7476c). A link kept wrongly costs a place until the next lookup
    /// asks again, one freed wrongly costs a call, so datad is the more careful.
    ///
    /// A call the module had before a restart of the daemon is judged by more than the answer: the
    /// follower must have looked for it too (it bound, registered and asked for the settings, which found
    /// no call). The modem may number its instances and muxes in a way the question does not match.
    fn check_done(&mut self, now: u64, token: u32, named: Option<usize>, answered: bool) {
        let Some(link) = self.pending_checks.remove(&token) else {
            return;
        };
        let verifying = self.verify.contains_key(&link);
        let Some(st) = self.link_state_mut(link) else {
            self.verify.remove(&link);
            return;
        };
        st.check = None;
        let call = st.call;
        // the follower knows more than the question: a call it saw is not given up for an answer
        if named == Some(usize::from(link)) || self.engine.call_seen_connected(call) {
            self.verify.remove(&link);
            return;
        }
        let looked = !verifying || self.engine.call_look(call) == Look::Done;
        if !answered {
            self.unanswered_checks = self.unanswered_checks.saturating_add(1);
            if self.unanswered_checks % 16 == 1 {
                self.engine.note(dataos_datacore::Note::CheckUnanswered);
            }
            if verifying {
                if looked {
                    let pause = now.saturating_add(self.cfg.verify_retry_ms);
                    self.verify.entry(link).or_default().next = pause;
                } else {
                    self.found_unlooked(now, link);
                }
            }
            return;
        }
        if !looked {
            // The follower could not look for the call, or is still looking: the modem's silence, which may
            // be a numbering that is not ours, proves nothing. The call is kept.
            self.found_unlooked(now, link);
            return;
        }
        // The question was asked for a follower that had looked for the call (`start_verifies`), and it
        // found nothing: the call is gone.
        self.verify.remove(&link);
        if !verifying {
            self.reclaimed_links = self.reclaimed_links.saturating_add(1);
        }
        self.end_with_down(now, link, owed_reason());
    }

    /// A restored call whose follower could not look for it was not named by the modem. It is asked about again
    /// after a pause, a bounded number of times, and counted. It is never lost for that.
    fn found_unlooked(&mut self, now: u64, link: u8) {
        self.unlooked_checks = self.unlooked_checks.saturating_add(1);
        let pause = now.saturating_add(self.cfg.verify_retry_ms);
        let Some(v) = self.verify.get_mut(&link) else {
            return;
        };
        v.unlooked = v.unlooked.saturating_add(1);
        if v.unlooked >= MAX_UNLOOKED {
            self.verify.remove(&link);
        } else {
            v.next = pause;
        }
    }

    /// Start the questions about restored calls the module was told are up, as many as there is room for
    /// next to the others. A call whose follower is still looking waits for it. One whose follower could not
    /// look is asked about to confirm it, and is never lost for the answer (`check_done`).
    fn start_verifies(&mut self, now: u64) {
        let links: Vec<u8> = self.verify.keys().copied().collect();
        for link in links {
            if self.pending_checks.len() >= MAX_CHECKS {
                break;
            }
            match self.verify.get_mut(&link) {
                Some(v) if v.next > now => continue,
                Some(v) => v.next = 0,
                None => continue,
            }
            let Some(st) = self.link_state_mut(link) else {
                self.verify.remove(&link);
                continue;
            };
            let (call, open) = (st.call, st.check.is_some());
            if open {
                continue;
            }
            if self.engine.call_seen_connected(call) {
                self.verify.remove(&link);
            } else if self.engine.call_look(call) != Look::Pending && !self.start_check(now, link) {
                // it could not be sent: again at the next turn of the follower
                let pause = now.saturating_add(self.cfg.verify_retry_ms);
                if let Some(v) = self.verify.get_mut(&link) {
                    v.next = pause;
                }
            }
        }
    }

    /// The first time the engine is ready: take back the links of the table an earlier instance
    /// left, if the engine kept the links of that instance. The module outlives the daemon, so its
    /// calls may run, and each link is followed again as the link of the process that held it.
    fn restore_when_ready(&mut self, now: u64) {
        if self.restored || !self.engine.is_ready() {
            return;
        }
        self.restored = true;
        self.boot = self
            .engine
            .net_mut()
            .boot_id()
            .unwrap_or_else(|_| "-".into());
        let table = self
            .engine
            .net_mut()
            .load_links()
            .and_then(|b| table::decode(&b, &self.boot));
        let adopted = self.engine.links_adopted();
        match table {
            Some(t) => {
                // the Downs a process was owed stay owed, whatever became of the links
                for d in t.dead {
                    self.restore_dead(now, d);
                }
                for row in t.rows {
                    if adopted {
                        self.restore_row(now, row);
                    } else if row.told {
                        // the device was set up again: the call the module was told is up is gone
                        let until = self.grace_end(now);
                        self.owe(row.link, row.proc, row.slot, owed_reason(), until);
                    }
                }
            }
            None if adopted => {
                // The links are there and nothing says whose they are: a call may run on any of them.
                // None goes to another call for the grace, and the module's releases and its next
                // lookups find them free after it.
                let until = now.saturating_add(self.cfg.orphan_grace_ms);
                for link in self.engine.adopted_links() {
                    self.engine.hold_link(link, until);
                }
            }
            None => {}
        }
    }

    /// A Down owed to a process by an earlier instance: the number is kept until it was written or the time is
    /// over. The time is that of the clock of the system, which runs on through the restart, and is no
    /// longer than a grace from now, so a table with a long time in it cannot hold a number for long. No
    /// connection is told before the daemon is ready, so the Down waits for `deliver`.
    fn restore_dead(&mut self, now: u64, d: Dead) {
        let until = d.until.min(self.grace_end(now));
        if until <= now || self.tombstones.contains_key(&d.link) {
            return;
        }
        self.owe(d.link, d.proc, d.slot, d.reason, until);
    }

    fn restore_row(&mut self, now: u64, r: Row) {
        let priority = if r.emergency {
            Priority::Emergency
        } else {
            Priority::Normal
        };
        let family = if r.requested[0] {
            Family::V4
        } else {
            Family::V6
        };
        let Ok(id) = self
            .engine
            .attach_call_at(now, usize::from(r.link), r.slot, priority, family)
        else {
            // the link cannot be followed: a call the module was told is up has ended
            if r.told {
                let until = self.grace_end(now);
                self.owe(r.link, r.proc, r.slot, owed_reason(), until);
            }
            return;
        };
        let other = match family {
            Family::V4 => Family::V6,
            Family::V6 => Family::V4,
        };
        let _ = self.engine.attach_family(now, id, other);
        let st = LinkState {
            call: id,
            key: LinkKey {
                slot: r.slot,
                apn: r.apn,
                apn_type: r.apn_type,
                apn_type_mask: r.apn_type_mask,
            },
            emergency: r.emergency,
            requested: r.requested,
            addr: [None, None],
            mtu: [None, None],
            triple: [0; 3],
            announced: false,
            // what the module was told before the restart stays told: the table says so again at the next write
            told: r.told,
            swallow_until: 0,
            swallowed: false,
            gave_up: false,
            checked_at: now,
            check: None,
        };
        // A module that reconnected before the engine was ready is here already: the link is its.
        if let Some(conn) = self.conn_of(r.proc) {
            self.hand_to(conn, r.link, st);
        } else {
            self.owner.insert(id, (ORPHAN, r.link));
            self.orphans.insert(
                r.link,
                Orphan {
                    st,
                    until: now.saturating_add(self.cfg.orphan_grace_ms),
                    proc: r.proc,
                },
            );
        }
        self.restored_links = self.restored_links.saturating_add(1);
        // The module was told this call was up. If it is gone, the module must hear that.
        if r.told {
            self.verify.insert(r.link, Verify::default());
        }
    }

    /// Write the table of links when it changed. Not before the table of an earlier instance was read.
    fn save_links(&mut self) {
        if !self.restored {
            return;
        }
        let mut rows: Vec<Row> = self
            .conns
            .values()
            .flat_map(|c| c.links.iter().map(move |(l, st)| row_of(*l, c.proc, st)))
            .collect();
        rows.extend(self.orphans.iter().map(|(l, o)| row_of(*l, o.proc, &o.st)));
        rows.sort_by_key(|r| r.link);
        let dead: Vec<Dead> = self
            .tombstones
            .iter()
            .map(|(l, t)| Dead {
                link: *l,
                proc: t.proc,
                slot: t.slot,
                reason: t.reason,
                until: t.until,
            })
            .collect();
        let bytes = table::encode(&self.boot, &rows, &dead);
        if bytes == self.last_saved {
            return;
        }
        match self.engine.net_mut().store_links(&bytes) {
            Ok(()) => self.last_saved = bytes,
            Err(_) => self.save_failures = self.save_failures.saturating_add(1),
        }
    }

    /// The earliest time the host must call `tick`: the engine's and the end of the time of an
    /// orphan or of a link kept for a process that was away.
    pub fn next_deadline(&self) -> Option<u64> {
        self.engine
            .next_deadline()
            .into_iter()
            .chain(self.orphans.values().map(|o| o.until))
            .chain(self.tombstones.values().map(|t| t.until))
            .chain(self.verify.values().map(|v| v.next).filter(|t| *t != 0))
            .min()
    }

    /// The APN type decides. A mask that is nothing but the emergency bit is an emergency
    /// profile too, one that lists emergency among other types is an ordinary call.
    fn is_emergency(&self, req: &RouteRequest) -> bool {
        req.apn_type == self.cfg.emergency_apn_type
            || (self.cfg.emergency_mask != 0 && req.apn_type_mask == self.cfg.emergency_mask)
    }

    /// Is there a call of this connection the module can use again? The modem is asked, for the
    /// family and then for the other one, and its answer is a hint only: a match needs the link
    /// to be one of this connection's, announced up, and its subscription, APN, APN type and mask
    /// (which tell an emergency call from an ordinary one) to be the request's. The name of the interface is always ours. The answer
    /// comes when the modem has answered or its time is over, from `route_events`.
    fn matching_call(
        &mut self,
        now: u64,
        conn: ConnId,
        txn: u32,
        req: RouteRequest,
        hint: MatchHint,
    ) -> Vec<Notify> {
        if !self.engine.is_ready() {
            return vec![refusal(txn, ResultCode::NotReady)];
        }
        let query = LookupQuery {
            subscription: req.slot,
            family: convert::engine_family(req.family),
            apn: req.apn.clone(),
            apn_type: (req.apn_type != dataos_nicm_abi::APN_TYPE_NOT_SET).then_some(req.apn_type),
            apn_type_mask: (req.apn_type_mask != 0).then_some(req.apn_type_mask),
            hint: convert::lookup_hint(hint),
        };
        let token = self.next_lookup;
        self.next_lookup = self.next_lookup.wrapping_add(1);
        match self.engine.start_lookup(now, token, query) {
            Ok(()) => {
                self.pending_matches.insert(
                    token,
                    PendingMatch {
                        conn,
                        txn,
                        slot: req.slot,
                        apn: req.apn,
                        apn_type: req.apn_type,
                        apn_type_mask: req.apn_type_mask,
                    },
                );
                Vec::new()
            }
            Err(StartError::Invalid) => vec![refusal(txn, ResultCode::Invalid)],
            Err(_) => vec![refusal(txn, ResultCode::NoMatch)],
        }
    }

    /// The modem answered a matching-call question, or its time was over.
    fn lookup_done(&mut self, token: u32, link: Option<usize>, companion: bool) {
        let Some(p) = self.pending_matches.remove(&token) else {
            return;
        };
        let answer = self.match_answer(&p, link, companion);
        if let Some(c) = self.conns.get_mut(&p.conn) {
            c.queue(answer);
        }
    }

    fn match_answer(&self, p: &PendingMatch, link: Option<usize>, companion: bool) -> Notify {
        let no = refusal(p.txn, ResultCode::NoMatch);
        let Some(link) = link.and_then(|l| u8::try_from(l).ok()) else {
            return no;
        };
        let Some(st) = self.conns.get(&p.conn).and_then(|c| c.links.get(&link)) else {
            return no;
        };
        // an emergency call is told by its APN type and mask, so they carry the kind as well
        let same = st.key.slot == p.slot
            && st.key.apn == p.apn
            && st.key.apn_type == p.apn_type
            && st.key.apn_type_mask == p.apn_type_mask;
        let Some(info) = self.engine.call_info(st.call) else {
            return no;
        };
        // announced means the module heard "up" and nothing since: a call that ended said "down"
        if !(same && st.announced) {
            return no;
        }
        Notify::RouteReply {
            txn: p.txn,
            code: ResultCode::Ok,
            link,
            existing: true,
            companion,
            ifname: info.ifname,
        }
    }

    fn route_lookup(&mut self, now: u64, conn: ConnId, txn: u32, req: RouteRequest) -> Notify {
        let reply = |code, link: u8, ifname: String, existing: bool| Notify::RouteReply {
            txn,
            code,
            link,
            existing,
            companion: existing,
            ifname,
        };
        let fail = |code| reply(code, 0, String::new(), false);
        if !self.engine.is_ready() {
            return fail(ResultCode::NotReady);
        }
        let family = convert::engine_family(req.family);
        // The APN type decides. A mask that is nothing but the emergency bit is an emergency
        // profile too, one that lists emergency among other types is an ordinary call.
        let emergency = self.is_emergency(&req);
        let key = LinkKey {
            slot: req.slot,
            apn: req.apn.clone(),
            apn_type: req.apn_type,
            apn_type_mask: req.apn_type_mask,
        };
        let Some(c) = self.conns.get(&conn) else {
            return fail(ResultCode::Invalid);
        };
        // The other family of a call that is up on a link belongs on that link. A
        // lookup that repeats one whose call never came up gets the same link again.
        let same = c
            .links
            .iter()
            .find(|(_, st)| {
                st.key == key
                    && !self.engine.call_is_closed(st.call)
                    && !self.engine.call_up_families(st.call).contains(&family)
            })
            .map(|(link, st)| (*link, st.call));
        if let Some((link, call)) = same {
            if !self.engine.call_families(call).contains(&family)
                && self.engine.attach_family(now, call, family).is_err()
            {
                return fail(ResultCode::BadState);
            }
            let mut stale = None;
            if let Some(st) = self
                .conns
                .get_mut(&conn)
                .and_then(|c| c.links.get_mut(&link))
            {
                st.requested[slot_of(family)] = true;
                // a repeated lookup is a new hand-out of the link: the question to the modem waits again
                st.checked_at = now;
                stale = st.check.take();
            }
            if let Some(t) = stale {
                self.pending_checks.remove(&t);
                self.engine.cancel_lookup(t);
            }
            let ifname = self
                .engine
                .call_info(call)
                .map(|i| i.ifname)
                .unwrap_or_default();
            // the other family of a call that is up: nicmd's modem lookup finds that instance and
            // answers with it, and with the companion flag
            let other_up = !self.engine.call_up_families(call).is_empty();
            return reply(ResultCode::Ok, link, ifname, other_up);
        }
        // nicmd takes back an interface that was handed out and has not come up since
        self.reclaim_unused(now);
        let held = self.ordinary_links_held(conn);
        let emergency_held = self.emergency_links_held(conn);
        // An ordinary call stays inside the connection's share. The rest of the
        // links belong to the other connection and to emergencies.
        if !emergency && held >= self.link_quota {
            return fail(ResultCode::NoLink);
        }
        // An emergency call has the reserve, and one more, but not every link.
        if emergency && emergency_held > self.engine.reserved_links() {
            return fail(ResultCode::NoLink);
        }
        let priority = if emergency {
            Priority::Emergency
        } else {
            Priority::Normal
        };
        let id = match self.engine.attach_call(now, req.slot, priority, family) {
            Ok(id) => id,
            Err(StartError::NoLink) => return fail(ResultCode::NoLink),
            Err(_) => return fail(ResultCode::Invalid),
        };
        let swallow_until = self
            .engine
            .call_link(id)
            // only a restart hold: the call that held a number a Down is owed for is not coming back
            .filter(|l| {
                self.engine.link_on_hold(*l)
                    && !u8::try_from(*l).is_ok_and(|n| self.tombstones.contains_key(&n))
            })
            .map_or(0, |l| self.engine.link_hold_until(l));
        let Some(link) = self.engine.call_link(id).and_then(|l| u8::try_from(l).ok()) else {
            let _ = self.engine.release_call(now, id);
            return fail(ResultCode::Invalid);
        };
        let ifname = self
            .engine
            .call_info(id)
            .map(|i| i.ifname)
            .unwrap_or_default();
        if let Some(c) = self.conns.get_mut(&conn) {
            c.links.insert(
                link,
                LinkState {
                    call: id,
                    key,
                    emergency,
                    requested: [family == Family::V4, family == Family::V6],
                    addr: [None, None],
                    mtu: [None, None],
                    triple: [0; 3],
                    announced: false,
                    told: false,
                    swallow_until,
                    swallowed: false,
                    gave_up: false,
                    checked_at: now,
                    check: None,
                },
            );
        }
        self.owner.insert(id, (conn, link));
        // The other family is followed too: the module may start it on this link without
        // a route lookup (a retry of one family of a dual-stack call).
        let other = match family {
            Family::V4 => Family::V6,
            Family::V6 => Family::V4,
        };
        let _ = self.engine.attach_family(now, id, other);
        reply(ResultCode::Ok, link, ifname, false)
    }

    /// Links this connection holds right now.
    pub fn links_held(&self, conn: ConnId) -> usize {
        self.conns.get(&conn).map_or(0, |c| c.links.len())
    }

    /// Links of emergency calls this connection holds right now.
    fn emergency_links_held(&self, conn: ConnId) -> usize {
        self.conns
            .get(&conn)
            .map_or(0, |c| c.links.values().filter(|st| st.emergency).count())
    }

    /// Links of ordinary calls this connection holds right now.
    fn ordinary_links_held(&self, conn: ConnId) -> usize {
        self.conns
            .get(&conn)
            .map_or(0, |c| c.links.values().filter(|st| !st.emergency).count())
    }
}

/// A route reply that names no link.
/// What a request is called in the log.
fn request_name(r: &Request) -> &'static str {
    match r {
        Request::Hello => "readiness question",
        Request::RouteLookup { .. } => "route lookup",
        Request::MatchingCall { .. } => "matching call",
        Request::LinkRelease { .. } => "link release",
        Request::QueryMtu { .. } => "mtu query",
        Request::ScreenState { .. } => "screen state",
    }
}

fn code_name(c: ResultCode) -> &'static str {
    match c {
        ResultCode::Ok => "Ok",
        ResultCode::Invalid => "Invalid",
        ResultCode::NoLink => "NoLink",
        ResultCode::NoSuchLink => "NoSuchLink",
        ResultCode::TooMany => "TooMany",
        ResultCode::BadState => "BadState",
        ResultCode::NotReady => "NotReady",
        ResultCode::Unsupported => "Unsupported",
        ResultCode::NoMatch => "NoMatch",
    }
}

fn refusal(txn: u32, code: ResultCode) -> Notify {
    Notify::RouteReply {
        txn,
        code,
        link: 0,
        existing: false,
        companion: false,
        ifname: String::new(),
    }
}

fn mtu_reply(txn: u32, code: ResultCode, v4: u32, v6: u32) -> Notify {
    Notify::MtuReply { txn, code, v4, v6 }
}
