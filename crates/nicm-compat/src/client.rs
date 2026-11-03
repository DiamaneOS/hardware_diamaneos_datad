// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The requests of the data module over the daemon protocol, and the restart
//! protocol it expects from the interface manager. Nothing in this file
//! panics, whatever the daemon sends.
use crate::coll::Table;
use dataos_wire::{IfaceEvent, MatchHint, Notify, Request, ResultCode, RouteRequest};

/// Requests that wait for their reply at the same time. The data module has a
/// few threads, a daemon that never answers cannot make this grow.
pub const MAX_WAITING: usize = 8;
/// Messages handled by one `poll`, so a flood cannot keep the caller in it.
pub const MAX_PER_POLL: usize = 64;
/// Messages `drain` reads at most, more than a socket holds.
pub const MAX_DRAIN: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NicmError {
    /// The daemon is not reachable.
    Transport,
    /// The request cannot be sent (a value outside the protocol's bounds).
    Invalid,
    /// Too many requests wait for a reply.
    TooMany,
    /// The daemon answered no.
    Refused(ResultCode),
}

pub trait Transport {
    /// Queue one request. Must not block.
    fn send(&mut self, req: &Request) -> Result<(), NicmError>;
    /// Next notification, if any. Must not block.
    fn recv(&mut self) -> Option<Notify>;
    /// The connection is about to be given up: stop the daemon from writing to it, so that what is read
    /// after this is all it will ever say. Nothing to do for a transport that is not a socket.
    fn close_read(&mut self) {}
}

/// The answer to a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    Route {
        link: u8,
        existing: bool,
        companion: bool,
        ifname: String,
        /// The technology for a Wi-Fi call that the modem named, 0 for none.
        tech: u16,
    },
    Done,
    Mtu {
        v4: u32,
        v6: u32,
    },
}

/// What the daemon tells the data module on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notice {
    Iface {
        link: u8,
        slot: u8,
        event: IfaceEvent,
    },
    /// The daemon went away or lost the modem. The module starts over, as it does
    /// when nicmd restarts (`DSI_NICM_POST_RESTART_STATE_INIT_START`).
    RestartStart,
    /// The daemon is ready again (`DSI_NICM_POST_RESTART_STATE_INIT_DONE`).
    RestartDone,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Route,
    Done,
    Mtu,
}

struct Waiting {
    kind: Kind,
    answer: Option<Result<Reply, NicmError>>,
}

pub struct Client<T: Transport> {
    tr: T,
    next_txn: u32,
    waiting: Table<u32, Waiting>,
    /// What the daemon said last about its readiness. None before it said anything.
    ready: Option<bool>,
    ready_count: u32,
    was_ready: bool,
    restart_open: bool,
    /// Answers and events that did not match anything.
    pub stale: u32,
}

impl<T: Transport> Client<T> {
    pub fn new(tr: T) -> Self {
        Client {
            tr,
            next_txn: 1,
            waiting: Table::new(),
            ready: None,
            ready_count: 0,
            was_ready: false,
            restart_open: false,
            stale: 0,
        }
    }

    /// The transport, for the veneer to swap the connection under it.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.tr
    }

    pub fn transport(&self) -> &T {
        &self.tr
    }

    /// Tests start the transaction numbers where a wrap-around is near. Nothing in the libraries calls this.
    pub fn set_next_txn_for_tests(&mut self, n: u32) {
        self.next_txn = n;
    }

    /// `Hello`: register and ask whether the daemon is ready. The answer arrives
    /// through `poll` and shows in `ready`.
    pub fn hello(&mut self) -> Result<(), NicmError> {
        self.tr.send(&Request::Hello)
    }

    /// What the daemon said last. None: nothing yet.
    pub fn ready(&self) -> Option<bool> {
        self.ready
    }

    /// How many readiness messages came so far, so a caller can tell that an
    /// answer to its own `hello` arrived.
    pub fn ready_count(&self) -> u32 {
        self.ready_count
    }

    fn begin(&mut self, kind: Kind, build: impl FnOnce(u32) -> Request) -> Result<u32, NicmError> {
        if self.waiting.len() >= MAX_WAITING {
            return Err(NicmError::TooMany);
        }
        let mut txn = self.next_txn;
        while txn == 0 || self.waiting.contains(&txn) {
            txn = txn.wrapping_add(1);
        }
        self.tr.send(&build(txn))?;
        self.next_txn = txn.wrapping_add(1);
        self.waiting.insert(txn, Waiting { kind, answer: None });
        Ok(txn)
    }

    pub fn route_lookup(&mut self, req: RouteRequest) -> Result<u32, NicmError> {
        self.begin(Kind::Route, |txn| Request::RouteLookup { txn, req })
    }

    /// A route lookup with the extended technology preference of the request.
    pub fn route_lookup_pref(&mut self, req: RouteRequest, xt_pref: u16) -> Result<u32, NicmError> {
        self.begin(Kind::Route, |txn| Request::RouteLookupPref {
            txn,
            req,
            xt_pref,
        })
    }

    /// Is there a call the module can use again? The answer is a `Reply::Route` with the link and
    /// the name of its interface, or a refusal with `ResultCode::NoMatch`.
    pub fn matching_call(&mut self, req: RouteRequest, hint: MatchHint) -> Result<u32, NicmError> {
        self.begin(Kind::Route, |txn| Request::MatchingCall { txn, req, hint })
    }

    pub fn link_release(&mut self, link: u8) -> Result<u32, NicmError> {
        self.begin(Kind::Done, |txn| Request::LinkRelease { txn, link })
    }

    pub fn query_mtu(&mut self, link: u8) -> Result<u32, NicmError> {
        self.begin(Kind::Mtu, |txn| Request::QueryMtu { txn, link })
    }

    pub fn screen_state(&mut self, on: bool) -> Result<u32, NicmError> {
        self.begin(Kind::Done, |txn| Request::ScreenState { txn, on })
    }

    /// The answer to a request, once it is here. It is handed out once.
    pub fn take_reply(&mut self, txn: u32) -> Option<Result<Reply, NicmError>> {
        self.waiting.get(&txn)?.answer.as_ref()?;
        self.waiting.remove(&txn)?.answer
    }

    /// Stop waiting for an answer (the caller timed out). A late one is dropped.
    pub fn forget(&mut self, txn: u32) {
        self.waiting.remove(&txn);
    }

    fn set_ready(&mut self, ready: bool, out: &mut Vec<Notice>) {
        self.ready = Some(ready);
        self.ready_count = self.ready_count.wrapping_add(1);
        if ready {
            self.was_ready = true;
            if self.restart_open {
                self.restart_open = false;
                out.push(Notice::RestartDone);
            }
        } else if self.was_ready && !self.restart_open {
            self.restart_open = true;
            out.push(Notice::RestartStart);
        }
    }

    fn answer(&mut self, txn: u32, kind: Kind, code: ResultCode, ok: Reply) {
        match self.waiting.get_mut(&txn) {
            Some(w) if w.kind == kind && w.answer.is_none() => {
                w.answer = Some(if code == ResultCode::Ok {
                    Ok(ok)
                } else {
                    Err(NicmError::Refused(code))
                });
            }
            _ => self.stale = self.stale.saturating_add(1),
        }
    }

    /// Handle what the daemon sent. At most `MAX_PER_POLL` messages, call again
    /// while the transport has more.
    pub fn poll(&mut self) -> Vec<Notice> {
        self.take(MAX_PER_POLL)
    }

    /// Handle everything the transport holds now, for a caller that closes the connection next and must not
    /// lose what the daemon already wrote to it.
    pub fn drain(&mut self) -> Vec<Notice> {
        self.take(MAX_DRAIN)
    }

    fn take(&mut self, limit: usize) -> Vec<Notice> {
        let mut out = Vec::new();
        for _ in 0..limit {
            let Some(n) = self.tr.recv() else { break };
            match n {
                Notify::HelloAck { ready } | Notify::Ready { ready } => {
                    self.set_ready(ready, &mut out)
                }
                Notify::RouteReply {
                    txn,
                    code,
                    link,
                    existing,
                    companion,
                    ifname,
                    tech,
                } => self.answer(
                    txn,
                    Kind::Route,
                    code,
                    Reply::Route {
                        link,
                        existing,
                        companion,
                        ifname,
                        tech,
                    },
                ),
                Notify::Done { txn, code } => self.answer(txn, Kind::Done, code, Reply::Done),
                Notify::MtuReply { txn, code, v4, v6 } => {
                    self.answer(txn, Kind::Mtu, code, Reply::Mtu { v4, v6 })
                }
                Notify::Event { link, slot, event } => {
                    out.push(Notice::Iface { link, slot, event })
                }
            }
        }
        out
    }

    /// The connection is given up: the daemon cannot write to it any more, what it wrote is read to the end,
    /// and then it is lost (`transport_lost`). All of it in one call, so that nothing the daemon says between
    /// the reading and the closing is lost. A Down is among what it says.
    pub fn finish(&mut self) -> Vec<Notice> {
        let mut out = self.drain();
        self.tr.close_read();
        out.extend(self.drain());
        out.extend(self.transport_lost());
        out
    }

    /// The daemon connection is gone: every request that waits fails and the
    /// module is told to start over.
    pub fn transport_lost(&mut self) -> Vec<Notice> {
        for (_, w) in self.waiting.iter_mut() {
            if w.answer.is_none() {
                w.answer = Some(Err(NicmError::Transport));
            }
        }
        let mut out = Vec::new();
        self.set_ready(false, &mut out);
        out
    }

    /// A new connection to the daemon is up. Register again and ask for readiness.
    pub fn reconnected(&mut self) -> Result<(), NicmError> {
        self.hello()
    }
}
