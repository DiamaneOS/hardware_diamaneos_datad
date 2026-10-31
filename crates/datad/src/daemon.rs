// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The main loop. One thread does everything: it hears the name service (the modem comes and
//! goes), takes connections, reads their requests, reads what the modem sends the QMI clients,
//! runs the timers of the server and the engine, and writes out what the server has to say to
//! the connections and what the engine has to say to the modem. Every step of it is bounded, so
//! a flood on one socket cannot starve the others, and a peer that stops reading is closed
//! instead of being waited for.
use crate::ipc::{Ipc, IpcFault, IpcId, Read};
use crate::outbox::{Dropped, Outbox, Sent};
use crate::server::{ConnId, Server};
use crate::table::Proc;
use crate::transport::{LinkStats, QmiLink, Qrtr};
use dataos_datacore::{Note, Trace};
use dataos_netcfg::NetOps;
use dataos_wire::{IfaceEvent, Notify};
use std::collections::BTreeMap;
use std::os::fd::RawFd;

/// Connections taken, messages read per connection and control packets read in one step. What is left waits for the next step, which comes at once.
const ACCEPTS_PER_STEP: usize = 8;
const READS_PER_CONN: usize = 8;
const CONTROL_PER_STEP: usize = 32;
/// What waits for a connection to take it: a few more than the server queues for it, and how long
/// the first of them may wait. A module that does not read for this long is stuck or dead.
const CONN_OUT_ITEMS: usize = crate::server::MAX_QUEUED;
const CONN_OUT_BYTES: usize = 64 * 1024;
const CONN_OUT_WAIT_MS: u64 = 10_000;
/// The wait for a socket while some output is blocked, and the longest wait at all.
const BUSY_WAIT_MS: u64 = 25;
const MAX_WAIT_MS: u64 = 1_000;

/// The monotonic clock in milliseconds. It must stop in suspend (`CLOCK_MONOTONIC`) or the
/// local deadlines fire right after a resume.
pub trait Clock {
    fn now_ms(&mut self) -> u64;
}

pub trait Poller {
    /// Wait until one of the descriptors can be read or the time is over. An error is returned
    /// after the implementation has waited as long as it could, so the loop does not spin.
    fn wait(&mut self, fds: &[RawFd], timeout_ms: u64) -> std::io::Result<()>;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DaemonStats {
    pub accepted: u32,
    /// Peers the server turned away (UID, label or too many).
    pub rejected: u32,
    pub accept_faults: u32,
    /// Connections closed for a message the protocol does not allow.
    pub closed_protocol: u32,
    /// Closed by the peer.
    pub closed_by_peer: u32,
    /// Closed because the socket failed.
    pub closed_fault: u32,
    /// Closed because the module did not read: too much queued, or the first message waited too long.
    pub closed_blocked: u32,
    pub poll_errors: u32,
    /// Questions about unused links the modem did not answer or refused (see `Server::unanswered_checks`).
    pub unanswered_checks: u32,
}

pub struct Daemon<Q: Qrtr, N: NetOps, I: Ipc> {
    server: Server<QmiLink<Q>, N>,
    ipc: I,
    conns: BTreeMap<ConnId, IpcId>,
    out: Outbox<ConnId>,
    stats: DaemonStats,
}

#[derive(Clone, Copy)]
enum Cause {
    Protocol,
    Peer,
    Fault,
    Blocked,
}

impl<Q: Qrtr, N: NetOps, I: Ipc> Daemon<Q, N, I> {
    pub fn new(server: Server<QmiLink<Q>, N>, ipc: I) -> Self {
        Daemon {
            server,
            ipc,
            conns: BTreeMap::new(),
            out: Outbox::new(CONN_OUT_ITEMS, CONN_OUT_BYTES, CONN_OUT_WAIT_MS),
            stats: DaemonStats::default(),
        }
    }

    pub fn server(&mut self) -> &mut Server<QmiLink<Q>, N> {
        &mut self.server
    }

    pub fn ipc(&mut self) -> &mut I {
        &mut self.ipc
    }

    pub fn stats(&self) -> DaemonStats {
        self.stats
    }

    pub fn link_stats(&mut self) -> LinkStats {
        self.server.engine().qmi_mut().stats()
    }

    pub fn connections(&self) -> usize {
        self.conns.len()
    }

    /// What the engine wants written down once. They carry no identifiers.
    pub fn take_notes(&mut self) -> Vec<Note> {
        self.server.engine().take_notes()
    }

    /// What the host writes to the log. They carry no identifiers.
    pub fn take_trace(&mut self) -> Vec<Trace> {
        self.server.engine().take_trace()
    }

    /// The descriptors to wait on.
    pub fn fds(&mut self) -> Vec<RawFd> {
        let mut fds = self.ipc.fds();
        fds.extend(self.server.engine().qmi_mut().fds());
        fds
    }

    /// One pass over everything, without waiting. True: there may be more to do right away.
    pub fn step(&mut self, now: u64) -> bool {
        // the modem first: a restart changes what every other input means
        let (events, mut more) = self
            .server
            .engine()
            .qmi_mut()
            .poll_control(now, CONTROL_PER_STEP);
        for ev in events {
            self.server.on_service_event(now, ev);
        }
        more |= self.accept_new();
        more |= self.read_conns(now);
        let (datagrams, left) = self.server.engine().qmi_mut().poll_clients(now);
        more |= left;
        for (client, bytes) in datagrams {
            self.server.on_qmi(now, client, &bytes);
        }
        if self.server.next_deadline().is_some_and(|d| d <= now) {
            self.server.tick(now);
        }
        self.server.engine().qmi_mut().flush(now);
        self.stats.unanswered_checks = self.server.unanswered_checks();
        more | self.write_conns(now)
    }

    /// How long the loop may sleep after a step that left nothing to do: until the next timer,
    /// at most a second, and not long while some output waits for room.
    pub fn wait_ms(&mut self, now: u64) -> u64 {
        let link = self.server.engine().qmi_mut();
        let blocked = link.blocked();
        let from_link = link.next_deadline();
        let deadline = self
            .server
            .next_deadline()
            .into_iter()
            .chain(from_link)
            .chain(self.out.next_deadline())
            .min();
        let until = deadline.map_or(MAX_WAIT_MS, |d| d.saturating_sub(now).clamp(1, MAX_WAIT_MS));
        if blocked || !self.out.is_empty() {
            until.min(BUSY_WAIT_MS)
        } else {
            until
        }
    }

    /// Run until `stop` says so. What the engine wants written down goes to `note`, and what the host logs at the
    /// information level (the modem, the bring-up, the handshake with the data module and every refusal) to `trace`.
    pub fn run(
        &mut self,
        clock: &mut impl Clock,
        poller: &mut impl Poller,
        stop: &dyn Fn() -> bool,
        note: &mut dyn FnMut(Note),
        trace: &mut dyn FnMut(Trace),
    ) {
        while !stop() {
            let now = clock.now_ms();
            let wait = if self.step(now) { 0 } else { self.wait_ms(now) };
            for n in self.take_notes() {
                note(n);
            }
            for t in self.take_trace() {
                trace(t);
            }
            let fds = self.fds();
            if poller.wait(&fds, wait).is_err() {
                self.stats.poll_errors = self.stats.poll_errors.saturating_add(1);
            }
        }
    }

    fn accept_new(&mut self) -> bool {
        for n in 0..ACCEPTS_PER_STEP {
            match self.ipc.accept() {
                Ok(Some((id, peer))) => match self.server.accept_proc(
                    Proc {
                        pid: peer.pid,
                        ino: peer.ino,
                    },
                    peer.uid,
                    &peer.label,
                ) {
                    Ok(conn) => {
                        self.conns.insert(conn, id);
                        self.stats.accepted = self.stats.accepted.saturating_add(1);
                        self.server.engine().trace(Trace::ClientConnected);
                    }
                    Err(_) => {
                        self.ipc.close(id);
                        self.stats.rejected = self.stats.rejected.saturating_add(1);
                        self.server.engine().trace(Trace::ClientRejected);
                    }
                },
                Ok(None) => return false,
                Err(_) => {
                    self.stats.accept_faults = self.stats.accept_faults.saturating_add(1);
                    return false;
                }
            }
            if n.saturating_add(1) == ACCEPTS_PER_STEP {
                return true;
            }
        }
        false
    }

    fn read_conns(&mut self, now: u64) -> bool {
        let mut more = false;
        let conns: Vec<(ConnId, IpcId)> = self.conns.iter().map(|(c, i)| (*c, *i)).collect();
        for (conn, id) in conns {
            for n in 0..READS_PER_CONN {
                match self.ipc.recv(id) {
                    Ok(Read::Message(bytes)) => {
                        if self.server.on_datagram(now, conn, &bytes).is_err() {
                            self.close_conn(now, conn, Cause::Protocol);
                            break;
                        }
                        more |= n.saturating_add(1) == READS_PER_CONN;
                    }
                    Ok(Read::Empty) | Err(IpcFault::Busy) => break,
                    Ok(Read::Closed) => {
                        self.close_conn(now, conn, Cause::Peer);
                        break;
                    }
                    Err(IpcFault::Gone) => {
                        self.close_conn(now, conn, Cause::Fault);
                        break;
                    }
                }
            }
        }
        more
    }

    /// Queue what the server has to say, write what can be written, close the connections that
    /// cannot take it. True: a connection was closed, which can make the server say more, so the
    /// next step comes at once.
    fn write_conns(&mut self, now: u64) -> bool {
        let mut closing: Vec<(ConnId, Cause)> = Vec::new();
        let conns: Vec<ConnId> = self.conns.keys().copied().collect();
        for conn in conns {
            if self.server.overflowed(conn) {
                closing.push((conn, Cause::Blocked));
                continue;
            }
            for datagram in self.server.drain_encoded(conn) {
                if self.out.push(conn, datagram, now).is_err() {
                    closing.push((conn, Cause::Blocked));
                    break;
                }
            }
        }
        let Self {
            out, ipc, conns, ..
        } = self;
        // A Down that is owed stays owed until the socket took it: the server is told which were written.
        let mut written: Vec<(ConnId, u8)> = Vec::new();
        let dropped = out.flush(now, |conn, bytes| match conns.get(&conn) {
            None => Sent::Failed,
            Some(id) => match ipc.send(*id, bytes) {
                Ok(()) => {
                    if let Ok(Notify::Event {
                        link,
                        event: IfaceEvent::Down(_),
                        ..
                    }) = Notify::decode(bytes)
                    {
                        written.push((conn, link));
                    }
                    Sent::Done
                }
                Err(IpcFault::Busy) => Sent::Busy,
                Err(IpcFault::Gone) => Sent::Failed,
            },
        });
        for (conn, link) in written {
            self.server.written(conn, link);
        }
        for d in dropped {
            closing.push(match d {
                Dropped::Expired(conn) => (conn, Cause::Blocked),
                Dropped::Failed(conn) => (conn, Cause::Fault),
            });
        }
        let closed = !closing.is_empty();
        for (conn, cause) in closing {
            self.close_conn(now, conn, cause);
        }
        closed
    }

    fn close_conn(&mut self, now: u64, conn: ConnId, cause: Cause) {
        let Some(id) = self.conns.remove(&conn) else {
            return;
        };
        self.ipc.close(id);
        self.server.close(now, conn);
        let (counter, why) = match cause {
            Cause::Protocol => (&mut self.stats.closed_protocol, "protocol error"),
            Cause::Peer => (&mut self.stats.closed_by_peer, "closed by the peer"),
            Cause::Fault => (&mut self.stats.closed_fault, "socket fault"),
            Cause::Blocked => (&mut self.stats.closed_blocked, "peer too slow"),
        };
        *counter = counter.saturating_add(1);
        self.server.engine().trace(Trace::ClientClosed(why));
    }
}
