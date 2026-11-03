// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The QMI transport of the engine over QRTR sockets. One socket is the control socket: it
//! registers lookups with the name service and hears which of the modem's data services come and
//! go (`qrtr::Services`), and that is how the daemon learns of a modem restart. Every QMI client of
//! the engine (one per leg of a call, one for the data format, one for the data port, one per
//! lookup) is a socket of its own, sending to the chosen server of its service and hearing only
//! that server. A send that finds no room waits in the outbox and goes out later, in order.
//!
//! The socket calls are behind `Qrtr`, so the whole of it runs on the host against `fake`. The
//! faults are the kinds the kernel paths know (`ns.c` and `af_qrtr.c` of the qcom module, read for
//! this file **[V source]**): `EAGAIN` while the flow control of a remote node holds a send back,
//! `ENOBUFS` and `ENOMEM` for memory, `ECONNRESET` for a node that is not known, `ENODEV` and
//! `EPIPE` for an endpoint that is gone, and `ENETRESET` on every socket when a new name service binds
//! the control port (`qrtr_reset_ports` runs from `__qrtr_bind` for that port, so with the name service
//! of the kernel, which binds it once at start, this is effectively out of reach and the handling
//! only keeps the daemon from trusting sockets that were reset). After that nothing can be trusted, so everything is closed, the
//! modem counts as gone, and the lookups are made again.
use crate::outbox::{Outbox, Sent};
use crate::qrtr::{Control, Peer, Services, CTRL_PORT, WANTED};
use dataos_datacore::{ClientId, Qmi, QmiError, ServiceEvent};
use dataos_qmi::frame::MAX_DATAGRAM;
use std::collections::BTreeMap;
use std::os::fd::RawFd;

pub type SockId = u32;

/// What went wrong with a socket call, by what the daemon does about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// No room right now.
    Retry,
    /// No memory or buffers right now. Retried like `Retry` and counted.
    Exhausted,
    /// The destination is gone.
    PeerGone,
    /// The socket was reset (the name service closed). Everything starts over.
    Reset,
    Other,
}

/// The QRTR socket calls the transport needs.
pub trait Qrtr {
    /// A new datagram socket on an unused port of this node.
    fn open(&mut self) -> Result<SockId, Fault>;
    fn close(&mut self, sock: SockId);
    fn local(&self, sock: SockId) -> Option<Peer>;
    fn send(&mut self, sock: SockId, to: Peer, bytes: &[u8]) -> Result<(), Fault>;
    /// The next datagram, if there is one. A datagram that was cut short or came from an address
    /// that is no QRTR address is read and left out.
    fn recv(&mut self, sock: SockId) -> Result<Option<(Peer, Vec<u8>)>, Fault>;
    /// The descriptors to wait on.
    fn fds(&self) -> Vec<RawFd>;
}

/// Clients the transport opens at most. A call has two legs, 15 links make 30, and the
/// bring-up and the lookups need a few more.
pub const MAX_CLIENTS: usize = 48;
/// Datagrams one client may have waiting to go out, and their bytes.
const OUT_ITEMS: usize = 8;
const OUT_BYTES: usize = 16 * 1024;
/// How long a send waits for room. The steps of the engine time out after 3 s at the least.
const OUT_WAIT_MS: u64 = 2_000;
/// Datagrams read from one client per pass, so a chatty one cannot starve the others (and no more
/// than this many times the number of clients in one step).
const PER_CLIENT: usize = 4;
/// Time between two attempts to open the control socket, doubling up to the second value.
const REOPEN_FIRST_MS: u64 = 100;
const REOPEN_MAX_MS: u64 = 5_000;
/// A control socket that lived this long was healthy, so the next reset starts the backoff again.
const HEALTHY_MS: u64 = 30_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkStats {
    /// Times everything was closed and started over.
    pub resets: u32,
    /// Times the control socket could not be opened or the lookups not be sent.
    pub lookup_failures: u32,
    /// Datagrams on the control socket that did not come from the name service or did not decode.
    pub bad_control: u32,
    /// Datagrams on a client socket that did not come from the client's server.
    pub foreign: u32,
    /// Sends that found no memory or buffers.
    pub exhausted: u32,
    /// Sends that waited in the outbox.
    pub queued: u32,
    /// Outbox queues thrown away because the client stayed blocked or failed.
    pub send_dropped: u32,
    /// Sends the engine was told had failed.
    pub send_failed: u32,
    /// Clients closed because their socket failed on receive.
    pub recv_faults: u32,
    /// Zero-length datagrams from a client's server: the flow control of the qcom QRTR module telling
    /// that a send which was held back may go now. They carry no message.
    pub resumes: u32,
}

struct Client {
    sock: SockId,
    target: Peer,
}

enum Ctrl {
    Closed { retry_at: u64 },
    Open { sock: SockId, name_service: Peer },
}

pub struct QmiLink<Q: Qrtr> {
    io: Q,
    ctrl: Ctrl,
    services: Services,
    clients: BTreeMap<ClientId, Client>,
    next_client: ClientId,
    out: Outbox<ClientId>,
    now: u64,
    reset_pending: bool,
    reopen_ms: u64,
    opened_at: u64,
    wanted: &'static [u8],
    max_clients: usize,
    stats: LinkStats,
}

impl<Q: Qrtr> QmiLink<Q> {
    pub fn new(io: Q) -> Self {
        Self::for_services(io, &WANTED, MAX_CLIENTS)
    }

    /// A transport for another daemon: the services that make the modem up and how many clients it may open.
    pub fn for_services(io: Q, wanted: &'static [u8], max_clients: usize) -> Self {
        QmiLink {
            io,
            ctrl: Ctrl::Closed { retry_at: 0 },
            services: Services::wanting(0, wanted),
            clients: BTreeMap::new(),
            next_client: 1,
            out: Outbox::new(OUT_ITEMS, OUT_BYTES, OUT_WAIT_MS),
            now: 0,
            reset_pending: false,
            reopen_ms: REOPEN_FIRST_MS,
            opened_at: 0,
            wanted,
            max_clients,
            stats: LinkStats::default(),
        }
    }

    pub fn io(&self) -> &Q {
        &self.io
    }

    pub fn io_mut(&mut self) -> &mut Q {
        &mut self.io
    }

    pub fn stats(&self) -> LinkStats {
        self.stats
    }

    pub fn services(&self) -> &Services {
        &self.services
    }

    pub fn client_count(&self) -> usize {
        self.clients.len()
    }

    /// Some send is waiting for room, so the main loop looks again soon.
    pub fn blocked(&self) -> bool {
        !self.out.is_empty()
    }

    pub fn fds(&self) -> Vec<RawFd> {
        self.io.fds()
    }

    /// When the transport needs the main loop again: the end of a wait for room, or the next try
    /// to open the control socket.
    pub fn next_deadline(&self) -> Option<u64> {
        let reopen = match self.ctrl {
            Ctrl::Closed { retry_at } => Some(retry_at),
            Ctrl::Open { .. } => None,
        };
        reopen.into_iter().chain(self.out.next_deadline()).min()
    }

    /// Open the control socket when it is closed and its time has come, then read what the name
    /// service says. The events are what the engine must be told about the modem, in order. The
    /// flag says there may be more to read than the budget allowed.
    pub fn poll_control(&mut self, now: u64, budget: usize) -> (Vec<ServiceEvent>, bool) {
        self.now = now;
        let mut events = Vec::new();
        if self.reset_pending {
            events.extend(self.reset());
        }
        if matches!(self.ctrl, Ctrl::Closed { retry_at } if now >= retry_at) {
            self.open_control();
        }
        let Ctrl::Open { sock, name_service } = self.ctrl else {
            return (events, false);
        };
        let mut more = false;
        for i in 0..budget {
            match self.io.recv(sock) {
                Ok(Some((from, bytes))) => {
                    match Control::decode(&bytes).filter(|_| from == name_service) {
                        Some(c) => events.extend(self.services.apply(c)),
                        None => self.stats.bad_control = self.stats.bad_control.saturating_add(1),
                    }
                    more = i.saturating_add(1) == budget;
                }
                Ok(None) => break,
                Err(Fault::Retry | Fault::Exhausted) => break,
                Err(_) => {
                    // the control socket is the only thing that tells us about the modem
                    events.extend(self.reset());
                    break;
                }
            }
        }
        (events, more)
    }

    /// The datagrams the modem sent to our clients, a few from each client, and whether some client
    /// may have more. Every client is served in every pass, so one that talks a lot does not starve
    /// the others.
    pub fn poll_clients(&mut self, now: u64) -> (Vec<(ClientId, Vec<u8>)>, bool) {
        self.now = now;
        let mut got = Vec::new();
        let mut more = false;
        let mut resumed = false;
        let ids: Vec<ClientId> = self.clients.keys().copied().collect();
        for id in ids {
            for n in 0..PER_CLIENT {
                let Some(c) = self.clients.get(&id) else {
                    break;
                };
                let (sock, target) = (c.sock, c.target);
                match self.io.recv(sock) {
                    // After a flow control wait the kernel queues an empty datagram to the sender
                    // (`qrtr_tx_resume`), from the address of the server, for every socket that
                    // waited for it. It is no message: it says the outbox may try again.
                    Ok(Some((from, bytes))) if from == target && bytes.is_empty() => {
                        self.stats.resumes = self.stats.resumes.saturating_add(1);
                        resumed = true;
                    }
                    Ok(Some((from, bytes))) if from == target => got.push((id, bytes)),
                    Ok(Some(_)) => self.stats.foreign = self.stats.foreign.saturating_add(1),
                    Ok(None) | Err(Fault::Retry | Fault::Exhausted) => break,
                    Err(Fault::Reset) => {
                        self.reset_pending = true;
                        break;
                    }
                    Err(_) => {
                        // the engine finds out when it sends, or when its step runs out of time
                        self.stats.recv_faults = self.stats.recv_faults.saturating_add(1);
                        self.drop_client(id);
                        break;
                    }
                }
                more |= n.saturating_add(1) == PER_CLIENT;
            }
        }
        if resumed {
            self.flush(now);
        }
        (got, more)
    }

    /// Try again the sends that found no room. A client that stays blocked too long, or whose
    /// destination is gone, loses what waited for it.
    pub fn flush(&mut self, now: u64) {
        self.now = now;
        let mut reset = false;
        let mut exhausted = 0u32;
        let Self {
            io, clients, out, ..
        } = self;
        let dropped = out.flush(now, |id, bytes| {
            let Some(c) = clients.get(&id) else {
                return Sent::Failed;
            };
            match io.send(c.sock, c.target, bytes) {
                Ok(()) => Sent::Done,
                Err(Fault::Retry) => Sent::Busy,
                Err(Fault::Exhausted) => {
                    exhausted = exhausted.saturating_add(1);
                    Sent::Busy
                }
                Err(Fault::Reset) => {
                    reset = true;
                    Sent::Failed
                }
                Err(_) => Sent::Failed,
            }
        });
        self.reset_pending |= reset;
        self.stats.exhausted = self.stats.exhausted.saturating_add(exhausted);
        let lost = u32::try_from(dropped.len()).unwrap_or(u32::MAX);
        self.stats.send_dropped = self.stats.send_dropped.saturating_add(lost);
    }

    fn open_control(&mut self) {
        match self.try_open_control() {
            Some((sock, node, name_service)) => {
                self.services = Services::wanting(node, self.wanted);
                self.ctrl = Ctrl::Open { sock, name_service };
                self.opened_at = self.now;
            }
            None => {
                self.stats.lookup_failures = self.stats.lookup_failures.saturating_add(1);
                self.close_later();
            }
        }
    }

    /// A socket with the three lookups sent, and the node and the name service it talks to.
    fn try_open_control(&mut self) -> Option<(SockId, u32, Peer)> {
        let sock = self.io.open().ok()?;
        let name_service = self.io.local(sock).map(|local| Peer {
            node: local.node,
            port: CTRL_PORT,
        });
        let sent = name_service.is_some_and(|ns| {
            self.wanted.iter().all(|s| {
                self.io
                    .send(sock, ns, &Control::lookup(*s).encode())
                    .is_ok()
            })
        });
        match name_service {
            Some(ns) if sent => Some((sock, ns.node, ns)),
            _ => {
                self.io.close(sock);
                None
            }
        }
    }

    /// Everything is closed and the lookups are made again later. The modem counts as gone.
    fn reset(&mut self) -> Vec<ServiceEvent> {
        self.reset_pending = false;
        self.stats.resets = self.stats.resets.saturating_add(1);
        if let Ctrl::Open { sock, .. } = self.ctrl {
            self.io.close(sock);
            if self.now.saturating_sub(self.opened_at) >= HEALTHY_MS {
                self.reopen_ms = REOPEN_FIRST_MS;
            }
        }
        let ids: Vec<ClientId> = self.clients.keys().copied().collect();
        for id in ids {
            self.drop_client(id);
        }
        self.close_later();
        self.services.clear()
    }

    fn close_later(&mut self) {
        self.ctrl = Ctrl::Closed {
            retry_at: self.now.saturating_add(self.reopen_ms),
        };
        self.reopen_ms = self.reopen_ms.saturating_mul(2).min(REOPEN_MAX_MS);
    }

    fn drop_client(&mut self, id: ClientId) {
        if let Some(c) = self.clients.remove(&id) {
            self.out.forget(id);
            self.io.close(c.sock);
        }
    }

    fn queue(&mut self, client: ClientId, datagram: &[u8]) -> Result<(), QmiError> {
        match self.out.push(client, datagram.to_vec(), self.now) {
            Ok(()) => {
                self.stats.queued = self.stats.queued.saturating_add(1);
                Ok(())
            }
            Err(_) => self.send_failed(),
        }
    }

    fn send_failed(&mut self) -> Result<(), QmiError> {
        self.stats.send_failed = self.stats.send_failed.saturating_add(1);
        Err(QmiError::Unavailable)
    }
}

impl<Q: Qrtr> Qmi for QmiLink<Q> {
    fn open_client(&mut self, service: u8) -> Result<ClientId, QmiError> {
        let target = self.services.target(service).ok_or(QmiError::Unavailable)?;
        if self.clients.len() >= self.max_clients {
            return Err(QmiError::Unavailable);
        }
        let sock = match self.io.open() {
            Ok(s) => s,
            Err(Fault::Reset) => {
                self.reset_pending = true;
                return Err(QmiError::Unavailable);
            }
            Err(_) => return Err(QmiError::Unavailable),
        };
        // numbers are not used twice: 4 billion openings are years of uptime
        let id = self.next_client;
        self.next_client = self.next_client.wrapping_add(1);
        self.clients.insert(id, Client { sock, target });
        Ok(id)
    }

    fn close_client(&mut self, client: ClientId) {
        self.drop_client(client);
    }

    fn send(&mut self, client: ClientId, datagram: &[u8]) -> Result<(), QmiError> {
        let Some(c) = self.clients.get(&client) else {
            return Err(QmiError::Unavailable);
        };
        if datagram.len() > MAX_DATAGRAM {
            return self.send_failed();
        }
        let (sock, target) = (c.sock, c.target);
        // behind what waits already, or the order of the requests would change
        if self.out.waiting(client) {
            return self.queue(client, datagram);
        }
        match self.io.send(sock, target, datagram) {
            Ok(()) => Ok(()),
            Err(Fault::Retry) => self.queue(client, datagram),
            Err(Fault::Exhausted) => {
                self.stats.exhausted = self.stats.exhausted.saturating_add(1);
                self.queue(client, datagram)
            }
            Err(Fault::Reset) => {
                self.reset_pending = true;
                self.send_failed()
            }
            Err(Fault::PeerGone | Fault::Other) => self.send_failed(),
        }
    }
}
