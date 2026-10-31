// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Fakes of the QRTR sockets with the name service behind them, and of the socket of the protocol,
//! for the host tests. Sockets
//! queue the datagrams that are sent to them. The name service keeps its servers per node and
//! port, answers a lookup with the servers that match and an empty one, and tells the lookups
//! of every change, as `ns.c` does. Faults can be set up for the next calls. No modem is behind
//! it: a test reads what was sent and delivers what the modem would answer.
use crate::ipc::{Ipc, IpcFault, IpcId, PeerInfo, Read};
use crate::qrtr::{Control, Peer, CTRL_PORT, DEL_LOOKUP, DEL_SERVER, NEW_LOOKUP, NEW_SERVER};
use crate::transport::{Fault, Qrtr, SockId};
use std::collections::{BTreeMap, VecDeque};
use std::os::fd::RawFd;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Server {
    pub service: u32,
    pub instance: u32,
    pub node: u32,
    pub port: u32,
}

struct Sock {
    local: Peer,
    inbox: VecDeque<(Peer, Vec<u8>)>,
}

pub struct FakeQrtr {
    pub local_node: u32,
    next_sock: SockId,
    next_port: u32,
    socks: BTreeMap<SockId, Sock>,
    /// The servers the name service knows.
    pub servers: Vec<Server>,
    /// Who asked for what: socket and service (0: all).
    lookups: Vec<(SockId, u32)>,
    /// What went to the modem, by socket and destination.
    pub sent: Vec<(SockId, Peer, Vec<u8>)>,
    /// Faults for the next sends to something that is no name service, and to the name service.
    pub send_faults: VecDeque<Fault>,
    /// One entry per send to the name service: None passes, a fault fails it.
    pub control_faults: VecDeque<Option<Fault>>,
    /// Faults for the next opens.
    pub open_faults: VecDeque<Fault>,
    /// A fault for the next receive on a socket.
    pub recv_faults: BTreeMap<SockId, Fault>,
    pub opened: u32,
    pub closed: Vec<SockId>,
    /// The flow control of the qcom module: a destination takes this many data packets and holds
    /// the senders back after that (`EAGAIN`) until `resume`. One flow per destination port, shared
    /// by every sender on this node.
    pub flow_limit: Option<u32>,
    flows: BTreeMap<Peer, Flow>,
}

#[derive(Default)]
struct Flow {
    pending: u32,
    waiters: Vec<SockId>,
}

impl FakeQrtr {
    pub fn new(local_node: u32) -> Self {
        FakeQrtr {
            local_node,
            next_sock: 1,
            next_port: 0x4000,
            socks: BTreeMap::new(),
            servers: Vec::new(),
            lookups: Vec::new(),
            sent: Vec::new(),
            send_faults: VecDeque::new(),
            control_faults: VecDeque::new(),
            open_faults: VecDeque::new(),
            recv_faults: BTreeMap::new(),
            opened: 0,
            closed: Vec::new(),
            flow_limit: None,
            flows: BTreeMap::new(),
        }
    }

    pub fn name_service(&self) -> Peer {
        Peer {
            node: self.local_node,
            port: CTRL_PORT,
        }
    }

    pub fn is_open(&self, sock: SockId) -> bool {
        self.socks.contains_key(&sock)
    }

    pub fn open_sockets(&self) -> Vec<SockId> {
        self.socks.keys().copied().collect()
    }

    /// Put a datagram into a socket, as if `from` had sent it.
    pub fn deliver(&mut self, sock: SockId, from: Peer, bytes: &[u8]) {
        if let Some(s) = self.socks.get_mut(&sock) {
            s.inbox.push_back((from, bytes.to_vec()));
        }
    }

    fn notify(&mut self, command: u32, srv: Option<Server>, only: Option<SockId>) {
        let words = srv.map_or([0; 4], |s| [s.service, s.instance, s.node, s.port]);
        let bytes = Control { command, words }.encode();
        let ns = self.name_service();
        let to: Vec<SockId> = self
            .lookups
            .iter()
            .filter(|(sock, service)| {
                only.is_none_or(|o| o == *sock)
                    && srv.is_none_or(|s| *service == 0 || *service == s.service)
            })
            .map(|(sock, _)| *sock)
            .collect();
        for sock in to {
            self.deliver(sock, ns, &bytes);
        }
    }

    /// A server registers. One on a known node and port is replaced without a word, as in `ns.c`.
    pub fn announce(&mut self, service: u32, instance: u32, node: u32, port: u32) {
        let srv = Server {
            service,
            instance,
            node,
            port,
        };
        self.servers
            .retain(|s| !(s.node == srv.node && s.port == srv.port));
        self.servers.push(srv);
        self.notify(NEW_SERVER, Some(srv), None);
    }

    /// A server goes. Its lookups hear of it.
    pub fn withdraw(&mut self, node: u32, port: u32) {
        let gone: Vec<Server> = self
            .servers
            .iter()
            .filter(|s| s.node == node && s.port == port)
            .copied()
            .collect();
        self.servers.retain(|s| !(s.node == node && s.port == port));
        for s in gone {
            self.notify(DEL_SERVER, Some(s), None);
        }
    }

    /// A node says goodbye. Every server of it goes, one removal at a time.
    pub fn bye(&mut self, node: u32) {
        let ports: Vec<u32> = self
            .servers
            .iter()
            .filter(|s| s.node == node)
            .map(|s| s.port)
            .collect();
        for port in ports {
            self.withdraw(node, port);
        }
    }

    /// The destination took what it had and tells its waiting senders (every socket that was held
    /// back since) with an empty datagram from its own address, as `qrtr_tx_resume` does.
    pub fn resume(&mut self, to: Peer) {
        let waiters = self
            .flows
            .remove(&to)
            .map(|f| f.waiters)
            .unwrap_or_default();
        for w in waiters {
            self.deliver(w, to, &[]);
        }
    }

    /// How many lookups are registered.
    pub fn lookup_count(&self) -> usize {
        self.lookups.len()
    }

    fn control(&mut self, sock: SockId, bytes: &[u8]) {
        let Some(c) = Control::decode(bytes) else {
            return;
        };
        let service = c.words[0];
        match c.command {
            NEW_LOOKUP => {
                self.lookups.push((sock, service));
                let known: Vec<Server> = self
                    .servers
                    .iter()
                    .filter(|s| service == 0 || s.service == service)
                    .copied()
                    .collect();
                for s in known {
                    self.notify(NEW_SERVER, Some(s), Some(sock));
                }
                // the end of the list
                self.notify(NEW_SERVER, None, Some(sock));
            }
            DEL_LOOKUP => self
                .lookups
                .retain(|(s, svc)| !(*s == sock && *svc == service)),
            _ => {}
        }
    }
}

impl Qrtr for FakeQrtr {
    fn open(&mut self) -> Result<SockId, Fault> {
        if let Some(f) = self.open_faults.pop_front() {
            return Err(f);
        }
        let id = self.next_sock;
        self.next_sock += 1;
        let port = self.next_port;
        self.next_port += 1;
        let local = Peer {
            node: self.local_node,
            port,
        };
        self.socks.insert(
            id,
            Sock {
                local,
                inbox: VecDeque::new(),
            },
        );
        self.opened += 1;
        Ok(id)
    }

    fn close(&mut self, sock: SockId) {
        if self.socks.remove(&sock).is_some() {
            self.closed.push(sock);
        }
        self.lookups.retain(|(s, _)| *s != sock);
        self.recv_faults.remove(&sock);
    }

    fn local(&self, sock: SockId) -> Option<Peer> {
        self.socks.get(&sock).map(|s| s.local)
    }

    fn send(&mut self, sock: SockId, to: Peer, bytes: &[u8]) -> Result<(), Fault> {
        if !self.socks.contains_key(&sock) {
            return Err(Fault::Other);
        }
        if to == self.name_service() {
            if let Some(f) = self.control_faults.pop_front().flatten() {
                return Err(f);
            }
            self.control(sock, bytes);
            return Ok(());
        }
        if let Some(f) = self.send_faults.pop_front() {
            return Err(f);
        }
        if let Some(limit) = self.flow_limit {
            let flow = self.flows.entry(to).or_default();
            if flow.pending >= limit {
                if !flow.waiters.contains(&sock) {
                    flow.waiters.push(sock);
                }
                return Err(Fault::Retry);
            }
            flow.pending += 1;
        }
        self.sent.push((sock, to, bytes.to_vec()));
        Ok(())
    }

    fn recv(&mut self, sock: SockId) -> Result<Option<(Peer, Vec<u8>)>, Fault> {
        if let Some(f) = self.recv_faults.remove(&sock) {
            return Err(f);
        }
        match self.socks.get_mut(&sock) {
            Some(s) => Ok(s.inbox.pop_front()),
            None => Err(Fault::Other),
        }
    }

    fn fds(&self) -> Vec<RawFd> {
        Vec::new()
    }
}

struct Conn {
    inbox: VecDeque<Read>,
    written: Vec<Vec<u8>>,
    /// Sends find no room while this is set.
    blocked: bool,
    broken: bool,
    /// Writes fail while reads still work.
    write_fails: bool,
    closed: bool,
}

/// The socket of the protocol: peers that connect, messages they send, messages that were
/// written to them.
#[derive(Default)]
pub struct FakeIpc {
    next: IpcId,
    waiting: VecDeque<(IpcId, PeerInfo)>,
    conns: BTreeMap<IpcId, Conn>,
    /// The next accept fails with this.
    pub accept_fault: Option<IpcFault>,
}

impl FakeIpc {
    pub fn new() -> Self {
        FakeIpc {
            next: 1,
            ..Default::default()
        }
    }

    /// A peer connects and waits to be accepted.
    pub fn connect(&mut self, pid: u32, uid: u32, label: &str) -> IpcId {
        self.connect_as(pid, 0, uid, label)
    }

    /// The same, and the process has this identity (what the kernel's pidfd inode is to the real socket).
    pub fn connect_as(&mut self, pid: u32, ino: u64, uid: u32, label: &str) -> IpcId {
        let id = self.next;
        self.next += 1;
        self.conns.insert(
            id,
            Conn {
                inbox: VecDeque::new(),
                written: Vec::new(),
                blocked: false,
                broken: false,
                write_fails: false,
                closed: false,
            },
        );
        self.waiting.push_back((
            id,
            PeerInfo {
                pid,
                ino,
                uid,
                label: label.to_string(),
            },
        ));
        id
    }

    /// A message from the peer.
    pub fn push(&mut self, id: IpcId, bytes: &[u8]) {
        if let Some(c) = self.conns.get_mut(&id) {
            c.inbox.push_back(Read::Message(bytes.to_vec()));
        }
    }

    /// The peer closes.
    pub fn hang_up(&mut self, id: IpcId) {
        if let Some(c) = self.conns.get_mut(&id) {
            c.inbox.push_back(Read::Closed);
        }
    }

    /// The connection breaks: the next read and write fail.
    pub fn break_conn(&mut self, id: IpcId) {
        if let Some(c) = self.conns.get_mut(&id) {
            c.broken = true;
        }
    }

    /// Writes to the peer fail from now on, reads still work.
    pub fn fail_writes(&mut self, id: IpcId) {
        if let Some(c) = self.conns.get_mut(&id) {
            c.write_fails = true;
        }
    }

    /// The peer stops reading (or starts again): writes find no room.
    pub fn block_writes(&mut self, id: IpcId, on: bool) {
        if let Some(c) = self.conns.get_mut(&id) {
            c.blocked = on;
        }
    }

    /// What was written to the peer since the last call.
    pub fn take_written(&mut self, id: IpcId) -> Vec<Vec<u8>> {
        self.conns
            .get_mut(&id)
            .map(|c| std::mem::take(&mut c.written))
            .unwrap_or_default()
    }

    pub fn is_closed(&self, id: IpcId) -> bool {
        self.conns.get(&id).is_none_or(|c| c.closed)
    }
}

impl Ipc for FakeIpc {
    fn accept(&mut self) -> Result<Option<(IpcId, PeerInfo)>, IpcFault> {
        if let Some(f) = self.accept_fault.take() {
            return Err(f);
        }
        Ok(self.waiting.pop_front())
    }

    fn recv(&mut self, id: IpcId) -> Result<Read, IpcFault> {
        match self.conns.get_mut(&id) {
            Some(c) if c.broken => Err(IpcFault::Gone),
            Some(c) if !c.closed => Ok(c.inbox.pop_front().unwrap_or(Read::Empty)),
            _ => Err(IpcFault::Gone),
        }
    }

    fn send(&mut self, id: IpcId, bytes: &[u8]) -> Result<(), IpcFault> {
        match self.conns.get_mut(&id) {
            Some(c) if c.broken || c.closed || c.write_fails => Err(IpcFault::Gone),
            Some(c) if c.blocked => Err(IpcFault::Busy),
            Some(c) => {
                c.written.push(bytes.to_vec());
                Ok(())
            }
            None => Err(IpcFault::Gone),
        }
    }

    fn close(&mut self, id: IpcId) {
        if let Some(c) = self.conns.get_mut(&id) {
            c.closed = true;
        }
    }

    fn fds(&self) -> Vec<RawFd> {
        Vec::new()
    }
}
