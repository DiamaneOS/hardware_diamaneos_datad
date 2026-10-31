// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! A rig for the tests of the main loop: the daemon over the fake sockets, with the simulated
//! modem behind the QRTR ports of the fake name service. Made-up node and port numbers.
#![allow(dead_code)]
use dataos_datacore::engine::{Config, Engine};
use dataos_datacore::sim::SimModem;
use dataos_datacore::{ClientId, Qmi};
use dataos_datad::daemon::Daemon;
use dataos_datad::fake::{FakeIpc, FakeQrtr};
use dataos_datad::ipc::IpcId;
use dataos_datad::qrtr::Peer;
use dataos_datad::server::{Server, ServerConfig};
use dataos_datad::transport::{Fault, QmiLink, Qrtr, SockId};
use dataos_netcfg::FakeNet;
use dataos_qmi::{dpm, wda, wds};
use dataos_wire::{Notify, Request};
use std::collections::BTreeMap;
use std::os::fd::RawFd;

pub const LOCAL: u32 = 1;
pub const MODEM: u32 = 0;
pub const WDS_PORT: u32 = 100;
pub const WDA_PORT: u32 = 101;
pub const DPM_PORT: u32 = 102;
pub const LABEL: &str = "u:r:rild:s0";

/// The fake sockets with the simulated modem behind the ports of the modem node.
pub struct SimQrtr {
    pub fake: FakeQrtr,
    pub sim: SimModem,
    clients: BTreeMap<SockId, ClientId>,
}

impl SimQrtr {
    pub fn new() -> Self {
        let mut sim = SimModem::new();
        sim.require_call = true;
        SimQrtr {
            fake: FakeQrtr::new(LOCAL),
            sim,
            clients: BTreeMap::new(),
        }
    }

    /// The modem registers its three services.
    pub fn announce_modem(&mut self) {
        self.fake
            .announce(u32::from(wds::SERVICE), 1, MODEM, WDS_PORT);
        self.fake
            .announce(u32::from(wda::SERVICE), 1, MODEM, WDA_PORT);
        self.fake
            .announce(u32::from(dpm::SERVICE), 1, MODEM, DPM_PORT);
    }

    /// The modem restarts: its state is gone, the name service tells that its servers are gone,
    /// and when `back` they register again.
    pub fn restart_modem(&mut self, back: bool) {
        self.sim.restart();
        self.clients.clear();
        self.fake.bye(MODEM);
        if back {
            self.announce_modem();
        }
    }

    fn service_of_port(port: u32) -> Option<u8> {
        match port {
            WDS_PORT => Some(wds::SERVICE),
            WDA_PORT => Some(wda::SERVICE),
            DPM_PORT => Some(dpm::SERVICE),
            _ => None,
        }
    }

    fn port_of_service(service: u8) -> u32 {
        match service {
            wds::SERVICE => WDS_PORT,
            wda::SERVICE => WDA_PORT,
            _ => DPM_PORT,
        }
    }

    /// Hand what the simulated modem has queued (answers, and indications it made up) to the
    /// sockets of the clients it belongs to.
    pub fn pump_sim(&mut self) {
        while let Some((client, bytes)) = self.sim.inbox.pop_front() {
            let sock = self
                .clients
                .iter()
                .find(|(_, c)| **c == client)
                .map(|(s, _)| *s);
            let service = self.sim.service_of(client);
            if let (Some(sock), Some(service)) = (sock, service) {
                let from = Peer {
                    node: MODEM,
                    port: Self::port_of_service(service),
                };
                self.fake.deliver(sock, from, &bytes);
            }
        }
    }
}

impl Qrtr for SimQrtr {
    fn open(&mut self) -> Result<SockId, Fault> {
        self.fake.open()
    }

    fn close(&mut self, sock: SockId) {
        if let Some(c) = self.clients.remove(&sock) {
            self.sim.close_client(c);
        }
        self.fake.close(sock);
    }

    fn local(&self, sock: SockId) -> Option<Peer> {
        self.fake.local(sock)
    }

    fn send(&mut self, sock: SockId, to: Peer, bytes: &[u8]) -> Result<(), Fault> {
        let service = Self::service_of_port(to.port).filter(|_| to.node == MODEM);
        let Some(service) = service else {
            return self.fake.send(sock, to, bytes);
        };
        // faults are set up on the fake
        if let Some(f) = self.fake.send_faults.pop_front() {
            return Err(f);
        }
        let client = match self.clients.get(&sock) {
            Some(c) => *c,
            None => {
                let c = self.sim.open_client(service).map_err(|_| Fault::Other)?;
                self.clients.insert(sock, c);
                c
            }
        };
        self.sim.send(client, bytes).map_err(|_| Fault::Other)?;
        self.pump_sim();
        Ok(())
    }

    fn recv(&mut self, sock: SockId) -> Result<Option<(Peer, Vec<u8>)>, Fault> {
        self.fake.recv(sock)
    }

    fn fds(&self) -> Vec<RawFd> {
        Vec::new()
    }
}

pub type Rig = Daemon<SimQrtr, FakeNet, FakeIpc>;

pub fn rig_with(mut qrtr: SimQrtr) -> Rig {
    qrtr.announce_modem();
    rig_without_modem(qrtr)
}

pub fn rig_without_modem(qrtr: SimQrtr) -> Rig {
    let engine = Engine::new(Config::default(), QmiLink::new(qrtr), FakeNet::new());
    Daemon::new(Server::new(ServerConfig::default(), engine), FakeIpc::new())
}

pub fn rig() -> Rig {
    rig_with(SimQrtr::new())
}

/// The daemon's steps at this time until it has nothing left to do. Replies of the simulated
/// modem are there at once, so a chain of requests takes a few steps.
pub fn settle(d: &mut Rig, now: u64) {
    for _ in 0..60 {
        d.step(now);
    }
}

pub fn sim(d: &mut Rig) -> &mut SimQrtr {
    d.server().engine().qmi_mut().io_mut()
}

/// A peer of the radio process connects and is taken.
pub fn module(d: &mut Rig, pid: u32, now: u64) -> IpcId {
    let id = d.ipc().connect(pid, 1001, LABEL);
    settle(d, now);
    id
}

/// A peer of the radio process with the number of an earlier process and another identity.
pub fn module_as(d: &mut Rig, pid: u32, ino: u64, now: u64) -> IpcId {
    let id = d.ipc().connect_as(pid, ino, 1001, LABEL);
    settle(d, now);
    id
}

pub fn say(d: &mut Rig, id: IpcId, req: Request) {
    d.ipc().push(id, &req.encode().unwrap());
}

/// What the daemon wrote to the module since the last call.
pub fn heard(d: &mut Rig, id: IpcId) -> Vec<Notify> {
    d.ipc()
        .take_written(id)
        .iter()
        .map(|b| Notify::decode(b).unwrap())
        .collect()
}
