// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! A small simulated modem for host tests. It answers the WDS, WDA and DPM
//! requests the engine sends and can inject network-side events. All values
//! are made up (documentation address ranges). No live network is involved,
//! which is also how emergency scenarios are exercised: simulation only.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
use crate::engine::{Engine, Qmi, QmiError};
use crate::model::ClientId;
use dataos_netcfg::NetOps;
use dataos_qmi::frame::{Builder, Frame, Kind};
use dataos_qmi::{dpm, wda, wds};
use std::collections::{BTreeMap, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug)]
pub struct SimNetwork {
    pub v4: Option<(Ipv4Addr, Ipv4Addr, Ipv4Addr, u32)>, // address, gateway, mask, mtu
    pub v6: Option<(Ipv6Addr, u8, u32)>,                 // address, prefix, mtu
    pub dns_v4: Ipv4Addr,
    pub dns_v6: Ipv6Addr,
}

impl Default for SimNetwork {
    fn default() -> Self {
        SimNetwork {
            v4: Some((
                "192.0.2.10".parse().unwrap(),
                "192.0.2.9".parse().unwrap(),
                "255.255.255.252".parse().unwrap(),
                1400,
            )),
            v6: Some(("2001:db8:1:2:0:0:0:5".parse().unwrap(), 64, 1380)),
            dns_v4: "192.0.2.53".parse().unwrap(),
            dns_v6: "2001:db8::53".parse().unwrap(),
        }
    }
}

#[derive(Default)]
struct SimClient {
    service: u8,
    family: Option<wds::IpFamily>,
    mux: Option<u8>,
    sub: Option<u32>,
    handle: Option<u32>,
    connected: bool,
    ind_registered: bool,
}

#[derive(Default)]
pub struct SimModem {
    next: ClientId,
    clients: BTreeMap<ClientId, SimClient>,
    pub inbox: VecDeque<(ClientId, Vec<u8>)>,
    /// Message IDs received, in order, with the client.
    pub requests: Vec<(ClientId, u16)>,
    /// Every request as it arrived, with the service of the client that sent it.
    pub frames: Vec<(u8, Vec<u8>)>,
    /// Message IDs of the WDS requests only (IDs overlap between services).
    pub wds_requests: Vec<u16>,
    pub network: SimNetwork,
    /// Families for which Start Network fails with this verbose reason.
    pub fail_start: Vec<(wds::IpFamily, u16, i16)>,
    /// Message IDs that get no answer (any service).
    pub mute: Vec<u16>,
    /// Services that answer nothing at all.
    pub mute_service: Vec<u8>,
    /// (service, message ID) pairs that are answered with a failure.
    pub reject: Vec<(u8, u16)>,
    /// Mux IDs that Bind Mux Data Port refuses (a stale binding, say).
    pub reject_mux_ids: Vec<u8>,
    /// Bind Mux Data Port requests to refuse by their number, counted from 0.
    pub reject_bind_mux_requests: Vec<usize>,
    bind_mux_seen: usize,
    /// Get Runtime Settings requests that get no answer, by their number counted from 0.
    pub mute_settings_requests: Vec<usize>,
    settings_seen: usize,
    /// Get Runtime Settings answers only for a client whose call is up: its own, or
    /// one that another client started on its mux ID (`external_connect`).
    pub require_call: bool,
    external_up: Vec<u8>,
    /// The real modem refuses a data format (QMI error 0x46, invalid operation) for a data port that no
    /// Open Port request has opened. Set this to take the data format without it.
    pub format_without_port: bool,
    port_open: bool,
    /// Refuse to hand out clients of this service.
    pub refuse_service: Vec<u8>,
    /// Refuse every send (the socket of the client is gone).
    pub fail_sends: bool,
    /// Send the Connected indication before the Start Network response.
    pub connect_before_response: bool,
    /// Runtime settings TLVs (tag, value) added to every Get Runtime Settings
    /// answer, and tags left out of it.
    pub settings_extra: Vec<(u8, Vec<u8>)>,
    pub settings_drop: Vec<u8>,
    /// Every Start Network request as it arrived, with the client it came from.
    pub start_frames: Vec<(ClientId, Vec<u8>)>,
    /// What a route lookup answers, by the IP family it asked for (4 or 6): the TLVs that follow
    /// the success result. A family without an entry gets the success and nothing else.
    pub route_answers: BTreeMap<u8, Vec<(u8, Vec<u8>)>>,
    /// Every route lookup request as it arrived, with the client it came from.
    pub route_frames: Vec<(ClientId, Vec<u8>)>,
    /// Leave the block of TLV 0x01 out of the route lookup answers, which the real modem always sends.
    pub route_no_block: bool,
    /// The subscription of every Bind Subscription request, in order.
    pub bound_subscriptions: Vec<u32>,
    /// Extended IP configuration indications that were not sent because the
    /// client never registered for them.
    pub ext_ip_unregistered: u32,
    pub closed: Vec<ClientId>,
    /// The transaction ID of the last request each client sent, so a test can
    /// answer with a frame the engine takes for the real answer.
    pub last_txn: BTreeMap<ClientId, u16>,
    next_handle: u32,
}

impl SimModem {
    pub fn new() -> Self {
        SimModem {
            next: 100,
            next_handle: 0x1000,
            ..Default::default()
        }
    }

    pub fn client_of(&self, family: wds::IpFamily) -> Option<ClientId> {
        self.clients
            .iter()
            .find(|(_, c)| c.service == wds::SERVICE && c.family == Some(family))
            .map(|(id, _)| *id)
    }

    /// Open clients of a service, in the order they were opened.
    pub fn client_ids(&self, service: u8) -> Vec<ClientId> {
        self.clients
            .iter()
            .filter(|(_, c)| c.service == service)
            .map(|(id, _)| *id)
            .collect()
    }

    /// The service a client was opened for.
    pub fn service_of(&self, client: ClientId) -> Option<u8> {
        self.clients.get(&client).map(|c| c.service)
    }

    pub fn mux_of(&self, client: ClientId) -> Option<u8> {
        self.clients.get(&client).and_then(|c| c.mux)
    }

    pub fn sub_of(&self, client: ClientId) -> Option<u32> {
        self.clients.get(&client).and_then(|c| c.sub)
    }

    /// How many WDS requests with this message ID arrived.
    pub fn count_requests(&self, id: u16) -> usize {
        self.wds_requests.iter().filter(|m| **m == id).count()
    }

    /// The network drops the call of this client.
    pub fn network_disconnect(&mut self, client: ClientId, kind: u16, reason: i16) {
        if let Some(c) = self.clients.get_mut(&client) {
            c.connected = false;
        }
        let mut v = Vec::new();
        v.extend_from_slice(&kind.to_le_bytes());
        v.extend_from_slice(&reason.to_le_bytes());
        let ind = Builder::indication(wds::id::PACKET_SERVICE_STATUS)
            .tlv(0x01, &[1, 0])
            .and_then(|b| b.tlv(0x11, &v))
            .and_then(|b| b.build())
            .unwrap();
        self.inbox.push_back((client, ind));
    }

    /// A packet service status indication: connected (2) or not, with the
    /// "reconfiguration required" flag.
    pub fn packet_status(&mut self, client: ClientId, status: u8, reconfiguration: bool) {
        let ind = Builder::indication(wds::id::PACKET_SERVICE_STATUS)
            .tlv(0x01, &[status, u8::from(reconfiguration)])
            .and_then(|b| b.build())
            .unwrap();
        self.inbox.push_back((client, ind));
    }

    /// A packet service status indication that names the IP family it is about.
    pub fn packet_status_for(&mut self, client: ClientId, status: u8, family: wds::IpFamily) {
        let ind = Builder::indication(wds::id::PACKET_SERVICE_STATUS)
            .tlv(0x01, &[status, 0])
            .and_then(|b| b.u8(0x12, family.to_u8()))
            .and_then(|b| b.build())
            .unwrap();
        self.inbox.push_back((client, ind));
    }

    /// Another client started an IPv4 call on this mux ID. Every client bound to it that
    /// registered for indications is told, as the modem does, with the family of the call.
    pub fn external_connect(&mut self, mux: u8) {
        self.external_connect_family(mux, wds::IpFamily::V4);
    }

    /// Another client started a call of this family on this mux ID.
    pub fn external_connect_family(&mut self, mux: u8, family: wds::IpFamily) {
        if !self.external_up.contains(&mux) {
            self.external_up.push(mux);
        }
        let targets: Vec<ClientId> = self
            .clients
            .iter()
            .filter(|(_, c)| c.mux == Some(mux) && c.ind_registered)
            .map(|(id, _)| *id)
            .collect();
        for id in targets {
            let ind = self.connected_ind(Some(family));
            self.inbox.push_back((id, ind));
        }
    }

    /// The call another client started on this mux ID ended.
    pub fn external_disconnect(&mut self, mux: u8, kind: u16, reason: i16) {
        self.external_up.retain(|m| *m != mux);
        let targets: Vec<ClientId> = self
            .clients
            .iter()
            .filter(|(_, c)| c.mux == Some(mux) && c.ind_registered)
            .map(|(id, _)| *id)
            .collect();
        for id in targets {
            self.network_disconnect(id, kind, reason);
        }
    }

    fn call_is_up(&self, client: ClientId) -> bool {
        self.clients
            .get(&client)
            .is_some_and(|c| c.connected || c.mux.is_some_and(|m| self.external_up.contains(&m)))
    }

    /// The network changed the configuration of this client's call.
    pub fn extended_ip_config(&mut self, client: ClientId, mask: u32) {
        // A real modem sends these only to clients that asked with Indication Register.
        if !self.clients.get(&client).is_some_and(|c| c.ind_registered) {
            self.ext_ip_unregistered += 1;
            return;
        }
        let ind = Builder::indication(wds::id::EXTENDED_IP_CONFIG)
            .u32(0x10, mask)
            .and_then(|b| b.build())
            .unwrap();
        self.inbox.push_back((client, ind));
    }

    /// Modem restart: all clients are gone and the data port is closed again.
    pub fn restart(&mut self) {
        self.clients.clear();
        self.inbox.clear();
        self.port_open = false;
    }

    fn connected_ind(&self, family: Option<wds::IpFamily>) -> Vec<u8> {
        let mut b = Builder::indication(wds::id::PACKET_SERVICE_STATUS)
            .tlv(0x01, &[2, 0])
            .unwrap();
        if let Some(f) = family {
            b = b.u8(0x12, f.to_u8()).unwrap();
        }
        b.build().unwrap()
    }

    fn settings(&self, family: Option<wds::IpFamily>, txn: u16) -> Vec<u8> {
        let mut tlvs: Vec<(u8, Vec<u8>)> = Vec::new();
        match family {
            Some(wds::IpFamily::V6) => {
                if let Some((a, p, mtu)) = self.network.v6 {
                    let mut v = a.octets().to_vec();
                    v.push(p);
                    tlvs.push((0x25, v));
                    tlvs.push((0x27, self.network.dns_v6.octets().to_vec()));
                    tlvs.push((0x29, mtu.to_le_bytes().to_vec()));
                }
                tlvs.push((0x2b, vec![6]));
            }
            _ => {
                if let Some((a, gw, mask, mtu)) = self.network.v4 {
                    tlvs.push((0x1e, u32::from(a).to_le_bytes().to_vec()));
                    tlvs.push((0x20, u32::from(gw).to_le_bytes().to_vec()));
                    tlvs.push((0x21, u32::from(mask).to_le_bytes().to_vec()));
                    tlvs.push((0x15, u32::from(self.network.dns_v4).to_le_bytes().to_vec()));
                    tlvs.push((0x29, mtu.to_le_bytes().to_vec()));
                }
                tlvs.push((0x2b, vec![4]));
            }
        }
        tlvs.retain(|(t, _)| !self.settings_drop.contains(t));
        tlvs.extend(self.settings_extra.iter().cloned());
        let mut b = Builder::response(txn, wds::id::GET_RUNTIME_SETTINGS)
            .ok()
            .unwrap();
        for (t, v) in tlvs {
            b = b.tlv(t, &v).unwrap();
        }
        b.build().unwrap()
    }
}

impl Qmi for SimModem {
    fn open_client(&mut self, service: u8) -> Result<ClientId, QmiError> {
        if self.refuse_service.contains(&service) {
            return Err(QmiError::Unavailable);
        }
        self.next += 1;
        self.clients.insert(
            self.next,
            SimClient {
                service,
                ..Default::default()
            },
        );
        Ok(self.next)
    }

    fn close_client(&mut self, client: ClientId) {
        self.clients.remove(&client);
        self.closed.push(client);
    }

    fn send(&mut self, client: ClientId, datagram: &[u8]) -> Result<(), QmiError> {
        if self.fail_sends || !self.clients.contains_key(&client) {
            return Err(QmiError::Unavailable);
        }
        let f = Frame::parse(datagram).expect("engine sent a malformed request");
        assert_eq!(f.kind, Kind::Request);
        self.requests.push((client, f.id));
        if let Some(service) = self.service_of(client) {
            self.frames.push((service, datagram.to_vec()));
        }
        self.last_txn.insert(client, f.txn);
        if self.clients.get(&client).map(|c| c.service) == Some(wds::SERVICE) {
            self.wds_requests.push(f.id);
        }
        let service = self.clients.get(&client).map(|c| c.service);
        if self.mute.contains(&f.id) || service.is_some_and(|s| self.mute_service.contains(&s)) {
            return Ok(());
        }
        if service == Some(wds::SERVICE) && f.id == wds::id::GET_RUNTIME_SETTINGS {
            let nth = self.settings_seen;
            self.settings_seen += 1;
            if self.mute_settings_requests.contains(&nth) {
                return Ok(());
            }
        }
        let txn = f.txn;
        let ok = |id| Builder::response(txn, id).ok().unwrap().build().unwrap();
        let fail = |id| {
            Builder::response(txn, id)
                .fail(0x0003)
                .unwrap()
                .build()
                .unwrap()
        };
        let mut out: Vec<Vec<u8>> = Vec::new();
        let (service, family) = {
            let c = self.clients.get(&client).unwrap();
            (c.service, c.family)
        };
        if self.reject.contains(&(service, f.id)) {
            out.push(fail(f.id));
            for o in out {
                self.inbox.push_back((client, o));
            }
            return Ok(());
        }
        match (service, f.id) {
            (wda::SERVICE, wda::SET_DATA_FORMAT)
                if !self.port_open && !self.format_without_port =>
            {
                out.push(
                    Builder::response(txn, f.id)
                        .fail(0x0046)
                        .unwrap()
                        .build()
                        .unwrap(),
                )
            }
            (wda::SERVICE, wda::SET_DATA_FORMAT) => out.push(
                Builder::response(txn, f.id)
                    .ok()
                    .unwrap()
                    .u32(0x11, wda::LINK_LAYER_RAW_IP)
                    .unwrap()
                    .build()
                    .unwrap(),
            ),
            (dpm::SERVICE, dpm::OPEN_PORT) => {
                self.port_open = true;
                out.push(ok(f.id));
            }
            (wds::SERVICE, wds::id::BIND_MUX_DATA_PORT) => {
                let mux = f.tlv(0x11).map(|v| v[0]);
                let nth = self.bind_mux_seen;
                self.bind_mux_seen += 1;
                if mux.is_some_and(|m| self.reject_mux_ids.contains(&m))
                    || self.reject_bind_mux_requests.contains(&nth)
                {
                    out.push(fail(f.id));
                } else {
                    self.clients.get_mut(&client).unwrap().mux = mux;
                    out.push(ok(f.id));
                }
            }
            (wds::SERVICE, wds::id::BIND_SUBSCRIPTION) => {
                self.clients.get_mut(&client).unwrap().sub = f
                    .tlv(0x01)
                    .map(|v| u32::from_le_bytes(v.try_into().unwrap()));
                self.bound_subscriptions
                    .extend(self.clients.get(&client).and_then(|c| c.sub));
                out.push(ok(f.id));
            }
            (wds::SERVICE, wds::id::SET_IP_FAMILY) => {
                self.clients.get_mut(&client).unwrap().family =
                    f.tlv(0x01).and_then(|v| wds::IpFamily::from_u8(v[0]));
                out.push(ok(f.id));
            }
            (wds::SERVICE, wds::id::START_NETWORK) => {
                self.start_frames.push((client, datagram.to_vec()));
                let fam = family.unwrap_or(wds::IpFamily::V4);
                if self.clients.get(&client).and_then(|c| c.mux).is_none() {
                    // like the modem: a client not bound to a data port cannot start a call
                    out.push(fail(f.id));
                } else if let Some((_, kind, reason)) =
                    self.fail_start.iter().find(|(x, _, _)| *x == fam)
                {
                    let mut v = Vec::new();
                    v.extend_from_slice(&kind.to_le_bytes());
                    v.extend_from_slice(&reason.to_le_bytes());
                    out.push(
                        Builder::response(txn, f.id)
                            .fail(0x000e)
                            .unwrap()
                            .u16(0x10, 1)
                            .unwrap()
                            .tlv(0x11, &v)
                            .unwrap()
                            .build()
                            .unwrap(),
                    );
                } else {
                    self.next_handle += 1;
                    let h = self.next_handle;
                    let c = self.clients.get_mut(&client).unwrap();
                    c.handle = Some(h);
                    c.connected = true;
                    let resp = Builder::response(txn, f.id)
                        .ok()
                        .unwrap()
                        .u32(0x01, h)
                        .unwrap()
                        .build()
                        .unwrap();
                    let ind = self.connected_ind(family);
                    if self.connect_before_response {
                        out.push(ind);
                        out.push(resp);
                    } else {
                        out.push(resp);
                        out.push(ind);
                    }
                }
            }
            (wds::SERVICE, wds::id::GET_RUNTIME_SETTINGS) => {
                if self.require_call && !self.call_is_up(client) {
                    // the answer of a modem to a question about a call that is not there
                    out.push(
                        Builder::response(txn, f.id)
                            .fail(dataos_qmi::QmiStatus::ERR_OUT_OF_CALL)
                            .unwrap()
                            .build()
                            .unwrap(),
                    );
                } else {
                    out.push(self.settings(family, txn));
                }
            }
            (wds::SERVICE, wds::id::ROUTE_LOOKUP) => {
                self.route_frames.push((client, datagram.to_vec()));
                let asked = f.tlv(0x19).and_then(|v| v.first().copied());
                let mut b = Builder::response(txn, f.id).ok().unwrap();
                if !self.route_no_block {
                    b = b.tlv(0x01, &[0; 10]).unwrap();
                }
                for (tag, value) in asked
                    .and_then(|fam| self.route_answers.get(&fam))
                    .into_iter()
                    .flatten()
                {
                    b = b.tlv(*tag, value).unwrap();
                }
                out.push(b.build().unwrap());
            }
            (wds::SERVICE, wds::id::STOP_NETWORK) => {
                self.clients.get_mut(&client).unwrap().connected = false;
                out.push(ok(f.id));
            }
            (wds::SERVICE, wds::id::INDICATION_REGISTER) => {
                self.clients.get_mut(&client).unwrap().ind_registered =
                    f.tlv(0x12) == Some(&[1u8][..]);
                out.push(ok(f.id));
            }
            _ => out.push(fail(f.id)),
        }
        for o in out {
            self.inbox.push_back((client, o));
        }
        Ok(())
    }
}

/// Deliver everything the modem has queued until it is quiet.
pub fn pump<N: NetOps>(engine: &mut Engine<SimModem, N>, now: u64) {
    for _ in 0..1000 {
        let next = engine.qmi_mut().inbox.pop_front();
        match next {
            Some((client, bytes)) => engine.on_qmi(now, client, &bytes),
            None => return,
        }
    }
    panic!("modem and engine did not settle");
}
