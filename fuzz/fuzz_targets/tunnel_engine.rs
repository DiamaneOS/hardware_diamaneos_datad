// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The Wi-Fi tunnel engine against a modem that says anything: messages of the reverse transport and of DFS to its
//! clients, with the transaction IDs the engine waits for, `0x11c` segments behind a connect, time passing, the
//! modem going away and coming back, and kernel calls that fail. Every datagram is zeroed after it was read, the
//! engine settles, and what it holds in the kernel stays bounded.
#![no_main]
use dataos_datacore::ServiceEvent;
use dataos_fuzz::{encode, messages, tlvs, Input, INDICATION};
use dataos_qmi::dfs;
use dataos_qmi::frame::Frame;
use dataos_qmi::reverse::{self, tech};
use dataos_qmi::wds;
use dataos_wlan_tunnel::engine::{Config, Engine};
use dataos_wlan_tunnel::fake::{FakeKernel, SimModem};
use dataos_wlan_tunnel::KernelError;
use libfuzzer_sys::fuzz_target;
use std::net::IpAddr;

/// Datagrams one step may cause before the engine counts as stuck in a loop with the modem.
const SETTLE: usize = 4096;

struct Rig {
    e: Engine<SimModem, FakeKernel>,
    m: SimModem,
    k: FakeKernel,
    now: u64,
}

impl Rig {
    fn pump(&mut self) {
        for _ in 0..SETTLE {
            let next = self.m.0.borrow_mut().inbox.pop_front();
            let Some((client, mut bytes)) = next else {
                let _ = self.e.take_lines();
                self.check();
                return;
            };
            self.e.on_qmi(self.now, client, &mut bytes);
            assert!(bytes.iter().all(|b| *b == 0), "a datagram was not zeroed");
        }
        panic!("the engine and the modem did not settle");
    }

    fn check(&self) {
        let k = self.k.0.borrow();
        assert!(k.states.len() <= 64, "{} ESP states", k.states.len());
        assert!(k.policies.len() <= 128, "{} policies", k.policies.len());
        assert!(k.rules.len() <= 64, "{} rules", k.rules.len());
        assert!(k.forwards.len() <= 64, "{} forwards", k.forwards.len());
        assert!(k.sockets.len() <= 2048, "{} sockets", k.sockets.len());
        assert!(k.tuples.len() <= 4096, "{} tuples", k.tuples.len());
        assert!(self.e.ready_clients() <= 8);
    }

    /// The last transaction this client sent, which is what the engine waits for.
    fn last_txn(&self, client: u32) -> u16 {
        let m = self.m.0.borrow();
        m.sent
            .iter()
            .rev()
            .find(|(c, _, _, _)| *c == client)
            .and_then(|(_, _, _, b)| Frame::parse(b).ok().map(|f| f.txn))
            .unwrap_or(0)
    }

    fn clients(&self, service: Option<u8>) -> Vec<(u32, u8)> {
        self.m
            .0
            .borrow()
            .clients
            .iter()
            .filter(|(_, c)| service.is_none_or(|s| s == c.service))
            .map(|(id, c)| (*id, c.service))
            .collect()
    }
}

const WDS_MESSAGES: [u16; 4] = [
    reverse::id::REVERSE_IND,
    reverse::id::IPSEC_SA,
    reverse::id::REVERSE_ANSWER,
    reverse::id::BIND_CLIENT,
];

/// A message of the modem for this client: one a parser of its service reads, or another.
fn message(inp: &mut Input<'_>, r: &Rig, client: u32, service: u8) -> Vec<u8> {
    let wanted: Vec<&messages::Message> = messages::ALL
        .iter()
        .filter(|m| {
            if service == wds::SERVICE {
                WDS_MESSAGES.contains(&m.id) || m.id < 0x30
            } else {
                (0x30..=0x35).contains(&m.id)
            }
        })
        .collect();
    let (kind, id, known) = match wanted.get(inp.below(wanted.len() + 1)) {
        Some(m) => (m.kind, m.id, m.tlvs),
        None => {
            // a plain answer to whatever was asked last
            let id =
                r.m.0
                    .borrow()
                    .sent
                    .iter()
                    .rev()
                    .find(|(c, _, _, _)| *c == client)
                    .map_or(0, |s| s.2);
            (2, id, &[(0x02u8, dataos_fuzz::Shape::Result)][..])
        }
    };
    let txn = if inp.one_in(8) {
        inp.u16()
    } else {
        r.last_txn(client)
    };
    let list = tlvs(inp, known, dfs::MAX_MESSAGE);
    encode(kind, txn, id, &list)
}

fn addr_tlv(a: IpAddr) -> (u8, Vec<u8>) {
    match a {
        IpAddr::V4(a) => (0x12, u32::from(a).to_le_bytes().to_vec()),
        IpAddr::V6(a) => {
            let mut v = a.octets().to_vec();
            v.push(64);
            (0x14, v)
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut inp = Input(data);
    let (m, k) = (SimModem::default(), FakeKernel::default());
    {
        let mut s = k.0.borrow_mut();
        s.device_present = true;
        s.addrs = vec![
            ("wlan0".into(), 30, "192.0.2.10".parse().unwrap()),
            ("wlan0".into(), 30, "2001:db8:1:2::10".parse().unwrap()),
            ("rmnet_data1".into(), 31, "203.0.113.5".parse().unwrap()),
        ];
        s.sockets.clear();
    }
    let e = Engine::new(Config::default(), m.clone(), k.clone());
    let mut r = Rig {
        e,
        m,
        k,
        now: 1_000,
    };
    r.e.start(r.now);
    r.e.on_service(r.now, ServiceEvent::ModemUp);
    r.pump();

    for _ in 0..48 {
        if inp.is_empty() {
            break;
        }
        match inp.u8() % 16 {
            // a message for a client
            0..=6 => {
                let all = r.clients(None);
                let Some((client, service)) = inp.pick(&all) else {
                    continue;
                };
                let b = message(&mut inp, &r, client, service);
                r.m.0.borrow_mut().inbox.push_back((client, b));
                r.pump();
            }
            // bytes that may be anything
            7 => {
                let all = r.clients(None);
                let Some((client, _)) = inp.pick(&all) else {
                    continue;
                };
                let n = usize::from(inp.u8());
                let b = inp.exact(n);
                r.m.0.borrow_mut().inbox.push_back((client, b));
                r.pump();
            }
            // a connect, with the segments of 0x11c the modem sends after its response
            8..=10 => {
                let wds_clients = r.clients(Some(wds::SERVICE));
                let Some((client, _)) = inp.pick(&wds_clients) else {
                    continue;
                };
                let sa_id = u32::from(inp.u16() % 4);
                let mut segments = Vec::new();
                for _ in 0..inp.below(4) {
                    let size = inp.u8() % 4;
                    let segment = inp.u8() % 4;
                    let mut head = (sa_id as u16).to_le_bytes().to_vec();
                    head.extend([size, segment]);
                    let mut list = vec![(0x01u8, head)];
                    for t in tlvs(&mut inp, messages::SA_SEGMENT, 8000) {
                        if t.0 != 0x01 {
                            list.push(t);
                        }
                    }
                    segments.push(encode(INDICATION, 0, reverse::id::IPSEC_SA, &list));
                }
                {
                    let mut mm = r.m.0.borrow_mut();
                    mm.sa_id = sa_id;
                    mm.sa_segments = segments;
                }
                let t = inp
                    .pick(&[
                        tech::IWLAN_S2B,
                        tech::LOCAL_BREAKOUT,
                        tech::CIWLAN,
                        tech::IWLAN_S2B_PROXY,
                        0,
                    ])
                    .unwrap_or(0);
                let a: IpAddr = if inp.bool() {
                    "203.0.113.5".parse().unwrap()
                } else {
                    "2001:db8:aa:bb::5".parse().unwrap()
                };
                let status = if inp.one_in(4) { 0 } else { 1 };
                let list = vec![
                    (0x01, u32::to_le_bytes(status).to_vec()),
                    (0x02, inp.u32().to_le_bytes().to_vec()),
                    (0x10, t.to_le_bytes().to_vec()),
                    addr_tlv(a),
                ];
                let b = encode(INDICATION, 0, reverse::id::REVERSE_IND, &list);
                r.m.0.borrow_mut().inbox.push_back((client, b));
                r.pump();
            }
            // time
            11 | 12 => {
                r.now = r.now.saturating_add(u64::from(inp.u16()) * 10);
                r.e.tick(r.now);
                r.pump();
            }
            // the modem goes, and comes back or not
            13 => {
                r.e.on_service(r.now, ServiceEvent::ModemDown);
                r.pump();
                if inp.bool() {
                    r.e.on_service(r.now, ServiceEvent::ModemUp);
                    r.pump();
                }
            }
            // the next kernel call of a kind that was made fails
            14 => {
                let mut kk = r.k.0.borrow_mut();
                let names: Vec<String> = kk.log.iter().rev().take(32).cloned().collect();
                if let Some(n) = names.get(inp.below(names.len())) {
                    let err = match inp.u8() % 3 {
                        0 => KernelError::NotFound,
                        1 => KernelError::Exists,
                        _ => KernelError::Failed(i32::from(inp.u8())),
                    };
                    kk.fail.insert(n.clone(), err);
                }
            }
            // the modem's sends fail for a while
            _ => {
                let on = inp.bool();
                r.m.0.borrow_mut().send_fails = on;
            }
        }
    }
    r.m.0.borrow_mut().send_fails = false;
    r.now = r.now.saturating_add(600_000);
    r.e.tick(r.now);
    r.pump();
});
