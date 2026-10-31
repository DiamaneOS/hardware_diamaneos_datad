// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The engine against a modem that lies. Frames carry a valid header, the
//! transaction ID the engine is waiting for and the message ID it asked
//! about, so they get past the stale checks and into the field parsers of
//! each step. The books must stay straight afterwards: no panic, no link held
//! by a call that ended, and every link free again once the calls are released.
use dataos_datacore::engine::{Config, Engine, ServiceEvent};
use dataos_datacore::sim::{pump, SimModem};
use dataos_datacore::*;
use dataos_netcfg::FakeNet;
use dataos_qmi::wds::{self, id};
use dataos_qmi::{dpm, wda, Builder};

type E = Engine<SimModem, FakeNet>;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
}

fn junk(rng: &mut Rng, n: usize) -> Vec<u8> {
    (0..n)
        .map(|_| {
            if rng.below(3) == 0 {
                rng.byte()
            } else {
                rng.byte() % 3
            }
        })
        .collect()
}

/// A response to `mid` with this transaction and random TLVs, most of them well formed.
fn response(rng: &mut Rng, txn: u16, mid: u16) -> Vec<u8> {
    let mut b = Builder::response(txn, mid);
    // the result: success 70% of the time, sometimes missing or malformed
    b = match rng.below(10) {
        0..=6 => b.ok().unwrap(),
        7 => b.fail(rng.below(20) as u16).unwrap(),
        8 => {
            let n = rng.below(6);
            b.tlv(0x02, &junk(rng, n)).unwrap()
        }
        _ => b,
    };
    let tags: &[u8] = match mid {
        id::START_NETWORK => &[0x01, 0x10, 0x11],
        id::GET_RUNTIME_SETTINGS => &[
            0x15, 0x16, 0x1e, 0x20, 0x21, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
        ],
        _ => &[0x11, 0x12, 0x13, 0x16],
    };
    for &t in tags {
        if rng.below(100) < 60 {
            let n = match (t, rng.below(10)) {
                (0x25 | 0x26, 0..=6) => 17,
                (0x27 | 0x28, 0..=6) => 16,
                (_, 0..=6) => 4,
                (_, _) => rng.below(40),
            };
            let mut v = junk(rng, n);
            // a prefix that is sometimes legal
            if matches!(t, 0x25 | 0x26) && n == 17 {
                v[16] = rng.byte() % 130;
            }
            b = b.tlv(t, &v).unwrap();
        }
    }
    b.build().unwrap()
}

fn indication(rng: &mut Rng) -> Vec<u8> {
    let mut b = match rng.below(3) {
        0 => Builder::indication(id::PACKET_SERVICE_STATUS),
        1 => Builder::indication(id::EXTENDED_IP_CONFIG),
        _ => Builder::indication(rng.next() as u16),
    };
    if rng.below(10) < 8 {
        b = b.tlv(0x01, &[1 + rng.byte() % 4, rng.byte() % 2]).unwrap();
    }
    if rng.below(2) == 0 {
        b = b.tlv(0x10, &junk(rng, 4)).unwrap();
    }
    if rng.below(2) == 0 {
        b = b.tlv(0x11, &junk(rng, 4)).unwrap();
    }
    if rng.below(2) == 0 {
        b = b.tlv(0x12, &[rng.byte() % 10]).unwrap();
    }
    b.build().unwrap()
}

const WDS_IDS: [u16; 7] = [
    id::BIND_MUX_DATA_PORT,
    id::BIND_SUBSCRIPTION,
    id::SET_IP_FAMILY,
    id::INDICATION_REGISTER,
    id::START_NETWORK,
    id::GET_RUNTIME_SETTINGS,
    id::STOP_NETWORK,
];

fn new_engine() -> E {
    let cfg = Config {
        link_count: 3,
        reserve_links: 1,
        ..Config::default()
    };
    Engine::new(cfg, SimModem::new(), FakeNet::new())
}

#[test]
fn lying_modem_never_breaks_the_books() {
    let mut rng = Rng(0xbad_f00d);
    let mut disconnected = 0;
    let mut connected = 0;
    let mut stale_total = 0u32;
    let mut malformed_total = 0u32;
    let mut dropped_total = 0u32;
    for _round in 0..4000 {
        let mut e = new_engine();
        e.on_service_event(0, ServiceEvent::ModemUp);
        pump(&mut e, 0);
        let mut ids = Vec::new();
        for n in 0..1 + rng.below(2) {
            let p = CallParams {
                slot: Slot(n as u8),
                apn: Some("internet.example".into()),
                ip_version: [IpVersion::V4, IpVersion::V6, IpVersion::V4V6][rng.below(3)],
                priority: if rng.below(4) == 0 {
                    Priority::Emergency
                } else {
                    Priority::Normal
                },
                ..Default::default()
            };
            if let Ok(id) = e.start_call(1, p) {
                ids.push(id);
            }
        }
        // let the real modem answer a few messages, then lie
        for _ in 0..rng.below(9) {
            if let Some((c, b)) = e.qmi_mut().inbox.pop_front() {
                e.on_qmi(1, c, &b);
            }
        }
        for _ in 0..1 + rng.below(8) {
            let clients = e.qmi_mut().client_ids(wds::SERVICE);
            if clients.is_empty() {
                break;
            }
            let c = clients[rng.below(clients.len())];
            let txn = e.qmi_mut().last_txn.get(&c).copied().unwrap_or(1);
            let bytes = match rng.below(10) {
                0..=5 => {
                    let mid = WDS_IDS[rng.below(WDS_IDS.len())];
                    response(&mut rng, txn, mid)
                }
                6..=8 => indication(&mut rng),
                _ => {
                    let n = rng.below(30);
                    junk(&mut rng, n)
                }
            };
            e.on_qmi(2, c, &bytes);
            if rng.below(6) == 0 {
                // the real modem keeps talking in between
                if let Some((c, b)) = e.qmi_mut().inbox.pop_front() {
                    e.on_qmi(2, c, &b);
                }
            }
            if rng.below(12) == 0 {
                e.tick(2 + rng.next() % 40_000);
            }
        }
        if rng.below(8) == 0 {
            e.qmi_mut().restart();
            e.net_mut().modem_restart();
            e.on_service_event(3, ServiceEvent::ModemDown);
            e.on_service_event(4, ServiceEvent::ModemUp);
        }
        pump(&mut e, 5);
        e.tick(100_000);
        // every call ended exactly once or is still running
        let events = e.take_events();
        for id in &ids {
            let ends = events
                .iter()
                .filter(|ev| matches!(ev, Event::Disconnected { call, .. } if call == id))
                .count();
            assert!(ends <= 1, "call {id} ended {ends} times");
            if ends == 1 {
                disconnected += 1;
                assert!(
                    !e.call_holds_link(*id),
                    "an ended call still holds its link"
                );
            }
            if events
                .iter()
                .any(|ev| matches!(ev, Event::Connected { call } if call == id))
            {
                connected += 1;
            }
        }
        // links in use equal the calls that hold one
        let holding = ids.iter().filter(|id| e.call_holds_link(**id)).count();
        assert_eq!(e.link_total() - e.free_links(), holding);
        let s = e.stats();
        stale_total += s.stale;
        malformed_total += s.malformed;
        dropped_total += s.dropped_optional;
        for id in ids {
            let _ = e.release_call(6, id);
        }
        assert_eq!(e.free_links(), e.link_total());
    }
    // the lies reached the parsers: some calls came up on odd data, some ended on it
    assert!(
        connected > 100 && disconnected > 100,
        "{connected} {disconnected}"
    );
    assert!(stale_total > 500, "stale checks hardly ran: {stale_total}");
    assert!(
        malformed_total > 100,
        "indication parsers hardly failed: {malformed_total}"
    );
    assert!(
        dropped_total > 20,
        "lenient settings hardly reached: {dropped_total}"
    );
}

#[test]
fn a_response_to_another_message_is_not_taken_for_the_answer() {
    // right transaction, wrong message: the engine keeps waiting
    let mut e = new_engine();
    e.on_service_event(0, ServiceEvent::ModemUp);
    pump(&mut e, 0);
    e.qmi_mut().mute_service.push(wds::SERVICE);
    let call = e
        .start_call(
            1,
            CallParams {
                apn: Some("x.example".into()),
                ..Default::default()
            },
        )
        .unwrap();
    let c = e.qmi_mut().client_ids(wds::SERVICE)[0];
    let txn = e.qmi_mut().last_txn[&c];
    // the engine asked Bind Mux Data Port. A Start Network answer must not move it on.
    let wrong = Builder::response(txn, id::START_NETWORK)
        .ok()
        .unwrap()
        .u32(0x01, 5)
        .unwrap()
        .build()
        .unwrap();
    e.on_qmi(2, c, &wrong);
    assert_eq!(e.stats().stale, 1);
    assert_eq!(e.qmi_mut().count_requests(id::BIND_SUBSCRIPTION), 0);
    assert!(e.call_is_active(call));
    // the right answer does
    let right = Builder::response(txn, id::BIND_MUX_DATA_PORT)
        .ok()
        .unwrap()
        .build()
        .unwrap();
    e.qmi_mut().mute_service.clear();
    e.on_qmi(3, c, &right);
    assert_eq!(e.qmi_mut().count_requests(id::BIND_SUBSCRIPTION), 1);
}

#[test]
fn the_bringup_answers_are_checked_for_message_and_transaction() {
    let mut e = new_engine();
    e.qmi_mut().mute_service.push(dpm::SERVICE);
    e.on_service_event(0, ServiceEvent::ModemUp);
    let c = e.qmi_mut().client_ids(dpm::SERVICE)[0];
    let txn = e.qmi_mut().last_txn[&c];
    // a good answer to another message, then a good message with another transaction
    let other = Builder::response(txn, id::STOP_NETWORK)
        .ok()
        .unwrap()
        .build()
        .unwrap();
    let wrong_txn = Builder::response(txn.wrapping_add(1), dpm::OPEN_PORT)
        .ok()
        .unwrap()
        .build()
        .unwrap();
    e.on_qmi(1, c, &other);
    e.on_qmi(1, c, &wrong_txn);
    assert_eq!(e.stats().stale, 2);
    assert!(
        e.qmi_mut().client_ids(wda::SERVICE).is_empty(),
        "still on the first step"
    );
    let right = Builder::response(txn, dpm::OPEN_PORT)
        .ok()
        .unwrap()
        .build()
        .unwrap();
    e.qmi_mut().mute_service.clear();
    e.on_qmi(1, c, &right);
    assert_eq!(e.qmi_mut().client_ids(wda::SERVICE).len(), 1);
}
