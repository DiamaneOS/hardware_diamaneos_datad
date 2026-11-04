// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The data call engine against a modem that says anything: responses with the transaction the engine waits
//! for and the TLVs of WDS, WDA and DPM, indications, raw bytes, route lookups, time and modem restarts. The books
//! must stay straight: a call ends at most once, an ended call holds no link, and every link is free once the calls
//! are released.
#![no_main]
use dataos_datacore::engine::{Config, Engine, ServiceEvent};
use dataos_datacore::sim::SimModem;
use dataos_datacore::*;
use dataos_fuzz::{encode, messages, tlvs, Input, Shape, RESPONSE};
use dataos_netcfg::FakeNet;
use dataos_qmi::frame::MAX_DATAGRAM;
use dataos_qmi::wds::{self, id};
use dataos_qmi::{dpm, wda};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

type E = Engine<SimModem, FakeNet>;

const SETTLE: usize = 4096;

fn pump(e: &mut E, now: u64) {
    for _ in 0..SETTLE {
        let next = e.qmi_mut().inbox.pop_front();
        match next {
            Some((client, bytes)) => e.on_qmi(now, client, &bytes),
            None => return,
        }
    }
    panic!("the engine and the modem did not settle");
}

const ANSWERED: [u16; 9] = [
    id::BIND_MUX_DATA_PORT,
    id::BIND_SUBSCRIPTION,
    id::SET_IP_FAMILY,
    id::INDICATION_REGISTER,
    id::START_NETWORK,
    id::GET_RUNTIME_SETTINGS,
    id::STOP_NETWORK,
    id::ROUTE_LOOKUP,
    wda::SET_DATA_FORMAT,
];

fn message(inp: &mut Input<'_>, txn: u16) -> Vec<u8> {
    let txn = if inp.one_in(8) { inp.u16() } else { txn };
    let known: Vec<&messages::Message> = messages::ALL
        .iter()
        .filter(|m| m.id < 0x30 || m.id == id::ROUTE_LOOKUP || m.id == id::EXTENDED_IP_CONFIG)
        .collect();
    match inp.u8() % 4 {
        // a message a parser reads
        0 | 1 => {
            let Some(m) = known.get(inp.below(known.len())) else {
                return Vec::new();
            };
            let list = tlvs(inp, m.tlvs, MAX_DATAGRAM);
            encode(m.kind, txn, m.id, &list)
        }
        // a response with only the result, to a message the engine sends
        2 => {
            let mid = inp.pick(&ANSWERED).unwrap_or(0);
            let list = tlvs(
                inp,
                &[(0x02, Shape::Result), (0x01, Shape::W(4))],
                MAX_DATAGRAM,
            );
            encode(RESPONSE, txn, mid, &list)
        }
        _ => {
            let n = usize::from(inp.u8() % 64);
            inp.exact(n)
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut inp = Input(data);
    let cfg = Config {
        link_count: 3,
        reserve_links: 1,
        ..Config::default()
    };
    let mut e: E = Engine::new(cfg, SimModem::new(), FakeNet::new());
    let mut now = 0u64;
    e.on_service_event(now, ServiceEvent::ModemUp);
    pump(&mut e, now);
    let mut calls = Vec::new();
    // an attached call keeps its link after it ended, until it is released
    let mut attached = Vec::new();
    let mut ended: BTreeMap<CallId, u32> = BTreeMap::new();
    let mut lookups: BTreeMap<u32, u32> = BTreeMap::new();
    let mut next_token = 1u32;

    for _ in 0..64 {
        if inp.is_empty() {
            break;
        }
        match inp.u8() % 16 {
            0 | 1 => {
                let attach = inp.one_in(4);
                let p = CallParams {
                    slot: Slot(inp.u8() % 2),
                    apn: Some("internet.example".into()),
                    ip_version: [IpVersion::V4, IpVersion::V6, IpVersion::V4V6][inp.below(3)],
                    priority: if inp.one_in(4) {
                        Priority::Emergency
                    } else {
                        Priority::Normal
                    },
                    attach,
                    ..Default::default()
                };
                if let Ok(id) = e.start_call(now, p) {
                    calls.push(id);
                    if attach {
                        attached.push(id);
                    }
                }
            }
            2 => {
                let q = LookupQuery {
                    subscription: inp.u8() % 3,
                    family: if inp.bool() { Family::V4 } else { Family::V6 },
                    apn: Some("ims.example".into()),
                    apn_type: None,
                    apn_type_mask: None,
                    hint: LookupHint::default(),
                };
                if e.start_lookup(now, next_token, q).is_ok() {
                    lookups.insert(next_token, 0);
                }
                next_token = next_token.wrapping_add(1);
            }
            // the real modem answers what waits
            3 | 4 => {
                for _ in 0..inp.below(8) {
                    let next = e.qmi_mut().inbox.pop_front();
                    if let Some((c, b)) = next {
                        e.on_qmi(now, c, &b);
                    }
                }
            }
            // a lie, to a client of any service
            5..=10 => {
                let services = [wds::SERVICE, wda::SERVICE, dpm::SERVICE];
                let s = inp.pick(&services).unwrap_or(wds::SERVICE);
                let clients = e.qmi_mut().client_ids(s);
                let Some(c) = inp.pick(&clients) else {
                    continue;
                };
                let txn = e.qmi_mut().last_txn.get(&c).copied().unwrap_or(1);
                let b = message(&mut inp, txn);
                e.on_qmi(now, c, &b);
            }
            11 | 12 => {
                now = now.saturating_add(u64::from(inp.u16()) * 4);
                e.tick(now);
            }
            13 => {
                e.qmi_mut().restart();
                e.net_mut().modem_restart();
                e.on_service_event(now, ServiceEvent::ModemDown);
                e.on_service_event(now, ServiceEvent::ModemUp);
            }
            14 => {
                if let Some(id) = inp.pick(&calls) {
                    let _ = e.stop_call(now, id);
                }
            }
            _ => {
                if let Some(token) = inp.pick(&lookups.keys().copied().collect::<Vec<_>>()) {
                    e.cancel_lookup(token);
                    lookups.remove(&token);
                }
            }
        }
        for ev in e.take_events() {
            match ev {
                Event::Disconnected { call, .. } => {
                    let n = ended.entry(call).or_default();
                    *n += 1;
                    assert_eq!(*n, 1, "call {call} ended twice");
                    if !attached.contains(&call) {
                        assert!(
                            !e.call_holds_link(call),
                            "an ended call still holds its link"
                        );
                    }
                }
                Event::LookupDone { token, link, .. } => {
                    let n = lookups.get_mut(&token).expect("an answer to no lookup");
                    *n += 1;
                    assert_eq!(*n, 1, "lookup {token} answered twice");
                    assert!(link.is_none_or(|l| l < e.link_total()));
                }
                _ => {}
            }
        }
        let holding = calls.iter().filter(|id| e.call_holds_link(**id)).count();
        assert!(e.link_total() - e.free_links() >= holding);
    }
    pump(&mut e, now);
    now = now.saturating_add(600_000);
    e.tick(now);
    pump(&mut e, now);
    let _ = e.take_events();
    for id in calls {
        let _ = e.release_call(now, id);
    }
    pump(&mut e, now);
    e.tick(now.saturating_add(600_000));
    pump(&mut e, now.saturating_add(600_000));
    assert_eq!(
        e.free_links(),
        e.link_total(),
        "a link is held after every call was released"
    );
});
