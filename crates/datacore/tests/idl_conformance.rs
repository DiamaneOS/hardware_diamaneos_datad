// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Every QMI message the engine sends and the simulated modem answers with, against the IDL tables of the
//! stock `libqmiservices.so` (`../qmi/tests/idl/idl-expected.txt`). The scenarios of the engine prove its state machine
//! against this modem. This proves that the modem speaks the layouts of the real one, so that they prove
//! something about the real one. The route lookup is left out, it is in no table.
#[path = "../../qmi/tests/idl/mod.rs"]
mod idl;

use dataos_datacore::engine::ServiceEvent;
use dataos_datacore::sim::SimModem;
use dataos_datacore::*;
use dataos_netcfg::FakeNet;
use dataos_qmi::wds::{self, IpFamily};
use dataos_qmi::{dpm, wda, Frame};
use idl::Spec;

type E = Engine<SimModem, FakeNet>;

fn name(service: u8) -> &'static str {
    match service {
        wds::SERVICE => "wds",
        wda::SERVICE => "wda",
        dpm::SERVICE => "dpm",
        other => panic!("service {other:#x}"),
    }
}

/// Deliver what the modem queued, as `pump` does, and check each message on the way.
fn pump_checked(e: &mut E, spec: &Spec, now: u64, seen: &mut usize) {
    for _ in 0..1000 {
        let Some((client, bytes)) = e.qmi_mut().inbox.pop_front() else {
            return;
        };
        let service = e.qmi_mut().service_of(client).unwrap();
        let f = Frame::parse(&bytes).unwrap();
        if f.id != wds::id::ROUTE_LOOKUP {
            if let Err(why) = spec.check_frame(name(service), &f) {
                panic!(
                    "modem to engine, {} {:?} {:#06x}: {why}",
                    name(service),
                    f.kind,
                    f.id
                );
            }
            *seen += 1;
        }
        e.on_qmi(now, client, &bytes);
    }
    panic!("modem and engine did not settle");
}

fn params(v: IpVersion) -> CallParams {
    CallParams {
        slot: Slot(0),
        apn: Some("a".repeat(wds::limits::MAX_APN)),
        username: Some("u".repeat(wds::limits::MAX_CRED)),
        password: Some("p".repeat(wds::limits::MAX_CRED)),
        auth: Some(wds::Auth::Chap),
        ip_version: v,
        technology_preference: Some(1),
        profile_index: Some(2),
        ..Default::default()
    }
}

#[test]
fn what_the_engine_and_the_simulated_modem_say_fits_the_stock_tables() {
    let spec = Spec::load();
    let mut e: E = Engine::new(Config::default(), SimModem::new(), FakeNet::new());
    let mut seen = 0;
    e.on_service_event(0, ServiceEvent::ModemUp);
    pump_checked(&mut e, &spec, 0, &mut seen);
    assert!(e.is_ready());

    // a dual stack call: bind, family, register, start, settings
    let id = e.start_call(1, params(IpVersion::V4V6)).unwrap();
    pump_checked(&mut e, &spec, 1, &mut seen);
    assert_eq!(e.take_events(), vec![Event::Connected { call: id }]);

    // the network changes the configuration, one family drops with a verbose reason, a status names a family
    let c4 = e.qmi_mut().client_of(IpFamily::V4).unwrap();
    let c6 = e.qmi_mut().client_of(IpFamily::V6).unwrap();
    e.qmi_mut().extended_ip_config(c4, wds::settings::MTU);
    e.qmi_mut().packet_status_for(c4, 2, IpFamily::V4);
    e.qmi_mut().network_disconnect(c6, 3, 8);
    pump_checked(&mut e, &spec, 50, &mut seen);
    e.stop_call(60, id).unwrap();
    pump_checked(&mut e, &spec, 60, &mut seen);

    // a start that the network refuses, with the call end reasons
    e.qmi_mut().fail_start.push((IpFamily::V4, 3, 36));
    let _ = e.start_call(70, params(IpVersion::V4)).unwrap();
    pump_checked(&mut e, &spec, 70, &mut seen);

    let requests = e.qmi_mut().frames.clone();
    for (service, bytes) in &requests {
        let f = Frame::parse(bytes).unwrap();
        if f.id == wds::id::ROUTE_LOOKUP {
            continue;
        }
        if let Err(why) = spec.check_frame(name(*service), &f) {
            panic!("engine to modem, {} {:#06x}: {why}", name(*service), f.id);
        }
    }
    // the run covered every message the engine builds
    let ids = |service: u8| -> Vec<u16> {
        let mut v: Vec<u16> = requests
            .iter()
            .filter(|(s, _)| *s == service)
            .map(|(_, b)| Frame::parse(b).unwrap().id)
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    };
    use wds::id;
    assert_eq!(
        ids(wds::SERVICE),
        vec![
            id::INDICATION_REGISTER,
            id::START_NETWORK,
            id::STOP_NETWORK,
            id::GET_RUNTIME_SETTINGS,
            id::SET_IP_FAMILY,
            id::BIND_MUX_DATA_PORT,
            id::BIND_SUBSCRIPTION
        ]
    );
    assert_eq!(ids(wda::SERVICE), vec![wda::SET_DATA_FORMAT]);
    assert_eq!(ids(dpm::SERVICE), vec![dpm::OPEN_PORT]);
    assert!(seen > 20, "{seen} messages checked");
}
