// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Data call scenarios against the simulated modem. Every address, APN and
//! number is made up. Emergency behaviour is covered by simulation only.
use dataos_datacore::engine::ServiceEvent;
use dataos_datacore::sim::{pump, SimModem};
use dataos_datacore::*;
use dataos_netcfg::fake::Call as NetCall;
use dataos_netcfg::{FakeNet, NetError, NetOps, PipeState, SetupMarker, SharedNet, STOCK_FEATURES};
use dataos_qmi::wds::{self, IpFamily};
use dataos_qmi::{dpm, wda, Frame};
use std::net::IpAddr;

type E = Engine<SimModem, FakeNet>;

fn engine_with(cfg: Config) -> E {
    Engine::new(cfg, SimModem::new(), FakeNet::new())
}

fn engine() -> E {
    engine_with(Config::default())
}

fn up(e: &mut E) {
    e.on_service_event(0, ServiceEvent::ModemUp);
    pump(e, 0);
    assert!(e.is_ready());
}

fn params(slot: u8, v: IpVersion) -> CallParams {
    CallParams {
        slot: Slot(slot),
        apn: Some("internet.example".into()),
        ip_version: v,
        technology_preference: Some(1),
        ..Default::default()
    }
}

fn emergency(slot: u8, v: IpVersion) -> CallParams {
    CallParams {
        apn: Some("sos.example".into()),
        profile_index: Some(9),
        priority: Priority::Emergency,
        ..params(slot, v)
    }
}

fn connect(e: &mut E, p: CallParams) -> CallId {
    let id = e.start_call(1, p).unwrap();
    pump(e, 1);
    id
}

fn net_calls(e: &E) -> &Vec<NetCall> {
    &e.net().calls
}

#[test]
fn bringup_sets_data_format_opens_port_sets_up_ipa_and_registers_every_mux() {
    let mut e = engine();
    e.on_service_event(0, ServiceEvent::ModemUp);
    assert!(!e.is_ready());
    pump(&mut e, 0);
    assert!(e.is_ready());
    let ids: Vec<u16> = e.qmi_mut().requests.iter().map(|(_, m)| *m).collect();
    assert_eq!(ids, vec![wda::SET_DATA_FORMAT, dpm::OPEN_PORT]);

    let n = Config::default().link_count as usize;
    let calls = net_calls(&e);
    // the device is asked for its endpoint and brought up, its offloads are switched on, then both pipes are
    // set up with the stock format, then the links are made, each followed by its offloads and its mux channel
    let f = Config::default().ipa;
    assert!(
        calls[0]
            == NetCall::IpaEndpoint {
                device: "rmnet_ipa0".into()
            }
    );
    assert!(
        calls[1]
            == NetCall::SetLink {
                name: "rmnet_ipa0".into(),
                up: true,
                mtu: None
            }
    );
    assert!(
        calls[2]
            == NetCall::SetFeatures {
                name: "rmnet_ipa0".into(),
                wanted: STOCK_FEATURES.iter().map(|f| f.to_string()).collect()
            }
    );
    assert!(
        calls[3]
            == NetCall::IpaEgress {
                device: "rmnet_ipa0".into(),
                pipes: f.egress.clone()
            }
    );
    assert!(
        calls[4]
            == NetCall::IpaIngress {
                device: "rmnet_ipa0".into(),
                pipes: f.ingress.clone()
            }
    );
    let created: Vec<(String, u8)> = calls
        .iter()
        .filter_map(|c| match c {
            NetCall::CreateLink { name, mux_id } => Some((name.clone(), *mux_id)),
            _ => None,
        })
        .collect();
    assert_eq!(created.len(), n);
    assert_eq!(created[0], ("rmnet_data0".to_string(), 1));
    assert_eq!(created[n - 1], (format!("rmnet_data{}", n - 1), n as u8));
    let muxes: Vec<(u8, String)> = calls
        .iter()
        .filter_map(|c| match c {
            NetCall::IpaAddMux { mux_id, link, .. } => Some((*mux_id, link.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(muxes.len(), n, "every link is registered with the device");
    assert!(created
        .iter()
        .all(|(name, mux)| muxes.contains(&(*mux, name.clone()))));
    assert!(e.net().data_path_ok("rmnet_data0") && e.net().data_path_ok("rmnet_data14"));
    // the offloads are on for the device and for every link, as on the stock phone
    for name in
        std::iter::once("rmnet_ipa0".to_string()).chain((0..n).map(|i| format!("rmnet_data{i}")))
    {
        let on = e.net().features_of(&name);
        assert!(
            STOCK_FEATURES.iter().all(|f| on.iter().any(|x| x == f)),
            "{name}: {on:?}"
        );
    }
    assert!(e.net().egress_has_csum_header("rmnet_ipa0"));
}

/// The data format request of the bring-up is the one stock sends: raw IP, protocol 9 both ways, the
/// downlink limits that are also those of the ingress pipe, and the extension flags.
#[test]
fn the_wda_request_of_the_bringup_is_the_one_stock_sends() {
    let mut e = engine();
    up(&mut e);
    let frames = e.qmi_mut().frames.clone();
    let wda_frame = frames
        .iter()
        .find(|(s, b)| *s == wda::SERVICE && Frame::parse(b).unwrap().tlv(0x12).is_some())
        .map(|(_, b)| b.clone())
        .expect("a data format request");
    let f = Frame::parse(&wda_frame).unwrap();
    let word = |t: u8| u32::from_le_bytes(f.tlv(t).unwrap().try_into().unwrap());
    assert_eq!((word(0x11), word(0x12), word(0x13)), (2, 9, 9));
    assert_eq!((word(0x15), word(0x16)), (63, 64844));
    assert_eq!((word(0x1b), word(0x1c)), (32, 16384));
    assert_eq!(f.tlv(0x1d).unwrap(), &[1, 1]);
    // the limits of the downlink pipe are the same numbers
    let ingress = &Config::default().ipa.ingress[1];
    assert_eq!((ingress.agg_byte_limit, ingress.agg_pkt_limit), (64844, 63));
}

#[test]
fn ipv4_call_connects_and_configures_the_link() {
    let mut e = engine();
    up(&mut e);
    let id = connect(&mut e, params(0, IpVersion::V4));
    assert_eq!(e.take_events(), vec![Event::Connected { call: id }]);

    // request order of the one WDS client
    let seq: Vec<u16> = e
        .qmi_mut()
        .requests
        .iter()
        .skip(2)
        .map(|(_, m)| *m)
        .collect();
    assert_eq!(
        seq,
        vec![
            wds::id::BIND_MUX_DATA_PORT,
            wds::id::BIND_SUBSCRIPTION,
            wds::id::SET_IP_FAMILY,
            wds::id::INDICATION_REGISTER,
            wds::id::START_NETWORK,
            wds::id::GET_RUNTIME_SETTINGS
        ]
    );
    let client = e.qmi_mut().client_of(IpFamily::V4).unwrap();
    assert_eq!(e.qmi_mut().mux_of(client), Some(1));
    assert_eq!(e.qmi_mut().sub_of(client), Some(1));

    let info = e.call_info(id).unwrap();
    assert_eq!(info.ifname, "rmnet_data0");
    let v4 = info.v4.unwrap();
    assert_eq!(v4.mtu, Some(1400));
    assert!(info.v6.is_none());

    let last: Vec<&NetCall> = net_calls(&e).iter().rev().take(2).collect();
    assert!(matches!(
        last[0],
        NetCall::AddAddr {
            prefix: 30,
            addr: IpAddr::V4(_),
            ..
        }
    ));
    assert!(matches!(
        last[1],
        NetCall::SetLink {
            up: true,
            mtu: Some(1400),
            ..
        }
    ));
}

#[test]
fn call_started_before_the_modem_is_up_waits() {
    let mut e = engine();
    let id = e.start_call(0, params(0, IpVersion::V4)).unwrap();
    pump(&mut e, 0);
    assert!(e.take_events().is_empty());
    assert!(e.call_is_active(id));
    assert_eq!(e.qmi_mut().count_requests(wds::id::START_NETWORK), 0);
    up(&mut e);
    assert_eq!(e.take_events(), vec![Event::Connected { call: id }]);
}

#[test]
fn dual_stack_connects_once_with_both_families() {
    let mut e = engine();
    up(&mut e);
    let id = connect(&mut e, params(0, IpVersion::V4V6));
    assert_eq!(e.take_events(), vec![Event::Connected { call: id }]);
    let info = e.call_info(id).unwrap();
    assert!(info.v4.is_some() && info.v6.is_some());
    // link MTU is the smaller of 1400 and 1380
    assert!(net_calls(&e).iter().any(|c| matches!(
        c,
        NetCall::SetLink {
            up: true,
            mtu: Some(1380),
            ..
        }
    )));
    // IPv6: link-local with the network's identifier plus the global address
    // without an on-link prefix route
    let v6: Vec<_> = net_calls(&e)
        .iter()
        .filter_map(|c| match c {
            NetCall::AddAddr {
                addr: IpAddr::V6(a),
                prefix,
                flags,
                ..
            } => Some((*a, *prefix, *flags)),
            _ => None,
        })
        .collect();
    assert_eq!(v6.len(), 2);
    assert_eq!(v6[0].0.segments()[0], 0xfe80);
    assert_eq!(v6[0].1, 64);
    assert!(v6[0].2.no_dad && !v6[0].2.no_prefix_route);
    assert!(v6[1].2.no_dad && v6[1].2.no_prefix_route);
    assert!(net_calls(&e)
        .iter()
        .any(|c| matches!(c, NetCall::SetIpv6 { cfg, .. } if !cfg.disable_ipv6)));
}

#[test]
fn one_family_failing_gives_partial_connection_with_the_reason() {
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().fail_start.push((IpFamily::V6, 6, 33));
    let id = connect(&mut e, params(0, IpVersion::V4V6));
    assert_eq!(
        e.take_events(),
        vec![Event::PartiallyConnected { call: id }]
    );
    let info = e.call_info(id).unwrap();
    assert!(info.v4.is_some() && info.v6.is_none());
    assert_eq!(
        info.end_v6,
        Some(EndReason::Network {
            kind: 6,
            reason: 33
        })
    );
}

#[test]
fn all_families_failing_disconnects_and_frees_the_link() {
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().fail_start.push((IpFamily::V4, 6, 27));
    let id = connect(&mut e, params(0, IpVersion::V4));
    assert_eq!(
        e.take_events(),
        vec![Event::Disconnected {
            call: id,
            reason: EndReason::Network {
                kind: 6,
                reason: 27
            }
        }]
    );
    // no address was ever added
    assert!(!net_calls(&e)
        .iter()
        .any(|c| matches!(c, NetCall::AddAddr { .. })));
    // the same link is used again
    e.qmi_mut().fail_start.clear();
    e.release_call(2, id).unwrap();
    let id2 = connect(&mut e, params(0, IpVersion::V4));
    assert_eq!(e.call_info(id2).unwrap().ifname, "rmnet_data0");
}

#[test]
fn user_stop_sends_stop_network_and_cleans_up() {
    let mut e = engine();
    up(&mut e);
    let id = connect(&mut e, params(0, IpVersion::V4));
    e.take_events();
    e.stop_call(5, id).unwrap();
    pump(&mut e, 5);
    assert_eq!(
        e.take_events(),
        vec![Event::Disconnected {
            call: id,
            reason: EndReason::Local(LocalReason::UserRequested)
        }]
    );
    assert_eq!(e.qmi_mut().count_requests(wds::id::STOP_NETWORK), 1);
    let calls = net_calls(&e);
    assert!(calls.iter().any(|c| matches!(c, NetCall::DelAddr { .. })));
    assert!(matches!(
        calls.last().unwrap(),
        NetCall::SetLink { up: false, .. }
    ));
}

#[test]
fn network_disconnect_on_single_family_call() {
    let mut e = engine();
    up(&mut e);
    let id = connect(&mut e, params(0, IpVersion::V4));
    e.take_events();
    let c = e.qmi_mut().client_of(IpFamily::V4).unwrap();
    e.qmi_mut().network_disconnect(c, 3, 36);
    pump(&mut e, 9);
    assert_eq!(
        e.take_events(),
        vec![Event::Disconnected {
            call: id,
            reason: EndReason::Network {
                kind: 3,
                reason: 36
            }
        }]
    );
}

#[test]
fn one_dual_stack_family_dropping_is_a_reconfiguration() {
    let mut e = engine();
    up(&mut e);
    let id = connect(&mut e, params(0, IpVersion::V4V6));
    e.take_events();
    let c6 = e.qmi_mut().client_of(IpFamily::V6).unwrap();
    e.qmi_mut().network_disconnect(c6, 3, 8);
    pump(&mut e, 9);
    assert_eq!(e.take_events(), vec![Event::Reconfigured { call: id }]);
    assert!(e.call_info(id).unwrap().v6.is_none());
    let c4 = e.qmi_mut().client_of(IpFamily::V4).unwrap();
    e.qmi_mut().network_disconnect(c4, 3, 8);
    pump(&mut e, 10);
    assert!(matches!(
        e.take_events().as_slice(),
        [Event::Disconnected { .. }]
    ));
}

#[test]
fn connected_indication_before_the_start_response_is_not_lost() {
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().connect_before_response = true;
    let id = connect(&mut e, params(0, IpVersion::V4));
    assert_eq!(e.take_events(), vec![Event::Connected { call: id }]);
}

#[test]
fn local_steps_time_out_but_start_network_never_does() {
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().mute.push(wds::id::BIND_MUX_DATA_PORT);
    let id = e.start_call(100, params(0, IpVersion::V4)).unwrap();
    pump(&mut e, 100);
    assert_eq!(e.next_deadline(), Some(100 + 10_000));
    e.tick(10_099);
    assert!(e.take_events().is_empty());
    e.tick(10_100);
    assert_eq!(
        e.take_events(),
        vec![Event::Disconnected {
            call: id,
            reason: EndReason::Local(LocalReason::Timeout)
        }]
    );

    // Start Network without any answer: no deadline, no event, however long.
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().mute.push(wds::id::START_NETWORK);
    let id = e.start_call(0, params(0, IpVersion::V4)).unwrap();
    pump(&mut e, 0);
    assert_eq!(e.next_deadline(), None);
    e.tick(3_600_000);
    assert!(e.take_events().is_empty());
    assert!(e.call_is_active(id));
    // the user can still cancel it
    e.stop_call(3_600_001, id).unwrap();
    assert!(matches!(
        e.take_events().as_slice(),
        [Event::Disconnected { .. }]
    ));
}

#[test]
fn modem_restart_ends_calls_and_waiting_calls_survive() {
    let mut e = engine();
    up(&mut e);
    let a = connect(&mut e, params(0, IpVersion::V4));
    e.take_events();
    e.qmi_mut().restart();
    e.on_service_event(20, ServiceEvent::ModemDown);
    assert_eq!(
        e.take_events(),
        vec![Event::Disconnected {
            call: a,
            reason: EndReason::Local(LocalReason::ModemRestart)
        }]
    );
    assert!(!e.is_ready());
    // a call requested while the modem is down waits for it
    let b = e.start_call(21, params(1, IpVersion::V4)).unwrap();
    pump(&mut e, 21);
    assert!(e.take_events().is_empty());
    e.on_service_event(30, ServiceEvent::ModemUp);
    pump(&mut e, 30);
    assert_eq!(e.take_events(), vec![Event::Connected { call: b }]);
    // the second slot is bound to subscription 2
    let c = e.qmi_mut().client_of(IpFamily::V4).unwrap();
    assert_eq!(e.qmi_mut().sub_of(c), Some(2));
}

#[test]
fn bringup_is_retried_after_a_failure() {
    let mut e = engine();
    e.qmi_mut().refuse_service.push(wda::SERVICE);
    e.on_service_event(0, ServiceEvent::ModemUp);
    assert!(!e.is_ready());
    assert_eq!(e.next_deadline(), Some(2_000));
    e.qmi_mut().refuse_service.clear();
    e.tick(2_000);
    pump(&mut e, 2_000);
    assert!(e.is_ready());
}

#[test]
fn configuration_change_updates_address_and_mtu() {
    let mut e = engine();
    up(&mut e);
    let id = connect(&mut e, params(0, IpVersion::V4));
    e.take_events();
    let c = e.qmi_mut().client_of(IpFamily::V4).unwrap();
    e.qmi_mut().network.v4 = Some((
        "192.0.2.14".parse().unwrap(),
        "192.0.2.13".parse().unwrap(),
        "255.255.255.252".parse().unwrap(),
        1360,
    ));
    e.qmi_mut().extended_ip_config(c, wds::settings::MTU);
    pump(&mut e, 50);
    let ev = e.take_events();
    assert!(ev.contains(&Event::MtuChanged {
        call: id,
        family: Family::V4,
        mtu: 1360
    }));
    assert!(ev.contains(&Event::Reconfigured { call: id }));
    let calls = net_calls(&e);
    assert!(calls.iter().any(|c| matches!(c, NetCall::DelAddr { .. })));
    let adds = calls
        .iter()
        .filter(|c| matches!(c, NetCall::AddAddr { .. }))
        .count();
    assert_eq!(adds, 2);
}

#[test]
fn links_are_limited_to_the_handle_count_and_reused() {
    let cfg = Config {
        link_count: 2,
        reserve_links: 0,
        ..Config::default()
    };
    let mut e = engine_with(cfg);
    up(&mut e);
    let a = connect(&mut e, params(0, IpVersion::V4));
    let b = connect(&mut e, params(1, IpVersion::V4));
    assert_ne!(
        e.call_info(a).unwrap().ifname,
        e.call_info(b).unwrap().ifname
    );
    assert_eq!(
        e.start_call(2, params(0, IpVersion::V4)).unwrap_err(),
        StartError::NoLink
    );
    e.stop_call(3, a).unwrap();
    pump(&mut e, 3);
    e.release_call(3, a).unwrap();
    assert!(e.start_call(4, params(0, IpVersion::V4)).is_ok());
}

#[test]
fn two_sims_have_independent_calls() {
    let mut e = engine();
    up(&mut e);
    let a = connect(&mut e, params(0, IpVersion::V4));
    let b = connect(&mut e, params(1, IpVersion::V4));
    let ev = e.take_events();
    assert!(
        ev.contains(&Event::Connected { call: a }) && ev.contains(&Event::Connected { call: b })
    );
    assert_eq!(e.call_info(a).unwrap().ifname, "rmnet_data0");
    assert_eq!(e.call_info(b).unwrap().ifname, "rmnet_data1");
    // stopping one leaves the other
    e.stop_call(7, a).unwrap();
    pump(&mut e, 7);
    assert_eq!(e.take_events().len(), 1);
    assert!(e.call_is_active(b));
}

#[test]
fn invalid_slot_is_refused_before_anything_is_sent() {
    let mut e = engine();
    up(&mut e);
    let before = e.qmi_mut().requests.len();
    assert_eq!(
        e.start_call(1, params(2, IpVersion::V4)).unwrap_err(),
        StartError::Invalid
    );
    assert_eq!(e.qmi_mut().requests.len(), before);
}

#[test]
fn qmi_client_refused_and_link_failure_fail_the_call_cleanly() {
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().refuse_service.push(wds::SERVICE);
    let id = e.start_call(1, params(0, IpVersion::V4)).unwrap();
    pump(&mut e, 1);
    assert_eq!(
        e.take_events(),
        vec![Event::Disconnected {
            call: id,
            reason: EndReason::Local(LocalReason::NoQmiClient)
        }]
    );

    // a kernel refusal while configuring the link
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().refuse_service.clear();
    e.net_mut().fail_next = Some(("add", NetError::Os(1)));
    let id = connect(&mut e, params(0, IpVersion::V4));
    assert_eq!(
        e.take_events(),
        vec![Event::Disconnected {
            call: id,
            reason: EndReason::Local(LocalReason::LinkFailed)
        }]
    );
}

#[test]
fn garbage_from_the_modem_never_panics_and_is_counted() {
    let mut e = engine();
    up(&mut e);
    let id = connect(&mut e, params(0, IpVersion::V4));
    e.take_events();
    let c = e.qmi_mut().client_of(IpFamily::V4).unwrap();
    // deterministic pseudo-random datagrams, plus truncations of a valid one
    let mut x: u64 = 0x1234_5678_9abc_def0;
    for n in 0..5000 {
        let len = (n % 200) as usize;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            buf.push((x >> 33) as u8);
        }
        e.on_qmi(10, c, &buf);
    }
    e.on_qmi(10, 9999, &[0, 1, 2]);
    assert!(e.stats().malformed > 0 && e.stats().unknown_client == 1);
    // the call survived or ended cleanly, never inconsistent
    let ev = e.take_events();
    assert!(ev.iter().all(|x| matches!(
        x,
        Event::Disconnected { .. } | Event::Reconfigured { .. } | Event::MtuChanged { .. }
    )));
    let _ = id;
}

#[test]
fn release_of_an_active_call_stops_silently() {
    let mut e = engine();
    up(&mut e);
    let id = connect(&mut e, params(0, IpVersion::V4));
    e.take_events();
    e.release_call(5, id).unwrap();
    assert!(e.take_events().is_empty());
    assert!(e.call_info(id).is_none());
    assert!(!e.qmi_mut().closed.is_empty());
}

#[test]
fn a_repeated_modem_up_does_not_redo_bring_up_under_running_calls() {
    let mut e = engine();
    up(&mut e);
    let id = connect(&mut e, params(0, IpVersion::V4));
    e.take_events();
    let before = e.qmi_mut().requests.len();
    e.on_service_event(9, ServiceEvent::ModemUp);
    pump(&mut e, 9);
    assert_eq!(e.qmi_mut().requests.len(), before, "nothing was sent");
    assert!(e.is_ready() && e.call_is_active(id));
    assert!(e.take_events().is_empty());
}

#[test]
fn an_ended_call_is_only_closed_until_released() {
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().fail_start.push((IpFamily::V4, 6, 27));
    let id = connect(&mut e, params(0, IpVersion::V4));
    e.take_events();
    assert!(e.call_is_closed(id) && !e.call_is_active(id));
}

// ---- emergency and call setup parameters ---------------------------------

/// TLVs of every Start Network request the modem received, in arrival order.
fn start_tlvs(e: &mut E) -> Vec<Vec<(u8, Vec<u8>)>> {
    e.qmi_mut()
        .start_frames
        .iter()
        .map(|(_, bytes)| {
            let f = Frame::parse(bytes).unwrap();
            assert_eq!(f.id, wds::id::START_NETWORK);
            f.tlvs().map(|(t, v)| (t, v.to_vec())).collect()
        })
        .collect()
}

#[test]
fn emergency_call_reaches_the_modem_with_every_parameter_unchanged() {
    // Simulation only. The call carries an emergency APN, a profile index, the
    // technology preference and four setup parameters the engine has no name
    // for. Both legs must send exactly these bytes and nothing else.
    let mut e = engine();
    up(&mut e);
    let mut p = emergency(0, IpVersion::V4V6);
    p.username = Some("user-test".into());
    p.password = Some("pw-test".into());
    p.auth = Some(wds::Auth::PapOrChap);
    p.start_tlvs = vec![
        RawTlv {
            tag: 0x41,
            value: vec![0x10, 0, 0, 0],
        }, // an APN type
        RawTlv {
            tag: 0x42,
            value: vec![0x80, 0, 0, 0, 0, 0, 0, 0],
        }, // an APN type mask
        RawTlv {
            tag: 0x43,
            value: vec![1, 2, 3, 4, 5, 6, 7],
        }, // a handoff context
        RawTlv {
            tag: 0x44,
            value: vec![3],
        }, // an SSC mode
    ];
    let id = connect(&mut e, p);
    assert_eq!(e.take_events(), vec![Event::Connected { call: id }]);

    let sent = start_tlvs(&mut e);
    assert_eq!(sent.len(), 2, "one Start Network per family");
    for (family_byte, tlvs) in [(4u8, &sent[0]), (6u8, &sent[1])] {
        assert_eq!(
            *tlvs,
            vec![
                (0x14, b"sos.example".to_vec()),
                (0x17, b"user-test".to_vec()),
                (0x18, b"pw-test".to_vec()),
                (0x16, vec![3]),
                (0x19, vec![family_byte]),
                (0x30, vec![1]),
                (0x31, vec![9]),
                (0x41, vec![0x10, 0, 0, 0]),
                (0x42, vec![0x80, 0, 0, 0, 0, 0, 0, 0]),
                (0x43, vec![1, 2, 3, 4, 5, 6, 7]),
                (0x44, vec![3]),
            ]
        );
    }
}

#[test]
fn an_ordinary_call_sends_no_extra_tlvs() {
    let mut e = engine();
    up(&mut e);
    connect(&mut e, params(0, IpVersion::V4));
    let sent = start_tlvs(&mut e);
    let tags: Vec<u8> = sent[0].iter().map(|(t, _)| *t).collect();
    assert_eq!(tags, vec![0x14, 0x19, 0x30]);
}

#[test]
fn parameters_that_cannot_be_sent_are_refused_before_a_link_is_taken() {
    let mut e = engine();
    up(&mut e);
    let free = e.free_links();
    let mut p = params(0, IpVersion::V4);
    p.apn = Some("x".repeat(wds::limits::MAX_APN + 1));
    assert_eq!(e.start_call(1, p).unwrap_err(), StartError::Invalid);
    let mut p = params(0, IpVersion::V4);
    p.start_tlvs = vec![RawTlv {
        tag: 0x19,
        value: vec![6],
    }]; // would shadow the IP family
    assert_eq!(e.start_call(1, p).unwrap_err(), StartError::Invalid);
    assert_eq!(e.free_links(), free);
    assert_eq!(e.qmi_mut().start_frames.len(), 0);
}

#[test]
fn a_refused_subscription_binding_ends_an_ordinary_call_before_start_network() {
    // Data on the wrong SIM is worse than no data, so an ordinary call ends.
    let mut e = engine();
    up(&mut e);
    e.qmi_mut()
        .reject
        .push((wds::SERVICE, wds::id::BIND_SUBSCRIPTION));
    let id = connect(&mut e, params(0, IpVersion::V4));
    assert_eq!(
        e.take_events(),
        vec![Event::Disconnected {
            call: id,
            reason: EndReason::Local(LocalReason::BindFailed)
        }]
    );
    assert_eq!(e.qmi_mut().count_requests(wds::id::START_NETWORK), 0);
    assert_eq!(e.stats().bind_refusals_passed, 0);
}

#[test]
fn a_refused_ip_family_ends_an_ordinary_call_before_start_network() {
    let mut e = engine();
    up(&mut e);
    e.qmi_mut()
        .reject
        .push((wds::SERVICE, wds::id::SET_IP_FAMILY));
    let id = connect(&mut e, params(0, IpVersion::V4));
    assert_eq!(
        e.take_events(),
        vec![Event::Disconnected {
            call: id,
            reason: EndReason::Local(LocalReason::BindFailed)
        }]
    );
    assert_eq!(e.qmi_mut().count_requests(wds::id::START_NETWORK), 0);
}

#[test]
fn an_emergency_call_goes_on_when_the_subscription_binding_is_refused() {
    // No SIM means there may be nothing to bind to. The call must still try.
    let mut e = engine();
    up(&mut e);
    e.qmi_mut()
        .reject
        .push((wds::SERVICE, wds::id::BIND_SUBSCRIPTION));
    let id = connect(&mut e, emergency(0, IpVersion::V4));
    assert_eq!(e.take_events(), vec![Event::Connected { call: id }]);
    assert_eq!(e.qmi_mut().count_requests(wds::id::START_NETWORK), 1);
    assert_eq!(e.stats().bind_refusals_passed, 1);
    let c = e.qmi_mut().client_of(IpFamily::V4).unwrap();
    assert_eq!(e.qmi_mut().sub_of(c), None, "never bound");
}

#[test]
fn an_emergency_call_goes_on_when_the_ip_family_is_refused() {
    let mut e = engine();
    up(&mut e);
    e.qmi_mut()
        .reject
        .push((wds::SERVICE, wds::id::SET_IP_FAMILY));
    let id = connect(&mut e, emergency(0, IpVersion::V4));
    assert_eq!(e.take_events(), vec![Event::Connected { call: id }]);
    assert_eq!(e.stats().bind_refusals_passed, 1);
    // the family still reached the modem in Start Network
    assert_eq!(
        start_tlvs(&mut e)[0]
            .iter()
            .find(|t| t.0 == 0x19)
            .unwrap()
            .1,
        vec![4]
    );
}

#[test]
fn an_emergency_call_goes_on_when_the_modem_does_not_answer_the_binding() {
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().mute.push(wds::id::BIND_SUBSCRIPTION);
    let id = e.start_call(100, emergency(0, IpVersion::V4)).unwrap();
    pump(&mut e, 100);
    assert!(e.take_events().is_empty(), "waiting for the answer");
    e.tick(100 + 10_000);
    pump(&mut e, 10_100);
    assert_eq!(e.take_events(), vec![Event::Connected { call: id }]);
    assert_eq!(e.stats().bind_refusals_passed, 1);

    // an ordinary call ends with a timeout in the same situation
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().mute.push(wds::id::BIND_SUBSCRIPTION);
    let id = e.start_call(100, params(0, IpVersion::V4)).unwrap();
    pump(&mut e, 100);
    e.tick(10_100);
    assert_eq!(
        e.take_events(),
        vec![Event::Disconnected {
            call: id,
            reason: EndReason::Local(LocalReason::Timeout)
        }]
    );
}

#[test]
fn a_refused_data_port_binding_ends_even_an_emergency_call() {
    // Without the mux binding there is no data path at all.
    let mut e = engine();
    up(&mut e);
    e.qmi_mut()
        .reject
        .push((wds::SERVICE, wds::id::BIND_MUX_DATA_PORT));
    let id = connect(&mut e, emergency(0, IpVersion::V4));
    assert_eq!(
        e.take_events(),
        vec![Event::Disconnected {
            call: id,
            reason: EndReason::Local(LocalReason::BindFailed)
        }]
    );
}

#[test]
fn indication_register_is_sent_and_extended_ip_config_depends_on_it() {
    let mut e = engine();
    up(&mut e);
    connect(&mut e, params(0, IpVersion::V4));
    e.take_events();
    let c = e.qmi_mut().client_of(IpFamily::V4).unwrap();
    e.qmi_mut().extended_ip_config(c, wds::settings::MTU);
    pump(&mut e, 5);
    assert_eq!(
        e.qmi_mut().ext_ip_unregistered,
        0,
        "the client had registered"
    );
    assert_eq!(e.qmi_mut().count_requests(wds::id::INDICATION_REGISTER), 1);
}

#[test]
fn a_failed_or_unanswered_indication_register_does_not_stop_the_call() {
    let mut e = engine();
    up(&mut e);
    e.qmi_mut()
        .reject
        .push((wds::SERVICE, wds::id::INDICATION_REGISTER));
    let id = connect(&mut e, params(0, IpVersion::V4));
    assert_eq!(e.take_events(), vec![Event::Connected { call: id }]);
    assert_eq!(e.stats().ind_register_refusals, 1);
    // such a client gets no configuration change indications
    let c = e.qmi_mut().client_of(IpFamily::V4).unwrap();
    e.qmi_mut().extended_ip_config(c, wds::settings::MTU);
    assert_eq!(e.qmi_mut().ext_ip_unregistered, 1);

    let mut e = engine();
    up(&mut e);
    e.qmi_mut().mute.push(wds::id::INDICATION_REGISTER);
    let id = e.start_call(0, params(0, IpVersion::V4)).unwrap();
    pump(&mut e, 0);
    e.tick(10_000);
    pump(&mut e, 10_000);
    assert_eq!(e.take_events(), vec![Event::Connected { call: id }]);
}

// ---- links: restart, exhaustion, reserve ---------------------------------

#[test]
fn a_modem_restart_makes_the_links_and_the_ipa_state_again() {
    let mut e = engine();
    up(&mut e);
    let n = Config::default().link_count as usize;
    connect(&mut e, params(0, IpVersion::V4));
    e.take_events();
    assert!(e.net().data_path_ok("rmnet_data0"));

    // what the kernel does: free rmnet_ipa0 with the modem, register a new one
    e.qmi_mut().restart();
    e.net_mut().modem_restart();
    e.on_service_event(20, ServiceEvent::ModemDown);
    assert_eq!(e.net().link_count(), 0);
    assert!(!e.net().data_path_ok("rmnet_data0"));
    e.take_events();
    e.on_service_event(30, ServiceEvent::ModemUp);
    pump(&mut e, 30);
    assert!(e.is_ready());
    assert_eq!(e.net().link_count(), n, "all links are back");
    assert_eq!(
        e.net().mux_channels("rmnet_ipa0"),
        n,
        "and registered again"
    );
    assert!(e.net().data_path_ok("rmnet_data0") && e.net().data_path_ok("rmnet_data14"));

    // a call after the restart works and its link carries data
    let id = connect(&mut e, params(0, IpVersion::V4));
    assert_eq!(e.take_events(), vec![Event::Connected { call: id }]);
    let ifname = e.call_info(id).unwrap().ifname;
    assert!(e.net().data_path_ok(&ifname));
}

#[test]
fn links_left_by_an_earlier_daemon_are_deleted_by_name_and_made_again() {
    // The daemon crashed and was restarted. Links survive a crash. The new
    // instance deletes each name blindly, it never dumps the links.
    let mut net = FakeNet::new();
    net.create_rmnet_link(
        "rmnet_ipa0",
        "rmnet_data0",
        9,
        dataos_netcfg::RmnetFlags::qmap_default(),
    )
    .unwrap();
    net.calls.clear();
    let mut e = Engine::new(Config::default(), SimModem::new(), net);
    up(&mut e);
    let deleted = e
        .net()
        .calls
        .iter()
        .filter(|c| matches!(c, NetCall::DeleteLink(n) if n == "rmnet_data0"))
        .count();
    assert_eq!(deleted, 1, "the stale link was deleted");
    let created: Vec<u8> = e
        .net()
        .calls
        .iter()
        .filter_map(|c| match c {
            NetCall::CreateLink { name, mux_id } if name == "rmnet_data0" => Some(*mux_id),
            _ => None,
        })
        .collect();
    assert_eq!(created, vec![1], "made again with the right mux ID");
}

#[test]
fn bringup_waits_for_the_device_and_retries_with_a_growing_delay() {
    let mut e = engine();
    e.net_mut().remove_device("rmnet_ipa0");
    e.on_service_event(0, ServiceEvent::ModemUp);
    pump(&mut e, 0);
    assert!(!e.is_ready(), "no device, no IPA setup");
    assert_eq!(e.next_deadline(), Some(2_000));
    e.tick(2_000);
    pump(&mut e, 2_000);
    assert!(!e.is_ready());
    assert_eq!(e.next_deadline(), Some(2_000 + 4_000));
    e.tick(6_000);
    pump(&mut e, 6_000);
    assert_eq!(e.next_deadline(), Some(6_000 + 8_000));
    // the driver registers the device
    e.net_mut().add_device("rmnet_ipa0");
    e.tick(14_000);
    pump(&mut e, 14_000);
    assert!(e.is_ready());
    assert!(e.net().data_path_ok("rmnet_data0"));
    // the next outage starts from the short delay again
    e.on_service_event(20_000, ServiceEvent::ModemDown);
    e.net_mut().remove_device("rmnet_ipa0");
    e.on_service_event(21_000, ServiceEvent::ModemUp);
    pump(&mut e, 21_000);
    assert_eq!(e.next_deadline(), Some(21_000 + 2_000));
}

#[test]
fn the_delay_between_bringup_attempts_has_a_ceiling() {
    let cfg = Config {
        retry_ms: 1_000,
        retry_max_ms: 5_000,
        ..Config::default()
    };
    let mut e = engine_with(cfg);
    e.net_mut().remove_device("rmnet_ipa0");
    e.on_service_event(0, ServiceEvent::ModemUp);
    pump(&mut e, 0);
    let mut now = 0;
    let mut gaps = Vec::new();
    for _ in 0..6 {
        let next = e.next_deadline().unwrap();
        gaps.push(next - now);
        now = next;
        e.tick(now);
        pump(&mut e, now);
    }
    assert_eq!(gaps, vec![1_000, 2_000, 4_000, 5_000, 5_000, 5_000]);
}

#[test]
fn bringup_steps_have_deadlines_so_a_silent_modem_cannot_stall_it() {
    let mut e = engine();
    e.qmi_mut().mute_service.push(wda::SERVICE);
    e.on_service_event(0, ServiceEvent::ModemUp);
    pump(&mut e, 0);
    assert_eq!(e.next_deadline(), Some(10_000));
    e.tick(10_000);
    assert!(!e.is_ready());
    assert_eq!(
        e.next_deadline(),
        Some(12_000),
        "retry after the first delay"
    );
    e.qmi_mut().mute_service.clear();
    e.tick(12_000);
    pump(&mut e, 12_000);
    assert!(e.is_ready());
}

/// The endpoint of the device and the pipe pair are the driver's answers, and they go to the modem: the
/// data format and the port mapper get the interface number, the port mapper gets the pipe pair, and the data port
/// binding of a call gets the interface number too.
#[test]
fn the_endpoint_and_the_pipe_pair_come_from_the_driver_and_go_to_the_modem() {
    use dataos_netcfg::Endpoint;
    let mut e = engine();
    e.net_mut().endpoint = Endpoint {
        epid: 7,
        consumer: 3,
        producer: 21,
    };
    up(&mut e);
    let words = |v: &[u32]| -> Vec<u8> { v.iter().flat_map(|x| x.to_le_bytes()).collect() };
    let has = |frames: &[(u8, Vec<u8>)], service: u8, id: u16, needle: &[u8]| {
        frames.iter().any(|(s, f)| {
            *s == service
                && Frame::parse(f).is_ok_and(|fr| fr.id == id)
                && f.windows(needle.len()).any(|w| w == needle)
        })
    };
    let frames = e.qmi_mut().frames.clone();
    // type 4 (embedded) and interface 7, in the data format and in the port mapper
    assert!(has(
        &frames,
        wda::SERVICE,
        wda::SET_DATA_FORMAT,
        &words(&[4, 7])
    ));
    assert!(has(
        &frames,
        dpm::SERVICE,
        dpm::OPEN_PORT,
        &words(&[4, 7, 3, 21])
    ));
    // a call binds its data port to the same interface
    connect(&mut e, params(0, IpVersion::V4));
    let frames = e.qmi_mut().frames.clone();
    assert!(has(
        &frames,
        wds::SERVICE,
        wds::id::BIND_MUX_DATA_PORT,
        &words(&[4, 7])
    ));
}

/// A device that cannot say which endpoint it is, or cannot be brought up, fails the attempt, which is
/// made again later. The numbers of the modem are not guessed.
#[test]
fn a_device_that_cannot_give_its_endpoint_or_come_up_fails_the_attempt() {
    for kind in ["ipa_endpoint", "set"] {
        let mut e = engine();
        e.net_mut().fail_next = Some((kind, NetError::Os(19)));
        e.on_service_event(0, ServiceEvent::ModemUp);
        pump(&mut e, 0);
        assert!(!e.is_ready(), "{kind}");
        assert!(
            e.qmi_mut().requests.is_empty(),
            "{kind}: nothing went to the modem"
        );
        e.tick(2_000);
        pump(&mut e, 2_000);
        assert!(e.is_ready(), "{kind}: the second attempt works");
    }
}

/// Stock leaves `accept_ra` and `autoconf` of a link alone and switches IPv6 on while a call runs and off
/// when it ends. A call of the other family touches nothing.
#[test]
fn ipv6_is_switched_on_with_a_call_and_off_when_it_ends_and_nothing_else_is_set() {
    let v6_calls = |e: &E| -> Vec<bool> {
        net_calls(e)
            .iter()
            .filter_map(|c| match c {
                NetCall::SetIpv6 { cfg, .. } => Some(cfg.disable_ipv6),
                _ => None,
            })
            .collect()
    };
    let mut e = engine();
    up(&mut e);
    let id = connect(&mut e, params(0, IpVersion::V4));
    assert_eq!(e.take_events(), vec![Event::Connected { call: id }]);
    e.stop_call(2, id).unwrap();
    pump(&mut e, 2);
    e.release_call(3, id).unwrap();
    assert!(v6_calls(&e).is_empty(), "an IPv4 call does not touch IPv6");
    e.take_events();
    let id = connect(&mut e, params(0, IpVersion::V6));
    assert_eq!(e.take_events(), vec![Event::Connected { call: id }]);
    assert_eq!(v6_calls(&e), [false], "on while it runs");
    e.stop_call(4, id).unwrap();
    pump(&mut e, 4);
    e.release_call(5, id).unwrap();
    assert_eq!(
        v6_calls(&e),
        [false, true],
        "and off when the link is let go"
    );
    // the link was taken down first
    let calls = net_calls(&e);
    let down = calls
        .iter()
        .rposition(|c| matches!(c, NetCall::SetLink { up: false, .. }))
        .unwrap();
    let off = calls
        .iter()
        .rposition(|c| matches!(c, NetCall::SetIpv6 { .. }))
        .unwrap();
    assert!(down < off);
}

#[test]
fn a_refused_data_format_fails_bringup_and_leaves_no_links() {
    let mut e = engine();
    e.qmi_mut()
        .reject
        .push((wda::SERVICE, wda::SET_DATA_FORMAT));
    e.on_service_event(0, ServiceEvent::ModemUp);
    pump(&mut e, 0);
    assert!(!e.is_ready());
    assert_eq!(e.net().link_count(), 0);
    // the device was asked for its endpoint and brought up, and nothing more: no pipe, no link
    assert!(net_calls(&e)
        .iter()
        .all(|c| matches!(c, NetCall::IpaEndpoint { .. } | NetCall::SetLink { .. })));
}

#[test]
fn a_refused_ipa_pipe_setup_fails_bringup() {
    for kind in ["ipa_egress", "ipa_ingress"] {
        let mut e = engine();
        e.net_mut().fail_next = Some((kind, NetError::Os(14)));
        e.on_service_event(0, ServiceEvent::ModemUp);
        pump(&mut e, 0);
        assert!(!e.is_ready(), "{kind}");
        assert_eq!(e.net().link_count(), 0, "{kind}");
        e.tick(2_000);
        pump(&mut e, 2_000);
        assert!(e.is_ready(), "{kind}: second attempt works");
        // a pipe whose ioctl failed is not taken for set up: the retry sends it again
        assert!(
            e.net().data_path_ok("rmnet_data0"),
            "{kind}: both pipes exist"
        );
    }
}

#[test]
fn a_link_that_vanished_fails_one_call_and_comes_back_for_the_next() {
    let mut e = engine();
    up(&mut e);
    // someone (or a kernel bug) removed the link
    e.net_mut().delete_link("rmnet_data0").unwrap();
    let a = connect(&mut e, params(0, IpVersion::V4));
    assert_eq!(
        e.take_events(),
        vec![Event::Disconnected {
            call: a,
            reason: EndReason::Local(LocalReason::LinkFailed)
        }]
    );
    e.release_call(2, a).unwrap();
    let b = connect(&mut e, params(0, IpVersion::V4));
    assert_eq!(e.take_events(), vec![Event::Connected { call: b }]);
    assert_eq!(e.call_info(b).unwrap().ifname, "rmnet_data0");
    assert!(e.net().data_path_ok("rmnet_data0"));
}

#[test]
fn only_the_first_fifteen_mux_ids_exist_so_there_are_fifteen_links() {
    assert_eq!(
        Config::default().link_count as usize,
        dataos_netcfg::ipa::MAX_MUX_CHANNELS
    );
    // a sixteenth link would fail its mux registration like the driver does
    let cfg = Config {
        link_count: 16,
        ..Config::default()
    };
    let mut e = engine_with(cfg);
    up(&mut e);
    assert_eq!(e.net().mux_channels("rmnet_ipa0"), 15);
    assert_eq!(e.stats().link_errors, 1);
}

#[test]
fn a_call_that_ended_gives_its_link_back_without_being_released() {
    // One link. The first call fails and nobody releases it. The next call
    // must still get the link.
    let cfg = Config {
        link_count: 1,
        reserve_links: 0,
        ..Config::default()
    };
    let mut e = engine_with(cfg);
    up(&mut e);
    e.qmi_mut().fail_start.push((IpFamily::V4, 6, 27));
    let a = connect(&mut e, params(0, IpVersion::V4));
    assert!(e.call_is_closed(a) && !e.call_holds_link(a));
    assert_eq!(e.free_links(), 1);
    e.qmi_mut().fail_start.clear();
    let b = connect(&mut e, params(1, IpVersion::V4));
    let ev = e.take_events();
    assert!(ev.contains(&Event::Connected { call: b }), "{ev:?}");
    // the ended call is still there for its end reason, and releasing it does not free b's link
    assert!(e.call_info(a).is_some());
    e.release_call(5, a).unwrap();
    assert_eq!(e.free_links(), 0);
}

#[test]
fn a_stopped_call_gives_its_link_back_and_leaves_it_down() {
    let mut e = engine();
    up(&mut e);
    let free = e.free_links();
    let a = connect(&mut e, params(0, IpVersion::V4));
    assert_eq!(e.free_links(), free - 1);
    e.stop_call(3, a).unwrap();
    pump(&mut e, 3);
    assert_eq!(e.free_links(), free);
    assert!(matches!(
        net_calls(&e).last().unwrap(),
        NetCall::SetLink { up: false, .. }
    ));
}

#[test]
fn ordinary_calls_cannot_take_the_reserve_but_an_emergency_call_can() {
    let cfg = Config {
        link_count: 4,
        reserve_links: 2,
        ..Config::default()
    };
    let mut e = engine_with(cfg);
    up(&mut e);
    connect(&mut e, params(0, IpVersion::V4));
    connect(&mut e, params(0, IpVersion::V4));
    assert_eq!(e.free_links(), 2);
    assert_eq!(
        e.start_call(2, params(0, IpVersion::V4)).unwrap_err(),
        StartError::NoLink,
        "the last two links are for emergencies"
    );
    let a = connect(&mut e, emergency(0, IpVersion::V4));
    let b = connect(&mut e, emergency(1, IpVersion::V4));
    let ev = e.take_events();
    assert!(
        ev.contains(&Event::Connected { call: a }) && ev.contains(&Event::Connected { call: b })
    );
    assert_eq!(e.free_links(), 0);
    assert_eq!(
        e.start_call(3, emergency(0, IpVersion::V4)).unwrap_err(),
        StartError::NoLink,
        "nothing is left for a fifth"
    );
}

#[test]
fn the_reserve_is_available_again_when_the_emergency_call_ends() {
    let cfg = Config {
        link_count: 2,
        reserve_links: 1,
        ..Config::default()
    };
    let mut e = engine_with(cfg);
    up(&mut e);
    connect(&mut e, params(0, IpVersion::V4));
    let sos = connect(&mut e, emergency(0, IpVersion::V4));
    e.stop_call(5, sos).unwrap();
    pump(&mut e, 5);
    assert_eq!(e.free_links(), 1);
    assert_eq!(
        e.start_call(6, params(0, IpVersion::V4)).unwrap_err(),
        StartError::NoLink,
        "still reserved"
    );
    assert!(e.start_call(6, emergency(0, IpVersion::V4)).is_ok());
}

// ---- runtime settings ----------------------------------------------------

#[test]
fn the_link_mtu_of_a_dual_stack_call_never_drops_below_what_ipv6_needs() {
    let mut e = engine();
    up(&mut e);
    let v4 = e.qmi_mut().network.v4.unwrap();
    e.qmi_mut().network.v4 = Some((v4.0, v4.1, v4.2, 1000));
    let id = connect(&mut e, params(0, IpVersion::V4V6));
    assert_eq!(e.take_events(), vec![Event::Connected { call: id }]);
    let mtus: Vec<Option<u32>> = net_calls(&e)
        .iter()
        .filter_map(|c| match c {
            NetCall::SetLink { up: true, mtu, .. } => Some(*mtu),
            _ => None,
        })
        .collect();
    assert!(mtus.iter().all(|m| m.is_none_or(|m| m >= 1280)), "{mtus:?}");
    assert_eq!(*mtus.last().unwrap(), Some(1280));
    // the family value is still reported unchanged, the link value is what was applied
    let info = e.call_info(id).unwrap();
    assert_eq!(info.link_mtu, Some(1280));
    assert_eq!(info.v4.unwrap().mtu, Some(1000));

    // without IPv6 the small MTU is used as it is
    let mut e = engine();
    up(&mut e);
    let v4 = e.qmi_mut().network.v4.unwrap();
    e.qmi_mut().network.v4 = Some((v4.0, v4.1, v4.2, 1000));
    let id = connect(&mut e, params(0, IpVersion::V4));
    assert!(net_calls(&e).iter().any(|c| matches!(
        c,
        NetCall::SetLink {
            up: true,
            mtu: Some(1000),
            ..
        }
    )));
    assert_eq!(e.call_info(id).unwrap().link_mtu, Some(1000));
}

#[test]
fn odd_optional_settings_do_not_fail_the_call() {
    let mut e = engine();
    up(&mut e);
    let long = "a".repeat(300);
    let mut names = vec![1u8];
    names.extend_from_slice(&(long.len() as u16).to_le_bytes());
    names.extend_from_slice(long.as_bytes());
    e.qmi_mut().settings_extra = vec![
        (0x24, names),         // a 300-byte P-CSCF name
        (0x2a, vec![5, 1]),    // a damaged domain list
        (0x26, vec![1, 2, 3]), // not a gateway
    ];
    let id = connect(&mut e, params(0, IpVersion::V4V6));
    assert_eq!(e.take_events(), vec![Event::Connected { call: id }]);
    assert!(e.stats().dropped_optional >= 3);
    let info = e.call_info(id).unwrap();
    assert!(info.v4.unwrap().settings.pcscf_domains.is_empty());
}

#[test]
fn a_broken_address_still_fails_the_call() {
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().settings_drop = vec![0x1e];
    e.qmi_mut().settings_extra = vec![(0x1e, vec![1, 2, 3])];
    let id = connect(&mut e, params(0, IpVersion::V4));
    assert_eq!(
        e.take_events(),
        vec![Event::Disconnected {
            call: id,
            reason: EndReason::Local(LocalReason::BadSettings)
        }]
    );
}

#[test]
fn a_connected_indication_refetches_the_settings_only_when_it_asks_for_it() {
    let mut e = engine();
    up(&mut e);
    connect(&mut e, params(0, IpVersion::V4));
    e.take_events();
    let c = e.qmi_mut().client_of(IpFamily::V4).unwrap();
    let fetches = |e: &mut E| e.qmi_mut().count_requests(wds::id::GET_RUNTIME_SETTINGS);
    assert_eq!(fetches(&mut e), 1);
    // connected again, nothing to reconfigure: no new request, no event
    e.qmi_mut().packet_status(c, 2, false);
    pump(&mut e, 5);
    assert_eq!(fetches(&mut e), 1);
    assert!(e.take_events().is_empty());
    // connected with the reconfiguration flag: the settings are fetched again
    e.qmi_mut().packet_status(c, 2, true);
    pump(&mut e, 6);
    assert_eq!(fetches(&mut e), 2);
    assert!(e.take_events().contains(&Event::Reconfigured { call: 1 }));
}

// ---- a restarted daemon, a replaced device ---------------------------------

type Shared = Engine<SimModem, SharedNet>;

fn daemon_on(net: &SharedNet) -> Shared {
    Engine::new(Config::default(), SimModem::new(), net.clone())
}

fn up_at(e: &mut Shared, now: u64) {
    e.on_service_event(now, ServiceEvent::ModemUp);
    pump(e, now);
}

fn pipe_calls(net: &SharedNet) -> (usize, usize) {
    let n = net.0.borrow();
    let egress = n
        .calls
        .iter()
        .filter(|c| matches!(c, NetCall::IpaEgress { .. }))
        .count();
    let ingress = n
        .calls
        .iter()
        .filter(|c| matches!(c, NetCall::IpaIngress { .. }))
        .count();
    (egress, ingress)
}

#[test]
fn a_restarted_daemon_with_the_modem_still_up_becomes_ready() {
    // The first daemon sets the pipes up and dies. The kernel keeps them, and
    // the IPA driver refuses to set a pipe up twice. The second daemon must
    // not try, or it never becomes ready and every call, EIMS included, waits.
    let net = SharedNet::new();
    let mut a = daemon_on(&net);
    up_at(&mut a, 0);
    assert!(a.is_ready());
    assert_eq!(pipe_calls(&net), (1, 1));
    drop(a);

    let mut b = daemon_on(&net);
    up_at(&mut b, 10);
    assert!(b.is_ready(), "ready without a modem restart");
    assert_eq!(net.0.borrow().pipe_refusals, 0);
    assert_eq!(pipe_calls(&net), (1, 1), "the pipes were not set up again");
    assert_eq!(b.stats().pipes_skipped, 1);
    // links made again and carrying data
    assert!(net.0.borrow().data_path_ok("rmnet_data0"));
    let id = b.start_call(11, params(0, IpVersion::V4)).unwrap();
    pump(&mut b, 11);
    assert_eq!(b.take_events(), vec![Event::Connected { call: id }]);
}

#[test]
fn a_new_interface_index_means_the_device_is_set_up_again() {
    let net = SharedNet::new();
    let mut a = daemon_on(&net);
    up_at(&mut a, 0);
    drop(a);
    // the modem restarted while no daemon ran: new rmnet_ipa0, no pipes
    net.0.borrow_mut().modem_restart();
    let mut b = daemon_on(&net);
    up_at(&mut b, 10);
    assert!(b.is_ready());
    assert_eq!(pipe_calls(&net), (2, 2), "set up again for the new device");
    assert_eq!(b.stats().pipes_skipped, 0);
    assert!(net.0.borrow().data_path_ok("rmnet_data0"));
}

#[test]
fn a_marker_from_another_boot_is_not_trusted() {
    let net = SharedNet::new();
    let mut a = daemon_on(&net);
    up_at(&mut a, 0);
    drop(a);
    let before = net.0.borrow_mut().ifindex("rmnet_ipa0").unwrap();
    // After a reboot rmnet_ipa0 registers in the same order and gets the same
    // interface index, and it has no pipes. Only the boot ID tells the markers apart.
    net.0.borrow_mut().reboot();
    assert_eq!(net.0.borrow_mut().ifindex("rmnet_ipa0").unwrap(), before);
    let stale = net.0.borrow().marker.clone().unwrap();
    assert_ne!(stale.boot_id, net.0.borrow_mut().boot_id().unwrap());
    assert_eq!(stale.ifindex, before);
    let mut b = daemon_on(&net);
    up_at(&mut b, 10);
    assert!(b.is_ready());
    assert_eq!(b.stats().pipes_skipped, 0);
    assert_eq!(pipe_calls(&net), (2, 2));
    assert!(
        net.0.borrow().data_path_ok("rmnet_data0"),
        "the pipes exist in this boot"
    );
}

#[test]
fn the_marker_is_stored_after_each_pipe_so_a_crash_between_them_loses_nothing() {
    let net = SharedNet::new();
    let mut a = daemon_on(&net);
    net.0.borrow_mut().fail_next = Some(("ipa_ingress", NetError::Os(14)));
    up_at(&mut a, 0);
    assert!(!a.is_ready(), "the second pipe failed");
    let m = net.0.borrow().marker.clone().unwrap();
    // the driver refused the second ioctl, so it is not left as a doubt
    assert_eq!((m.egress, m.ingress), (PipeState::Done, PipeState::Missing));
    drop(a);
    // the next daemon does not try the first pipe again (the driver would refuse)
    let mut b = daemon_on(&net);
    up_at(&mut b, 10);
    assert!(b.is_ready());
    assert_eq!(net.0.borrow().pipe_refusals, 0);
    assert_eq!(pipe_calls(&net), (1, 1));
}

#[test]
fn a_retry_in_the_same_daemon_does_not_repeat_the_pipe_that_worked() {
    let net = SharedNet::new();
    let mut e = daemon_on(&net);
    net.0.borrow_mut().fail_next = Some(("ipa_ingress", NetError::Os(14)));
    up_at(&mut e, 0);
    assert!(!e.is_ready());
    e.tick(2_000);
    pump(&mut e, 2_000);
    assert!(e.is_ready());
    assert_eq!(net.0.borrow().pipe_refusals, 0);
}

#[test]
fn a_marker_that_cannot_be_written_does_not_stop_bringup() {
    let net = SharedNet::new();
    net.0.borrow_mut().marker_unwritable = true;
    let mut e = daemon_on(&net);
    up_at(&mut e, 0);
    assert!(e.is_ready());
    assert!(net.0.borrow().marker.is_none());
}

#[test]
fn a_device_already_set_up_may_refuse_the_data_format_and_the_port_again() {
    for (service, msg) in [
        (wda::SERVICE, wda::SET_DATA_FORMAT),
        (dpm::SERVICE, dpm::OPEN_PORT),
    ] {
        let net = SharedNet::new();
        let mut a = daemon_on(&net);
        up_at(&mut a, 0);
        drop(a);
        // the modem keeps the state of the first daemon and refuses a second request
        let mut b = daemon_on(&net);
        b.qmi_mut().reject.push((service, msg));
        up_at(&mut b, 10);
        assert!(b.is_ready(), "refusal of {msg:#x} passed over");
        assert_eq!(b.stats().bringup_refusals_passed, 1);
    }
}

#[test]
fn a_device_already_set_up_may_leave_the_port_request_unanswered() {
    let net = SharedNet::new();
    let mut a = daemon_on(&net);
    up_at(&mut a, 0);
    drop(a);
    let mut b = daemon_on(&net);
    b.qmi_mut().mute_service.push(dpm::SERVICE);
    up_at(&mut b, 10);
    assert!(!b.is_ready());
    b.tick(10 + 10_000);
    assert!(b.is_ready(), "passed over after the deadline");
}

#[test]
fn a_fresh_device_must_not_pass_a_refused_port_over() {
    // only a device that was set up by an earlier instance gets that leniency
    let mut e = engine();
    e.qmi_mut().reject.push((dpm::SERVICE, dpm::OPEN_PORT));
    e.on_service_event(0, ServiceEvent::ModemUp);
    pump(&mut e, 0);
    assert!(!e.is_ready());
    assert_eq!(e.stats().bringup_refusals_passed, 0);
    assert_eq!(e.net().link_count(), 0);
    assert_eq!(e.next_deadline(), Some(2_000));
}

#[test]
fn the_device_is_checked_at_every_call_start() {
    // rmnet_ipa0 was replaced and nobody told the daemon: no modem-down event
    let mut e = engine();
    up(&mut e);
    let a = connect(&mut e, params(0, IpVersion::V4));
    e.take_events();
    e.qmi_mut().restart();
    e.net_mut().modem_restart();
    let b = e.start_call(30, params(1, IpVersion::V4)).unwrap();
    assert!(
        !e.is_ready(),
        "the daemon noticed and set everything up again"
    );
    assert_eq!(e.stats().device_changes, 1);
    assert_eq!(
        e.take_events(),
        vec![Event::Disconnected {
            call: a,
            reason: EndReason::Local(LocalReason::ModemRestart)
        }]
    );
    pump(&mut e, 30);
    assert!(e.is_ready());
    assert_eq!(e.take_events(), vec![Event::Connected { call: b }]);
    assert!(e.net().data_path_ok(&e.call_info(b).unwrap().ifname));
}

#[test]
fn a_device_that_is_gone_makes_a_new_call_wait() {
    let mut e = engine();
    up(&mut e);
    e.net_mut().remove_device("rmnet_ipa0");
    let id = e.start_call(5, params(0, IpVersion::V4)).unwrap();
    pump(&mut e, 5);
    assert!(!e.is_ready() && e.call_is_active(id));
    assert!(e.take_events().is_empty());
    // the driver registers it again, the retry finishes the job
    e.net_mut().add_device("rmnet_ipa0");
    e.tick(5 + 2_000);
    pump(&mut e, 5 + 2_000);
    assert_eq!(e.take_events(), vec![Event::Connected { call: id }]);
}

// ---- bring-up timing ---------------------------------------------------------

#[test]
fn the_retry_delay_starts_over_after_a_modem_restart() {
    let mut e = engine();
    e.net_mut().remove_device("rmnet_ipa0");
    e.on_service_event(0, ServiceEvent::ModemUp);
    pump(&mut e, 0);
    let mut now = 0;
    for _ in 0..4 {
        now = e.next_deadline().unwrap();
        e.tick(now);
        pump(&mut e, now);
    }
    assert!(
        e.next_deadline().unwrap() - now >= 16_000,
        "the delay has grown"
    );
    e.on_service_event(now + 1, ServiceEvent::ModemDown);
    e.on_service_event(now + 2, ServiceEvent::ModemUp);
    pump(&mut e, now + 2);
    assert_eq!(e.next_deadline(), Some(now + 2 + 2_000));
}

#[test]
fn a_modem_up_while_a_retry_is_pending_starts_bringup_at_once() {
    let mut e = engine();
    e.net_mut().remove_device("rmnet_ipa0");
    e.on_service_event(0, ServiceEvent::ModemUp);
    pump(&mut e, 0);
    assert!(!e.is_ready());
    e.net_mut().add_device("rmnet_ipa0");
    e.on_service_event(500, ServiceEvent::ModemUp);
    pump(&mut e, 500);
    assert!(e.is_ready(), "no wait for the retry at 2000");
}

#[test]
fn a_call_that_is_stopping_ends_when_the_modem_goes_down() {
    let mut e = engine();
    up(&mut e);
    let id = connect(&mut e, params(0, IpVersion::V4));
    e.take_events();
    e.qmi_mut().mute.push(wds::id::STOP_NETWORK);
    e.stop_call(5, id).unwrap();
    pump(&mut e, 5);
    assert!(
        e.take_events().is_empty(),
        "still waiting for the stop answer"
    );
    e.qmi_mut().restart();
    e.on_service_event(6, ServiceEvent::ModemDown);
    assert_eq!(
        e.take_events(),
        vec![Event::Disconnected {
            call: id,
            reason: EndReason::Local(LocalReason::ModemRestart)
        }]
    );
}

// ---- the reserve and the emergency link ------------------------------------

#[test]
fn links_that_failed_to_be_made_are_not_counted_as_reserve() {
    // 13 links work, 2 fail at the mux channel. The reserve is 2 of the 13.
    let mut e = engine();
    e.net_mut().mux_limit = 13;
    up(&mut e);
    assert_eq!(e.free_usable_links(), 13);
    for n in 0..11 {
        let id = connect(&mut e, params(0, IpVersion::V4));
        assert_eq!(
            e.take_events(),
            vec![Event::Connected { call: id }],
            "call {n}"
        );
    }
    assert_eq!(
        e.start_call(2, params(0, IpVersion::V4)).unwrap_err(),
        StartError::NoLink,
        "the two links left are for emergencies"
    );
    let sos = connect(&mut e, emergency(0, IpVersion::V4));
    assert_eq!(e.take_events(), vec![Event::Connected { call: sos }]);
}

#[test]
fn a_broken_link_is_a_last_resort_for_an_emergency_call_and_is_tried_again() {
    let cfg = Config {
        link_count: 2,
        reserve_links: 0,
        ..Config::default()
    };
    let mut e = engine_with(cfg);
    e.net_mut().mux_limit = 1;
    up(&mut e);
    // ordinary calls never get the broken link
    let a = connect(&mut e, params(0, IpVersion::V4));
    assert_eq!(e.take_events(), vec![Event::Connected { call: a }]);
    assert_eq!(
        e.start_call(2, params(0, IpVersion::V4)).unwrap_err(),
        StartError::NoLink
    );
    // an emergency call tries it, it is still broken
    let sos = connect(&mut e, emergency(0, IpVersion::V4));
    assert_eq!(
        e.take_events(),
        vec![Event::Disconnected {
            call: sos,
            reason: EndReason::Local(LocalReason::LinkFailed)
        }]
    );
    // the kernel allows it now: the next try makes it
    e.release_call(5, sos).unwrap();
    e.net_mut().mux_limit = 15;
    let sos = connect(&mut e, emergency(0, IpVersion::V4));
    assert_eq!(e.take_events(), vec![Event::Connected { call: sos }]);
    assert_eq!(e.free_usable_links(), 0);
}

#[test]
fn an_emergency_call_with_a_refused_data_port_binding_moves_to_another_link_once() {
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().reject_mux_ids.push(1); // the first link's mux ID is refused
    let id = connect(&mut e, emergency(0, IpVersion::V4V6));
    assert_eq!(e.take_events(), vec![Event::Connected { call: id }]);
    assert_eq!(e.call_info(id).unwrap().ifname, "rmnet_data1");
    assert_eq!(e.stats().emergency_relinks, 1);
    // both legs are bound to the new link's mux ID, and the first link is free again
    let c4 = e.qmi_mut().client_of(IpFamily::V4).unwrap();
    let c6 = e.qmi_mut().client_of(IpFamily::V6).unwrap();
    assert_eq!(
        (e.qmi_mut().mux_of(c4), e.qmi_mut().mux_of(c6)),
        (Some(2), Some(2))
    );
    let free = e.free_links();
    assert_eq!(free, e.link_total() - 1);
    assert!(e.net().data_path_ok("rmnet_data1"));
}

#[test]
fn an_ordinary_call_does_not_get_a_second_link_after_a_refused_binding() {
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().reject_mux_ids.push(1);
    let id = connect(&mut e, params(0, IpVersion::V4));
    assert_eq!(
        e.take_events(),
        vec![Event::Disconnected {
            call: id,
            reason: EndReason::Local(LocalReason::BindFailed)
        }]
    );
    assert_eq!(e.stats().emergency_relinks, 0);
}

#[test]
fn the_emergency_retry_happens_once_and_needs_another_link() {
    // both of the first two links refuse: one retry, then the call ends
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().reject_mux_ids.extend([1, 2]);
    let id = connect(&mut e, emergency(0, IpVersion::V4));
    assert_eq!(
        e.take_events(),
        vec![Event::Disconnected {
            call: id,
            reason: EndReason::Local(LocalReason::BindFailed)
        }]
    );
    assert_eq!(e.stats().emergency_relinks, 1);

    // one link only: nothing to move to
    let cfg = Config {
        link_count: 1,
        reserve_links: 0,
        ..Config::default()
    };
    let mut e = engine_with(cfg);
    up(&mut e);
    e.qmi_mut().reject_mux_ids.push(1);
    let id = connect(&mut e, emergency(0, IpVersion::V4));
    assert_eq!(
        e.take_events(),
        vec![Event::Disconnected {
            call: id,
            reason: EndReason::Local(LocalReason::BindFailed)
        }]
    );
    assert_eq!(e.stats().emergency_relinks, 0);
}

#[test]
fn an_emergency_call_waits_only_the_short_deadline_for_each_step_it_passes_over() {
    let mut e = engine();
    up(&mut e);
    for id in [
        wds::id::BIND_SUBSCRIPTION,
        wds::id::SET_IP_FAMILY,
        wds::id::INDICATION_REGISTER,
    ] {
        e.qmi_mut().mute.push(id);
    }
    let call = e.start_call(0, emergency(0, IpVersion::V4)).unwrap();
    pump(&mut e, 0);
    let short = Config::default().emergency_qmi_timeout_ms;
    assert_eq!(short, 3_000);
    for step in 1..=3u64 {
        assert_eq!(e.next_deadline(), Some(step * short), "step {step}");
        assert_eq!(
            e.qmi_mut().start_frames.len(),
            0,
            "Start Network waits for the steps"
        );
        e.tick(step * short);
        pump(&mut e, step * short);
    }
    assert_eq!(
        e.qmi_mut().start_frames.len(),
        1,
        "sent after 9 s, not 30 s"
    );
    assert_eq!(e.take_events(), vec![Event::Connected { call }]);

    // an ordinary call keeps the long deadline
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().mute.push(wds::id::BIND_SUBSCRIPTION);
    e.start_call(0, params(0, IpVersion::V4)).unwrap();
    pump(&mut e, 0);
    assert_eq!(e.next_deadline(), Some(10_000));
}

// ---- the short deadline is only for the steps that are passed over ----------

#[test]
fn a_slow_settings_refetch_never_ends_a_working_call() {
    // A connected emergency call, the refetch of the
    // settings after an Extended IP Config indication goes unanswered.
    for (name, p) in [
        ("emergency", emergency(0, IpVersion::V4)),
        ("ordinary", params(0, IpVersion::V4)),
    ] {
        let mut e = engine();
        up(&mut e);
        let id = connect(&mut e, p);
        assert_eq!(
            e.take_events(),
            vec![Event::Connected { call: id }],
            "{name}"
        );
        e.qmi_mut().mute.push(wds::id::GET_RUNTIME_SETTINGS);
        let c = e.qmi_mut().client_of(IpFamily::V4).unwrap();
        e.qmi_mut().extended_ip_config(c, wds::settings::MTU);
        pump(&mut e, 100);
        // the refetch is out, with the long deadline
        assert_eq!(e.next_deadline(), Some(100 + 10_000), "{name}");
        e.tick(100 + 3_000);
        e.tick(100 + 10_000);
        assert!(e.take_events().is_empty(), "{name}: the call stays up");
        assert!(
            e.call_is_active(id) && e.call_info(id).unwrap().v4.is_some(),
            "{name}"
        );
        assert_eq!(e.stats().refresh_timeouts, 1, "{name}");
        assert_eq!(e.next_deadline(), None);
        // the next indication asks again and the answer is used
        e.qmi_mut().mute.clear();
        e.qmi_mut().extended_ip_config(c, wds::settings::MTU);
        pump(&mut e, 20_000);
        assert!(
            e.take_events().contains(&Event::Reconfigured { call: id }),
            "{name}"
        );
    }
}

#[test]
fn only_the_passed_over_steps_get_the_short_emergency_deadline() {
    // data port binding: ends the leg, so the long deadline
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().mute.push(wds::id::BIND_MUX_DATA_PORT);
    e.start_call(0, emergency(0, IpVersion::V4)).unwrap();
    pump(&mut e, 0);
    assert_eq!(e.next_deadline(), Some(10_000));
    // the first settings of a call that is coming up: the same
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().mute.push(wds::id::GET_RUNTIME_SETTINGS);
    e.start_call(0, emergency(0, IpVersion::V4)).unwrap();
    pump(&mut e, 0);
    assert_eq!(e.next_deadline(), Some(10_000));
    // stopping: the same
    let mut e = engine();
    up(&mut e);
    let id = connect(&mut e, emergency(0, IpVersion::V4));
    e.take_events();
    e.qmi_mut().mute.push(wds::id::STOP_NETWORK);
    e.stop_call(0, id).unwrap();
    pump(&mut e, 0);
    assert_eq!(e.next_deadline(), Some(10_000));
}

// ---- the marker: intent record, missing marker, unreadable boot ID ----------

fn kernel_pipes(net: &SharedNet) -> (bool, bool) {
    let n = net.0.borrow();
    let (e, i) = pipe_calls_in(&n);
    (e > 0, i > 0)
}

fn pipe_calls_in(n: &FakeNet) -> (usize, usize) {
    (
        n.calls
            .iter()
            .filter(|c| matches!(c, NetCall::IpaEgress { .. }))
            .count(),
        n.calls
            .iter()
            .filter(|c| matches!(c, NetCall::IpaIngress { .. }))
            .count(),
    )
}

#[test]
fn a_crash_between_a_pipe_ioctl_and_the_write_of_its_done_record_does_not_block_the_next_daemon() {
    // stores: 1 intent egress, 2 done egress, 3 intent ingress, 4 done ingress.
    // `stop_at_ingress` stands for a daemon that died before it sent the second ioctl
    // (budget, ingress ioctl made, refusals the next daemon must see)
    for (allowed, stop_at_ingress, refusals) in [(1u32, true, 1u32), (2, true, 0), (3, false, 1)] {
        let net = SharedNet::new();
        net.0.borrow_mut().marker_stores_left = Some(allowed);
        if stop_at_ingress {
            net.0.borrow_mut().fail_next = Some(("ipa_ingress", NetError::Os(4)));
        }
        let mut a = daemon_on(&net);
        up_at(&mut a, 0);
        assert!(a.stats().marker_store_failures >= 1, "allowed {allowed}");
        assert_eq!(a.is_ready(), !stop_at_ingress, "allowed {allowed}");
        drop(a);
        let m = net.0.borrow().marker.clone().unwrap();
        assert!(
            m.egress == PipeState::Pending
                || m.ingress == PipeState::Pending
                || (m.egress, m.ingress) == (PipeState::Done, PipeState::Missing),
            "allowed {allowed}: the record shows what is not sure"
        );
        net.0.borrow_mut().marker_stores_left = None;
        let mut b = daemon_on(&net);
        up_at(&mut b, 10);
        assert!(b.is_ready(), "allowed {allowed}: the next daemon is ready");
        assert!(
            net.0.borrow().data_path_ok("rmnet_data0"),
            "allowed {allowed}"
        );
        assert_eq!(net.0.borrow().pipe_refusals, refusals, "allowed {allowed}");
        assert_eq!(b.stats().pipes_found, refusals, "allowed {allowed}");
        let done = net.0.borrow().marker.clone().unwrap();
        assert_eq!(
            (done.egress, done.ingress),
            (PipeState::Done, PipeState::Done)
        );
    }
}

#[test]
fn a_pipe_nobody_started_still_fails_on_invalid() {
    // a genuine configuration error is not taken for "it exists"
    let net = SharedNet::new();
    let mut a = daemon_on(&net);
    net.0.borrow_mut().fail_next = Some(("ipa_egress", NetError::Invalid));
    up_at(&mut a, 0);
    assert!(!a.is_ready());
    assert_eq!(a.stats().pipes_found, 0);
    // the retry of the same instance is just as strict, although its own intent record is on disk
    net.0.borrow_mut().fail_next = Some(("ipa_egress", NetError::Invalid));
    a.tick(2_000);
    pump(&mut a, 2_000);
    assert!(!a.is_ready());
    assert_eq!(a.stats().pipes_found, 0);
}

#[test]
fn a_pending_pipe_is_not_taken_for_done_after_another_kind_of_error() {
    let net = SharedNet::new();
    let idx = net.0.borrow_mut().ifindex("rmnet_ipa0").unwrap();
    net.0.borrow_mut().marker = Some(SetupMarker {
        boot_id: "boot-1".into(),
        ifindex: idx,
        egress: PipeState::Pending,
        ingress: PipeState::Missing,
    });
    let mut b = daemon_on(&net);
    net.0.borrow_mut().fail_next = Some(("ipa_egress", NetError::Os(14)));
    up_at(&mut b, 0);
    assert!(!b.is_ready());
    assert_eq!(b.stats().pipes_found, 0);
}

#[test]
fn a_pending_pipe_stays_pending_after_an_error_that_is_not_invalid() {
    // stores: egress intent and done, ingress intent, then the done record is lost
    let net = SharedNet::new();
    net.0.borrow_mut().marker_stores_left = Some(3);
    let mut a = daemon_on(&net);
    up_at(&mut a, 0);
    drop(a);
    net.0.borrow_mut().marker_stores_left = None;
    let m = net.0.borrow().marker.clone().unwrap();
    assert_eq!((m.egress, m.ingress), (PipeState::Done, PipeState::Pending));
    // the next daemon meets another error on the pending pipe: still not sure
    let mut b = daemon_on(&net);
    net.0.borrow_mut().fail_next = Some(("ipa_ingress", NetError::Os(14)));
    up_at(&mut b, 10);
    assert!(!b.is_ready());
    let m = net.0.borrow().marker.clone().unwrap();
    assert_eq!(
        (m.egress, m.ingress),
        (PipeState::Done, PipeState::Pending),
        "the doubt stays where there was one"
    );
    // so the retry sends the request again, and the driver says the pipe is up
    b.tick(12_000);
    pump(&mut b, 12_000);
    assert!(b.is_ready());
    assert_eq!(b.stats().pipes_found, 1);
}

#[test]
fn without_any_marker_a_restarted_daemon_finds_its_pipes_through_the_driver() {
    // the directory could not be written at all: the driver says the pipes are up, so the marker is not needed
    let net = SharedNet::new();
    net.0.borrow_mut().marker_unwritable = true;
    let mut a = daemon_on(&net);
    up_at(&mut a, 0);
    assert!(a.is_ready());
    assert!(
        a.stats().marker_store_failures >= 4,
        "every write was counted"
    );
    let notes = a.take_notes();
    assert_eq!(
        notes
            .iter()
            .filter(|n| matches!(n, Note::MarkerStoreFailed(_)))
            .count(),
        1,
        "and told once: {notes:?}"
    );
    assert!(a.take_notes().is_empty());
    drop(a);
    net.0.borrow_mut().marker_unwritable = false;
    let mut b = daemon_on(&net);
    up_at(&mut b, 10);
    assert!(b.is_ready(), "the driver reports both pipes as up");
    assert!(net.0.borrow().pipe_refusals >= 2);
    assert_eq!(b.stats().pipes_found, 2);
}

#[test]
fn an_unreadable_boot_id_does_not_switch_the_marker_off() {
    let net = SharedNet::new();
    net.0.borrow_mut().boot_id_unreadable = true;
    let mut a = daemon_on(&net);
    up_at(&mut a, 0);
    assert!(a.is_ready());
    assert_eq!(a.take_notes(), vec![Note::BootIdUnreadable]);
    assert_eq!(net.0.borrow().marker.as_ref().unwrap().boot_id, "-");
    drop(a);
    // the restarted daemon can read it now or not, the index alone decides
    for readable in [false, true] {
        net.0.borrow_mut().boot_id_unreadable = !readable;
        let mut b = daemon_on(&net);
        up_at(&mut b, 10);
        assert!(b.is_ready(), "boot ID readable: {readable}");
        assert_eq!(net.0.borrow().pipe_refusals, 0, "readable: {readable}");
        assert_eq!(b.stats().pipes_skipped, 1);
    }
    // and a new interface index still means a new device
    net.0.borrow_mut().modem_restart();
    let mut c = daemon_on(&net);
    up_at(&mut c, 20);
    assert!(c.is_ready() && net.0.borrow().data_path_ok("rmnet_data0"));
    assert_eq!(c.stats().pipes_skipped, 0);
}

#[test]
fn a_marker_with_a_boot_id_is_still_trusted_when_the_boot_id_cannot_be_read_now() {
    let net = SharedNet::new();
    let mut a = daemon_on(&net);
    up_at(&mut a, 0);
    assert!(a.is_ready());
    assert_eq!(net.0.borrow().marker.as_ref().unwrap().boot_id, "boot-1");
    drop(a);
    net.0.borrow_mut().boot_id_unreadable = true;
    let mut b = daemon_on(&net);
    up_at(&mut b, 10);
    assert!(b.is_ready());
    assert_eq!(b.stats().pipes_skipped, 1, "the index alone decides");
    assert_eq!(net.0.borrow().pipe_refusals, 0);
}

#[test]
fn half_a_setup_counts_as_a_set_up_modem_side_but_still_sends_the_missing_pipe() {
    // egress done, ingress never started: the data format and port requests were made
    // in this modem lifetime, so a refusal is passed over, and the missing pipe is sent
    let net = SharedNet::new();
    let idx = net.0.borrow_mut().ifindex("rmnet_ipa0").unwrap();
    net.0.borrow_mut().marker = Some(SetupMarker {
        boot_id: "boot-1".into(),
        ifindex: idx,
        egress: PipeState::Done,
        ingress: PipeState::Missing,
    });
    let mut b = daemon_on(&net);
    b.qmi_mut()
        .reject
        .push((wda::SERVICE, wda::SET_DATA_FORMAT));
    up_at(&mut b, 0);
    assert!(b.is_ready());
    assert_eq!(b.stats().bringup_refusals_passed, 1);
    assert_eq!(pipe_calls(&net), (0, 1), "only the missing pipe");
}

#[test]
fn one_pipe_that_failed_once_does_not_block_a_modem_that_refuses_a_repeated_request() {
    // In one daemon instance: the egress pipe works,
    // the ingress ioctl fails once, and the modem refuses the data format and the port
    // request a second time
    let net = SharedNet::new();
    let mut a = daemon_on(&net);
    net.0.borrow_mut().fail_next = Some(("ipa_ingress", NetError::Os(4)));
    up_at(&mut a, 0);
    assert!(!a.is_ready());
    let m = net.0.borrow().marker.clone().unwrap();
    assert_eq!((m.egress, m.ingress), (PipeState::Done, PipeState::Missing));
    a.qmi_mut()
        .reject
        .push((wda::SERVICE, wda::SET_DATA_FORMAT));
    a.qmi_mut().reject.push((dpm::SERVICE, dpm::OPEN_PORT));
    a.tick(2_000);
    pump(&mut a, 2_000);
    assert!(a.is_ready(), "the repeat is passed over");
    assert_eq!(a.stats().bringup_refusals_passed, 2);
    assert_eq!(
        net.0.borrow().pipe_refusals,
        0,
        "the egress pipe is not sent again"
    );
    assert!(net.0.borrow().data_path_ok("rmnet_data0"));
}

#[test]
fn a_failed_lookup_of_the_device_is_not_a_replaced_device() {
    // an error that is not "not found" says nothing about the device: the running
    // calls and the readiness stay
    let mut e = engine();
    up(&mut e);
    let a = connect(&mut e, params(0, IpVersion::V4));
    e.take_events();
    e.net_mut().ifindex_error = Some(NetError::Os(5));
    let b = e.start_call(10, params(1, IpVersion::V4)).unwrap();
    assert!(e.is_ready());
    assert_eq!(e.stats().device_changes, 0);
    assert!(e.call_is_active(a));
    e.net_mut().ifindex_error = None;
    pump(&mut e, 10);
    assert!(e.take_events().contains(&Event::Connected { call: b }));
    let _ = kernel_pipes;
}

#[test]
fn a_broken_link_that_works_again_is_counted_again() {
    let cfg = Config {
        link_count: 2,
        reserve_links: 0,
        ..Config::default()
    };
    let mut e = engine_with(cfg);
    e.net_mut().mux_limit = 1;
    up(&mut e);
    assert_eq!(e.free_usable_links(), 1);
    e.net_mut().mux_limit = 15;
    let sos = connect(&mut e, emergency(0, IpVersion::V4)); // takes the working link
    let sos2 = connect(&mut e, emergency(1, IpVersion::V4)); // retries the broken one
    assert!(e.take_events().contains(&Event::Connected { call: sos2 }));
    e.release_call(5, sos).unwrap();
    e.release_call(5, sos2).unwrap();
    assert_eq!(
        e.free_usable_links(),
        2,
        "the link made it, it counts again"
    );
}

#[test]
fn an_emergency_call_moves_only_while_every_leg_is_still_at_the_binding() {
    // the second Bind Mux Data Port is refused, the first leg is already further
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().reject_bind_mux_requests.push(1);
    let id = connect(&mut e, emergency(0, IpVersion::V4V6));
    assert_eq!(
        e.take_events(),
        vec![Event::PartiallyConnected { call: id }]
    );
    assert_eq!(e.stats().emergency_relinks, 0, "the call stays where it is");
    assert_eq!(e.call_info(id).unwrap().ifname, "rmnet_data0");
    assert!(e.call_info(id).unwrap().v4.is_some());
}

#[test]
fn an_emergency_call_does_not_move_to_a_link_that_cannot_be_made() {
    // link 0 works and refuses the binding, every other link is broken
    let mut e = engine();
    e.net_mut().mux_limit = 1;
    up(&mut e);
    e.qmi_mut().reject_mux_ids.push(1);
    let id = connect(&mut e, emergency(0, IpVersion::V4));
    assert_eq!(
        e.take_events(),
        vec![Event::Disconnected {
            call: id,
            reason: EndReason::Local(LocalReason::BindFailed)
        }]
    );
    assert_eq!(e.stats().emergency_relinks, 0);
}

// ---- attached calls: the data module starts the network, the engine follows ----

fn attach(e: &mut E, family: Family) -> CallId {
    let id = e.attach_call(1, 1, Priority::Normal, family).unwrap();
    pump(e, 1);
    id
}

#[test]
fn an_attached_call_binds_registers_and_waits_without_starting_a_network() {
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().require_call = true;
    let id = attach(&mut e, Family::V4);
    assert!(e.take_events().is_empty());
    assert_eq!(e.qmi_mut().count_requests(wds::id::START_NETWORK), 0);
    assert_eq!(e.call_link(id), Some(0));
    assert_eq!(e.call_families(id), vec![Family::V4]);
    // the bind, the registration and the first look
    let ids = e.qmi_mut().wds_requests.clone();
    assert_eq!(
        ids,
        vec![
            wds::id::BIND_MUX_DATA_PORT,
            wds::id::BIND_SUBSCRIPTION,
            wds::id::SET_IP_FAMILY,
            wds::id::INDICATION_REGISTER,
            wds::id::GET_RUNTIME_SETTINGS
        ]
    );
    assert_eq!(e.stats().bringup_refusals_passed, 0);
}

#[test]
fn an_attached_call_configures_the_link_when_the_call_connects_elsewhere() {
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().require_call = true;
    let id = attach(&mut e, Family::V4);
    e.qmi_mut().external_connect(1);
    pump(&mut e, 2);
    assert_eq!(
        e.take_events(),
        vec![Event::LegUp {
            call: id,
            family: Family::V4
        }]
    );
    let info = e.call_info(id).unwrap();
    assert_eq!(info.ifname, "rmnet_data0");
    assert!(info.v4.is_some());
    assert!(e
        .net()
        .has_address("rmnet_data0", "192.0.2.10".parse().unwrap()));
    assert_eq!(e.qmi_mut().count_requests(wds::id::START_NETWORK), 0);
}

#[test]
fn an_attached_call_finds_a_call_that_connected_before_its_registration() {
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().require_call = true;
    e.qmi_mut().external_connect(1);
    let id = attach(&mut e, Family::V4);
    assert_eq!(
        e.take_events(),
        vec![Event::LegUp {
            call: id,
            family: Family::V4
        }]
    );
}

#[test]
fn an_attached_call_that_loses_its_call_keeps_the_link_and_follows_the_next_one() {
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().require_call = true;
    let id = attach(&mut e, Family::V4);
    e.qmi_mut().external_connect(1);
    pump(&mut e, 2);
    e.take_events();
    e.qmi_mut().external_disconnect(1, 3, 26);
    pump(&mut e, 3);
    let ev = e.take_events();
    assert_eq!(ev.len(), 1);
    assert!(matches!(
        ev[0],
        Event::LegDown { call, family: Family::V4, reason: EndReason::Network { kind: 3, reason: 26 } } if call == id
    ));
    assert!(!e
        .net()
        .has_address("rmnet_data0", "192.0.2.10".parse().unwrap()));
    assert!(
        e.call_holds_link(id),
        "the link is held until it is released"
    );
    assert_eq!(e.free_links(), 14);
    // and nothing is up on it: the link is down
    let last = e.net().calls.iter().rev().find_map(|c| match c {
        NetCall::SetLink { name, up, .. } if name == "rmnet_data0" => Some(*up),
        _ => None,
    });
    assert_eq!(last, Some(false));
    // the same link again
    e.qmi_mut().external_connect(1);
    pump(&mut e, 4);
    assert_eq!(
        e.take_events(),
        vec![Event::LegUp {
            call: id,
            family: Family::V4
        }]
    );
}

#[test]
fn an_attached_call_follows_the_companion_family_on_the_same_link() {
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().require_call = true;
    let id = attach(&mut e, Family::V4);
    e.qmi_mut().external_connect(1);
    pump(&mut e, 2);
    e.take_events();
    assert_eq!(e.attach_family(3, id, Family::V6), Ok(()));
    pump(&mut e, 3);
    assert_eq!(
        e.take_events(),
        vec![Event::LegUp {
            call: id,
            family: Family::V6
        }],
        "the family is up on a link whose call is up"
    );
    assert_eq!(e.call_families(id), vec![Family::V4, Family::V6]);
    // a live leg is not added twice, and a call that does not exist has no companion
    assert_eq!(e.attach_family(3, id, Family::V6), Err(StartError::Invalid));
    assert_eq!(
        e.attach_family(3, 999, Family::V6),
        Err(StartError::NoSuchCall)
    );
}

#[test]
fn a_release_gives_the_link_back_and_nothing_else_does() {
    let mut e = engine();
    up(&mut e);
    let id = attach(&mut e, Family::V4);
    assert_eq!(e.free_links(), 14);
    e.take_events();
    e.release_call(5, id).unwrap();
    assert_eq!(e.free_links(), 15);
    assert!(e.take_events().is_empty(), "a release is not an event");
}

#[test]
fn a_refused_binding_ends_the_legs_but_the_link_stays_until_it_is_released() {
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().reject_mux_ids.push(1);
    let id = attach(&mut e, Family::V4);
    let ev = e.take_events();
    assert!(matches!(
        ev[0],
        Event::LegFailed { call, family: Family::V4, reason: EndReason::Local(LocalReason::BindFailed) } if call == id
    ));
    assert!(matches!(ev[1], Event::Disconnected { call, .. } if call == id));
    assert_eq!(ev.len(), 2);
    assert!(e.call_holds_link(id));
    assert_eq!(e.free_links(), 14);
    assert_eq!(e.stats().emergency_relinks, 0);
    e.release_call(5, id).unwrap();
    assert_eq!(e.free_links(), 15);
}

#[test]
fn an_attached_emergency_call_stays_on_the_link_the_data_module_was_given() {
    // the relink of an own emergency call would move it to a link nobody told the data module about
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().reject_mux_ids.push(1);
    let id = e
        .attach_call(1, 1, Priority::Emergency, Family::V4)
        .unwrap();
    pump(&mut e, 1);
    assert_eq!(e.stats().emergency_relinks, 0);
    assert_eq!(e.call_link(id), Some(0));
}

#[test]
fn a_modem_restart_ends_an_attached_call_and_the_link_stays_held() {
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().require_call = true;
    let id = attach(&mut e, Family::V4);
    e.qmi_mut().external_connect(1);
    pump(&mut e, 2);
    e.take_events();
    e.on_service_event(5, ServiceEvent::ModemDown);
    let ev = e.take_events();
    assert!(matches!(
        ev.last(),
        Some(Event::Disconnected { call, reason: EndReason::Local(LocalReason::ModemRestart) }) if *call == id
    ));
    assert!(e.call_holds_link(id));
    assert_eq!(e.attach_family(6, id, Family::V6), Err(StartError::Invalid));
}

#[test]
fn an_attached_call_is_refused_when_only_the_reserve_is_left() {
    let cfg = Config {
        link_count: 3,
        reserve_links: 2,
        ..Config::default()
    };
    let mut e = engine_with(cfg);
    up(&mut e);
    let a = e.attach_call(1, 1, Priority::Normal, Family::V4);
    assert!(a.is_ok());
    let b = e.attach_call(1, 1, Priority::Normal, Family::V4);
    assert_eq!(b, Err(StartError::NoLink));
    let sos = e.attach_call(1, 1, Priority::Emergency, Family::V4);
    assert!(sos.is_ok());
}

#[test]
fn the_end_of_a_call_that_was_never_followed_is_no_news() {
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().require_call = true;
    let id = attach(&mut e, Family::V4);
    // the modem reports the end of a call the leg never saw come up
    e.qmi_mut().external_disconnect(1, 3, 26);
    pump(&mut e, 2);
    assert!(e.take_events().is_empty());
    assert_eq!(
        e.call_families(id),
        vec![Family::V4],
        "the leg is still there"
    );
    e.qmi_mut().external_connect(1);
    pump(&mut e, 3);
    assert_eq!(
        e.take_events(),
        vec![Event::LegUp {
            call: id,
            family: Family::V4
        }]
    );
}

#[test]
fn one_family_that_cannot_be_followed_does_not_end_the_call_of_the_other() {
    let mut e = engine();
    up(&mut e);
    e.qmi_mut().require_call = true;
    // the second Bind Mux Data Port is the one of the companion family
    e.qmi_mut().reject_bind_mux_requests.push(1);
    let id = attach(&mut e, Family::V4);
    assert_eq!(e.attach_family(2, id, Family::V6), Ok(()));
    pump(&mut e, 2);
    let ev = e.take_events();
    assert_eq!(
        ev,
        vec![Event::LegFailed {
            call: id,
            family: Family::V6,
            reason: EndReason::Local(LocalReason::BindFailed)
        }],
        "no Disconnected: the other family is still followed"
    );
    assert_eq!(e.call_families(id), vec![Family::V4]);
    e.qmi_mut().external_connect(1);
    pump(&mut e, 3);
    assert_eq!(
        e.take_events(),
        vec![Event::LegUp {
            call: id,
            family: Family::V4
        }]
    );
}

#[test]
fn a_restarted_daemon_that_finds_the_device_set_up_keeps_the_links_and_their_addresses() {
    // The stock daemon does not touch the links of a call that outlives it: it flushes an address
    // only when the kernel reports the link down. The module's call is still up.
    let net = SharedNet::new();
    let mut a = daemon_on(&net);
    up_at(&mut a, 0);
    assert!(a.is_ready());
    let ip: IpAddr = "192.0.2.10".parse().unwrap();
    net.0
        .borrow_mut()
        .add_address("rmnet_data0", ip, 30, dataos_netcfg::AddrFlags::default())
        .unwrap();
    drop(a);
    let mark = net.0.borrow().calls.len();
    let mut b = daemon_on(&net);
    up_at(&mut b, 10);
    assert!(b.is_ready());
    assert_eq!(b.stats().pipes_skipped, 1);
    let deleted = net
        .0
        .borrow()
        .calls
        .iter()
        .skip(mark)
        .filter(|c| matches!(c, NetCall::DeleteLink(_)))
        .count();
    assert_eq!(deleted, 0, "no link of the earlier daemon was deleted");
    assert!(
        net.0.borrow().has_address("rmnet_data0", ip),
        "the address is still there"
    );
    assert_eq!(
        net.0.borrow().link_count(),
        15,
        "every link exists, none twice"
    );
}
