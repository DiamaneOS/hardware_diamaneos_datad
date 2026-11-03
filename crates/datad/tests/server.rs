// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The daemon protocol against the simulated modem. The data module starts its
//! calls itself, which the test plays with the modem's `external_connect`.
//! Made-up values only.
use dataos_datacore::engine::{Config, Engine, ServiceEvent};
use dataos_datacore::sim::SimModem;
use dataos_datad::server::{Reject, Server, ServerConfig};
use dataos_netcfg::FakeNet;
use dataos_qmi::wds;
use dataos_wire::*;

type S = Server<SimModem, FakeNet>;

const LABEL: &str = "u:r:rild:s0";
const INTERNET_MASK: u64 = 0x1;
const EMERGENCY_MASK: u64 = 0x200;

fn server_with(cfg: Config) -> S {
    let mut s = Server::new(
        ServerConfig::default(),
        Engine::new(cfg, SimModem::new(), FakeNet::new()),
    );
    s.engine().qmi_mut().require_call = true;
    s
}

fn server() -> S {
    server_with(Config::default())
}

static PIDS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(100);

/// A connection of a process of its own.
fn accept(s: &mut S) -> u32 {
    accept_as(s, PIDS.fetch_add(1, std::sync::atomic::Ordering::SeqCst))
}

/// A connection of the process with this number, as the library makes it: it says Hello at once, and what
/// it is told, the links it took over and the Downs it is owed, comes after the answer. The answer itself is
/// taken out, the rest stays queued.
fn accept_as(s: &mut S, pid: u32) -> u32 {
    let now = s.last_now();
    reconnect_as(s, pid, now)
}

/// The same at this time.
fn reconnect_as(s: &mut S, pid: u32, now: u64) -> u32 {
    let c = s.accept(pid, 1001, LABEL).unwrap();
    s.request(now, c, Request::Hello);
    let rest: Vec<Notify> = s
        .drain(c)
        .into_iter()
        .filter(|n| !matches!(n, Notify::HelloAck { .. }))
        .collect();
    s.conns_requeue(c, rest);
    c
}

const MODULE: u32 = 4242;

fn pump(s: &mut S, now: u64) {
    loop {
        let next = s.engine().qmi_mut().inbox.pop_front();
        match next {
            Some((c, b)) => s.on_qmi(now, c, &b),
            None => return,
        }
    }
}

fn modem_up(s: &mut S) {
    s.on_service_event(0, ServiceEvent::ModemUp);
    pump(s, 0);
}

fn route(slot: u8, family: Family, apn: &str, mask: u64) -> RouteRequest {
    RouteRequest {
        slot,
        family,
        apn: Some(apn.into()),
        apn_type: 1,
        apn_type_mask: mask,
    }
}

fn internet(family: Family) -> RouteRequest {
    route(0, family, "internet.example", INTERNET_MASK)
}

/// Look up a link and return the reply.
fn lookup(s: &mut S, conn: u32, txn: u32, req: RouteRequest) -> Notify {
    s.request(1, conn, Request::RouteLookup { txn, req });
    pump(s, 1);
    let mut got = s.drain(conn);
    let at = got
        .iter()
        .position(|n| matches!(n, Notify::RouteReply { .. }))
        .unwrap();
    let reply = got.remove(at);
    // events that came with it stay for the test
    s.conns_requeue(conn, got);
    reply
}

fn link_of(n: &Notify) -> u8 {
    match n {
        Notify::RouteReply {
            code: ResultCode::Ok,
            link,
            ..
        } => *link,
        other => panic!("no link: {other:?}"),
    }
}

fn code_of(n: &Notify) -> ResultCode {
    match n {
        Notify::RouteReply { code, .. } | Notify::Done { code, .. } => *code,
        other => panic!("no code: {other:?}"),
    }
}

fn events(s: &mut S, conn: u32) -> Vec<(u8, IfaceEvent)> {
    s.drain(conn)
        .into_iter()
        .filter_map(|n| match n {
            Notify::Event { link, event, .. } => Some((link, event)),
            _ => None,
        })
        .collect()
}

fn simple(s: &mut S, conn: u32, req: Request) -> Notify {
    s.request(1, conn, req);
    s.drain(conn).pop().unwrap()
}

#[test]
fn only_the_radio_process_may_connect() {
    let mut s = server();
    assert_eq!(s.accept(4242, 2000, LABEL).unwrap_err(), Reject::Uid);
    assert_eq!(s.accept(4242, 0, LABEL).unwrap_err(), Reject::Uid);
    // the right UID is not enough: a second process of the radio UID has another label
    assert_eq!(
        s.accept(4242, 1001, "u:r:hal_radio_default:s0")
            .unwrap_err(),
        Reject::Label
    );
    assert_eq!(s.accept(4242, 1001, "").unwrap_err(), Reject::Label);
    assert_eq!(s.accept(4242, 1000, LABEL).unwrap_err(), Reject::Uid);
    for _ in 0..4 {
        accept(&mut s);
    }
    assert_eq!(
        s.accept(4242, 1001, LABEL).unwrap_err(),
        Reject::TooManyConnections
    );
}

#[test]
fn a_datagram_that_does_not_decode_is_a_protocol_violation() {
    let mut s = server();
    let c = accept(&mut s);
    assert!(s.on_datagram(1, c, &[1, 2, 3]).is_err());
    assert!(s
        .on_datagram(1, c, &Request::Hello.encode().unwrap())
        .is_ok());
    assert!(matches!(
        s.drain(c).pop(),
        Some(Notify::HelloAck { ready: false })
    ));
    // a reply type is not a request
    let bad = Notify::Ready { ready: true }.encode().unwrap();
    assert!(s.on_datagram(1, c, &bad).is_err());
}

#[test]
fn a_call_the_module_starts_is_followed_and_told_back_with_interface_events() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    assert!(matches!(
        simple(&mut s, c, Request::Hello),
        Notify::HelloAck { ready: true }
    ));
    let r = lookup(&mut s, c, 7, internet(Family::V4));
    let Notify::RouteReply { txn, ifname, .. } = &r else {
        panic!()
    };
    assert_eq!((*txn, ifname.as_str(), link_of(&r)), (7, "rmnet_data0", 0));
    assert!(events(&mut s, c).is_empty(), "nothing is up yet");
    // the module's own call connects on the mux ID of the link
    s.engine().qmi_mut().external_connect(1);
    pump(&mut s, 2);
    assert_eq!(
        events(&mut s, c),
        vec![
            // nicmd posts no MTU event at the first configuration of a call: its stored MTUs
            // start at 0 and an event goes out only when a known one changes (`setMtu`)
            (0, IfaceEvent::Up),
            (
                0,
                IfaceEvent::NewAddr {
                    family: Family::V4,
                    addr: "192.0.2.10".parse().unwrap(),
                    prefix: 30
                }
            ),
        ]
    );
    // the module asks for the MTU of the link, the daemon never started a network
    let m = simple(&mut s, c, Request::QueryMtu { txn: 8, link: 0 });
    assert_eq!(
        m,
        Notify::MtuReply {
            txn: 8,
            code: ResultCode::Ok,
            v4: 1400,
            v6: 1400
        }
    );
    assert_eq!(
        s.engine().qmi_mut().count_requests(wds::id::START_NETWORK),
        0
    );
    // the call ends
    s.engine().qmi_mut().external_disconnect(1, 3, 26);
    pump(&mut s, 3);
    let ev = events(&mut s, c);
    assert_eq!(ev.len(), 2);
    assert!(matches!(
        ev[0].1,
        IfaceEvent::DelAddr {
            family: Family::V4,
            ..
        }
    ));
    assert!(matches!(
        ev[1].1,
        IfaceEvent::Down(EndReason::Network {
            kind: 3,
            reason: 26
        })
    ));
    // and the link is free again at once, as nicmd frees an interface at its down: a release that
    // comes late has nothing to release
    assert_eq!(s.engine().free_links(), 15);
    let late = simple(&mut s, c, Request::LinkRelease { txn: 9, link: 0 });
    assert_eq!(code_of(&late), ResultCode::NoSuchLink);
}

#[test]
fn the_other_family_of_the_same_call_gets_the_same_link_and_no_second_up() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    let a = lookup(&mut s, c, 1, internet(Family::V4));
    s.engine().qmi_mut().external_connect(1);
    pump(&mut s, 2);
    events(&mut s, c);
    let b = lookup(&mut s, c, 2, internet(Family::V6));
    assert_eq!(link_of(&a), link_of(&b));
    s.engine()
        .qmi_mut()
        .external_connect_family(1, wds::IpFamily::V6);
    pump(&mut s, 3);
    let ev = events(&mut s, c);
    assert!(!ev.iter().any(|(_, e)| *e == IfaceEvent::Up), "{ev:?}");
    assert!(ev.iter().any(|(_, e)| matches!(
        e,
        IfaceEvent::NewAddr {
            family: Family::V6,
            ..
        }
    )));
    assert_eq!(s.engine().free_links(), 14, "one link for both families");
    // each family has its own MTU
    assert_eq!(
        simple(
            &mut s,
            c,
            Request::QueryMtu {
                txn: 5,
                link: link_of(&a)
            }
        ),
        Notify::MtuReply {
            txn: 5,
            code: ResultCode::Ok,
            v4: 1400,
            v6: 1380
        }
    );
    // one family going away is not the end of the link
    let v6 = s.engine().qmi_mut().client_of(wds::IpFamily::V6).unwrap();
    s.engine().qmi_mut().network_disconnect(v6, 3, 26);
    pump(&mut s, 4);
    let ev = events(&mut s, c);
    assert_eq!(ev.len(), 1, "{ev:?}");
    assert!(matches!(
        ev[0].1,
        IfaceEvent::DelAddr {
            family: Family::V6,
            ..
        }
    ));
    let v4 = s.engine().qmi_mut().client_of(wds::IpFamily::V4).unwrap();
    s.engine().qmi_mut().network_disconnect(v4, 3, 26);
    pump(&mut s, 5);
    let ev = events(&mut s, c);
    assert!(
        matches!(ev.last().unwrap().1, IfaceEvent::Down(_)),
        "{ev:?}"
    );
    // the link went back with the down, and the next lookups take the next numbers
    assert_eq!(s.engine().free_links(), 15);
    let other = lookup(
        &mut s,
        c,
        3,
        route(0, Family::V4, "other.example", INTERNET_MASK),
    );
    assert_eq!(link_of(&other), 0);
    let second = lookup(&mut s, c, 4, internet(Family::V4));
    assert_eq!(link_of(&second), 1);
}

#[test]
fn a_second_call_of_the_same_apn_and_family_gets_a_link_of_its_own() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    let first = link_of(&lookup(&mut s, c, 1, internet(Family::V4)));
    s.engine().qmi_mut().external_connect(first + 1);
    pump(&mut s, 2);
    events(&mut s, c);
    // the first is up on IPv4, so a second PDN of the same APN and family is another link
    let second = link_of(&lookup(&mut s, c, 2, internet(Family::V4)));
    assert_ne!(second, first);
    assert_eq!(s.links_held(c), 2);
}

#[test]
fn a_lookup_that_repeats_one_whose_call_never_came_up_gets_the_same_link() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    let a = lookup(&mut s, c, 1, internet(Family::V4));
    let b = lookup(&mut s, c, 2, internet(Family::V4));
    assert_eq!(link_of(&a), link_of(&b));
    assert_eq!(s.engine().free_links(), 14);
}

#[test]
fn a_lookup_before_bringup_is_refused_as_not_ready_and_works_after() {
    let mut s = server();
    let c = accept(&mut s);
    s.request(
        0,
        c,
        Request::RouteLookup {
            txn: 1,
            req: internet(Family::V4),
        },
    );
    assert_eq!(code_of(&s.drain(c).pop().unwrap()), ResultCode::NotReady);
    modem_up(&mut s);
    assert_eq!(
        code_of(&lookup(&mut s, c, 2, internet(Family::V4))),
        ResultCode::Ok
    );
}

#[test]
fn an_emergency_apn_type_may_use_the_reserve_and_is_not_counted_against_the_share() {
    let mut s = server_with(Config {
        link_count: 6,
        reserve_links: 2,
        ..Config::default()
    });
    modem_up(&mut s);
    assert_eq!(s.link_quota(), 2);
    let c = accept(&mut s);
    let apns = ["a.example", "b.example", "c.example", "d.example"];
    let codes: Vec<ResultCode> = apns
        .iter()
        .enumerate()
        .map(|(i, a)| {
            code_of(&lookup(
                &mut s,
                c,
                i as u32,
                route(0, Family::V4, a, INTERNET_MASK),
            ))
        })
        .collect();
    assert_eq!(
        codes,
        vec![
            ResultCode::Ok,
            ResultCode::Ok,
            ResultCode::NoLink,
            ResultCode::NoLink
        ],
        "the share of one connection is two"
    );
    let sos = lookup(
        &mut s,
        c,
        10,
        route_typed(Family::V4, "sos.example", 512, EMERGENCY_MASK | 1),
    );
    assert_eq!(
        code_of(&sos),
        ResultCode::Ok,
        "the type decides, not the mask"
    );
    let sos2 = lookup(
        &mut s,
        c,
        11,
        route(0, Family::V4, "sos2.example", EMERGENCY_MASK),
    );
    assert_eq!(code_of(&sos2), ResultCode::Ok, "the reserve is for it");
    // two ordinary and two emergency links are held, a third emergency link is the last
    // one a connection gets (the reserve and one more)
    let r = lookup(
        &mut s,
        c,
        12,
        route(0, Family::V4, "sos3.example", EMERGENCY_MASK),
    );
    assert_eq!(code_of(&r), ResultCode::Ok);
    let last = lookup(
        &mut s,
        c,
        20,
        route(0, Family::V4, "sos4.example", EMERGENCY_MASK),
    );
    assert_eq!(
        code_of(&last),
        ResultCode::NoLink,
        "and then the cap of emergency links of a connection is reached"
    );
}

#[test]
fn the_screen_state_and_the_mtu_query_have_defined_answers() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    let l = link_of(&lookup(&mut s, c, 1, internet(Family::V4)));
    assert!(s.screen_on());
    assert_eq!(
        simple(&mut s, c, Request::ScreenState { txn: 23, on: false }),
        Notify::Done {
            txn: 23,
            code: ResultCode::Ok
        }
    );
    assert!(!s.screen_on());
    // the MTU of a link nothing is up on, and of one that does not exist
    assert_eq!(
        code_of_mtu(&simple(&mut s, c, Request::QueryMtu { txn: 24, link: l })),
        ResultCode::BadState
    );
    assert_eq!(
        code_of_mtu(&simple(&mut s, c, Request::QueryMtu { txn: 25, link: 9 })),
        ResultCode::NoSuchLink
    );
}

fn code_of_mtu(n: &Notify) -> ResultCode {
    match n {
        Notify::MtuReply { code, .. } => *code,
        other => panic!("{other:?}"),
    }
}

#[test]
fn links_are_private_to_a_connection_and_free_when_it_closes() {
    let mut s = server();
    modem_up(&mut s);
    let a = accept(&mut s);
    let b = accept(&mut s);
    let la = link_of(&lookup(&mut s, a, 1, internet(Family::V4)));
    let lb = link_of(&lookup(&mut s, b, 1, internet(Family::V4)));
    assert_ne!(la, lb);
    // b cannot release or query a's link
    assert_eq!(
        code_of(&simple(
            &mut s,
            b,
            Request::LinkRelease { txn: 5, link: la }
        )),
        ResultCode::NoSuchLink
    );
    assert_eq!(
        code_of_mtu(&simple(&mut s, b, Request::QueryMtu { txn: 6, link: la })),
        ResultCode::NoSuchLink
    );
    // and does not hear its events
    s.engine().qmi_mut().external_connect(la + 1);
    pump(&mut s, 2);
    assert!(!events(&mut s, a).is_empty());
    assert!(events(&mut s, b).is_empty());
    // closing a frees a's links only, once the time a closed connection's calls are kept is over
    s.close(3, a);
    s.tick(3 + grace());
    assert_eq!(s.engine().free_links(), 14);
}

#[test]
fn a_modem_restart_ends_the_call_frees_the_links_and_flips_ready() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    lookup(&mut s, c, 1, internet(Family::V4));
    s.engine().qmi_mut().external_connect(1);
    pump(&mut s, 2);
    s.drain(c);
    s.on_service_event(5, ServiceEvent::ModemDown);
    let out = s.drain(c);
    let down = out.iter().any(|n| {
        matches!(
            n,
            Notify::Event {
                event: IfaceEvent::Down(EndReason::Local(LocalReason::ModemRestart)),
                ..
            }
        )
    });
    assert!(down, "{out:?}");
    assert!(out.contains(&Notify::Ready { ready: false }));
    assert_eq!(
        s.engine().free_links(),
        15,
        "the module starts over, so the link is free"
    );
    s.request(
        6,
        c,
        Request::RouteLookup {
            txn: 3,
            req: internet(Family::V4),
        },
    );
    assert_eq!(code_of(&s.drain(c).pop().unwrap()), ResultCode::NotReady);
    s.on_service_event(7, ServiceEvent::ModemUp);
    pump(&mut s, 7);
    assert!(s.drain(c).contains(&Notify::Ready { ready: true }));
    assert_eq!(
        code_of(&lookup(&mut s, c, 4, internet(Family::V4))),
        ResultCode::Ok
    );
}

#[test]
fn a_refused_binding_tells_the_module_and_the_link_stays_until_it_is_released() {
    let mut s = server();
    modem_up(&mut s);
    s.engine().qmi_mut().reject_mux_ids.push(1);
    let c = accept(&mut s);
    let l = link_of(&lookup(&mut s, c, 1, internet(Family::V4)));
    let ev = events(&mut s, c);
    // nicmd posts a failed operation only for an interface it announced up, and the module aborts its own
    // start on one, so nothing is sent before the first up (`postEvent`)
    let _ = l;
    assert_eq!(ev, vec![]);
    assert_eq!(s.dropped_before_up(), 1);
    assert_eq!(s.engine().free_links(), 14);
    // a new lookup for the same call does not reuse the ended one
    let again = link_of(&lookup(&mut s, c, 2, internet(Family::V4)));
    assert_ne!(again, l);
    simple(&mut s, c, Request::LinkRelease { txn: 3, link: l });
    assert_eq!(s.engine().free_links(), 14);
}

#[test]
fn closing_a_connection_frees_its_links() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    for i in 0..3 {
        lookup(
            &mut s,
            c,
            i,
            route(0, Family::V4, &format!("apn{i}.example"), INTERNET_MASK),
        );
    }
    assert_eq!(s.engine().free_links(), 12);
    s.close(5, c);
    assert_eq!(
        s.engine().free_links(),
        12,
        "kept for the module that comes back"
    );
    s.tick(5 + grace());
    assert_eq!(s.engine().free_links(), 15);
    // and a connection after that starts clean
    let d = accept(&mut s);
    assert_eq!(s.links_held(d), 0);
    assert_eq!(link_of(&lookup(&mut s, d, 1, internet(Family::V4))), 0);
}

#[test]
fn a_bad_slot_is_invalid_and_takes_no_link() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    let r = lookup(
        &mut s,
        c,
        1,
        route(9, Family::V4, "x.example", INTERNET_MASK),
    );
    assert_eq!(code_of(&r), ResultCode::Invalid);
    assert_eq!(s.engine().free_links(), 15);
}

#[test]
fn random_request_sequences_keep_the_books_straight() {
    let mut x: u64 = 0x1234_5678;
    let mut next = move |n: usize| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        (x % n as u64) as usize
    };
    for _ in 0..300 {
        let mut s = server();
        modem_up(&mut s);
        let conns = [accept(&mut s), accept(&mut s)];
        let mut now = 1;
        for _ in 0..60 {
            now += 1;
            let c = conns[next(2)];
            match next(8) {
                0..=2 => {
                    let apn = format!("apn{}.example", next(5));
                    let mask = if next(6) == 0 {
                        EMERGENCY_MASK
                    } else {
                        INTERNET_MASK
                    };
                    let fam = if next(2) == 0 { Family::V4 } else { Family::V6 };
                    s.request(
                        now,
                        c,
                        Request::RouteLookup {
                            txn: now as u32,
                            req: route(next(3) as u8, fam, &apn, mask),
                        },
                    );
                }
                3 => s.request(
                    now,
                    c,
                    Request::LinkRelease {
                        txn: 1,
                        link: next(16) as u8,
                    },
                ),
                4 => s.request(
                    now,
                    c,
                    Request::QueryMtu {
                        txn: 1,
                        link: next(16) as u8,
                    },
                ),
                5 => s.engine().qmi_mut().external_connect(1 + next(15) as u8),
                6 => s
                    .engine()
                    .qmi_mut()
                    .external_disconnect(1 + next(15) as u8, 1, 1),
                _ => {
                    if next(10) == 0 {
                        s.on_service_event(now, ServiceEvent::ModemDown);
                        s.on_service_event(now, ServiceEvent::ModemUp);
                    }
                }
            }
            pump(&mut s, now);
            for c in conns {
                s.drain(c);
            }
            // every link is free or held by exactly one connection
            let held: usize = conns.iter().map(|c| s.links_held(*c)).sum();
            assert_eq!(s.engine().free_links() + held, 15);
        }
        for c in conns {
            s.close(now, c);
        }
        s.tick(now + grace());
        assert_eq!(
            s.engine().free_links(),
            15,
            "everything is free after both closed"
        );
    }
}

#[test]
fn a_connection_that_stops_reading_cannot_make_the_queue_grow() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    // a thousand questions and no reading
    for i in 0..1000 {
        s.request(1, c, Request::QueryMtu { txn: i, link: 9 });
    }
    assert!(s.overflowed(c));
    let got = s.drain(c);
    assert_eq!(got.len(), dataos_datad::server::MAX_QUEUED);
    // the first ones are kept, the rest is gone, and the caller is told to close
    assert!(
        matches!(got[0], Notify::Ready { ready: true })
            || matches!(got[0], Notify::MtuReply { .. })
    );
    let d = accept(&mut s);
    assert!(!s.overflowed(d));
}

/// A followed IPv4 call that is up, its events taken.
fn followed_v4(s: &mut S) -> u32 {
    modem_up(s);
    let c = accept_as(s, MODULE);
    lookup(s, c, 1, internet(Family::V4));
    s.engine().qmi_mut().external_connect(1);
    pump(s, 2);
    events(s, c);
    c
}

/// The network changes the configuration of the call of the IPv4 follower and says so.
fn network_changes_v4(s: &mut S, addr: &str, mtu: u32) {
    let client = s.engine().qmi_mut().client_of(wds::IpFamily::V4).unwrap();
    s.engine().qmi_mut().network.v4 = Some((
        addr.parse().unwrap(),
        "192.0.2.9".parse().unwrap(),
        "255.255.255.252".parse().unwrap(),
        mtu,
    ));
    s.engine()
        .qmi_mut()
        .extended_ip_config(client, wds::settings::MTU);
    pump(s, 3);
}

#[test]
fn a_change_of_address_and_mtu_of_a_followed_call_reaches_the_module() {
    let mut s = server();
    let c = followed_v4(&mut s);
    network_changes_v4(&mut s, "192.0.2.14", 1300);
    let ev = events(&mut s, c);
    let old: std::net::IpAddr = "192.0.2.10".parse().unwrap();
    let new: std::net::IpAddr = "192.0.2.14".parse().unwrap();
    assert_eq!(
        ev,
        vec![
            (
                0,
                IfaceEvent::MtuUpdate {
                    family: Family::V4,
                    mtu: 1300
                }
            ),
            (
                0,
                IfaceEvent::DelAddr {
                    family: Family::V4,
                    addr: old,
                    prefix: 30
                }
            ),
            (
                0,
                IfaceEvent::NewAddr {
                    family: Family::V4,
                    addr: new,
                    prefix: 30
                }
            ),
            (0, IfaceEvent::Reconfigured),
        ]
    );
    // and a change of the MTU alone is told as an MTU update and a reconfiguration
    network_changes_v4(&mut s, "192.0.2.14", 1280);
    let ev = events(&mut s, c);
    assert_eq!(
        ev,
        vec![
            (
                0,
                IfaceEvent::MtuUpdate {
                    family: Family::V4,
                    mtu: 1280
                }
            ),
            (0, IfaceEvent::Reconfigured),
        ]
    );
}

#[test]
fn a_bad_refresh_of_a_followed_family_that_is_up_changes_nothing() {
    let mut s = server();
    let c = followed_v4(&mut s);
    let before = s.engine().stats().refresh_bad;
    // the answer has no IPv4 address
    s.engine().qmi_mut().settings_drop = vec![0x1e];
    network_changes_v4(&mut s, "192.0.2.14", 1300);
    assert_eq!(events(&mut s, c), vec![], "the module hears nothing");
    assert_eq!(
        s.engine().stats().refresh_bad,
        before + 1,
        "and it is counted"
    );
    // the books still say the family is up, and the call still ends in the usual way
    assert!(matches!(
        simple(&mut s, c, Request::QueryMtu { txn: 8, link: 0 }),
        Notify::MtuReply {
            code: ResultCode::Ok,
            v4: 1400,
            ..
        }
    ));
    s.engine().qmi_mut().settings_drop.clear();
    s.engine().qmi_mut().external_disconnect(1, 3, 26);
    pump(&mut s, 5);
    let ev = events(&mut s, c);
    assert!(
        ev.iter()
            .any(|(_, e)| matches!(e, IfaceEvent::DelAddr { .. })),
        "{ev:?}"
    );
    assert!(
        matches!(ev.last().unwrap().1, IfaceEvent::Down(_)),
        "{ev:?}"
    );
}

#[test]
fn a_family_that_was_up_and_then_failed_is_taken_away_with_its_address() {
    let mut s = server();
    let c = dual_followed(&mut s);
    // the kernel refuses the new configuration of the IPv4 side: it cannot be followed any more
    s.engine().net_mut().fail_next = Some(("set", dataos_netcfg::NetError::Os(5)));
    network_changes_v4(&mut s, "192.0.2.14", 1300);
    let ev = events(&mut s, c);
    assert!(
        ev.iter().any(|(_, e)| matches!(
            e,
            IfaceEvent::DelAddr {
                family: Family::V4,
                ..
            }
        )),
        "{ev:?}"
    );
    assert!(
        !ev.iter().any(|(_, e)| matches!(e, IfaceEvent::Down(_))),
        "IPv6 is still up: {ev:?}"
    );
    // the books agree: the IPv4 side has no MTU of its own any more, it has the link's
    assert!(matches!(
        simple(&mut s, c, Request::QueryMtu { txn: 8, link: 0 }),
        Notify::MtuReply {
            code: ResultCode::Ok,
            v4: 1380,
            v6: 1380,
            ..
        }
    ));
}

fn dual_followed(s: &mut S) -> u32 {
    let c = followed_v4(s);
    lookup(s, c, 2, internet(Family::V6));
    s.engine()
        .qmi_mut()
        .external_connect_family(1, wds::IpFamily::V6);
    pump(s, 3);
    events(s, c);
    c
}

#[test]
fn an_indication_for_the_other_family_is_passed_over() {
    let mut s = server();
    let c = dual_followed(&mut s);
    let before = s.engine().stats().other_family_indications;
    // the modem tells the IPv6 client that the IPv4 call is gone, as it may tell every client of a mux
    let v6 = s.engine().qmi_mut().client_of(wds::IpFamily::V6).unwrap();
    s.engine()
        .qmi_mut()
        .packet_status_for(v6, 1, wds::IpFamily::V4);
    pump(&mut s, 4);
    assert_eq!(events(&mut s, c), vec![], "IPv6 is still up");
    assert_eq!(s.engine().stats().other_family_indications, before + 1);
    // its own family's indication still works
    s.engine()
        .qmi_mut()
        .packet_status_for(v6, 1, wds::IpFamily::V6);
    pump(&mut s, 5);
    let ev = events(&mut s, c);
    assert!(
        ev.iter().any(|(_, e)| matches!(
            e,
            IfaceEvent::DelAddr {
                family: Family::V6,
                ..
            }
        )),
        "{ev:?}"
    );
}

fn route_typed(family: Family, apn: &str, apn_type: u32, mask: u64) -> RouteRequest {
    RouteRequest {
        slot: 0,
        family,
        apn: Some(apn.into()),
        apn_type,
        apn_type_mask: mask,
    }
}

#[test]
fn a_profile_that_lists_emergency_among_other_types_is_an_ordinary_call() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    let quota = s.link_quota();
    // an IMS profile whose mask also has the emergency bit
    for i in 0..quota {
        let r = lookup(
            &mut s,
            c,
            i as u32 + 1,
            route_typed(
                Family::V4,
                &format!("ims{i}.example"),
                64,
                0x40 | EMERGENCY_MASK,
            ),
        );
        assert_eq!(code_of(&r), ResultCode::Ok, "lookup {i}");
    }
    let one_too_many = lookup(
        &mut s,
        c,
        100,
        route_typed(Family::V4, "ims-more.example", 64, 0x40 | EMERGENCY_MASK),
    );
    assert_eq!(
        code_of(&one_too_many),
        ResultCode::NoLink,
        "it stays inside the share of an ordinary call"
    );
    // a call of the emergency type still gets the reserve
    let e = lookup(
        &mut s,
        c,
        101,
        route_typed(Family::V4, "sos.example", 512, EMERGENCY_MASK),
    );
    assert_eq!(code_of(&e), ResultCode::Ok);
}

#[test]
fn emergency_links_of_one_connection_are_capped_at_the_reserve_plus_one() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    let cap = s.engine().reserved_links() + 1;
    for i in 0..cap {
        let r = lookup(
            &mut s,
            c,
            i as u32 + 1,
            route_typed(Family::V4, &format!("sos{i}.example"), 512, EMERGENCY_MASK),
        );
        assert_eq!(code_of(&r), ResultCode::Ok, "emergency lookup {i}");
    }
    let more = lookup(
        &mut s,
        c,
        100,
        route_typed(Family::V4, "sos-more.example", 512, EMERGENCY_MASK),
    );
    assert_eq!(code_of(&more), ResultCode::NoLink);
}

#[test]
fn a_late_release_after_a_modem_restart_does_not_free_the_new_call() {
    let mut s = server();
    let c = followed_v4(&mut s);
    // the modem restarts: the module starts over
    s.on_service_event(5, ServiceEvent::ModemDown);
    s.drain(c);
    s.on_service_event(6, ServiceEvent::ModemUp);
    pump(&mut s, 6);
    s.drain(c);
    // an emergency call gets a link, and not the number the old call had
    let e = lookup(
        &mut s,
        c,
        4,
        route_typed(Family::V4, "sos.example", 512, EMERGENCY_MASK),
    );
    let new_link = link_of(&e);
    assert_ne!(
        new_link, 0,
        "the number of the old call is not reused at once"
    );
    // the module's late release of the old call finds nothing and frees nothing
    let late = simple(&mut s, c, Request::LinkRelease { txn: 5, link: 0 });
    assert_eq!(code_of(&late), ResultCode::NoSuchLink);
    assert_eq!(
        s.engine().free_links(),
        14,
        "the emergency call keeps its link"
    );
    // after the hold the number is back in use
    let mut later = 6 + grace();
    s.on_service_event(later, ServiceEvent::ModemDown);
    s.drain(c);
    later += 1;
    s.on_service_event(later, ServiceEvent::ModemUp);
    pump(&mut s, later);
}

#[test]
fn a_family_the_module_starts_without_a_lookup_is_followed() {
    let mut s = server();
    let c = followed_v4(&mut s);
    // the module retries IPv6 on the held link and skips the route lookup
    s.engine()
        .qmi_mut()
        .external_connect_family(1, wds::IpFamily::V6);
    pump(&mut s, 3);
    let ev = events(&mut s, c);
    assert!(
        ev.iter().any(|(_, e)| matches!(
            e,
            IfaceEvent::NewAddr {
                family: Family::V6,
                ..
            }
        )),
        "{ev:?}"
    );
    assert!(
        !ev.iter().any(|(_, e)| *e == IfaceEvent::Up),
        "the link was up already: {ev:?}"
    );
}

#[test]
fn a_family_nobody_asked_for_that_cannot_be_followed_is_not_reported() {
    let mut s = server();
    modem_up(&mut s);
    // every subscription binding is refused: the leg of the requested family ends, and the
    // follower of the other family, which the module never asked for, ends without a word
    s.engine()
        .qmi_mut()
        .reject
        .push((wds::SERVICE, wds::id::BIND_SUBSCRIPTION));
    let c = accept(&mut s);
    let r = lookup(&mut s, c, 1, internet(Family::V4));
    assert_eq!(code_of(&r), ResultCode::Ok);
    pump(&mut s, 2);
    assert_eq!(events(&mut s, c), vec![]);
    assert_eq!(
        s.dropped_before_up(),
        1,
        "one failure, for the family that was asked for, held back"
    );
}

#[test]
fn a_closed_connection_keeps_its_links_for_a_while_and_a_reconnect_takes_them_over() {
    let mut s = server();
    let c = followed_v4(&mut s);
    // the connection breaks, the call of the module is still up
    s.close(10, c);
    assert_eq!(s.engine().free_links(), 14, "the link is held");
    let c2 = reconnect_as(&mut s, MODULE, 10);
    assert_eq!(s.links_held(c2), 1, "and it is the reconnected module's");
    // the module on the new connection still names the link it was given
    assert!(matches!(
        simple(&mut s, c2, Request::QueryMtu { txn: 1, link: 0 }),
        Notify::MtuReply {
            code: ResultCode::Ok,
            v4: 1400,
            ..
        }
    ));
    // the call ends: the module on the new connection hears it, and the link is free
    s.engine().qmi_mut().external_disconnect(1, 3, 26);
    pump(&mut s, 11);
    assert!(events(&mut s, c2)
        .iter()
        .any(|(_, e)| matches!(e, IfaceEvent::Down(_))));
    assert_eq!(s.engine().free_links(), 15);
    // a link nobody takes over is freed when the time is over
    s.close(15, c2);
    let c3 = followed_v4_on(&mut s, 20);
    s.close(30, c3);
    assert_eq!(s.engine().free_links(), 14);
    s.tick(30 + grace());
    assert_eq!(s.engine().free_links(), 15);
}

fn followed_v4_on(s: &mut S, now: u64) -> u32 {
    let c = accept_as(s, MODULE);
    lookup(s, c, 50, internet(Family::V4));
    s.engine().qmi_mut().external_connect(1);
    pump(s, now);
    events(s, c);
    c
}

#[test]
fn ordinary_calls_keep_their_share_after_emergency_calls() {
    let mut s = server_with(Config {
        link_count: 6,
        reserve_links: 2,
        ..Config::default()
    });
    modem_up(&mut s);
    let c = accept(&mut s);
    assert_eq!(s.link_quota(), 2);
    // two emergency links first, then the share of an ordinary call is still two
    for (i, apn) in ["sos1.example", "sos2.example"].iter().enumerate() {
        let r = lookup(
            &mut s,
            c,
            i as u32 + 1,
            route_typed(Family::V4, apn, 512, EMERGENCY_MASK),
        );
        assert_eq!(code_of(&r), ResultCode::Ok);
    }
    for (i, apn) in ["a.example", "b.example"].iter().enumerate() {
        let r = lookup(
            &mut s,
            c,
            10 + i as u32,
            route(0, Family::V4, apn, INTERNET_MASK),
        );
        assert_eq!(code_of(&r), ResultCode::Ok, "ordinary lookup {i}");
    }
    let third = lookup(
        &mut s,
        c,
        20,
        route(0, Family::V4, "c.example", INTERNET_MASK),
    );
    assert_eq!(code_of(&third), ResultCode::NoLink);
}

#[test]
fn an_unreadable_refresh_answer_changes_nothing_on_a_working_family() {
    let mut s = server();
    let c = followed_v4(&mut s);
    let before = s.engine().stats().refresh_bad;
    // the modem answers the settings request with an error
    s.engine()
        .qmi_mut()
        .reject
        .push((wds::SERVICE, wds::id::GET_RUNTIME_SETTINGS));
    network_changes_v4(&mut s, "192.0.2.14", 1300);
    assert_eq!(events(&mut s, c), vec![]);
    assert_eq!(s.engine().stats().refresh_bad, before + 1);
    // and the next good answer is taken
    s.engine().qmi_mut().reject.clear();
    network_changes_v4(&mut s, "192.0.2.14", 1300);
    let ev = events(&mut s, c);
    assert!(
        ev.iter()
            .any(|(_, e)| matches!(e, IfaceEvent::NewAddr { .. })),
        "{ev:?}"
    );
}

#[test]
fn a_reconnect_may_release_a_link_it_never_looked_at_first() {
    let mut s = server();
    let c = followed_v4(&mut s);
    s.close(10, c);
    let c2 = accept_as(&mut s, MODULE);
    // the call is up, so the release is answered and the link stays (a start of another user failed)
    assert_eq!(
        code_of(&simple(
            &mut s,
            c2,
            Request::LinkRelease { txn: 1, link: 0 }
        )),
        ResultCode::Ok
    );
    assert_eq!(s.engine().free_links(), 14);
    assert_eq!(s.kept_releases(), 1);
    // the call ends and the link goes back
    s.engine().qmi_mut().external_disconnect(1, 3, 26);
    pump(&mut s, 11);
    assert_eq!(s.engine().free_links(), 15);
}

#[test]
fn the_subscription_of_the_module_is_bound_as_it_is_and_comes_back_in_the_events() {
    // the module passes the WDS subscription: 0 default, 1 the first SIM, 2 the second, 0xff
    // "don't care" for a call that belongs to no SIM
    for wds_subs in [0u8, 1, 2, 0xff] {
        let mut s = server();
        modem_up(&mut s);
        let c = accept(&mut s);
        let r = lookup(
            &mut s,
            c,
            1,
            route(wds_subs, Family::V4, "internet.example", INTERNET_MASK),
        );
        assert_eq!(code_of(&r), ResultCode::Ok, "subscription {wds_subs}");
        pump(&mut s, 2);
        let client = s.engine().qmi_mut().client_of(wds::IpFamily::V4).unwrap();
        assert_eq!(
            s.engine().qmi_mut().sub_of(client),
            Some(u32::from(wds_subs)),
            "the value bound is the one the module gave"
        );
        s.engine().qmi_mut().external_connect(1);
        pump(&mut s, 3);
        let slots: Vec<u8> = s
            .drain(c)
            .into_iter()
            .filter_map(|n| match n {
                Notify::Event { slot, .. } => Some(slot),
                _ => None,
            })
            .collect();
        assert!(!slots.is_empty());
        assert!(
            slots.iter().all(|x| *x == wds_subs),
            "the event names the subscription as the module compares it: {slots:?}"
        );
    }
}

#[test]
fn a_subscription_the_phone_does_not_have_is_invalid_and_takes_no_link() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    for wds_subs in [3u8, 4, 0x80, 0xfe] {
        let r = lookup(
            &mut s,
            c,
            1,
            route(wds_subs, Family::V4, "internet.example", INTERNET_MASK),
        );
        assert_eq!(code_of(&r), ResultCode::Invalid);
    }
    assert_eq!(s.engine().free_links(), 15);
}

fn flags_of(n: &Notify) -> (bool, bool) {
    match n {
        Notify::RouteReply {
            existing,
            companion,
            ..
        } => (*existing, *companion),
        other => panic!("no route reply: {other:?}"),
    }
}

#[test]
fn the_answer_says_when_the_modem_has_the_call_already_and_when_it_is_the_other_family() {
    // nicmd asks the modem for an instance of the call: none for a new call, the other family's
    // instance for the second family of a dual-stack call
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    let first = lookup(&mut s, c, 1, internet(Family::V4));
    assert_eq!(flags_of(&first), (false, false));
    // the same family asked again before its call came up: still a new call
    let again = lookup(&mut s, c, 2, internet(Family::V4));
    assert_eq!(flags_of(&again), (false, false));
    s.engine().qmi_mut().external_connect(1);
    pump(&mut s, 3);
    let second = lookup(&mut s, c, 3, internet(Family::V6));
    assert_eq!(link_of(&first), link_of(&second));
    assert_eq!(flags_of(&second), (true, true));
}

#[test]
fn the_second_family_that_moves_the_link_mtu_gets_an_mtu_event_before_its_address() {
    // the link MTU is the smaller of the two families (1400 and 1380), so it moves from 1400 to 1380
    let mut s = server();
    let c = followed_v4(&mut s);
    lookup(&mut s, c, 2, internet(Family::V6));
    s.engine()
        .qmi_mut()
        .external_connect_family(1, wds::IpFamily::V6);
    pump(&mut s, 3);
    let ev = events(&mut s, c);
    let at = |f: &dyn Fn(&IfaceEvent) -> bool| ev.iter().position(|(_, e)| f(e));
    let mtu = at(&|e| {
        matches!(
            e,
            IfaceEvent::MtuUpdate {
                family: Family::V6,
                mtu: 1380
            }
        )
    });
    let addr = at(&|e| {
        matches!(
            e,
            IfaceEvent::NewAddr {
                family: Family::V6,
                ..
            }
        )
    });
    assert!(mtu.is_some() && addr.is_some(), "{ev:?}");
    assert!(mtu < addr, "the MTU comes before the address: {ev:?}");
}

/// Two links, one of them the reserve: the call of the module is up on link 0, the modem restarts, an
/// emergency call takes link 1, and the next emergency lookup within the hold gets the held link 0.
fn held_link_handed_to_an_emergency_call(s: &mut S) -> (u32, u8) {
    modem_up(s);
    let c = accept_as(s, MODULE);
    assert_eq!(link_of(&lookup(s, c, 1, internet(Family::V4))), 0);
    s.engine().qmi_mut().external_connect(1);
    pump(s, 2);
    s.on_service_event(5, ServiceEvent::ModemDown);
    s.on_service_event(6, ServiceEvent::ModemUp);
    pump(s, 6);
    s.drain(c);
    let first = lookup(
        s,
        c,
        2,
        route_typed(Family::V4, "sos1.example", 512, EMERGENCY_MASK),
    );
    assert_eq!(
        link_of(&first),
        1,
        "the link that is not on hold goes first"
    );
    let second = lookup(
        s,
        c,
        3,
        route_typed(Family::V4, "sos2.example", 512, EMERGENCY_MASK),
    );
    let held = link_of(&second);
    assert_eq!(
        held, 0,
        "nothing else is free, so the held link is handed out"
    );
    s.engine().qmi_mut().external_connect(1);
    pump(s, 7);
    s.drain(c);
    (c, held)
}

fn two_links() -> S {
    server_with(Config {
        link_count: 2,
        reserve_links: 1,
        ..Config::default()
    })
}

#[test]
fn the_late_release_of_the_old_call_does_not_end_the_emergency_call_on_its_number() {
    let mut s = two_links();
    let (c, held) = held_link_handed_to_an_emergency_call(&mut s);
    assert_eq!(s.engine().free_links(), 0);
    // the module's late release of the call that was on that number before the restart
    let late = simple(&mut s, c, Request::LinkRelease { txn: 9, link: held });
    assert_eq!(code_of(&late), ResultCode::Ok);
    assert_eq!(
        s.engine().free_links(),
        0,
        "the emergency call keeps its link"
    );
    assert_eq!(s.swallowed_releases(), 1);
    // the data path is still followed: its end is told as usual
    s.engine().qmi_mut().external_disconnect(1, 3, 26);
    pump(&mut s, 8);
    assert!(events(&mut s, c)
        .iter()
        .any(|(_, e)| matches!(e, IfaceEvent::Down(_))));
}

#[test]
fn every_release_of_a_marked_number_is_swallowed_until_its_hold_ends() {
    let mut s = two_links();
    modem_up(&mut s);
    let c = accept(&mut s);
    assert_eq!(link_of(&lookup(&mut s, c, 1, internet(Family::V4))), 0);
    s.engine().qmi_mut().external_connect(1);
    pump(&mut s, 2);
    s.on_service_event(5, ServiceEvent::ModemDown);
    s.on_service_event(6, ServiceEvent::ModemUp);
    pump(&mut s, 6);
    s.drain(c);
    s.engine().qmi_mut().external_disconnect(1, 3, 26);
    let sos = |n: &str| route_typed(Family::V4, &format!("{n}.example"), 512, EMERGENCY_MASK);
    assert_eq!(link_of(&lookup(&mut s, c, 2, sos("sos1"))), 1);
    let held = link_of(&lookup(&mut s, c, 3, sos("sos2")));
    assert_eq!(
        held, 0,
        "nothing else is free, so the held number goes to the emergency start"
    );
    // the late releases of the old call and the release of the start the module gives up are
    // all answered and none is carried out while the number is on hold (30 s after the restart)
    for txn in 4..7 {
        s.request(txn.into(), c, Request::LinkRelease { txn, link: held });
        assert_eq!(code_of(&s.drain(c).pop().unwrap()), ResultCode::Ok);
    }
    assert_eq!(s.engine().free_links(), 0);
    assert_eq!(s.swallowed_releases(), 3);
    // after the hold the release is a real one
    let after = 5 + ServerConfig::default().restart_hold_ms;
    s.request(after, c, Request::LinkRelease { txn: 7, link: held });
    assert_eq!(code_of(&s.drain(c).pop().unwrap()), ResultCode::Ok);
    assert_eq!(
        s.engine().free_links(),
        1,
        "the release after the hold frees it"
    );
    assert_eq!(s.swallowed_releases(), 3);
}

#[test]
fn a_swallowed_release_keeps_the_link_for_the_reclaim_or_the_close_of_the_connection() {
    let mut s = two_links();
    let (c, held) = held_link_handed_to_an_emergency_call(&mut s);
    assert_eq!(
        code_of(&simple(
            &mut s,
            c,
            Request::LinkRelease { txn: 1, link: held }
        )),
        ResultCode::Ok
    );
    s.close(10, c);
    s.tick(10 + grace());
    assert_eq!(
        s.engine().free_links(),
        2,
        "closing the connection gives both back"
    );
}

#[test]
fn the_mark_survives_the_close_of_the_connection_until_the_hold_ends() {
    let mut s = two_links();
    let (c, held) = held_link_handed_to_an_emergency_call(&mut s);
    s.close(10, c);
    let c2 = accept_as(&mut s, MODULE);
    // the late release of the old call comes on the new connection and is still the swallowed one
    assert_eq!(
        code_of(&simple(
            &mut s,
            c2,
            Request::LinkRelease { txn: 1, link: held }
        )),
        ResultCode::Ok
    );
    assert_eq!((s.swallowed_releases(), s.kept_releases()), (1, 0));
    // after the hold the call is up and the release is kept
    let after = 5 + ServerConfig::default().restart_hold_ms;
    s.request(after, c2, Request::LinkRelease { txn: 2, link: held });
    assert_eq!(code_of(&s.drain(c2).pop().unwrap()), ResultCode::Ok);
    assert_eq!((s.swallowed_releases(), s.kept_releases()), (1, 1));
    s.engine().qmi_mut().external_disconnect(held + 1, 3, 26);
    pump(&mut s, 11);
    // the call that was up is free, the other emergency link has not come up and stays for now
    assert_eq!(s.engine().free_links(), 1);
}

#[test]
fn a_second_restart_ends_the_mark_with_the_call() {
    let mut s = two_links();
    let (c, held) = held_link_handed_to_an_emergency_call(&mut s);
    s.on_service_event(20, ServiceEvent::ModemDown);
    s.on_service_event(21, ServiceEvent::ModemUp);
    pump(&mut s, 21);
    s.drain(c);
    // the call is gone with the restart, a release of its number finds nothing and is not swallowed
    assert_eq!(
        code_of(&simple(
            &mut s,
            c,
            Request::LinkRelease { txn: 1, link: held }
        )),
        ResultCode::NoSuchLink
    );
    assert_eq!(s.swallowed_releases(), 0);
}

#[test]
fn a_link_that_was_not_on_hold_is_released_at_once() {
    let mut s = two_links();
    modem_up(&mut s);
    let c = accept(&mut s);
    let l = link_of(&lookup(&mut s, c, 1, internet(Family::V4)));
    assert_eq!(
        code_of(&simple(&mut s, c, Request::LinkRelease { txn: 1, link: l })),
        ResultCode::Ok
    );
    assert_eq!(s.engine().free_links(), 2);
    assert_eq!(s.swallowed_releases(), 0);
}

// ---- the matching call ----------------------------------------------------------------------

/// A call of the module that is up on the next link of `c`: the lookup, the connect on the
/// mux ID of the link, the events taken. Gives the link.
fn call_up(s: &mut S, c: u32, txn: u32, req: RouteRequest) -> u8 {
    let link = link_of(&lookup(s, c, txn, req));
    s.engine().qmi_mut().external_connect(link + 1);
    pump(s, 2);
    events(s, c);
    link
}

/// The modem names this instance when it is asked about this IP family (4 or 6).
fn modem_names(s: &mut S, family: u8, instance: u8) {
    s.engine()
        .qmi_mut()
        .route_answers
        .insert(family, vec![(0x10, vec![instance])]);
}

/// Ask for a matching call and run the modem until the answer is here.
fn matching(s: &mut S, c: u32, txn: u32, req: RouteRequest) -> Notify {
    s.request(
        1,
        c,
        Request::MatchingCall {
            txn,
            req,
            hint: MatchHint::default(),
        },
    );
    pump(s, 1);
    take_reply(s, c, txn)
}

fn take_reply(s: &mut S, c: u32, txn: u32) -> Notify {
    let mut got = s.drain(c);
    let at = got
        .iter()
        .position(|n| matches!(n, Notify::RouteReply { txn: t, .. } if *t == txn))
        .unwrap_or_else(|| panic!("no answer for {txn}: {got:?}"));
    let reply = got.remove(at);
    s.conns_requeue(c, got);
    reply
}

fn no_match(n: &Notify) -> bool {
    matches!(
        n,
        Notify::RouteReply {
            code: ResultCode::NoMatch,
            link: 0,
            existing: false,
            companion: false,
            ifname,
            ..
        } if ifname.is_empty()
    )
}

/// The IP family byte of every route lookup request that reached the modem.
fn families_asked(s: &mut S) -> Vec<u8> {
    s.engine()
        .qmi_mut()
        .route_frames
        .iter()
        .map(|(_, b)| dataos_qmi::Frame::parse(b).unwrap().tlv(0x19).unwrap()[0])
        .collect()
}

fn lookups_asked(s: &mut S) -> usize {
    s.engine().qmi_mut().route_frames.len()
}

#[test]
fn a_second_request_for_the_apn_of_a_call_that_is_up_gets_that_interface() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    assert_eq!(call_up(&mut s, c, 1, internet(Family::V4)), 0);
    let free = s.engine().free_links();
    modem_names(&mut s, 4, 0);
    let r = matching(&mut s, c, 9, internet(Family::V4));
    assert_eq!(
        r,
        Notify::RouteReply {
            txn: 9,
            code: ResultCode::Ok,
            link: 0,
            existing: true,
            companion: false,
            ifname: "rmnet_data0".into(),
            tech: 0,
        }
    );
    // no new link and no new call: the interface is the one that is up
    assert_eq!(s.engine().free_links(), free);
    assert_eq!(s.links_held(c), 1);
    assert_eq!(
        lookups_asked(&mut s),
        1,
        "the family found it, no companion question"
    );
    // the second user gives its start up and releases the link: the call is up, so the link stays
    let d = simple(&mut s, c, Request::LinkRelease { txn: 10, link: 0 });
    assert_eq!(code_of(&d), ResultCode::Ok);
    assert_eq!(s.engine().free_links(), free);
    assert_eq!(s.kept_releases(), 1);
    assert_eq!(
        code_of(&matching(&mut s, c, 11, internet(Family::V4))),
        ResultCode::Ok
    );
    // when the call has ended, the release frees it
    s.engine().qmi_mut().external_disconnect(1, 3, 26);
    pump(&mut s, 3);
    assert_eq!(s.engine().free_links(), 15, "freed at the down");
    let d = simple(&mut s, c, Request::LinkRelease { txn: 12, link: 0 });
    assert_eq!(code_of(&d), ResultCode::NoSuchLink);
}

#[test]
fn the_other_family_of_a_call_that_is_up_is_found_with_the_companion_question() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    call_up(&mut s, c, 1, internet(Family::V4));
    // the modem knows the call by its IPv4 side only
    modem_names(&mut s, 4, 0);
    let r = matching(&mut s, c, 2, internet(Family::V6));
    assert_eq!(
        r,
        Notify::RouteReply {
            txn: 2,
            code: ResultCode::Ok,
            link: 0,
            existing: true,
            companion: true,
            ifname: "rmnet_data0".into(),
            tech: 0,
        }
    );
    assert_eq!(lookups_asked(&mut s), 2);
    // IPv6 was asked for first, and then the companion
    assert_eq!(families_asked(&mut s), [6, 4]);
}

#[test]
fn a_modem_that_has_no_call_for_the_request_means_no_matching_call() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    call_up(&mut s, c, 1, internet(Family::V4));
    let r = matching(&mut s, c, 2, internet(Family::V4));
    assert!(no_match(&r), "{r:?}");
    assert_eq!(lookups_asked(&mut s), 2, "both families were asked");
    assert_eq!(s.links_held(c), 1);
}

#[test]
fn an_instance_the_daemon_does_not_follow_is_no_matching_call() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    call_up(&mut s, c, 1, internet(Family::V4));
    // the modem names link 5, which nobody holds, and one that does not exist
    for named in [5u8, 200] {
        modem_names(&mut s, 4, named);
        modem_names(&mut s, 6, named);
        let r = matching(&mut s, c, 2, internet(Family::V4));
        assert!(no_match(&r), "{named}: {r:?}");
    }
}

#[test]
fn a_call_of_another_connection_is_no_matching_call() {
    let mut s = server();
    modem_up(&mut s);
    let a = accept(&mut s);
    let b = accept(&mut s);
    assert_eq!(call_up(&mut s, a, 1, internet(Family::V4)), 0);
    modem_names(&mut s, 4, 0);
    let r = matching(&mut s, b, 2, internet(Family::V4));
    assert!(no_match(&r), "{r:?}");
    // the owner of the call gets it
    assert_eq!(
        code_of(&matching(&mut s, a, 3, internet(Family::V4))),
        ResultCode::Ok
    );
}

#[test]
fn a_call_on_another_subscription_is_no_matching_call() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    let sim1 = route(1, Family::V4, "internet.example", INTERNET_MASK);
    assert_eq!(call_up(&mut s, c, 1, sim1.clone()), 0);
    modem_names(&mut s, 4, 0);
    let other = route(2, Family::V4, "internet.example", INTERNET_MASK);
    let r = matching(&mut s, c, 2, other);
    assert!(no_match(&r), "{r:?}");
    // the lookup asked the modem on the subscription of the request
    assert_eq!(s.engine().qmi_mut().bound_subscriptions.last(), Some(&2));
    assert_eq!(code_of(&matching(&mut s, c, 3, sim1)), ResultCode::Ok);
}

#[test]
fn a_call_with_another_apn_is_no_matching_call() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    call_up(&mut s, c, 1, internet(Family::V4));
    modem_names(&mut s, 4, 0);
    let ims = route(0, Family::V4, "ims.example", INTERNET_MASK);
    let r = matching(&mut s, c, 2, ims);
    assert!(no_match(&r), "{r:?}");
    let none = RouteRequest {
        apn: None,
        ..internet(Family::V4)
    };
    assert!(no_match(&matching(&mut s, c, 3, none)));
}

#[test]
fn a_call_with_another_apn_type_or_mask_is_no_matching_call() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    call_up(&mut s, c, 1, internet(Family::V4));
    modem_names(&mut s, 4, 0);
    // the same APN, but not for the same use
    let other_type = RouteRequest {
        apn_type: 2,
        ..internet(Family::V4)
    };
    let other_mask = RouteRequest {
        apn_type_mask: INTERNET_MASK | 0x4,
        ..internet(Family::V4)
    };
    assert!(no_match(&matching(&mut s, c, 2, other_type)));
    assert!(no_match(&matching(&mut s, c, 3, other_mask)));
    assert_eq!(
        code_of(&matching(&mut s, c, 4, internet(Family::V4))),
        ResultCode::Ok
    );
}

#[test]
fn a_link_that_is_not_up_is_no_matching_call() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    // the link was handed out and the module's call has not come up
    assert_eq!(link_of(&lookup(&mut s, c, 1, internet(Family::V4))), 0);
    modem_names(&mut s, 4, 0);
    let r = matching(&mut s, c, 2, internet(Family::V4));
    assert!(no_match(&r), "{r:?}");
    // it comes up and the answer changes
    s.engine().qmi_mut().external_connect(1);
    pump(&mut s, 2);
    events(&mut s, c);
    assert_eq!(
        code_of(&matching(&mut s, c, 3, internet(Family::V4))),
        ResultCode::Ok
    );
    // it goes down again: the link is held until the module gives it back, but it is no interface
    s.engine().qmi_mut().external_disconnect(1, 3, 26);
    pump(&mut s, 3);
    events(&mut s, c);
    assert!(no_match(&matching(&mut s, c, 4, internet(Family::V4))));
}

#[test]
fn an_emergency_call_and_an_ordinary_one_never_match_each_other() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    let sos = route_typed(Family::V4, "shared.example", 512, EMERGENCY_MASK);
    let plain = route_typed(Family::V4, "shared.example", 1, INTERNET_MASK);
    assert_eq!(call_up(&mut s, c, 1, sos.clone()), 0);
    modem_names(&mut s, 4, 0);
    assert!(no_match(&matching(&mut s, c, 2, plain.clone())));
    assert_eq!(code_of(&matching(&mut s, c, 3, sos)), ResultCode::Ok);
    // and the other way round
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    assert_eq!(call_up(&mut s, c, 1, plain), 0);
    modem_names(&mut s, 4, 0);
    let sos = route_typed(Family::V4, "shared.example", 512, EMERGENCY_MASK);
    assert!(no_match(&matching(&mut s, c, 2, sos)));
}

#[test]
fn the_name_of_the_interface_is_the_daemons_never_the_modems() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    call_up(&mut s, c, 1, internet(Family::V4));
    s.engine().qmi_mut().route_answers.insert(
        4,
        vec![
            (0x10, vec![0]),
            // whatever else the answer carries, a name or a path, is not read
            (0x11, b"../../evil0".to_vec()),
            (0x15, b"evil0".to_vec()),
        ],
    );
    let r = matching(&mut s, c, 2, internet(Family::V4));
    let Notify::RouteReply { ifname, .. } = &r else {
        panic!("{r:?}")
    };
    assert_eq!(ifname, "rmnet_data0");
}

#[test]
fn a_modem_that_does_not_answer_ends_the_question_at_its_deadline() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    call_up(&mut s, c, 1, internet(Family::V4));
    modem_names(&mut s, 4, 0);
    s.engine().qmi_mut().mute.push(wds::id::ROUTE_LOOKUP);
    s.request(
        1,
        c,
        Request::MatchingCall {
            txn: 2,
            req: internet(Family::V4),
            hint: MatchHint::default(),
        },
    );
    pump(&mut s, 1);
    assert!(s.drain(c).is_empty(), "the module waits");
    assert_eq!(s.open_questions(), 1);
    let limit = Config::default().lookup_timeout_ms;
    s.tick(1 + limit - 1);
    assert!(s.drain(c).is_empty());
    s.tick(1 + limit);
    let r = take_reply(&mut s, c, 2);
    assert!(no_match(&r), "{r:?}");
    assert_eq!(s.open_questions(), 0);
    // the wait is far shorter than the module's own 10 s
    assert!(limit * 4 <= 10_000);
}

#[test]
fn a_refused_question_or_an_answer_that_cannot_be_read_is_no_matching_call() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    call_up(&mut s, c, 1, internet(Family::V4));
    s.engine()
        .qmi_mut()
        .reject
        .push((wds::SERVICE, wds::id::ROUTE_LOOKUP));
    assert!(no_match(&matching(&mut s, c, 2, internet(Family::V4))));
    s.engine().qmi_mut().reject.clear();
    s.engine()
        .qmi_mut()
        .route_answers
        .insert(4, vec![(0x10, vec![0, 0])]);
    assert!(no_match(&matching(&mut s, c, 3, internet(Family::V4))));
    s.engine()
        .qmi_mut()
        .reject
        .push((wds::SERVICE, wds::id::BIND_SUBSCRIPTION));
    modem_names(&mut s, 4, 0);
    assert!(no_match(&matching(&mut s, c, 4, internet(Family::V4))));
}

#[test]
fn a_modem_restart_during_the_question_answers_no_matching_call() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    call_up(&mut s, c, 1, internet(Family::V4));
    s.engine().qmi_mut().mute.push(wds::id::ROUTE_LOOKUP);
    s.request(
        1,
        c,
        Request::MatchingCall {
            txn: 2,
            req: internet(Family::V4),
            hint: MatchHint::default(),
        },
    );
    pump(&mut s, 1);
    s.on_service_event(5, ServiceEvent::ModemDown);
    let r = take_reply(&mut s, c, 2);
    assert!(no_match(&r), "{r:?}");
    assert_eq!(s.open_questions(), 0);
}

#[test]
fn a_connection_that_closes_with_a_question_open_gets_no_answer_and_leaves_nothing() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    call_up(&mut s, c, 1, internet(Family::V4));
    modem_names(&mut s, 4, 0);
    let open = s.engine().qmi_mut().client_ids(wds::SERVICE).len();
    s.engine().qmi_mut().mute.push(wds::id::ROUTE_LOOKUP);
    s.request(
        1,
        c,
        Request::MatchingCall {
            txn: 2,
            req: internet(Family::V4),
            hint: MatchHint::default(),
        },
    );
    pump(&mut s, 1);
    assert_eq!(
        s.engine().qmi_mut().client_ids(wds::SERVICE).len(),
        open + 1
    );
    assert_eq!(s.open_questions(), 1);
    s.close(2, c);
    assert_eq!(s.open_questions(), 0);
    // the question's client is closed with the connection, not at its deadline
    assert_eq!(s.engine().qmi_mut().client_ids(wds::SERVICE).len(), open);
    let d = accept(&mut s);
    s.engine().qmi_mut().mute.clear();
    pump(&mut s, 3);
    s.tick(10_000);
    assert!(s.drain(d).is_empty());
    assert_eq!(s.engine().next_deadline(), None);
}

#[test]
fn the_question_needs_a_ready_daemon_a_known_subscription_and_a_free_place() {
    let mut s = server();
    let c = accept(&mut s);
    let r = matching(&mut s, c, 1, internet(Family::V4));
    assert_eq!(code_of(&r), ResultCode::NotReady);
    modem_up(&mut s);
    let bad = route(9, Family::V4, "internet.example", INTERNET_MASK);
    let r = matching(&mut s, c, 2, bad);
    assert_eq!(code_of(&r), ResultCode::Invalid);
    assert_eq!(lookups_asked(&mut s), 0);
    assert!(s.engine().qmi_mut().client_ids(wds::SERVICE).is_empty());
    // eight questions wait at most, the ninth is answered at once
    s.drain(c);
    s.engine().qmi_mut().mute.push(wds::id::BIND_SUBSCRIPTION);
    for txn in 10..18 {
        s.request(
            1,
            c,
            Request::MatchingCall {
                txn,
                req: internet(Family::V4),
                hint: MatchHint::default(),
            },
        );
    }
    assert!(s.drain(c).is_empty());
    assert_eq!(s.open_questions(), 8);
    s.request(
        1,
        c,
        Request::MatchingCall {
            txn: 18,
            req: internet(Family::V4),
            hint: MatchHint::default(),
        },
    );
    let r = take_reply(&mut s, c, 18);
    assert!(no_match(&r), "{r:?}");
    assert_eq!(s.open_questions(), 8);
}

#[test]
fn two_questions_open_at_once_are_answered_each_with_its_own_number() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    call_up(&mut s, c, 1, internet(Family::V4));
    modem_names(&mut s, 4, 0);
    s.request(
        1,
        c,
        Request::MatchingCall {
            txn: 20,
            req: internet(Family::V4),
            hint: MatchHint::default(),
        },
    );
    s.request(
        1,
        c,
        Request::MatchingCall {
            txn: 21,
            req: route(0, Family::V4, "ims.example", INTERNET_MASK),
            hint: MatchHint::default(),
        },
    );
    pump(&mut s, 1);
    let first = take_reply(&mut s, c, 20);
    let second = take_reply(&mut s, c, 21);
    assert_eq!(code_of(&first), ResultCode::Ok);
    assert!(no_match(&second), "{second:?}");
}

#[test]
fn the_apn_type_and_the_mask_go_to_the_modem_only_when_the_module_set_them() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    call_up(&mut s, c, 1, internet(Family::V4));
    let unset = RouteRequest {
        apn_type: 0x8000_0001,
        apn_type_mask: 0,
        ..internet(Family::V4)
    };
    matching(&mut s, c, 2, unset);
    matching(&mut s, c, 3, internet(Family::V4));
    let frames: Vec<Vec<u8>> = s
        .engine()
        .qmi_mut()
        .route_frames
        .iter()
        .map(|(_, b)| b.clone())
        .collect();
    let tlvs = |b: &[u8], tag: u8| {
        dataos_qmi::Frame::parse(b)
            .unwrap()
            .tlv(tag)
            .map(<[u8]>::to_vec)
    };
    // two questions each, one per family, the first two are the unset request's
    assert_eq!(frames.len(), 4);
    for b in frames.iter().take(2) {
        assert_eq!((tlvs(b, 0x38), tlvs(b, 0x3e)), (None, None));
    }
    for b in frames.iter().skip(2) {
        assert_eq!(tlvs(b, 0x38), Some(vec![1, 0, 0, 0]));
        assert_eq!(tlvs(b, 0x3e), Some(vec![1, 0, 0, 0, 0, 0, 0, 0]));
    }
}

// ---- the life of a link ------------------------------------------------------------------------

fn lookup_at(s: &mut S, conn: u32, txn: u32, now: u64, req: RouteRequest) -> Notify {
    s.request(now, conn, Request::RouteLookup { txn, req });
    pump(s, now);
    let mut got = s.drain(conn);
    let at = got
        .iter()
        .position(|n| matches!(n, Notify::RouteReply { .. }))
        .unwrap();
    let reply = got.remove(at);
    s.conns_requeue(conn, got);
    reply
}

fn apn(n: u32) -> RouteRequest {
    route(0, Family::V4, &format!("apn{n}.example"), INTERNET_MASK)
}

fn grace() -> u64 {
    ServerConfig::default().orphan_grace_ms
}

fn unused() -> u64 {
    ServerConfig::default().unused_release_ms
}

/// The follower dies at its data port binding, so the call is never announced, and the module
/// does not release a start that it does not give up.
#[test]
fn a_link_whose_follower_died_before_the_call_was_up_is_asked_about_30_seconds_after_hand_out() {
    let mut s = server();
    modem_up(&mut s);
    for m in 1..=15u8 {
        s.engine().qmi_mut().reject_mux_ids.push(m);
    }
    let c = accept(&mut s);
    for n in 0..7 {
        lookup_at(&mut s, c, n, 1, apn(n));
    }
    assert_eq!(s.links_held(c), 7);
    assert_eq!(
        code_of(&lookup_at(&mut s, c, 40, 2, apn(40))),
        ResultCode::NoLink
    );
    // there is no timer: the tick takes nothing back
    s.tick(1 + unused());
    pump(&mut s, 1 + unused());
    assert_eq!(s.reclaimed_links(), 0);
    // a lookup before the time asks nothing
    lookup_at(&mut s, c, 41, unused(), apn(41));
    assert_eq!(s.engine().qmi_mut().route_frames.len(), 0);
    // one at the time asks about four links (the closed followers too), the others wait for the next
    assert_eq!(
        code_of(&lookup_at(&mut s, c, 42, 1 + unused(), apn(42))),
        ResultCode::NoLink,
        "the answers are not there yet"
    );
    pump(&mut s, 1 + unused());
    assert_eq!(s.reclaimed_links(), 4);
    assert_eq!(
        code_of(&lookup_at(&mut s, c, 43, 1 + unused(), apn(43))),
        ResultCode::Ok
    );
    pump(&mut s, 1 + unused());
    assert_eq!(s.reclaimed_links(), 7);
    assert_eq!(s.links_held(c), 1);
}

/// The module keeps its call across the loss of the connection and names nothing.
#[test]
fn a_call_that_is_up_stays_with_the_module_that_reconnects() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept_as(&mut s, MODULE);
    let r = lookup(&mut s, c, 1, internet(Family::V4));
    let l = link_of(&r);
    let Notify::RouteReply { ifname, .. } = &r else {
        panic!()
    };
    s.engine().qmi_mut().external_connect(1);
    pump(&mut s, 2);
    events(&mut s, c);
    let a: std::net::IpAddr = "192.0.2.10".parse().unwrap();
    assert!(s.engine().net().has_address(ifname, a));
    s.close(10, c);
    let c2 = accept_as(&mut s, MODULE);
    assert_eq!(s.links_held(c2), 1, "it is the reconnected module's");
    s.tick(10 + grace() + 1);
    assert!(
        s.engine().net().has_address(ifname, a),
        "the live call lost its address"
    );
    assert_eq!(s.links_held(c2), 1);
    // and its number is not handed out again
    let r2 = lookup(
        &mut s,
        c2,
        2,
        route(0, Family::V4, "other.example", INTERNET_MASK),
    );
    assert_ne!(link_of(&r2), l);
    // the module still names it: the MTU is there
    assert!(matches!(
        simple(&mut s, c2, Request::QueryMtu { txn: 3, link: l }),
        Notify::MtuReply {
            code: ResultCode::Ok,
            ..
        }
    ));
}

/// The release of a start that never came up is swallowed, and the link is asked about 30 s
/// after the hand-out and freed when the modem has no call. An emergency link whose start the module
/// did not give up stays while its follower is open.
#[test]
fn a_swallowed_release_of_a_start_that_never_came_up_ends_with_the_reclaim() {
    let mut s = two_links();
    modem_up(&mut s);
    let c = accept(&mut s);
    assert_eq!(link_of(&lookup(&mut s, c, 1, internet(Family::V4))), 0);
    s.engine().qmi_mut().external_connect(1);
    pump(&mut s, 2);
    s.on_service_event(5, ServiceEvent::ModemDown);
    s.on_service_event(6, ServiceEvent::ModemUp);
    pump(&mut s, 6);
    s.drain(c);
    // the modem lost the call with the restart
    s.engine().qmi_mut().external_disconnect(1, 3, 26);
    let sos = |n: &str| route_typed(Family::V4, &format!("{n}.example"), 512, EMERGENCY_MASK);
    assert_eq!(link_of(&lookup_at(&mut s, c, 2, 7, sos("sos1"))), 1);
    let held = link_of(&lookup_at(&mut s, c, 3, 7, sos("sos2")));
    assert_eq!(held, 0, "the number on hold goes last");
    // the late release of the old call is swallowed, and so is the release of the start the module
    // gives up: the second one is what ends the exemption of an emergency start
    let rel = simple(&mut s, c, Request::LinkRelease { txn: 4, link: held });
    assert_eq!(code_of(&rel), ResultCode::Ok);
    let rel = simple(&mut s, c, Request::LinkRelease { txn: 8, link: held });
    assert_eq!(code_of(&rel), ResultCode::Ok);
    assert_eq!(s.swallowed_releases(), 2);
    assert_eq!(s.links_held(c), 2);
    // 30 s after the hand-out the next lookup asks about the start that was given up, and with no call
    // the link goes. The other emergency start has an open follower and is not asked about
    let ordinary = |n: u32| route(0, Family::V4, &format!("o{n}.example"), INTERNET_MASK);
    lookup_at(&mut s, c, 5, 7 + unused() - 1, ordinary(1));
    assert_eq!(s.engine().qmi_mut().route_frames.len(), 0);
    lookup_at(&mut s, c, 6, 7 + unused(), ordinary(2));
    pump(&mut s, 7 + unused());
    assert_eq!(s.reclaimed_links(), 1);
    assert_eq!(
        s.engine().qmi_mut().route_frames.len(),
        2,
        "one question, two families"
    );
    assert_eq!(
        s.links_held(c),
        1,
        "sos1 stays (the ordinary lookups found no link)"
    );
}

/// A repeated lookup is a new hand-out and starts the time again.
#[test]
fn a_link_handed_out_again_starts_its_time_again() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    let l = link_of(&lookup_at(&mut s, c, 1, 1_000, apn(1)));
    let again = lookup_at(&mut s, c, 2, 26_000, apn(1));
    assert_eq!(link_of(&again), l, "the same link for the same request");
    // 31 s after the first hand-out, 5 s after the second: not yet, and the modem is not asked
    lookup_at(&mut s, c, 3, 31_000, apn(2));
    assert_eq!(s.reclaimed_links(), 0);
    assert_eq!(s.engine().qmi_mut().route_frames.len(), 0);
    lookup_at(&mut s, c, 4, 26_000 + unused(), apn(3));
    pump(&mut s, 26_000 + unused());
    assert_eq!(s.reclaimed_links(), 1, "30 s after the second hand-out");
    assert_eq!(
        s.links_held(c),
        2,
        "the links of the other APNs are still there"
    );
}

/// The connection closes while the module's start on a link is pending.
#[test]
fn a_start_pending_when_the_connection_closed_is_still_the_modules_after_the_reconnect() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept_as(&mut s, MODULE);
    let l = link_of(&lookup(&mut s, c, 1, internet(Family::V4)));
    s.close(5, c);
    let c2 = accept_as(&mut s, MODULE);
    let n = link_of(&lookup(
        &mut s,
        c2,
        2,
        route(0, Family::V4, "ims.example", INTERNET_MASK),
    ));
    assert_ne!(
        n, l,
        "the number of the pending start is not handed out again"
    );
    // the old start fails and the module releases the number it was given
    let r = simple(&mut s, c2, Request::LinkRelease { txn: 3, link: l });
    assert_eq!(code_of(&r), ResultCode::Ok);
    assert_eq!(s.links_held(c2), 1, "the new call keeps its link");
    assert_eq!(s.engine().free_links(), 14);
}

/// The call goes down: nicmd takes the interface back at once (`stateDownHook`).
#[test]
fn a_link_is_free_again_when_its_call_goes_down() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    let l = link_of(&lookup(&mut s, c, 1, internet(Family::V4)));
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 2);
    events(&mut s, c);
    assert_eq!(s.engine().free_links(), 14);
    s.engine().qmi_mut().external_disconnect(l + 1, 3, 26);
    pump(&mut s, 3);
    let ev = events(&mut s, c);
    assert!(
        matches!(ev.last(), Some((_, IfaceEvent::Down(_)))),
        "the module is told: {ev:?}"
    );
    assert_eq!(s.engine().free_links(), 15);
    assert_eq!(s.links_held(c), 0);
    // a late release has nothing to release
    assert_eq!(
        code_of(&simple(&mut s, c, Request::LinkRelease { txn: 4, link: l })),
        ResultCode::NoSuchLink
    );
}

#[test]
fn the_links_of_a_closed_connection_go_only_to_a_connection_of_the_same_process() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept_as(&mut s, MODULE);
    let l = link_of(&lookup(&mut s, c, 1, internet(Family::V4)));
    s.close(5, c);
    let other = s.accept(777, 1001, LABEL).unwrap();
    assert_eq!(s.links_held(other), 0, "another process gets nothing");
    let back = accept_as(&mut s, MODULE);
    assert_eq!(s.links_held(back), 1);
    assert_eq!(
        code_of(&simple(
            &mut s,
            back,
            Request::LinkRelease { txn: 2, link: l }
        )),
        ResultCode::Ok
    );
}

#[test]
fn the_links_nobody_comes_back_for_are_freed_after_the_grace() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    lookup(&mut s, c, 1, internet(Family::V4));
    lookup(&mut s, c, 2, apn(2));
    s.close(5, c);
    assert_eq!(s.engine().free_links(), 13, "kept, the pending ones too");
    s.tick(5 + grace() - 1);
    assert_eq!(s.engine().free_links(), 13);
    s.tick(5 + grace());
    assert_eq!(s.engine().free_links(), 15);
}

#[test]
fn a_link_that_has_not_come_up_stays_when_the_modem_reports_a_call_on_it() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    let l = link_of(&lookup_at(&mut s, c, 1, 1, apn(1)));
    // the modem has a call for the request on this link, whose follower has not heard of it
    s.engine()
        .qmi_mut()
        .route_answers
        .insert(4, vec![(0x10, vec![l])]);
    lookup_at(&mut s, c, 2, 1 + unused(), apn(2));
    pump(&mut s, 1 + unused());
    assert_eq!(s.reclaimed_links(), 0);
    assert_eq!(s.links_held(c), 2);
    // it is asked again 30 s later, not at every lookup
    let asked = s.engine().qmi_mut().route_frames.len();
    lookup_at(&mut s, c, 3, 1 + unused() + 1, apn(3));
    assert_eq!(s.engine().qmi_mut().route_frames.len(), asked);
    s.engine().qmi_mut().route_answers.clear();
    lookup_at(&mut s, c, 4, 1 + 2 * unused(), apn(4));
    pump(&mut s, 1 + 2 * unused());
    assert_eq!(
        s.reclaimed_links(),
        2,
        "the call is gone, and the link of the lookup before is due too"
    );
}

#[test]
fn a_call_the_modem_names_on_another_link_does_not_keep_this_one() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    let l = link_of(&lookup_at(&mut s, c, 1, 1, apn(1)));
    s.engine()
        .qmi_mut()
        .route_answers
        .insert(4, vec![(0x10, vec![l + 5])]);
    lookup_at(&mut s, c, 2, 1 + unused(), apn(2));
    pump(&mut s, 1 + unused());
    assert_eq!(s.reclaimed_links(), 1);
    assert_eq!(s.links_held(c), 1, "the link of the lookup that asked");
}

#[test]
fn a_link_with_a_call_up_is_never_taken_back() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    let l = link_of(&lookup_at(&mut s, c, 1, 1, apn(1)));
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 2);
    events(&mut s, c);
    s.tick(10 * unused());
    pump(&mut s, 10 * unused());
    assert_eq!(s.reclaimed_links(), 0);
    assert_eq!(s.links_held(c), 1);
}

#[test]
fn the_next_deadline_covers_the_engine_the_orphans_and_the_numbers_kept_for_a_process() {
    let mut s = server();
    modem_up(&mut s);
    assert_eq!(s.next_deadline(), None);
    let c = accept(&mut s);
    // a link that has not come up is no timer: it is looked at when a lookup comes
    lookup_at(&mut s, c, 1, 100, apn(1));
    assert_eq!(s.next_deadline(), None);
    // an orphan: its time is over after the grace
    let c2 = accept_as(&mut s, MODULE);
    let up = link_of(&lookup_at(&mut s, c2, 2, 200, apn(2)));
    s.engine().qmi_mut().external_connect(up + 1);
    pump(&mut s, 201);
    events(&mut s, c2);
    s.close(300, c2);
    assert_eq!(s.next_deadline(), Some(300 + grace()));
    // and a call that goes down while its process is away leaves a number kept for it
    s.engine().qmi_mut().external_disconnect(up + 1, 3, 26);
    pump(&mut s, 400);
    assert_eq!(s.next_deadline(), Some(300 + grace()));
    s.close(400, c);
}

#[test]
fn a_link_idles_for_30_seconds_before_a_new_call_may_take_it() {
    assert_eq!(ServerConfig::default().unused_release_ms, 30_000);
}

#[test]
fn the_other_values_of_the_request_reach_the_modem_with_the_question() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    call_up(&mut s, c, 1, internet(Family::V4));
    let hint = MatchHint {
        profile_3gpp: Some(3),
        profile_3gpp2: Some(4),
        xt_pref: Some(0x0102),
        backup_name: Some(1),
        backup_type: Some(2),
    };
    s.request(
        1,
        c,
        Request::MatchingCall {
            txn: 2,
            req: internet(Family::V4),
            hint,
        },
    );
    pump(&mut s, 1);
    take_reply(&mut s, c, 2);
    let (_, bytes) = s.engine().qmi_mut().route_frames[0].clone();
    let f = dataos_qmi::Frame::parse(&bytes).unwrap();
    assert_eq!(f.tlv(0x31), Some(&[3u8][..]));
    assert_eq!(f.tlv(0x32), Some(&[4u8][..]));
    assert_eq!(f.tlv(0x34), Some(&[2u8, 1][..]));
    assert_eq!(f.tlv(0x3c), Some(&[1u8][..]));
    assert_eq!(f.tlv(0x3d), Some(&[2u8][..]));
}

#[test]
fn the_links_of_a_connection_that_closes_go_to_one_of_the_same_process_that_is_open_already() {
    let mut s = server();
    modem_up(&mut s);
    let old = accept_as(&mut s, MODULE);
    let l = link_of(&lookup(&mut s, old, 1, internet(Family::V4)));
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 2);
    events(&mut s, old);
    // the library reconnects before the old connection is seen to close
    let new = accept_as(&mut s, MODULE);
    assert_eq!(s.links_held(new), 0);
    s.close(10, old);
    assert_eq!(s.links_held(new), 1);
    s.tick(10 + grace() + 1);
    assert_eq!(s.links_held(new), 1, "and no time runs on it");
    assert_eq!(s.engine().free_links(), 14);
    // the call ends, and the module on the new connection hears it
    s.engine().qmi_mut().external_disconnect(l + 1, 3, 26);
    pump(&mut s, 11);
    assert!(events(&mut s, new)
        .iter()
        .any(|(_, e)| matches!(e, IfaceEvent::Down(_))));
    assert_eq!(s.engine().free_links(), 15);
}

// ---- the questions about links, and a module that comes back ----------------------------------------

fn sos(n: &str) -> RouteRequest {
    route_typed(Family::V4, &format!("{n}.example"), 512, EMERGENCY_MASK)
}

/// An emergency start that takes longer than 30 s (T3482) keeps its link while its follower is
/// open, whatever the modem says about a PDN that is still being set up.
#[test]
fn a_slow_emergency_start_keeps_its_link() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    let l = link_of(&lookup_at(&mut s, c, 1, 1, sos("sos")));
    // the timer alone does nothing, and a lookup of another process does not take the link
    s.tick(1 + 30_000);
    let other = accept(&mut s);
    let l2 = link_of(&lookup_at(&mut s, other, 2, 1 + 30_000, apn(1)));
    pump(&mut s, 1 + 30_000);
    assert_eq!(s.reclaimed_links(), 0);
    assert_eq!(s.engine().qmi_mut().route_frames.len(), 0, "not even asked");
    assert_ne!(l2, l);
    assert_eq!(s.links_held(c), 1);
    // the PDN comes up on the modem 5 s later and the module hears of it
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 36_000);
    let got = events(&mut s, c);
    assert_eq!(got.first(), Some(&(l, IfaceEvent::Up)));
}

/// The follower of an emergency link is closed, so it is asked about like any other link.
#[test]
fn an_emergency_link_with_a_closed_follower_is_asked_about() {
    let mut s = server();
    modem_up(&mut s);
    s.engine().qmi_mut().reject_mux_ids.push(1);
    let c = accept(&mut s);
    let l = link_of(&lookup_at(&mut s, c, 1, 1, sos("sos")));
    assert_eq!(l, 0);
    lookup_at(&mut s, c, 2, 1 + unused(), apn(1));
    pump(&mut s, 1 + unused());
    assert_eq!(s.reclaimed_links(), 1);
}

/// A link whose follower is closed is asked about too. The modem has the module's call on it.
#[test]
fn a_closed_follower_is_asked_about_while_the_modem_has_the_call() {
    let mut s = server();
    modem_up(&mut s);
    s.engine().qmi_mut().reject_mux_ids.push(1);
    let c = accept(&mut s);
    let l = link_of(&lookup_at(&mut s, c, 1, 1, apn(1)));
    assert_eq!(l, 0);
    s.engine()
        .qmi_mut()
        .route_answers
        .insert(4, vec![(0x10, vec![l])]);
    lookup_at(&mut s, c, 2, 1 + unused(), apn(2));
    pump(&mut s, 1 + unused());
    assert!(!s.engine().qmi_mut().route_frames.is_empty(), "asked");
    assert_eq!(s.reclaimed_links(), 0);
    assert_eq!(s.links_held(c), 2);
}

/// Only a well-formed answer that names no call frees a link.
#[test]
fn an_answer_that_says_nothing_keeps_the_link() {
    for how in 0..3 {
        let mut s = server();
        modem_up(&mut s);
        let c = accept(&mut s);
        lookup_at(&mut s, c, 1, 1, apn(1));
        match how {
            // no answer at all
            0 => s.engine().qmi_mut().mute.push(wds::id::ROUTE_LOOKUP),
            // the modem refuses the question
            1 => s
                .engine()
                .qmi_mut()
                .reject
                .push((wds::SERVICE, wds::id::ROUTE_LOOKUP)),
            // the answer lacks the block of TLV 1
            _ => s.engine().qmi_mut().route_no_block = true,
        }
        lookup_at(&mut s, c, 2, 1 + unused(), apn(2));
        pump(&mut s, 1 + unused());
        s.tick(1 + unused() + 2_000);
        pump(&mut s, 1 + unused() + 2_000);
        assert_eq!(s.reclaimed_links(), 0, "case {how}");
        assert_eq!(s.links_held(c), 2, "case {how}");
        assert_eq!(s.open_questions(), 0);
    }
    // and the same question with a well-formed answer that names nothing frees it
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    lookup_at(&mut s, c, 1, 1, apn(1));
    lookup_at(&mut s, c, 2, 1 + unused(), apn(2));
    pump(&mut s, 1 + unused());
    assert_eq!(s.reclaimed_links(), 1);
}

/// A link whose follower saw the modem say the call is connected is never asked about, as in nicmd
/// (the flag at +0x28 of the data call), although the follower has not finished with it.
#[test]
fn a_link_whose_follower_saw_the_connected_status_is_never_taken_back() {
    let mut s = server_with(Config {
        qmi_timeout_ms: 1_000_000,
        ..Config::default()
    });
    modem_up(&mut s);
    let c = accept(&mut s);
    let l = link_of(&lookup_at(&mut s, c, 1, 1, apn(1)));
    // the settings of the call never arrive, so the follower stays at the step after "connected"
    s.engine()
        .qmi_mut()
        .mute
        .push(wds::id::GET_RUNTIME_SETTINGS);
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 2);
    assert!(events(&mut s, c).is_empty());
    lookup_at(&mut s, c, 2, 1 + 10 * unused(), apn(2));
    pump(&mut s, 1 + 10 * unused());
    assert_eq!(s.engine().qmi_mut().route_frames.len(), 0);
    assert_eq!(s.reclaimed_links(), 0);
    assert_eq!(s.links_held(c), 2);
}

/// A question is not asked again while it is open.
#[test]
fn a_question_that_is_open_is_not_repeated() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    lookup_at(&mut s, c, 1, 1, apn(1));
    s.engine().qmi_mut().mute.push(wds::id::ROUTE_LOOKUP);
    let questions = |s: &mut S| {
        s.engine()
            .qmi_mut()
            .requests
            .iter()
            .filter(|(_, id)| *id == wds::id::ROUTE_LOOKUP)
            .count()
    };
    lookup_at(&mut s, c, 2, 1 + unused(), apn(2));
    assert_eq!(questions(&mut s), 1);
    lookup_at(&mut s, c, 3, 2 + unused(), apn(3));
    assert_eq!(questions(&mut s), 1, "the first is still open");
    // it ends at its deadline, unanswered, and the link is kept
    s.tick(1 + unused() + 2_000);
    pump(&mut s, 1 + unused() + 2_000);
    assert_eq!(s.reclaimed_links(), 0);
}

/// A zero-length datagram on the client of a question does not end it.
#[test]
fn a_zero_length_datagram_on_the_question_client_does_not_take_the_link_back() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    let l = link_of(&lookup_at(&mut s, c, 1, 1, apn(1)));
    s.engine()
        .qmi_mut()
        .route_answers
        .insert(4, vec![(0x10, vec![l])]);
    s.request(
        1 + unused(),
        c,
        Request::RouteLookup {
            txn: 2,
            req: apn(2),
        },
    );
    let lookup_client = *s
        .engine()
        .qmi_mut()
        .client_ids(wds::SERVICE)
        .last()
        .unwrap();
    // the resume notice arrives before the answers
    s.on_qmi(1 + unused(), lookup_client, &[]);
    pump(&mut s, 1 + unused());
    assert_eq!(s.reclaimed_links(), 0, "the modem names the link");
}

/// A call that goes down while its connection is closed is told to the module that comes back,
/// and its number waits until then.
#[test]
fn a_down_while_disconnected_is_told_and_the_number_waits_for_the_process() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept_as(&mut s, MODULE);
    let l = link_of(&lookup_at(&mut s, c, 1, 1, apn(1)));
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 2);
    assert!(events(&mut s, c).contains(&(l, IfaceEvent::Up)));
    s.close(3, c);
    s.engine().qmi_mut().external_disconnect(l + 1, 2, 2);
    pump(&mut s, 4);
    // another process gets another number
    let other = accept(&mut s);
    let l2 = link_of(&lookup_at(&mut s, other, 2, 5, apn(2)));
    assert_ne!(l2, l, "the number waits for the process that held it");
    // the process is back and hears that the call went down
    let back = reconnect_as(&mut s, MODULE, 6);
    let got = events(&mut s, back);
    assert!(
        matches!(got.as_slice(), [(n, IfaceEvent::Down(_))] if *n == l),
        "{got:?}"
    );
    // and then the number can be used again
    let l3 = link_of(&lookup_at(&mut s, other, 3, 6, apn(3)));
    assert_eq!(l3, l);
}

/// Nobody comes back: the number is free when the grace is over.
#[test]
fn a_number_kept_for_a_process_that_never_comes_back_is_free_after_the_grace() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept_as(&mut s, MODULE);
    let l = link_of(&lookup_at(&mut s, c, 1, 1, apn(1)));
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 2);
    s.close(3, c);
    s.engine().qmi_mut().external_disconnect(l + 1, 2, 2);
    pump(&mut s, 4);
    assert_eq!(s.next_deadline(), Some(3 + grace()));
    s.tick(3 + grace() - 1);
    let other = accept(&mut s);
    let held: Vec<u8> = (0..15u32)
        .map(|n| {
            link_of(&lookup_at(
                &mut s,
                other,
                100 + n,
                3 + grace() - 1,
                apn(100 + n),
            ))
        })
        .take(6)
        .collect();
    assert!(!held.contains(&l));
    s.tick(3 + grace());
    assert_eq!(s.next_deadline(), None);
    // another process than the one that held it hears nothing of it
    let stranger = accept(&mut s);
    assert!(events(&mut s, stranger).is_empty());
}

/// A module that takes its links over is told where its calls stand.
#[test]
fn a_module_that_comes_back_is_told_the_state_of_its_calls() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept_as(&mut s, MODULE);
    let l = link_of(&lookup_at(&mut s, c, 1, 1, internet(Family::V4)));
    lookup_at(&mut s, c, 2, 1, internet(Family::V6));
    s.engine()
        .qmi_mut()
        .external_connect_family(l + 1, wds::IpFamily::V4);
    s.engine()
        .qmi_mut()
        .external_connect_family(l + 1, wds::IpFamily::V6);
    pump(&mut s, 2);
    let first = events(&mut s, c);
    assert_eq!(first.first(), Some(&(l, IfaceEvent::Up)));
    // an event in flight when the module's connection was closed is lost with it
    s.close(3, c);
    let c2 = reconnect_as(&mut s, MODULE, 3);
    let told = events(&mut s, c2);
    assert_eq!(told.first(), Some(&(l, IfaceEvent::Up)));
    let kinds: Vec<&IfaceEvent> = told.iter().map(|(_, e)| e).collect();
    assert_eq!(
        kinds
            .iter()
            .filter(|e| matches!(
                e,
                IfaceEvent::NewAddr {
                    family: Family::V4,
                    ..
                }
            ))
            .count(),
        1
    );
    assert_eq!(
        kinds
            .iter()
            .filter(|e| matches!(
                e,
                IfaceEvent::NewAddr {
                    family: Family::V6,
                    ..
                }
            ))
            .count(),
        1
    );
    assert!(kinds.iter().any(|e| matches!(
        e,
        IfaceEvent::MtuUpdate {
            family: Family::V4,
            mtu: 1400
        }
    )));
    assert!(kinds.iter().any(|e| matches!(
        e,
        IfaceEvent::MtuUpdate {
            family: Family::V6,
            mtu: 1380
        }
    )));
    // a link that has not come up is told nothing
    let c3 = accept(&mut s);
    lookup_at(&mut s, c3, 9, 4, apn(9));
    s.close(5, c3);
    let c4 = accept_as(&mut s, 77);
    assert!(events(&mut s, c4).is_empty());
}

/// The library reconnects before the old connection is seen to close. The links move then.
#[test]
fn links_that_move_to_a_connection_that_is_open_already_are_told_too() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept_as(&mut s, MODULE);
    let l = link_of(&lookup_at(&mut s, c, 1, 1, internet(Family::V4)));
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 2);
    events(&mut s, c);
    let c2 = accept_as(&mut s, MODULE);
    assert!(
        events(&mut s, c2).is_empty(),
        "it does not hold the link yet"
    );
    s.close(3, c);
    let told = events(&mut s, c2);
    assert_eq!(told.first(), Some(&(l, IfaceEvent::Up)));
    assert!(told
        .iter()
        .any(|(_, e)| matches!(e, IfaceEvent::NewAddr { .. })));
}

/// Low: the reserve is counted over links not on hold.
#[test]
fn low_a_number_on_hold_is_no_part_of_the_reserve() {
    let mut s = server_with(Config {
        link_count: 3,
        reserve_links: 1,
        ..Config::default()
    });
    modem_up(&mut s);
    let c = accept(&mut s);
    s.engine().hold_link(2, 1_000_000);
    s.engine().hold_link(1, 1_000_000);
    // one link is free and not on hold: that one is the reserve
    assert_eq!(s.engine().free_usable_links(), 1);
    assert_eq!(
        code_of(&lookup_at(&mut s, c, 1, 1, apn(1))),
        ResultCode::NoLink
    );
}

/// Low: the questions about links that have not come up leave places for the questions of matching
/// calls, which a thread of the module waits for.
#[test]
fn low_questions_about_links_leave_places_for_matching_calls() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    for n in 0..6 {
        lookup_at(&mut s, c, n, 1, apn(n));
    }
    s.engine().qmi_mut().mute.push(wds::id::ROUTE_LOOKUP);
    lookup_at(&mut s, c, 10, 1 + unused(), apn(10));
    let asked = s
        .engine()
        .qmi_mut()
        .requests
        .iter()
        .filter(|(_, id)| *id == wds::id::ROUTE_LOOKUP)
        .count();
    assert_eq!(
        asked, 4,
        "at most four questions about links are open, of six that are due"
    );
    // a matching call still gets a place: it waits for its answer, and is not refused at once
    s.drain(c);
    s.request(
        2 + unused(),
        c,
        Request::MatchingCall {
            txn: 20,
            req: internet(Family::V4),
            hint: MatchHint::default(),
        },
    );
    assert_eq!(s.open_questions(), 1);
    assert!(s.drain(c).is_empty());
}

/// Low: the pause of the library between two tries to connect is 30 s at most (`state.rs`), and the
/// links of a closed connection are kept clearly longer, or a daemon that was away for a while
/// would find the calls of its modules gone as they came back.
#[test]
fn low_the_grace_is_clearly_longer_than_the_longest_pause_of_the_library() {
    assert_eq!(ServerConfig::default().orphan_grace_ms, 90_000);
    assert!(grace() >= 3 * 30_000);
}

/// Deliver what the modem queued, except what is for this client, which is kept back.
fn pump_except(s: &mut S, now: u64, held: u32) -> Vec<(u32, Vec<u8>)> {
    let mut kept = Vec::new();
    while let Some((c, b)) = s.engine().qmi_mut().inbox.pop_front() {
        if c == held {
            kept.push((c, b));
        } else {
            s.on_qmi(now, c, &b);
        }
    }
    kept
}

/// The question about a link is open, the call comes up on it meanwhile, and then the modem answers
/// that it has no call (the answer was for a moment before). The follower knows more.
#[test]
fn a_call_that_came_up_while_the_question_was_open_keeps_the_link() {
    for settings_arrive in [true, false] {
        let mut s = server_with(Config {
            qmi_timeout_ms: 1_000_000,
            ..Config::default()
        });
        modem_up(&mut s);
        let c = accept(&mut s);
        let l = link_of(&lookup_at(&mut s, c, 1, 1, apn(1)));
        let before = s.engine().qmi_mut().client_ids(wds::SERVICE);
        s.request(
            1 + unused(),
            c,
            Request::RouteLookup {
                txn: 2,
                req: apn(2),
            },
        );
        let asking = *s
            .engine()
            .qmi_mut()
            .client_ids(wds::SERVICE)
            .iter()
            .find(|id| !before.contains(id))
            .unwrap();
        // its binding of the subscription is answered, the question goes out, its answer is kept back
        let kept = pump_except(&mut s, 1 + unused(), asking);
        let mut answers = kept;
        // the call comes up on the link of the first lookup
        if !settings_arrive {
            s.engine()
                .qmi_mut()
                .mute
                .push(wds::id::GET_RUNTIME_SETTINGS);
        }
        s.engine().qmi_mut().external_connect(l + 1);
        answers.extend(pump_except(&mut s, 2 + unused(), asking));
        assert_eq!(
            events(&mut s, c).iter().any(|(_, e)| *e == IfaceEvent::Up),
            settings_arrive
        );
        // now the answer of before: no call
        for (client, bytes) in answers {
            s.on_qmi(3 + unused(), client, &bytes);
        }
        pump(&mut s, 3 + unused());
        assert_eq!(s.reclaimed_links(), 0, "settings arrive: {settings_arrive}");
        assert_eq!(s.links_held(c), 2);
    }
}

// ---- what the log gets ------------------------------------------------------------------------------------------

#[test]
fn the_readiness_question_is_traced_for_the_first_eight_answers_and_then_for_each_power_of_two() {
    use dataos_datacore::Trace;
    let mut s = server();
    // the library says Hello at once (that is the first answer), and then the data module asks every
    // hundred milliseconds while the daemon is not ready (a day has 864000)
    let c = accept(&mut s);
    for _ in 1..1100 {
        s.request(1, c, Request::Hello);
    }
    let counts: Vec<u32> = s
        .engine()
        .take_trace()
        .into_iter()
        .filter_map(|t| match t {
            Trace::HelloAnswered {
                ready: false,
                count,
            } => Some(count),
            _ => None,
        })
        .collect();
    assert_eq!(
        counts,
        vec![1, 2, 3, 4, 5, 6, 7, 8, 16, 32, 64, 128, 256, 512, 1024]
    );
    // the first answer of the other kind is traced at once
    modem_up(&mut s);
    s.engine().take_trace();
    s.request(2, c, Request::Hello);
    assert!(s.engine().take_trace().contains(&Trace::HelloAnswered {
        ready: true,
        count: 1
    }));
}

#[test]
fn a_refused_request_is_traced_with_its_name_and_code() {
    use dataos_datacore::Trace;
    let mut s = server();
    let c = accept(&mut s);
    s.engine().take_trace();
    // not ready: the route lookup is refused
    let r = lookup(&mut s, c, 7, internet(Family::V4));
    assert_eq!(code_of(&r), ResultCode::NotReady);
    assert!(s.engine().take_trace().contains(&Trace::Refused {
        request: "route lookup",
        code: "NotReady",
        count: 1
    }));
    // an answer that is no refusal leaves no trace of one
    modem_up(&mut s);
    s.engine().take_trace();
    let r = lookup(&mut s, c, 8, internet(Family::V4));
    assert_eq!(code_of(&r), ResultCode::Ok);
    assert!(!s
        .engine()
        .take_trace()
        .iter()
        .any(|t| matches!(t, Trace::Refused { .. })));
}

#[test]
fn the_daemon_becoming_ready_is_traced() {
    use dataos_datacore::Trace;
    let mut s = server();
    s.engine().take_trace();
    modem_up(&mut s);
    assert!(s.engine().take_trace().contains(&Trace::ReadyChanged(true)));
}

// ---- the route lookup with a technology preference --------------------------------------------

/// The modem answers a route lookup for IPv4 with this technology in its block.
fn modem_technology(s: &mut S, tech: u16) {
    let mut block = vec![0u8; 8];
    block.extend(tech.to_le_bytes());
    let q = s.engine().qmi_mut();
    q.route_no_block = true;
    q.route_answers.insert(4, vec![(0x01, block)]);
}

fn lookup_pref(s: &mut S, c: u32, txn: u32, req: RouteRequest, xt_pref: u16) {
    s.request(1, c, Request::RouteLookupPref { txn, req, xt_pref });
}

fn tech_of(n: &Notify) -> u16 {
    match n {
        Notify::RouteReply { tech, .. } => *tech,
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_preference_goes_to_the_modem_and_a_wifi_technology_comes_back_with_the_link() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    modem_technology(&mut s, 0x8021);
    lookup_pref(&mut s, c, 5, route(0, Family::V4, "ims.example", 0), 0x8021);
    // nothing until the modem answered
    assert!(s
        .drain(c)
        .iter()
        .all(|n| !matches!(n, Notify::RouteReply { .. })));
    pump(&mut s, 1);
    let reply = take_reply(&mut s, c, 5);
    assert_eq!(link_of(&reply), 0);
    assert_eq!(tech_of(&reply), 0x8021);
    let frame = s.engine().qmi_mut().route_frames[0].1.clone();
    let f = dataos_qmi::Frame::parse(&frame).unwrap();
    assert_eq!(f.tlv(0x34), Some(&[0x21, 0x80][..]));
}

#[test]
fn a_cellular_technology_is_not_passed_on() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    modem_technology(&mut s, 0x8880);
    lookup_pref(&mut s, c, 5, route(0, Family::V4, "a.example", 0), 1);
    pump(&mut s, 1);
    let reply = take_reply(&mut s, c, 5);
    assert_eq!(code_of(&reply), ResultCode::Ok);
    assert_eq!(tech_of(&reply), 0);
}

#[test]
fn a_lookup_without_a_preference_does_not_ask_the_modem() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    let reply = lookup(&mut s, c, 5, route(0, Family::V4, "a.example", 0));
    assert_eq!(tech_of(&reply), 0);
    assert_eq!(lookups_asked(&mut s), 0);
}

#[test]
fn an_emergency_lookup_with_a_preference_is_answered_at_once_and_asks_nothing() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    // nothing of the modem is run between the request and the answer
    modem_technology(&mut s, 0x8021);
    let emergency = route_typed(Family::V4, "sos", 512, 0);
    lookup_pref(&mut s, c, 5, emergency, 0x8021);
    let reply = take_reply(&mut s, c, 5);
    assert_eq!(code_of(&reply), ResultCode::Ok);
    assert_eq!(tech_of(&reply), 0);
    assert_eq!(lookups_asked(&mut s), 0);
    let q = s.engine().qmi_mut();
    assert!(q.route_frames.is_empty());
}

#[test]
fn a_refused_lookup_with_a_preference_asks_nothing() {
    let mut s = server();
    let c = accept(&mut s);
    lookup_pref(&mut s, c, 5, route(0, Family::V4, "a.example", 0), 1);
    let reply = take_reply(&mut s, c, 5);
    assert_eq!(code_of(&reply), ResultCode::NotReady);
    assert_eq!(lookups_asked(&mut s), 0);
}

#[test]
fn a_modem_that_does_not_answer_costs_the_deadline_and_the_link_is_still_given() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    lookup_pref(&mut s, c, 5, route(0, Family::V4, "a.example", 0), 1);
    // the modem's answers wait in its queue past the deadline
    assert!(s
        .drain(c)
        .iter()
        .all(|n| !matches!(n, Notify::RouteReply { .. })));
    s.tick(1 + 2_000);
    let reply = take_reply(&mut s, c, 5);
    assert_eq!(link_of(&reply), 0);
    assert_eq!(tech_of(&reply), 0);
}

#[test]
fn a_connection_that_closes_ends_the_question_of_its_route_lookup() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    lookup_pref(&mut s, c, 5, route(0, Family::V4, "a.example", 0), 1);
    s.close(1, c);
    pump(&mut s, 1);
    assert!(s.engine().take_events().is_empty());
}

#[test]
fn the_questions_of_preferences_leave_room_in_the_lookup_table() {
    let mut s = server();
    modem_up(&mut s);
    let c = accept(&mut s);
    modem_technology(&mut s, 0x8021);
    for txn in 0..4 {
        lookup_pref(&mut s, c, txn, route(0, Family::V4, "a.example", 0), 0x8021);
    }
    let room = s.engine().lookup_room();
    assert_eq!(room, dataos_datacore::engine::MAX_LOOKUPS - 4);
    lookup_pref(&mut s, c, 4, route(0, Family::V4, "a.example", 0), 0x8021);
    // answered at once, with no question
    assert_eq!(code_of(&take_reply(&mut s, c, 4)), ResultCode::Ok);
    assert_eq!(s.engine().lookup_room(), room);
}
