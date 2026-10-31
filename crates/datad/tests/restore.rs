// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! What a module hears and keeps when the daemon restarts or its connection goes.
use dataos_datacore::engine::{Config, Engine, ServiceEvent};
use dataos_datacore::sim::SimModem;
use dataos_datad::server::{Server, ServerConfig};
use dataos_datad::table::{self, Proc};
use dataos_netcfg::{NetOps, SharedNet};
use dataos_wire::*;

type S = Server<SimModem, SharedNet>;
const LABEL: &str = "u:r:rild:s0";
const MODULE: u32 = 4242;

fn daemon_with(net: &SharedNet, cfg: Config) -> S {
    let mut s = Server::new(
        ServerConfig::default(),
        Engine::new(cfg, SimModem::new(), net.clone()),
    );
    s.engine().qmi_mut().require_call = true;
    s
}

fn daemon(net: &SharedNet) -> S {
    daemon_with(net, Config::default())
}

/// A connection of this process, as the library makes it: it says Hello at once. The answer is taken out of
/// the queue, what the module is told after it stays.
fn connect(s: &mut S, pid: u32) -> u32 {
    let c = s.accept(pid, 1001, LABEL).unwrap();
    s.request(s.last_now(), c, Request::Hello);
    let rest: Vec<Notify> = s
        .drain(c)
        .into_iter()
        .filter(|n| !matches!(n, Notify::HelloAck { .. }))
        .collect();
    s.conns_requeue(c, rest);
    c
}

fn pump(s: &mut S, now: u64) {
    while let Some((c, b)) = s.engine().qmi_mut().inbox.pop_front() {
        s.on_qmi(now, c, &b);
    }
}

fn modem_up(s: &mut S, now: u64) {
    s.on_service_event(now, ServiceEvent::ModemUp);
    pump(s, now);
}

fn req(apn: &str) -> RouteRequest {
    RouteRequest {
        slot: 0,
        family: Family::V4,
        apn: Some(apn.into()),
        apn_type: 1,
        apn_type_mask: 1,
    }
}

fn sos(apn: &str) -> RouteRequest {
    RouteRequest {
        slot: 0,
        family: Family::V4,
        apn: Some(apn.into()),
        apn_type: 512,
        apn_type_mask: 0x200,
    }
}

fn lookup_reply(s: &mut S, conn: u32, txn: u32, now: u64, r: RouteRequest) -> Notify {
    s.request(now, conn, Request::RouteLookup { txn, req: r });
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

fn lookup(s: &mut S, conn: u32, txn: u32, now: u64, r: RouteRequest) -> u8 {
    match lookup_reply(s, conn, txn, now, r) {
        Notify::RouteReply {
            code: ResultCode::Ok,
            link,
            ..
        } => link,
        other => panic!("no link: {other:?}"),
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

fn is_down(e: &IfaceEvent) -> bool {
    matches!(e, IfaceEvent::Down(_))
}

fn first_daemon(net: &SharedNet) -> (S, u8) {
    let mut a = daemon(net);
    modem_up(&mut a, 0);
    let c = connect(&mut a, MODULE);
    let l = lookup(&mut a, c, 1, 1, req("internet.example"));
    a.engine().qmi_mut().external_connect(l + 1);
    pump(&mut a, 2);
    assert!(events(&mut a, c).contains(&(l, IfaceEvent::Up)));
    (a, l)
}

fn grace() -> u64 {
    ServerConfig::default().orphan_grace_ms
}

fn names_the_call(b: &mut S, l: u8) {
    b.engine()
        .qmi_mut()
        .route_answers
        .insert(4, vec![(0x10, vec![l])]);
}

fn boot(net: &SharedNet) -> String {
    net.0.borrow_mut().boot_id().unwrap()
}

fn saved(net: &SharedNet) -> table::Table {
    let file = net.0.borrow().links_file.clone().unwrap();
    table::decode(&file, &boot(net)).unwrap()
}

/// The module reconnects to the restarted daemon before its engine is ready. The restored link
/// is the open connection's, the call stays whole and its number is not reused after the grace.
#[test]
fn a_module_that_reconnects_before_the_restore_gets_its_link() {
    let net = SharedNet::new();
    let (a, l) = first_daemon(&net);
    drop(a);
    let mut b = daemon(&net);
    let back = b.accept(MODULE, 1001, LABEL).unwrap();
    b.request(1, back, Request::Hello);
    b.drain(back);
    names_the_call(&mut b, l);
    modem_up(&mut b, 10_000);
    assert_eq!(b.restored_links(), 1);
    assert_eq!(b.links_held(back), 1, "the open connection gets its link");
    b.engine().qmi_mut().external_connect(l + 1);
    pump(&mut b, 10_001);
    // the module asks for the other family of its call and gets the same link
    let mut v6 = req("internet.example");
    v6.family = Family::V6;
    assert_eq!(lookup(&mut b, back, 2, 10_002, v6), l);
    // the grace ends while the call runs and the connection is open
    b.tick(10_000 + grace());
    assert_eq!(b.links_held(back), 1, "the live call keeps its link");
    let other = connect(&mut b, 20);
    let l2 = lookup(&mut b, other, 3, 10_001 + grace(), req("other.example"));
    assert_ne!(l2, l, "the live call's number went to another call");
}

/// The modem has the module's call but does not name it on this link (a numbering that is
/// not datad's). The follower found the call, so it is kept.
#[test]
fn a_restored_live_call_the_follower_found_is_kept_when_the_modem_does_not_name_it() {
    let net = SharedNet::new();
    let (a, l) = first_daemon(&net);
    drop(a);
    let mut b = daemon(&net);
    b.engine().qmi_mut().external_connect(l + 1);
    modem_up(&mut b, 10_000);
    pump(&mut b, 10_001);
    let back = b.accept(MODULE, 1001, LABEL).unwrap();
    b.request(10_002, back, Request::Hello);
    let told = events(&mut b, back);
    assert!(!told.iter().any(|(_, e)| is_down(e)), "{told:?}");
    assert_eq!(b.links_held(back), 1);
    let other = connect(&mut b, 20);
    assert_ne!(lookup(&mut b, other, 2, 10_003, req("other.example")), l);
    assert_eq!(b.verifying(), 0, "nothing is left to confirm");
    assert_eq!(route_lookups(&mut b), 0, "and the modem was not asked");
}

/// The module reconnects while the question about its restored call is open and the call is
/// gone: it is told, after its Hello, and the number is free after that.
#[test]
fn a_restored_call_lost_after_the_module_reconnected_is_told() {
    let net = SharedNet::new();
    let (a, l) = first_daemon(&net);
    drop(a);
    let mut b = daemon(&net);
    b.on_service_event(10_000, ServiceEvent::ModemUp);
    while b.restored_links() == 0 {
        let (c, m) = b.engine().qmi_mut().inbox.pop_front().unwrap();
        b.on_qmi(10_000, c, &m);
    }
    let back = connect(&mut b, MODULE);
    assert_eq!(b.links_held(back), 1);
    pump(&mut b, 10_001);
    assert_eq!(b.links_held(back), 0, "the link went");
    b.request(10_002, back, Request::Hello);
    let told = events(&mut b, back);
    assert!(
        matches!(told.as_slice(), [(n, IfaceEvent::Down(_))] if *n == l),
        "{told:?}"
    );
    let other = connect(&mut b, 20);
    assert_eq!(lookup(&mut b, other, 2, 10_003, req("other.example")), l);
}

/// What the module missed comes after the answer to its Hello, because the library says INIT_DONE
/// at that answer and DSI drops events while it is not inited. The number is held until the Down is queued.
#[test]
fn the_down_of_a_tombstone_comes_after_the_hello_ack() {
    let net = SharedNet::new();
    let mut s = daemon(&net);
    modem_up(&mut s, 0);
    let c = connect(&mut s, MODULE);
    let l = lookup(&mut s, c, 1, 1, req("internet.example"));
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 2);
    s.drain(c);
    s.close(3, c);
    s.engine().qmi_mut().external_disconnect(l + 1, 3, 26);
    pump(&mut s, 4);
    let back = s.accept(MODULE, 1001, LABEL).unwrap();
    assert!(s.drain(back).is_empty(), "nothing before the Hello");
    // the number waits for the Down
    let other = connect(&mut s, 20);
    assert_ne!(lookup(&mut s, other, 2, 5, req("other.example")), l);
    s.request(6, back, Request::Hello);
    let got = s.drain(back);
    let down = got
        .iter()
        .position(|n| {
            matches!(
                n,
                Notify::Event {
                    event: IfaceEvent::Down(_),
                    ..
                }
            )
        })
        .unwrap();
    let ack = got
        .iter()
        .position(|n| matches!(n, Notify::HelloAck { ready: true }))
        .unwrap();
    assert!(ack < down, "{got:?}");
    assert_eq!(lookup(&mut s, other, 3, 7, req("third.example")), l);
}

/// The replay. A module whose daemon was not ready at its Hello hears the replay after the
/// readiness message, and no event of its links before it.
#[test]
fn the_replay_comes_after_the_ready_message() {
    let net = SharedNet::new();
    let (a, l) = first_daemon(&net);
    drop(a);
    let mut b = daemon(&net);
    names_the_call(&mut b, l);
    let back = b.accept(MODULE, 1001, LABEL).unwrap();
    b.request(1, back, Request::Hello);
    let got = b.drain(back);
    assert!(matches!(
        got.as_slice(),
        [Notify::HelloAck { ready: false }]
    ));
    modem_up(&mut b, 10_000);
    b.engine().qmi_mut().external_connect(l + 1);
    pump(&mut b, 10_001);
    let got = b.drain(back);
    let ready = got
        .iter()
        .position(|n| matches!(n, Notify::Ready { ready: true }))
        .unwrap();
    let up = got
        .iter()
        .position(|n| {
            matches!(
                n,
                Notify::Event {
                    event: IfaceEvent::Up,
                    ..
                }
            )
        })
        .unwrap();
    assert!(ready < up, "{got:?}");
}

/// The late release of the old call, which the mark exists for, is not the module giving up the
/// emergency start on that number. A slow start keeps its link.
#[test]
fn the_late_release_of_the_old_call_does_not_make_a_slow_emergency_start_reclaimable() {
    let net = SharedNet::new();
    let mut s = daemon_with(
        &net,
        Config {
            link_count: 2,
            reserve_links: 1,
            ..Config::default()
        },
    );
    modem_up(&mut s, 0);
    let c = connect(&mut s, MODULE);
    assert_eq!(lookup(&mut s, c, 1, 1, req("internet.example")), 0);
    s.engine().qmi_mut().external_connect(1);
    pump(&mut s, 2);
    s.on_service_event(5, ServiceEvent::ModemDown);
    s.on_service_event(6, ServiceEvent::ModemUp);
    pump(&mut s, 6);
    s.drain(c);
    s.engine().qmi_mut().external_disconnect(1, 3, 26);
    assert_eq!(lookup(&mut s, c, 2, 7, sos("sos1.example")), 1);
    let held = lookup(&mut s, c, 3, 7, sos("sos2.example"));
    assert_eq!(held, 0);
    s.request(8, c, Request::LinkRelease { txn: 4, link: held });
    s.drain(c);
    assert_eq!(s.swallowed_releases(), 1);
    let unused = ServerConfig::default().unused_release_ms;
    let other = connect(&mut s, 20);
    lookup_reply(&mut s, other, 5, 7 + unused, req("apn1.example"));
    pump(&mut s, 7 + unused);
    assert_eq!(
        s.reclaimed_links(),
        0,
        "the pending emergency start keeps its link"
    );
    assert_eq!(s.links_held(c), 2);
    s.engine().qmi_mut().external_connect(1);
    pump(&mut s, 8 + unused);
    assert!(events(&mut s, c).contains(&(0, IfaceEvent::Up)));
}

/// The second release. The module gives the start up and the release is swallowed too: now the
/// link is no start in progress and the reclaim takes it.
#[test]
fn a_second_swallowed_release_is_the_module_giving_the_start_up() {
    let net = SharedNet::new();
    let mut s = daemon_with(
        &net,
        Config {
            link_count: 2,
            reserve_links: 1,
            ..Config::default()
        },
    );
    modem_up(&mut s, 0);
    let c = connect(&mut s, MODULE);
    assert_eq!(lookup(&mut s, c, 1, 1, req("internet.example")), 0);
    s.engine().qmi_mut().external_connect(1);
    pump(&mut s, 2);
    s.on_service_event(5, ServiceEvent::ModemDown);
    s.on_service_event(6, ServiceEvent::ModemUp);
    pump(&mut s, 6);
    s.drain(c);
    s.engine().qmi_mut().external_disconnect(1, 3, 26);
    lookup(&mut s, c, 2, 7, sos("sos1.example"));
    let held = lookup(&mut s, c, 3, 7, sos("sos2.example"));
    s.request(8, c, Request::LinkRelease { txn: 4, link: held });
    s.request(9, c, Request::LinkRelease { txn: 5, link: held });
    s.drain(c);
    assert_eq!(s.swallowed_releases(), 2);
    let unused = ServerConfig::default().unused_release_ms;
    let other = connect(&mut s, 20);
    lookup_reply(&mut s, other, 6, 7 + unused, req("apn1.example"));
    pump(&mut s, 7 + unused);
    assert_eq!(s.reclaimed_links(), 1);
}

/// The hold of a tombstone. A number that is kept for a Down is handed out as a last resort
/// without the mark of a restart hold, because the call that held it is not coming back to release it.
#[test]
fn a_number_kept_for_a_down_is_not_marked_as_a_restart_hold() {
    let net = SharedNet::new();
    let mut s = daemon_with(
        &net,
        Config {
            link_count: 2,
            reserve_links: 1,
            ..Config::default()
        },
    );
    modem_up(&mut s, 0);
    let c = connect(&mut s, MODULE);
    let l = lookup(&mut s, c, 1, 1, req("internet.example"));
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 2);
    s.close(3, c);
    s.engine().qmi_mut().external_disconnect(l + 1, 3, 26);
    pump(&mut s, 4);
    assert_eq!(s.owed_downs(), 1);
    // an emergency lookup takes the last free number, which is kept for the Down
    let other = connect(&mut s, 20);
    assert_eq!(lookup(&mut s, other, 2, 5, sos("sos1.example")), 1);
    let last = lookup(&mut s, other, 3, 5, sos("sos2.example"));
    assert_eq!(last, l);
    // a release of it is a release, not the late one of an old call
    s.request(6, other, Request::LinkRelease { txn: 4, link: last });
    s.drain(other);
    assert_eq!(s.swallowed_releases(), 0);
}

/// A second restart before the module came back: the Down it is owed is in the table, so the
/// module is told after the second one.
#[test]
fn a_tombstone_survives_a_second_restart() {
    let net = SharedNet::new();
    let (a, l) = first_daemon(&net);
    drop(a);
    let mut b = daemon(&net);
    modem_up(&mut b, 10_000);
    pump(&mut b, 10_001);
    assert_eq!(
        b.owed_downs(),
        1,
        "the call is gone, the module is owed a Down"
    );
    assert_eq!(saved(&net).dead.len(), 1);
    drop(b);
    let mut c = daemon(&net);
    modem_up(&mut c, 20_000);
    assert_eq!(c.owed_downs(), 1);
    // the number waits
    let other = connect(&mut c, 20);
    assert_ne!(lookup(&mut c, other, 2, 20_001, req("other.example")), l);
    let back = c.accept(MODULE, 1001, LABEL).unwrap();
    c.request(20_002, back, Request::Hello);
    let told = events(&mut c, back);
    assert!(
        matches!(told.as_slice(), [(n, IfaceEvent::Down(_))] if *n == l),
        "{told:?}"
    );
    assert_eq!(c.owed_downs(), 0);
    assert_eq!(lookup(&mut c, other, 3, 20_003, req("third.example")), l);
}

/// A restored row is written back with the flag that the module was told, so a second restart
/// still asks about the call.
#[test]
fn the_told_flag_is_kept_when_the_table_is_written_after_a_restore() {
    let net = SharedNet::new();
    let (a, l) = first_daemon(&net);
    drop(a);
    let mut b = daemon(&net);
    names_the_call(&mut b, l);
    modem_up(&mut b, 10_000);
    let rows = saved(&net).rows;
    assert_eq!(rows.len(), 1);
    assert!(rows[0].told, "the module was told this call is up");
    // and a second restart, with the modem still having the call, asks about it again
    drop(b);
    let mut c = daemon(&net);
    names_the_call(&mut c, l);
    modem_up(&mut c, 20_000);
    assert_eq!(c.restored_links(), 1);
    assert!(
        c.engine()
            .qmi_mut()
            .requests
            .iter()
            .any(|(_, id)| *id == dataos_qmi::wds::id::ROUTE_LOOKUP),
        "nothing was asked"
    );
}

/// The follower saw the packet status "connected" and could not get the settings: nicmd's flag stays set
/// until the disconnect, so the link is not taken back as unused.
#[test]
fn a_follower_that_saw_connected_and_then_failed_keeps_the_link() {
    let net = SharedNet::new();
    let mut s = daemon(&net);
    modem_up(&mut s, 0);
    s.engine().qmi_mut().reject.push((
        dataos_qmi::wds::SERVICE,
        dataos_qmi::wds::id::GET_RUNTIME_SETTINGS,
    ));
    let c = connect(&mut s, MODULE);
    let l = lookup(&mut s, c, 1, 1, req("internet.example"));
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 2);
    s.drain(c);
    let unused = ServerConfig::default().unused_release_ms;
    let other = connect(&mut s, 20);
    lookup_reply(&mut s, other, 2, 1 + unused, req("apn1.example"));
    pump(&mut s, 1 + unused);
    assert_eq!(s.reclaimed_links(), 0, "the link of a connected call stays");
    assert_eq!(s.links_held(c), 1);
    assert_ne!(lookup(&mut s, other, 3, 2 + unused, req("apn2.example")), l);
}

/// A restored call is not lost for the modem's answer alone. While the follower is still looking
/// the question waits. When its look failed the call is kept and counted, asked about again a bounded number
/// of times, and never lost for that.
#[test]
fn a_restored_call_is_not_lost_before_the_follower_has_looked_for_it() {
    let net = SharedNet::new();
    let (a, l) = first_daemon(&net);
    drop(a);
    let mut b = daemon_with(
        &net,
        Config {
            qmi_timeout_ms: 1_000,
            ..Config::default()
        },
    );
    // the settings request of the follower gets no answer for a while
    b.engine()
        .qmi_mut()
        .mute
        .push(dataos_qmi::wds::id::GET_RUNTIME_SETTINGS);
    modem_up(&mut b, 10_000);
    pump(&mut b, 10_001);
    let back = b.accept(MODULE, 1001, LABEL).unwrap();
    b.request(10_002, back, Request::Hello);
    assert_eq!(b.links_held(back), 1, "the look is under way");
    assert!(events(&mut b, back).is_empty());
    assert_eq!(b.verifying(), 1);
    // the look fails at its deadline: the modem names nothing, and the call is kept all the same
    let retry = ServerConfig::default().verify_retry_ms;
    let mut now = 12_000;
    for round in 1..=3_u32 {
        b.tick(now);
        pump(&mut b, now);
        b.tick(now + 1);
        pump(&mut b, now + 1);
        assert!(events(&mut b, back).is_empty(), "round {round}");
        assert_eq!(b.unlooked_checks(), round);
        assert_eq!(b.links_held(back), 1);
        now += retry + 1;
    }
    // and after the bound it is asked about no more, and still kept
    b.tick(now);
    pump(&mut b, now);
    assert_eq!(b.verifying(), 0);
    assert_eq!(b.unlooked_checks(), 3);
    assert!(events(&mut b, back).is_empty());
    assert_eq!(b.links_held(back), 1);
    assert_eq!(b.owed_downs(), 0);
    let _ = l;
}

/// A restored call has a leg for each family. While one has looked and the other has not, the call has not
/// looked, and the modem is not asked about it. When the second look fails, the call is kept and counted.
#[test]
fn a_restored_call_with_one_leg_still_looking_is_not_asked_about_and_not_lost() {
    let net = SharedNet::new();
    let (a, l) = first_daemon(&net);
    drop(a);
    let mut b = daemon_with(
        &net,
        Config {
            qmi_timeout_ms: 1_000,
            ..Config::default()
        },
    );
    // the second leg gets no answer to its settings request, the first one is answered with no call
    b.engine().qmi_mut().mute_settings_requests.push(1);
    modem_up(&mut b, 10_000);
    pump(&mut b, 10_001);
    assert_eq!(b.look_of(l), Some(dataos_datacore::Look::Pending));
    assert_eq!(route_lookups(&mut b), 0, "the modem is not asked yet");
    assert_eq!(b.verifying(), 1);
    let back = b.accept(MODULE, 1001, LABEL).unwrap();
    b.request(10_002, back, Request::Hello);
    assert!(events(&mut b, back).is_empty());
    // the second look fails at its deadline, the call is kept
    for t in [12_000, 12_001] {
        b.tick(t);
        pump(&mut b, t);
    }
    assert_eq!(b.look_of(l), Some(dataos_datacore::Look::Failed));
    assert_eq!(b.unlooked_checks(), 1);
    assert!(events(&mut b, back).is_empty());
    assert_eq!(b.links_held(back), 1);
}

/// The questions about a restored call that could not look stop after the bound, and the reclaim of unused
/// links must not take over: the module was told the call is up, and only a Down from its follower, or its own
/// release, ends it. A route lookup for a new link a while later does not lose the call.
#[test]
fn a_restored_call_left_unlooked_is_not_lost_to_the_reclaim_of_unused_links() {
    let net = SharedNet::new();
    let (a, l) = first_daemon(&net);
    drop(a);
    let mut b = daemon_with(
        &net,
        Config {
            qmi_timeout_ms: 1_000,
            ..Config::default()
        },
    );
    b.engine()
        .qmi_mut()
        .mute
        .push(dataos_qmi::wds::id::GET_RUNTIME_SETTINGS);
    modem_up(&mut b, 10_000);
    pump(&mut b, 10_001);
    let back = b.accept(MODULE, 1001, LABEL).unwrap();
    b.request(10_002, back, Request::Hello);
    let retry = ServerConfig::default().verify_retry_ms;
    let mut now = 12_000;
    for _ in 1..=3_u32 {
        b.tick(now);
        pump(&mut b, now);
        b.tick(now + 1);
        pump(&mut b, now + 1);
        now += retry + 1;
    }
    b.tick(now);
    pump(&mut b, now);
    assert_eq!(b.verifying(), 0);
    assert_eq!(b.unlooked_checks(), 3);
    assert!(events(&mut b, back).is_empty());
    assert_eq!(b.links_held(back), 1);
    // another call of the module a while later: the route lookup for a new link runs the reclaim
    let later = now + ServerConfig::default().unused_release_ms + 1;
    let other = lookup(&mut b, back, 9, later, req("other.example"));
    assert_ne!(other, l);
    pump(&mut b, later);
    b.tick(later + 1_001);
    pump(&mut b, later + 1_001);
    let got = events(&mut b, back);
    assert!(!got.iter().any(|(_, e)| is_down(e)), "{got:?}");
    assert_eq!(b.links_held(back), 2, "the restored call and the new one");
    assert_eq!(b.owed_downs(), 0);
}

/// The other way round. The follower finds the call after the question was asked and the modem named nothing.
#[test]
fn a_restored_call_the_follower_finds_after_the_question_is_kept() {
    let net = SharedNet::new();
    let (a, l) = first_daemon(&net);
    drop(a);
    let mut b = daemon(&net);
    modem_up(&mut b, 10_000);
    // the question ran at the end of modem_up and was answered with no call, and the link went. Start again with
    // a follower that sees the call from the first look.
    drop(b);
    let net = SharedNet::new();
    let (a, l2) = first_daemon(&net);
    drop(a);
    let mut b = daemon(&net);
    b.engine().qmi_mut().external_connect(l2 + 1);
    modem_up(&mut b, 10_000);
    pump(&mut b, 10_001);
    assert_eq!(b.verifying(), 0);
    assert_eq!(b.owed_downs(), 0);
    let _ = l;
    let back = b.accept(MODULE, 1001, LABEL).unwrap();
    b.request(10_002, back, Request::Hello);
    assert_eq!(b.links_held(back), 1);
}

/// A restored link that ends any other way owes the module a Down too: the grace running out, and
/// a link that cannot be followed again.
#[test]
fn every_end_of_a_link_the_module_was_told_is_up_owes_it_a_down() {
    // the grace runs out
    let net = SharedNet::new();
    let (a, l) = first_daemon(&net);
    drop(a);
    let mut b = daemon(&net);
    names_the_call(&mut b, l);
    modem_up(&mut b, 10_000);
    b.tick(10_000 + grace());
    assert_eq!(b.owed_downs(), 1);
    let back = b.accept(MODULE, 1001, LABEL).unwrap();
    b.request(10_000 + grace() + 1, back, Request::Hello);
    let told = events(&mut b, back);
    assert!(
        matches!(told.as_slice(), [(n, IfaceEvent::Down(_))] if *n == l),
        "{told:?}"
    );
    // a link the engine cannot follow: the table names a link the pool does not have
    let net = SharedNet::new();
    let (a, _) = first_daemon(&net);
    drop(a);
    let t = saved(&net);
    let mut row = t.rows[0].clone();
    row.link = 14;
    let file = table::encode(&boot(&net), &[row], &[]);
    net.0.borrow_mut().links_file = Some(file);
    let mut c = daemon_with(
        &net,
        Config {
            link_count: 4,
            ..Config::default()
        },
    );
    modem_up(&mut c, 10_000);
    assert_eq!(c.restored_links(), 0);
    assert_eq!(c.owed_downs(), 1, "the module was told it is up");
}

/// The links are adopted and the table is gone or unreadable: no number goes to another call for the grace.
#[test]
fn links_adopted_without_a_table_are_held_for_the_grace() {
    let net = SharedNet::new();
    let (a, l) = first_daemon(&net);
    drop(a);
    net.0.borrow_mut().links_file = Some(b"garbage".to_vec());
    let mut b = daemon_with(
        &net,
        Config {
            link_count: 3,
            reserve_links: 0,
            ..Config::default()
        },
    );
    modem_up(&mut b, 10_000);
    assert!(b.engine().links_adopted());
    let other = connect(&mut b, 20);
    // every number is held, and a lookup still gets one as the last resort, but the hold is there
    assert!(b.engine().link_on_hold(usize::from(l)));
    b.tick(10_000 + grace() + 1);
    assert!(!b.engine().link_on_hold(usize::from(l)));
    assert_eq!(
        lookup(&mut b, other, 2, 10_000 + grace() + 2, req("other.example")),
        0
    );
}

/// Processes are told apart by their start time: a radio daemon that comes back with an old PID inherits nothing.
#[test]
fn a_process_with_the_pid_of_an_earlier_one_inherits_nothing() {
    let net = SharedNet::new();
    let mut a = daemon(&net);
    modem_up(&mut a, 0);
    let old = Proc {
        pid: MODULE,
        ino: 100,
    };
    let c = a.accept_proc(old, 1001, LABEL).unwrap();
    let l = lookup(&mut a, c, 1, 1, req("internet.example"));
    a.engine().qmi_mut().external_connect(l + 1);
    pump(&mut a, 2);
    a.drain(c);
    a.close(3, c);
    // the same PID, another start time
    let newer = a
        .accept_proc(
            Proc {
                pid: MODULE,
                ino: 200,
            },
            1001,
            LABEL,
        )
        .unwrap();
    a.request(4, newer, Request::Hello);
    assert_eq!(a.links_held(newer), 0);
    assert!(events(&mut a, newer).is_empty());
    // the process that held it gets it back
    let same = a.accept_proc(old, 1001, LABEL).unwrap();
    assert_eq!(a.links_held(same), 1);
    // the table keeps both numbers
    let rows = saved(&net).rows;
    assert_eq!(rows[0].proc, old);
}

/// Restored calls the module was told are up are asked about no more than MAX_CHECKS at a time, and
/// a released link takes its place in the queue with it.
#[test]
fn the_questions_about_restored_calls_are_bounded() {
    let net = SharedNet::new();
    let mut a = daemon(&net);
    modem_up(&mut a, 0);
    let c = connect(&mut a, MODULE);
    let mut links = Vec::new();
    for n in 0..7u32 {
        let l = lookup(&mut a, c, n + 1, 1, req(&format!("apn{n}.example")));
        a.engine().qmi_mut().external_connect(l + 1);
        links.push(l);
    }
    pump(&mut a, 2);
    assert_eq!(saved(&net).rows.iter().filter(|r| r.told).count(), 7);
    drop(a);
    let mut b = daemon(&net);
    // the follower of each call is muted, so the first look is open when the questions would start
    b.on_service_event(10_000, ServiceEvent::ModemUp);
    let mut most = 0;
    while let Some((cl, m)) = b.engine().qmi_mut().inbox.pop_front() {
        b.on_qmi(10_000, cl, &m);
        most = most.max(b.open_checks());
    }
    assert!(most <= 4, "{most} questions at once");
    assert_eq!(b.restored_links(), 7);
    // none of the calls exists on the modem: all are lost in the end, nothing is left waiting
    for t in 0..10 {
        b.tick(10_001 + t * 1_000);
        while let Some((cl, m)) = b.engine().qmi_mut().inbox.pop_front() {
            b.on_qmi(10_001 + t * 1_000, cl, &m);
            assert!(b.open_checks() <= 4);
        }
        if b.verifying() == 0 {
            break;
        }
    }
    assert_eq!(b.verifying(), 0);
    assert_eq!(b.owed_downs(), 7);
}

/// A released link takes its entry in the list of questions with it.
#[test]
fn a_link_the_module_releases_leaves_no_question_behind() {
    let net = SharedNet::new();
    let (a, l) = first_daemon(&net);
    drop(a);
    let mut b = daemon(&net);
    // keep the first look open so the question has not started
    b.engine()
        .qmi_mut()
        .mute
        .push(dataos_qmi::wds::id::GET_RUNTIME_SETTINGS);
    modem_up(&mut b, 10_000);
    let back = b.accept(MODULE, 1001, LABEL).unwrap();
    b.request(10_001, back, Request::Hello);
    assert_eq!(b.verifying(), 1);
    // the module releases the link: it is gone, and so is its place in the list of questions
    b.request(10_002, back, Request::LinkRelease { txn: 9, link: l });
    b.drain(back);
    assert_eq!(b.links_held(back), 0);
    assert_eq!(b.verifying(), 0);
    assert_eq!(b.open_checks(), 0);
    assert_eq!(
        b.owed_downs(),
        0,
        "the module asked for it, it is not owed a Down"
    );
}

/// Questions the modem does not answer are counted.
#[test]
fn a_modem_that_refuses_the_route_lookup_shows_in_the_count() {
    let net = SharedNet::new();
    let mut s = daemon(&net);
    modem_up(&mut s, 0);
    s.engine()
        .qmi_mut()
        .reject
        .push((dataos_qmi::wds::SERVICE, dataos_qmi::wds::id::ROUTE_LOOKUP));
    let c = connect(&mut s, MODULE);
    lookup(&mut s, c, 1, 1, req("internet.example"));
    let unused = ServerConfig::default().unused_release_ms;
    let other = connect(&mut s, 20);
    lookup_reply(&mut s, other, 2, 1 + unused, req("apn1.example"));
    pump(&mut s, 1 + unused);
    assert!(s.unanswered_checks() >= 1);
    assert_eq!(s.reclaimed_links(), 0);
}

fn route_lookups(s: &mut S) -> usize {
    s.engine()
        .qmi_mut()
        .requests
        .iter()
        .filter(|(_, id)| *id == dataos_qmi::wds::id::ROUTE_LOOKUP)
        .count()
}

/// A restored call that is lost while the module is connected and has been told what it missed: the Down
/// goes to it at once, there is no tombstone.
#[test]
fn a_restored_call_lost_while_the_module_is_connected_is_told_at_once() {
    let net = SharedNet::new();
    let (a, l) = first_daemon(&net);
    drop(a);
    let mut b = daemon(&net);
    let back = b.accept(MODULE, 1001, LABEL).unwrap();
    b.request(1, back, Request::Hello);
    b.drain(back);
    modem_up(&mut b, 10_000);
    pump(&mut b, 10_001);
    let told = events(&mut b, back);
    assert!(
        told.contains(&(
            l,
            IfaceEvent::Down(EndReason::Local(LocalReason::LinkFailed))
        )),
        "{told:?}"
    );
    assert_eq!(b.owed_downs(), 0, "nothing is left owed");
    assert_eq!(b.links_held(back), 0);
}

/// A call that came up while its module was away is told by the replay, and the table says so.
#[test]
fn a_call_that_came_up_while_the_module_was_away_is_told_by_the_replay() {
    let net = SharedNet::new();
    let mut s = daemon(&net);
    modem_up(&mut s, 0);
    let c = connect(&mut s, MODULE);
    let l = lookup(&mut s, c, 1, 1, req("internet.example"));
    s.close(2, c);
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 3);
    assert!(!saved(&net).rows[0].told, "nobody heard the Up");
    let back = s.accept(MODULE, 1001, LABEL).unwrap();
    s.request(4, back, Request::Hello);
    assert_eq!(events(&mut s, back).first(), Some(&(l, IfaceEvent::Up)));
    assert!(saved(&net).rows[0].told, "the replay told it");
}

/// A call that came up and went down while the module was away owes it nothing, it never heard of it.
#[test]
fn a_call_that_came_up_and_went_down_while_the_module_was_away_owes_it_nothing() {
    let net = SharedNet::new();
    let mut s = daemon(&net);
    modem_up(&mut s, 0);
    let c = connect(&mut s, MODULE);
    let l = lookup(&mut s, c, 1, 1, req("internet.example"));
    s.close(2, c);
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 3);
    s.engine().qmi_mut().external_disconnect(l + 1, 3, 26);
    pump(&mut s, 4);
    assert_eq!(s.owed_downs(), 0);
    let back = s.accept(MODULE, 1001, LABEL).unwrap();
    s.request(5, back, Request::Hello);
    assert!(events(&mut s, back).is_empty());
}

/// A modem restart ends the call of a restored link the module was told is up, though no address was
/// seen yet: the module hears the Down, now when it is connected and later when it is not.
#[test]
fn a_modem_restart_tells_the_module_down_for_a_restored_call() {
    // connected
    let net = SharedNet::new();
    let (a, l) = first_daemon(&net);
    drop(a);
    let mut b = daemon(&net);
    names_the_call(&mut b, l);
    let back = b.accept(MODULE, 1001, LABEL).unwrap();
    b.request(1, back, Request::Hello);
    b.drain(back);
    modem_up(&mut b, 10_000);
    b.on_service_event(10_100, ServiceEvent::ModemDown);
    let told = events(&mut b, back);
    assert!(told.iter().any(|(n, e)| *n == l && is_down(e)), "{told:?}");
    // away
    let net = SharedNet::new();
    let (a, l) = first_daemon(&net);
    drop(a);
    let mut b = daemon(&net);
    names_the_call(&mut b, l);
    modem_up(&mut b, 10_000);
    b.on_service_event(10_100, ServiceEvent::ModemDown);
    assert_eq!(b.owed_downs(), 1);
    let back = connect(&mut b, MODULE);
    // the modem is down: the module is told when the daemon is ready again
    b.request(10_200, back, Request::Hello);
    assert!(events(&mut b, back).is_empty());
    modem_up(&mut b, 10_300);
    let told = events(&mut b, back);
    assert!(told.iter().any(|(n, e)| *n == l && is_down(e)), "{told:?}");
}

/// A tombstone whose time ran out while the daemon was away is not taken back.
#[test]
fn an_owed_down_that_expired_before_the_restart_is_not_restored() {
    let net = SharedNet::new();
    let (a, _) = first_daemon(&net);
    drop(a);
    let mut b = daemon(&net);
    modem_up(&mut b, 10_000);
    pump(&mut b, 10_001);
    assert_eq!(b.owed_downs(), 1);
    drop(b);
    let mut c = daemon(&net);
    modem_up(&mut c, 10_000 + grace() + 5);
    assert_eq!(c.owed_downs(), 0);
    // and one that has not is
    drop(c);
    let net2 = SharedNet::new();
    let (a, _) = first_daemon(&net2);
    drop(a);
    let mut b = daemon(&net2);
    modem_up(&mut b, 10_000);
    pump(&mut b, 10_001);
    drop(b);
    let mut c = daemon(&net2);
    modem_up(&mut c, 10_000 + grace() - 5);
    assert_eq!(c.owed_downs(), 1);
}

/// The modem does not answer the question about a restored call: it is asked again later, not at once,
/// and the call is lost only by an answer.
#[test]
fn an_unanswered_question_about_a_restored_call_is_asked_again_after_a_pause() {
    let net = SharedNet::new();
    let (a, l) = first_daemon(&net);
    drop(a);
    let mut b = daemon(&net);
    b.engine()
        .qmi_mut()
        .reject
        .push((dataos_qmi::wds::SERVICE, dataos_qmi::wds::id::ROUTE_LOOKUP));
    modem_up(&mut b, 10_000);
    pump(&mut b, 10_001);
    let first = route_lookups(&mut b);
    assert!(first >= 1, "the question was asked");
    assert_eq!(b.verifying(), 1, "and not answered, the call is kept");
    assert!(b.unanswered_checks() >= 1);
    assert_eq!(b.owed_downs(), 0);
    // not at once
    b.tick(10_002);
    pump(&mut b, 10_002);
    assert_eq!(route_lookups(&mut b), first);
    assert_eq!(
        b.next_deadline(),
        Some(10_000 + ServerConfig::default().verify_retry_ms),
        "the pause is a deadline of the loop"
    );
    // after the pause, once more, and the modem takes it now
    b.engine().qmi_mut().reject.clear();
    let again = 10_000 + ServerConfig::default().verify_retry_ms;
    b.tick(again);
    pump(&mut b, again);
    assert!(route_lookups(&mut b) > first);
    let _ = l;
    assert_eq!(b.verifying(), 0);
    assert_eq!(b.owed_downs(), 1, "now the answer says the call is gone");
}

/// The question about a restored call waits for the follower's first look.
#[test]
fn nothing_is_asked_about_a_restored_call_before_its_follower_has_looked() {
    let net = SharedNet::new();
    let (a, _) = first_daemon(&net);
    drop(a);
    let mut b = daemon_with(
        &net,
        Config {
            qmi_timeout_ms: 1_000,
            ..Config::default()
        },
    );
    b.engine()
        .qmi_mut()
        .mute
        .push(dataos_qmi::wds::id::GET_RUNTIME_SETTINGS);
    modem_up(&mut b, 10_000);
    pump(&mut b, 10_001);
    assert_eq!(route_lookups(&mut b), 0);
    b.tick(12_000);
    pump(&mut b, 12_000);
    assert!(route_lookups(&mut b) >= 1);
}

/// A modem that refuses the question is noted for the log, the first time and then now and then.
#[test]
fn a_refused_question_is_noted_once_in_sixteen() {
    let net = SharedNet::new();
    let mut s = daemon(&net);
    modem_up(&mut s, 0);
    s.engine()
        .qmi_mut()
        .reject
        .push((dataos_qmi::wds::SERVICE, dataos_qmi::wds::id::ROUTE_LOOKUP));
    let c = connect(&mut s, MODULE);
    lookup(&mut s, c, 1, 1, req("internet.example"));
    let unused = ServerConfig::default().unused_release_ms;
    let other = connect(&mut s, 20);
    for n in 0..3u64 {
        let now = 1 + unused * (n + 1);
        lookup_reply(&mut s, other, 10 + n as u32, now, req("apn1.example"));
        pump(&mut s, now);
        s.tick(now);
    }
    let notes = s.engine().take_notes();
    assert_eq!(
        notes,
        vec![dataos_datacore::Note::CheckUnanswered],
        "one note for {} refusals",
        s.unanswered_checks()
    );
}

fn req_slot(apn: &str, slot: u8) -> RouteRequest {
    RouteRequest { slot, ..req(apn) }
}

/// What a restored link keeps of what it was handed out for: its kind, its families and its slot go back
/// to the table, and the Down it is owed names its slot.
#[test]
fn a_restored_link_keeps_its_kind_its_families_and_its_slot() {
    let net = SharedNet::new();
    let mut a = daemon(&net);
    modem_up(&mut a, 0);
    let c = connect(&mut a, MODULE);
    let l = lookup(&mut a, c, 1, 1, sos("sos.example"));
    let k = lookup(&mut a, c, 2, 1, req_slot("slot1.example", 1));
    a.engine().qmi_mut().external_connect(l + 1);
    a.engine().qmi_mut().external_connect(k + 1);
    pump(&mut a, 2);
    drop(a);
    // the calls are still there: the table keeps what the links were handed out for
    let mut b = daemon(&net);
    b.engine().qmi_mut().external_connect(l + 1);
    b.engine().qmi_mut().external_connect(k + 1);
    modem_up(&mut b, 10_000);
    pump(&mut b, 10_001);
    assert_eq!(b.restored_links(), 2);
    let rows = saved(&net).rows;
    let sos_row = rows.iter().find(|r| r.link == l).unwrap();
    assert!(sos_row.emergency, "an emergency start stays one");
    assert_eq!(sos_row.requested, [true, false], "the family it asked for");
    let slot_row = rows.iter().find(|r| r.link == k).unwrap();
    assert_eq!((slot_row.slot, slot_row.emergency), (1, false));
    drop(b);
    // both calls are gone on the modem now, so the module is owed a Down for each, with the slot of the link
    let mut c = daemon(&net);
    modem_up(&mut c, 20_000);
    pump(&mut c, 20_001);
    let back = c.accept(MODULE, 1001, LABEL).unwrap();
    c.request(20_002, back, Request::Hello);
    let got = c.drain(back);
    let slots: Vec<(u8, u8)> = got
        .iter()
        .filter_map(|n| match n {
            Notify::Event {
                link,
                slot,
                event: IfaceEvent::Down(_),
            } => Some((*link, *slot)),
            _ => None,
        })
        .collect();
    assert!(
        slots.contains(&(l, 0)) && slots.contains(&(k, 1)),
        "{slots:?}"
    );
}

/// The replay tells the state in the order the module expects: up, then per family the MTU and the address.
#[test]
fn the_replay_tells_up_then_the_mtu_and_the_address_of_each_family() {
    let net = SharedNet::new();
    let mut s = daemon(&net);
    modem_up(&mut s, 0);
    let c = connect(&mut s, MODULE);
    let l = lookup(&mut s, c, 1, 1, req("internet.example"));
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 2);
    s.drain(c);
    s.close(3, c);
    let back = s.accept(MODULE, 1001, LABEL).unwrap();
    s.request(4, back, Request::Hello);
    let kinds: Vec<&'static str> = events(&mut s, back)
        .iter()
        .map(|(_, e)| match e {
            IfaceEvent::Up => "up",
            IfaceEvent::MtuUpdate { .. } => "mtu",
            IfaceEvent::NewAddr { .. } => "addr",
            _ => "other",
        })
        .collect();
    assert_eq!(kinds, ["up", "mtu", "addr"]);
}

/// A restored link the module was not told is up is not asked about at once: it has the 30 s of any new link.
#[test]
fn a_restored_link_that_was_not_up_is_asked_about_after_the_time_of_a_new_link() {
    let net = SharedNet::new();
    let mut a = daemon(&net);
    modem_up(&mut a, 0);
    let c = connect(&mut a, MODULE);
    lookup(&mut a, c, 1, 1, req("internet.example"));
    drop(a);
    let mut b = daemon(&net);
    modem_up(&mut b, 10_000);
    assert_eq!(b.restored_links(), 1);
    let other = connect(&mut b, 20);
    let unused = ServerConfig::default().unused_release_ms;
    lookup_reply(&mut b, other, 2, 10_001, req("other.example"));
    pump(&mut b, 10_001);
    assert_eq!(route_lookups(&mut b), 0, "not asked at once");
    lookup_reply(&mut b, other, 3, 10_000 + unused, req("third.example"));
    pump(&mut b, 10_000 + unused);
    assert!(route_lookups(&mut b) >= 1, "asked after the time");
}

/// Nothing is queued for a connection that has not been told what it missed, and the state comes once, after its Hello.
#[test]
fn nothing_is_queued_for_a_connection_that_waits_for_its_hello() {
    let net = SharedNet::new();
    let mut s = daemon(&net);
    modem_up(&mut s, 0);
    let c = connect(&mut s, MODULE);
    let l = lookup(&mut s, c, 1, 1, req("internet.example"));
    s.close(2, c);
    let back = s.accept(MODULE, 1001, LABEL).unwrap();
    // the call comes up while the new connection has not said Hello
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 3);
    assert!(s.drain(back).is_empty(), "nothing before the Hello");
    s.request(4, back, Request::Hello);
    let got = events(&mut s, back);
    assert_eq!(
        got.iter().filter(|(_, e)| *e == IfaceEvent::Up).count(),
        1,
        "{got:?}"
    );
    // and then it hears what happens at once
    s.engine().qmi_mut().external_disconnect(l + 1, 3, 26);
    pump(&mut s, 5);
    assert!(events(&mut s, back).iter().any(|(_, e)| is_down(e)));
}

/// A link taken back as unused was never announced up, so the module is not told it is down.
#[test]
fn a_link_taken_back_as_unused_owes_the_module_no_down() {
    let net = SharedNet::new();
    let mut s = daemon(&net);
    modem_up(&mut s, 0);
    let c = connect(&mut s, MODULE);
    lookup(&mut s, c, 1, 1, req("internet.example"));
    s.drain(c);
    let unused = ServerConfig::default().unused_release_ms;
    let other = connect(&mut s, 20);
    lookup_reply(&mut s, other, 2, 1 + unused, req("apn1.example"));
    pump(&mut s, 1 + unused);
    assert_eq!(s.reclaimed_links(), 1);
    assert_eq!(s.links_held(c), 0);
    assert!(
        events(&mut s, c).is_empty(),
        "the module never heard of it up"
    );
    assert_eq!(s.owed_downs(), 0);
}

/// A restored link the module was not told is up stays not told in the table.
#[test]
fn a_restored_link_that_was_not_up_stays_not_told() {
    let net = SharedNet::new();
    let mut a = daemon(&net);
    modem_up(&mut a, 0);
    let c = connect(&mut a, MODULE);
    lookup(&mut a, c, 1, 1, req("internet.example"));
    assert!(!saved(&net).rows[0].told);
    drop(a);
    let mut b = daemon(&net);
    modem_up(&mut b, 10_000);
    assert_eq!(b.restored_links(), 1);
    assert!(!saved(&net).rows[0].told);
    assert_eq!(b.verifying(), 0, "nothing to confirm");
}

/// A link released while its question still waits for a place takes the question with it, also when
/// the places for questions are all taken, so the list is not cleaned at the next turn.
#[test]
fn a_released_link_takes_its_place_in_the_list_of_questions_with_it() {
    let net = SharedNet::new();
    let mut a = daemon(&net);
    modem_up(&mut a, 0);
    let c = connect(&mut a, MODULE);
    let mut links = Vec::new();
    for n in 0..7u32 {
        let l = lookup(&mut a, c, n + 1, 1, req(&format!("apn{n}.example")));
        a.engine().qmi_mut().external_connect(l + 1);
        links.push(l);
    }
    pump(&mut a, 2);
    drop(a);
    let mut b = daemon(&net);
    b.on_service_event(10_000, ServiceEvent::ModemUp);
    // one message at a time, until every place for a question is taken and the answers are still to come
    while b.open_checks() < 4 {
        let (cl, m) = b.engine().qmi_mut().inbox.pop_front().unwrap();
        b.on_qmi(10_000, cl, &m);
    }
    assert_eq!(b.open_checks(), 4);
    assert_eq!(b.verifying(), 7);
    let back = b.accept(MODULE, 1001, LABEL).unwrap();
    b.request(10_001, back, Request::Hello);
    // the highest numbers first: the questions are started in the order of the numbers, so these wait
    for (n, link) in links.iter().rev().enumerate() {
        b.request(
            10_002,
            back,
            Request::LinkRelease {
                txn: 9,
                link: *link,
            },
        );
        b.drain(back);
        assert_eq!(b.verifying(), 6 - n, "after the release of link {link}");
    }
}

/// A restart hold that is longer than the grace is not cut short by the Down that is owed.
#[test]
fn the_number_of_a_restart_stays_on_hold_as_long_as_the_restart_asks() {
    let net = SharedNet::new();
    let (a, l) = first_daemon(&net);
    drop(a);
    let mut b = Server::new(
        ServerConfig {
            restart_hold_ms: 200_000,
            ..ServerConfig::default()
        },
        Engine::new(Config::default(), SimModem::new(), net.clone()),
    );
    b.engine().qmi_mut().require_call = true;
    names_the_call(&mut b, l);
    modem_up(&mut b, 10_000);
    b.on_service_event(10_100, ServiceEvent::ModemDown);
    assert_eq!(b.owed_downs(), 1);
    assert_eq!(b.engine().link_hold_until(usize::from(l)), 10_100 + 200_000);
}

/// The Down an earlier process is owed is not for a new process with the same PID, which also has no reason to wait.
#[test]
fn a_down_owed_to_a_process_is_not_for_a_new_process_with_the_same_pid() {
    let net = SharedNet::new();
    let mut s = daemon(&net);
    modem_up(&mut s, 0);
    let old = Proc {
        pid: MODULE,
        ino: 100,
    };
    let c = s.accept_proc(old, 1001, LABEL).unwrap();
    s.request(0, c, Request::Hello);
    let l = lookup(&mut s, c, 1, 1, req("internet.example"));
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 2);
    s.drain(c);
    s.close(3, c);
    s.engine().qmi_mut().external_disconnect(l + 1, 3, 26);
    pump(&mut s, 4);
    assert_eq!(s.owed_downs(), 1);
    let newer = s
        .accept_proc(
            Proc {
                pid: MODULE,
                ino: 200,
            },
            1001,
            LABEL,
        )
        .unwrap();
    // it has nothing to wait for: it says Hello and its own call is told to it
    s.request(5, newer, Request::Hello);
    s.drain(newer);
    let k = lookup(&mut s, newer, 1, 5, req("other.example"));
    s.engine().qmi_mut().external_connect(k + 1);
    pump(&mut s, 6);
    assert!(events(&mut s, newer).iter().all(|(n, _)| *n != l));
    assert_eq!(
        s.owed_downs(),
        1,
        "the Down is still owed to the old process"
    );
    // the old process gets it
    let again = s.accept_proc(old, 1001, LABEL).unwrap();
    s.request(8, again, Request::Hello);
    assert!(events(&mut s, again)
        .iter()
        .any(|(n, e)| *n == l && is_down(e)));
}

/// A connection of another process with the same PID is not the connection of the process that held the link.
#[test]
fn a_restored_link_does_not_go_to_a_connection_of_another_process_with_the_same_pid() {
    let net = SharedNet::new();
    let mut a = daemon(&net);
    modem_up(&mut a, 0);
    let old = Proc {
        pid: MODULE,
        ino: 100,
    };
    let c = a.accept_proc(old, 1001, LABEL).unwrap();
    let l = lookup(&mut a, c, 1, 1, req("internet.example"));
    a.engine().qmi_mut().external_connect(l + 1);
    pump(&mut a, 2);
    drop(a);
    let mut b = daemon(&net);
    names_the_call(&mut b, l);
    let newer = b
        .accept_proc(
            Proc {
                pid: MODULE,
                ino: 200,
            },
            1001,
            LABEL,
        )
        .unwrap();
    modem_up(&mut b, 10_000);
    assert_eq!(b.restored_links(), 1);
    assert_eq!(b.links_held(newer), 0, "the link is not the new process's");
    let back = b.accept_proc(old, 1001, LABEL).unwrap();
    assert_eq!(b.links_held(back), 1);
}
