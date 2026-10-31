// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! What a module is told after a restart, and when. A connection is told what it missed only
//! after its Hello is answered with ready, a Down stays owed until the daemon has written it, and the
//! time of a Down in the table is the time of the system.
use dataos_datacore::engine::{Config, Engine, ServiceEvent};
use dataos_datacore::sim::SimModem;
use dataos_datad::server::{Server, ServerConfig};
use dataos_datad::table::{self, Proc};
use dataos_netcfg::{NetOps, SharedNet};
use dataos_wire::*;

type S = Server<SimModem, SharedNet>;
const LABEL: &str = "u:r:rild:s0";
const MODULE: u32 = 4242;

fn daemon(net: &SharedNet) -> S {
    let mut s = Server::new(
        ServerConfig::default(),
        Engine::new(Config::default(), SimModem::new(), net.clone()),
    );
    s.engine().qmi_mut().require_call = true;
    s
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

/// A connection that has said Hello, as the library does at once. What the module is told after that stays.
fn connect(s: &mut S, pid: u32, now: u64) -> u32 {
    let c = s.accept(pid, 1001, LABEL).unwrap();
    s.request(now, c, Request::Hello);
    let rest: Vec<Notify> = take(s, c)
        .into_iter()
        .filter(|n| !matches!(n, Notify::HelloAck { .. }))
        .collect();
    s.conns_requeue(c, rest);
    c
}

fn lookup(s: &mut S, conn: u32, txn: u32, now: u64, r: RouteRequest) -> u8 {
    s.request(now, conn, Request::RouteLookup { txn, req: r });
    pump(s, now);
    let mut got = s.drain(conn);
    let at = got
        .iter()
        .position(|n| matches!(n, Notify::RouteReply { .. }))
        .unwrap();
    let reply = got.remove(at);
    s.conns_requeue(conn, got);
    match reply {
        Notify::RouteReply {
            code: ResultCode::Ok,
            link,
            ..
        } => link,
        other => panic!("no link: {other:?}"),
    }
}

/// What is queued for the connection, without taking it as written: the way the daemon takes it.
fn take(s: &mut S, conn: u32) -> Vec<Notify> {
    s.drain_encoded(conn)
        .iter()
        .map(|d| Notify::decode(d).unwrap())
        .collect()
}

fn is_down(n: &Notify) -> bool {
    matches!(
        n,
        Notify::Event {
            event: IfaceEvent::Down(_),
            ..
        }
    )
}

fn is_up(n: &Notify) -> bool {
    matches!(
        n,
        Notify::Event {
            event: IfaceEvent::Up,
            ..
        }
    )
}

fn grace() -> u64 {
    ServerConfig::default().orphan_grace_ms
}

/// A module with a call up whose connection closes, and whose call then ends while it is away: the daemon
/// owes it a Down, which the table keeps.
fn tombstone_daemon(net: &SharedNet, t0: u64) -> (S, u8) {
    let mut a = daemon(net);
    modem_up(&mut a, t0);
    let c = connect(&mut a, MODULE, t0 + 1);
    let l = lookup(&mut a, c, 1, t0 + 1, req("internet.example"));
    a.engine().qmi_mut().external_connect(l + 1);
    pump(&mut a, t0 + 2);
    a.drain(c);
    a.close(t0 + 3, c);
    a.engine().qmi_mut().external_disconnect(l + 1, 3, 26);
    pump(&mut a, t0 + 4);
    assert_eq!(a.owed_downs(), 1);
    (a, l)
}

/// The module comes back to a restarted daemon before it is ready, and its Hello is answered "not
/// ready". The Down of the table is queued after the Ready message and not before it, because the library
/// says INIT_DONE at that message and DSI drops what comes before. The number is held until the Down is written.
#[test]
fn a_down_from_the_table_comes_after_ready_for_a_module_that_connected_before() {
    let net = SharedNet::new();
    let (a, l) = tombstone_daemon(&net, 0);
    drop(a);
    let mut b = daemon(&net);
    let back = b.accept(MODULE, 1001, LABEL).unwrap();
    b.request(5, back, Request::Hello);
    assert!(matches!(
        take(&mut b, back).as_slice(),
        [Notify::HelloAck { ready: false }]
    ));
    modem_up(&mut b, 10);
    let got = take(&mut b, back);
    let down = got.iter().position(is_down).expect("a Down");
    let ready = got
        .iter()
        .position(|n| matches!(n, Notify::Ready { ready: true }))
        .expect("Ready");
    assert!(ready < down, "{got:?}");
    // queued is not written: the number is still held, and the Down is still owed
    let other = connect(&mut b, 20, 11);
    assert_ne!(lookup(&mut b, other, 2, 11, req("other.example")), l);
    assert_eq!(b.owed_downs(), 1);
    // and a write to another connection does not free it
    b.written(other, l);
    assert_eq!(b.owed_downs(), 1);
    b.written(back, l);
    assert_eq!(b.owed_downs(), 0);
    assert_eq!(lookup(&mut b, other, 3, 12, req("third.example")), l);
}

/// The device was set up again while no daemon ran, so the call the module was told is up is gone.
/// The Down it is owed is queued to the connection that came before the daemon was ready, at the Ready message.
#[test]
fn a_down_for_a_device_set_up_again_reaches_a_module_that_connected_before_ready() {
    let net = SharedNet::new();
    let mut a = daemon(&net);
    modem_up(&mut a, 0);
    let c = connect(&mut a, MODULE, 1);
    let l = lookup(&mut a, c, 1, 1, req("internet.example"));
    a.engine().qmi_mut().external_connect(l + 1);
    pump(&mut a, 2);
    drop(a);
    net.0.borrow_mut().modem_restart();
    let mut b = daemon(&net);
    let back = b.accept(MODULE, 1001, LABEL).unwrap();
    b.request(5, back, Request::Hello);
    b.drain(back);
    modem_up(&mut b, 10);
    assert!(!b.engine().links_adopted());
    assert_eq!(b.owed_downs(), 1, "the Down is owed");
    let got = b.drain(back);
    let down = got.iter().position(is_down).expect("a Down");
    let ready = got
        .iter()
        .position(|n| matches!(n, Notify::Ready { ready: true }))
        .expect("Ready");
    assert!(ready < down, "{got:?}");
    assert_eq!(b.owed_downs(), 0, "and written");
    let other = connect(&mut b, 20, 11);
    assert_eq!(lookup(&mut b, other, 2, 11, req("other.example")), l);
}

/// Two connections of one process. The first took the links over and has not said Hello, the
/// second has. The call ends, and the Down goes to the connection that has been told, which is the second.
#[test]
fn a_down_owed_goes_to_the_connection_of_the_process_that_has_been_told() {
    let net = SharedNet::new();
    let mut s = daemon(&net);
    modem_up(&mut s, 0);
    let c0 = connect(&mut s, MODULE, 1);
    let l = lookup(&mut s, c0, 1, 1, req("internet.example"));
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 2);
    s.drain(c0);
    s.close(3, c0);
    let a = s.accept(MODULE, 1001, LABEL).unwrap();
    assert_eq!(s.links_held(a), 1);
    let b = connect(&mut s, MODULE, 4);
    s.drain(b);
    s.engine().qmi_mut().external_disconnect(l + 1, 3, 26);
    pump(&mut s, 5);
    s.close(6, a);
    let got = s.drain(b);
    assert!(got.iter().any(is_down), "{got:?}");
    assert_eq!(s.owed_downs(), 0);
}

/// A link goes to a connection that has not said Hello, because the one that held it closed. Its
/// state is queued after the answer to the Hello and not before it.
#[test]
fn a_link_handed_to_a_connection_before_its_hello_is_replayed_after_the_hello_ack() {
    let net = SharedNet::new();
    let mut s = daemon(&net);
    modem_up(&mut s, 0);
    let c0 = connect(&mut s, MODULE, 1);
    let l = lookup(&mut s, c0, 1, 1, req("internet.example"));
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 2);
    s.drain(c0);
    s.close(3, c0);
    let a = s.accept(MODULE, 1001, LABEL).unwrap();
    let b = s.accept(MODULE, 1001, LABEL).unwrap();
    s.close(4, a);
    assert!(s.drain(b).is_empty(), "nothing before the Hello");
    s.request(5, b, Request::Hello);
    let got = s.drain(b);
    let ack = got
        .iter()
        .position(|n| matches!(n, Notify::HelloAck { ready: true }))
        .expect("ack");
    let up = got.iter().position(is_up).expect("replay");
    assert!(ack < up, "{got:?}");
    assert_eq!(s.links_held(b), 1);
}

/// The time of the runtime is that of the system, which runs on through a restart of the
/// daemon, and the time of a Down in the table is no longer than a grace from the start of the next instance.
/// A table written by an instance that ran for hours does not hold a number for hours.
#[test]
fn a_down_of_the_table_holds_its_number_for_no_more_than_a_grace_from_the_restart() {
    const LONG: u64 = 50_000_000;
    let net = SharedNet::new();
    let (a, l) = tombstone_daemon(&net, LONG);
    drop(a);
    let mut b = daemon(&net);
    modem_up(&mut b, 1_000);
    assert_eq!(b.owed_downs(), 1);
    assert!(b.engine().link_hold_until(usize::from(l)) <= 1_000 + grace());
    b.tick(1_000 + grace() + 1);
    assert_eq!(b.owed_downs(), 0, "no longer owed after the grace");
    assert!(!b.engine().link_on_hold(usize::from(l)));
}

/// A table of another version is no table: every link the engine kept is held for the grace, and
/// none is followed.
#[test]
fn a_table_of_another_version_holds_every_link_and_follows_none() {
    let net = SharedNet::new();
    let mut a = daemon(&net);
    modem_up(&mut a, 0);
    let c = connect(&mut a, MODULE, 1);
    let l = lookup(&mut a, c, 1, 1, req("internet.example"));
    a.engine().qmi_mut().external_connect(l + 1);
    pump(&mut a, 2);
    drop(a);
    let boot = net.0.borrow_mut().boot_id().unwrap();
    let old = format!(
        "datad-links 2\nboot {boot}\nL {l} {MODULE} 0 0 1 1 1100 696e7465726e65742e6578616d706c65\n"
    );
    assert!(table::decode(old.as_bytes(), &boot).is_none());
    net.0.borrow_mut().links_file = Some(old.into_bytes());
    let mut b = daemon(&net);
    modem_up(&mut b, 10);
    assert_eq!(b.restored_links(), 0);
    assert!(b.engine().link_on_hold(usize::from(l)));
    let back = connect(&mut b, MODULE, 11);
    assert_eq!(
        b.links_held(back),
        0,
        "the call of the module is not followed"
    );
    let _ = Proc { pid: 0, ino: 0 };
}

/// A Down that is queued is still in the table, and still owed, until the daemon has written
/// it. A daemon that goes before the write leaves it for the next one.
#[test]
fn a_down_stays_in_the_table_until_it_was_written_to_the_socket() {
    let net = SharedNet::new();
    let mut s = daemon(&net);
    modem_up(&mut s, 0);
    let c = connect(&mut s, MODULE, 1);
    let l = lookup(&mut s, c, 1, 1, req("internet.example"));
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 2);
    s.drain(c);
    s.close(3, c);
    s.engine().qmi_mut().external_disconnect(l + 1, 3, 26);
    pump(&mut s, 4);
    let back = connect(&mut s, MODULE, 5);
    let boot = net.0.borrow_mut().boot_id().unwrap();
    let saved = |net: &SharedNet| {
        let file = net.0.borrow().links_file.clone().unwrap();
        table::decode(&file, &boot).unwrap()
    };
    // the Down is in the queue of the connection, not written
    assert_eq!(saved(&net).dead.len(), 1, "the table has not forgotten it");
    assert_eq!(s.owed_downs(), 1);
    // the connection closes before the write: the Down is owed again to the next connection
    s.close(6, back);
    assert_eq!(s.owed_downs(), 1);
    let again = connect(&mut s, MODULE, 7);
    assert!(take(&mut s, again).iter().any(is_down));
    // and a daemon that goes before the write leaves it to the next one
    drop(s);
    let mut c2 = daemon(&net);
    modem_up(&mut c2, 10);
    assert_eq!(c2.owed_downs(), 1);
    // written: it is gone from the table
    let third = connect(&mut c2, MODULE, 11);
    assert!(c2.drain(third).iter().any(is_down));
    assert_eq!(c2.owed_downs(), 0);
    assert!(saved(&net).dead.is_empty());
}

/// A modem restart while the process is away holds the number for the restart as well as for
/// the Down. Giving the Down does not end the hold of the restart, which is for the late release of the old
/// call, and the number is free when that time is over.
#[test]
fn giving_the_down_does_not_end_the_hold_of_a_modem_restart() {
    let net = SharedNet::new();
    let mut s = daemon(&net);
    modem_up(&mut s, 0);
    let c0 = connect(&mut s, MODULE, 1);
    let l = lookup(&mut s, c0, 1, 1, req("internet.example"));
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 2);
    s.drain(c0);
    s.close(3, c0);
    s.on_service_event(5, ServiceEvent::ModemDown);
    assert!(s.engine().link_on_hold(usize::from(l)));
    modem_up(&mut s, 6);
    let back = connect(&mut s, MODULE, 7);
    assert!(s.drain(back).iter().any(is_down));
    let restart_hold_end = 5 + ServerConfig::default().restart_hold_ms;
    assert!(8 < restart_hold_end);
    assert!(
        s.engine().link_on_hold(usize::from(l)),
        "the hold of the restart is still there"
    );
    let other = connect(&mut s, 20, 8);
    assert_ne!(lookup(&mut s, other, 2, 8, req("other.example")), l);
    s.tick(restart_hold_end + 1);
    assert!(!s.engine().link_on_hold(usize::from(l)));
}

/// A Down for a connection that has been told is owed like any other: the daemon took it from the
/// server and the write failed (or the daemon or the connection ended first). The number stays held, and the
/// next connection of the process is given the Down again.
#[test]
fn a_live_down_lost_with_its_connection_is_given_again_and_its_number_held() {
    let net = SharedNet::new();
    let mut s = daemon(&net);
    modem_up(&mut s, 0);
    let a = connect(&mut s, MODULE, 1);
    let l = lookup(&mut s, a, 1, 1, req("internet.example"));
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 2);
    assert!(take(&mut s, a).iter().any(is_up));
    s.engine().qmi_mut().external_disconnect(l + 1, 3, 26);
    pump(&mut s, 3);
    assert!(take(&mut s, a).iter().any(is_down), "taken, not written");
    assert_eq!(s.owed_downs(), 1);
    s.close(4, a);
    assert_eq!(s.owed_downs(), 1, "still owed");
    let other = connect(&mut s, 99, 5);
    assert_ne!(lookup(&mut s, other, 2, 5, req("other.example")), l);
    let b = connect(&mut s, MODULE, 6);
    let got = take(&mut s, b);
    assert!(got.iter().any(is_down), "{got:?}");
    s.written(b, l);
    assert_eq!(s.owed_downs(), 0);
    assert_eq!(lookup(&mut s, other, 3, 7, req("third.example")), l);
}

/// A Down queued to one connection and given back by its close is queued to a connection of the process
/// that has been told already, and not left for the grace to drop.
#[test]
fn a_down_given_back_by_a_closed_connection_reaches_a_told_mate() {
    let net = SharedNet::new();
    let mut s = daemon(&net);
    modem_up(&mut s, 0);
    let c0 = connect(&mut s, MODULE, 1);
    let l = lookup(&mut s, c0, 1, 1, req("internet.example"));
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 2);
    s.drain(c0);
    s.close(3, c0);
    s.engine().qmi_mut().external_disconnect(l + 1, 3, 26);
    pump(&mut s, 4);
    assert_eq!(s.owed_downs(), 1);
    let a = connect(&mut s, MODULE, 5);
    let b = connect(&mut s, MODULE, 6);
    assert!(!take(&mut s, b).iter().any(is_down), "the Down is a's");
    assert!(
        take(&mut s, a).iter().any(is_down),
        "queued to a, not written"
    );
    s.close(7, a);
    let got = take(&mut s, b);
    assert!(got.iter().any(is_down), "{got:?}");
    s.written(b, l);
    assert_eq!(s.owed_downs(), 0);
}

/// F-D. Two connections of a process have been told, and the Down of a call goes to the newer one, which is the
/// one the library listens to once it has connected again.
#[test]
fn a_down_goes_to_the_newest_connection_of_the_process_that_has_been_told() {
    let net = SharedNet::new();
    let mut s = daemon(&net);
    modem_up(&mut s, 0);
    let old = connect(&mut s, MODULE, 1);
    let l = lookup(&mut s, old, 1, 1, req("internet.example"));
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 2);
    let newer = connect(&mut s, MODULE, 3);
    s.drain(old);
    s.engine().qmi_mut().external_disconnect(l + 1, 3, 26);
    pump(&mut s, 4);
    assert!(take(&mut s, newer).iter().any(is_down));
    assert!(!take(&mut s, old).iter().any(is_down));
}

/// The daemon wrote the Down and ended before it reported it, so the table still has the tombstone. The
/// next instance gives the Down again after INIT_DONE and holds the number until that is written.
#[test]
fn a_down_written_and_not_reported_is_given_again_by_the_next_instance() {
    let net = SharedNet::new();
    let mut s = daemon(&net);
    modem_up(&mut s, 0);
    let c0 = connect(&mut s, MODULE, 1);
    let l = lookup(&mut s, c0, 1, 1, req("internet.example"));
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 2);
    s.drain(c0);
    s.close(3, c0);
    s.engine().qmi_mut().external_disconnect(l + 1, 3, 26);
    pump(&mut s, 4);
    let a = connect(&mut s, MODULE, 5);
    assert!(take(&mut s, a).iter().any(is_down), "written, not reported");
    drop(s);
    let mut b = daemon(&net);
    modem_up(&mut b, 10);
    assert_eq!(b.owed_downs(), 1);
    assert!(b.engine().link_on_hold(usize::from(l)));
    let back = connect(&mut b, MODULE, 11);
    assert!(take(&mut b, back).iter().any(is_down), "given again");
    assert!(
        b.engine().link_on_hold(usize::from(l)),
        "held until written"
    );
    b.written(back, l);
    assert!(!b.engine().link_on_hold(usize::from(l)));
}
