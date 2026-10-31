// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The data module keeps its calls when the daemon restarts, so the restarted daemon
//! must not hand their links to other calls. The table of the links handed out is kept in the state
//! directory (a fake of it here, shared between the two daemons of a test like the kernel is).
use dataos_datacore::engine::{Config, Engine, ServiceEvent};
use dataos_datacore::sim::SimModem;
use dataos_datad::server::{Server, ServerConfig};
use dataos_datad::table;
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

fn lookup(s: &mut S, conn: u32, txn: u32, now: u64, r: RouteRequest) -> u8 {
    s.request(now, conn, Request::RouteLookup { txn, req: r });
    pump(s, now);
    for n in s.drain(conn) {
        if let Notify::RouteReply {
            code: ResultCode::Ok,
            link,
            ..
        } = n
        {
            return link;
        }
    }
    panic!("no link");
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

fn file(net: &SharedNet) -> Option<Vec<u8>> {
    net.0.borrow().links_file.clone()
}

/// A daemon with a module of its own that has a call up on a link, and the state directory it left.
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

#[test]
fn the_link_of_a_live_call_is_not_handed_to_another_call_after_a_restart() {
    let net = SharedNet::new();
    let (a, l) = first_daemon(&net);
    assert!(file(&net).is_some(), "the table is kept");
    // the daemon is gone, the module and the modem go on
    drop(a);
    let mut b = daemon(&net);
    // the modem has the module's call on its link
    b.engine()
        .qmi_mut()
        .route_answers
        .insert(4, vec![(0x10, vec![l])]);
    modem_up(&mut b, 10_000);
    assert_eq!(b.restored_links(), 1);
    assert_eq!(b.engine().free_links(), 14, "the link is followed again");
    b.engine().qmi_mut().external_connect(l + 1);
    pump(&mut b, 10_001);
    // another process asks for a link
    let other = connect(&mut b, 20);
    let l2 = lookup(&mut b, other, 2, 10_002, req("other.example"));
    assert_ne!(l2, l, "one mux, two calls");
    // the module reconnects and takes its call over, up, with its address
    let back = b.accept(MODULE, 1001, LABEL).unwrap();
    assert_eq!(b.links_held(back), 1);
    // and is told after the answer to its Hello, not before
    assert!(events(&mut b, back).is_empty());
    b.request(10_003, back, Request::Hello);
    let told = events(&mut b, back);
    assert_eq!(told.first(), Some(&(l, IfaceEvent::Up)));
    assert!(told.iter().any(|(_, e)| matches!(
        e,
        IfaceEvent::NewAddr {
            family: Family::V4,
            ..
        }
    )));
}

#[test]
fn a_call_that_ended_while_the_daemon_was_away_is_told_to_the_module_that_comes_back() {
    let net = SharedNet::new();
    let (a, l) = first_daemon(&net);
    drop(a);
    let mut b = daemon(&net);
    modem_up(&mut b, 10_000);
    // the modem does not have the call any more: the question about the restored link is answered
    // with a call on no link
    pump(&mut b, 10_001);
    // the number is on hold until the module was told
    let other = connect(&mut b, 20);
    assert_ne!(lookup(&mut b, other, 2, 10_002, req("x.example")), l);
    let back = b.accept(MODULE, 1001, LABEL).unwrap();
    b.request(10_003, back, Request::Hello);
    let told = events(&mut b, back);
    assert!(
        matches!(told.as_slice(), [(n, IfaceEvent::Down(_))] if *n == l),
        "{told:?}"
    );
    assert_eq!(b.links_held(back), 0);
    // and then it can be used
    assert_eq!(lookup(&mut b, other, 3, 10_004, req("y.example")), l);
}

#[test]
fn a_restored_call_whose_module_never_comes_back_is_freed_after_the_grace() {
    let net = SharedNet::new();
    let (a, l) = first_daemon(&net);
    drop(a);
    let mut b = daemon(&net);
    // the modem has the call and says so
    b.engine()
        .qmi_mut()
        .route_answers
        .insert(4, vec![(0x10, vec![l])]);
    modem_up(&mut b, 10_000);
    b.engine().qmi_mut().external_connect(l + 1);
    pump(&mut b, 10_001);
    assert_eq!(
        b.next_deadline(),
        Some(10_000 + ServerConfig::default().orphan_grace_ms)
    );
    b.tick(10_000 + ServerConfig::default().orphan_grace_ms);
    assert_eq!(b.engine().free_links(), 15);
    // and the table no longer has it
    let t = table::decode(&file(&net).unwrap(), &net.0.borrow_mut().boot_id().unwrap()).unwrap();
    assert!(t.rows.is_empty());
    // the module was told the call is up and is owed a Down for the time it comes back
    assert_eq!(t.dead.len(), 1);
}

#[test]
fn the_table_is_not_overwritten_before_it_was_read() {
    let net = SharedNet::new();
    let (a, _) = first_daemon(&net);
    drop(a);
    let before = file(&net);
    let stores = net.0.borrow().links_stores;
    let mut b = daemon(&net);
    // the modem is not up yet: a module connects and asks
    let c = b.accept(MODULE, 1001, LABEL).unwrap();
    b.request(1, c, Request::Hello);
    b.tick(2);
    assert_eq!(file(&net), before);
    assert_eq!(net.0.borrow().links_stores, stores);
}

#[test]
fn a_table_of_another_boot_or_for_links_the_engine_did_not_keep_is_not_used() {
    // another boot
    let net = SharedNet::new();
    let (a, _) = first_daemon(&net);
    drop(a);
    let t = table::decode(&file(&net).unwrap(), &net.0.borrow_mut().boot_id().unwrap()).unwrap();
    net.0.borrow_mut().links_file = Some(table::encode("another-boot", &t.rows, &t.dead));
    let mut b = daemon(&net);
    modem_up(&mut b, 10_000);
    assert_eq!(b.restored_links(), 0);
    assert_eq!(b.engine().free_links(), 15);
    // a device set up afresh: no pipes were done by an earlier instance
    let net = SharedNet::new();
    let boot = net.0.borrow_mut().boot_id().unwrap();
    net.0.borrow_mut().links_file = Some(table::encode(
        &boot,
        &[table::Row {
            link: 3,
            proc: table::Proc {
                pid: MODULE,
                ino: 0,
            },
            slot: 0,
            apn: None,
            apn_type: 1,
            apn_type_mask: 1,
            emergency: false,
            told: true,
            requested: [true, false],
        }],
        &[],
    ));
    let mut c = daemon(&net);
    modem_up(&mut c, 0);
    assert_eq!(c.restored_links(), 0);
    assert!(!c.engine().links_adopted());
    // the call the module was told is up cannot be there: it is owed a Down
    assert_eq!(c.owed_downs(), 1);
    // garbage is not a table either
    net.0.borrow_mut().links_file = Some(b"garbage".to_vec());
    let mut d = daemon(&net);
    modem_up(&mut d, 0);
    assert_eq!(d.restored_links(), 0);
}

#[test]
fn the_table_changes_with_the_links_and_is_written_only_when_it_does() {
    let net = SharedNet::new();
    let mut s = daemon(&net);
    modem_up(&mut s, 0);
    let stores = |net: &SharedNet| net.0.borrow().links_stores;
    let first = stores(&net);
    assert_eq!(first, 1, "the empty table once");
    let c = s.accept(MODULE, 1001, LABEL).unwrap();
    s.request(1, c, Request::Hello);
    s.tick(2);
    assert_eq!(stores(&net), first, "nothing changed");
    let l = lookup(&mut s, c, 1, 3, req("internet.example"));
    assert_eq!(stores(&net), first + 1);
    let boot = net.0.borrow_mut().boot_id().unwrap();
    let rows = table::decode(&file(&net).unwrap(), &boot).unwrap().rows;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].link, rows[0].proc.pid, rows[0].told),
        (l, MODULE, false)
    );
    assert_eq!(rows[0].apn.as_deref(), Some("internet.example"));
    // the call comes up: the row says the module was told
    s.engine().qmi_mut().external_connect(l + 1);
    pump(&mut s, 4);
    let rows = table::decode(&file(&net).unwrap(), &boot).unwrap().rows;
    assert!(rows[0].told);
    // the connection closes: the process still holds it
    s.close(5, c);
    // and it stays in the table when the next change of anything writes it
    s.tick(6);
    let rows = table::decode(&file(&net).unwrap(), &boot).unwrap().rows;
    assert_eq!((rows.len(), rows[0].proc.pid), (1, MODULE));
    // the call ends and the module is not there: the row goes
    s.engine().qmi_mut().external_disconnect(l + 1, 3, 26);
    pump(&mut s, 6);
    assert!(table::decode(&file(&net).unwrap(), &boot)
        .unwrap()
        .rows
        .is_empty());
}

#[test]
fn a_table_that_cannot_be_written_is_counted_and_the_daemon_goes_on() {
    let net = SharedNet::new();
    net.0.borrow_mut().links_unwritable = true;
    let mut s = daemon(&net);
    modem_up(&mut s, 0);
    let c = connect(&mut s, MODULE);
    lookup(&mut s, c, 1, 1, req("internet.example"));
    assert!(s.save_failures() >= 1);
    assert_eq!(s.links_held(c), 1);
    // and when it works again the table is written
    net.0.borrow_mut().links_unwritable = false;
    s.tick(2);
    assert!(file(&net).is_some());
}

#[test]
fn a_link_that_was_handed_out_and_not_up_is_taken_back_and_not_asked_about() {
    let net = SharedNet::new();
    let mut a = daemon(&net);
    modem_up(&mut a, 0);
    let c = connect(&mut a, MODULE);
    let l = lookup(&mut a, c, 1, 1, req("internet.example"));
    drop(a);
    let mut b = daemon(&net);
    modem_up(&mut b, 10_000);
    assert_eq!(b.restored_links(), 1);
    assert_eq!(b.engine().free_links(), 14);
    // the module was not told the link is up, so nothing is asked and nothing is told to it
    assert!(!b
        .engine()
        .qmi_mut()
        .requests
        .iter()
        .any(|(_, id)| *id == dataos_qmi::wds::id::ROUTE_LOOKUP));
    let back = b.accept(MODULE, 1001, LABEL).unwrap();
    b.request(10_001, back, Request::Hello);
    assert!(events(&mut b, back).is_empty());
    assert_eq!(b.links_held(back), 1);
    // and the module that starts its call on that link has it followed
    b.engine().qmi_mut().external_connect(l + 1);
    pump(&mut b, 10_001);
    assert_eq!(events(&mut b, back).first(), Some(&(l, IfaceEvent::Up)));
}

#[test]
fn the_other_family_of_a_restored_call_is_followed_too() {
    let net = SharedNet::new();
    let (a, l) = first_daemon(&net);
    drop(a);
    let mut b = daemon(&net);
    b.engine()
        .qmi_mut()
        .route_answers
        .insert(4, vec![(0x10, vec![l])]);
    modem_up(&mut b, 10_000);
    b.engine().qmi_mut().external_connect(l + 1);
    b.engine()
        .qmi_mut()
        .external_connect_family(l + 1, dataos_qmi::wds::IpFamily::V6);
    pump(&mut b, 10_001);
    let back = b.accept(MODULE, 1001, LABEL).unwrap();
    b.request(10_002, back, Request::Hello);
    let told = events(&mut b, back);
    assert!(told.iter().any(|(_, e)| matches!(
        e,
        IfaceEvent::NewAddr {
            family: Family::V6,
            ..
        }
    )));
    assert!(told.iter().any(|(_, e)| matches!(
        e,
        IfaceEvent::NewAddr {
            family: Family::V4,
            ..
        }
    )));
}
