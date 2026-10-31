// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The requests of the data module through the wire protocol, the daemon
//! server, the engine and the simulated modem. Simulation only.
#![allow(clippy::disallowed_methods)] // test code, the list is for the shipped crates
use dataos_datacore::engine::{Config, Engine, ServiceEvent};
use dataos_datacore::sim::SimModem;
use dataos_datad::server::{Server, ServerConfig};
use dataos_netcfg::FakeNet;
use dataos_nicm_compat::{Client, NicmError, Notice, Reply, Transport};
use dataos_wire::{
    EndReason, Family, IfaceEvent, LocalReason, MatchHint, Notify, Request, ResultCode,
    RouteRequest,
};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

type S = Server<SimModem, FakeNet>;

const LABEL: &str = "u:r:rild:s0";

struct Loop {
    srv: Rc<RefCell<S>>,
    conn: u32,
    queue: VecDeque<Notify>,
    fail_sends: bool,
}

impl Transport for Loop {
    fn send(&mut self, req: &Request) -> Result<(), NicmError> {
        if self.fail_sends {
            return Err(NicmError::Transport);
        }
        // through the real wire format both ways
        let req = Request::decode(&req.encode().map_err(|_| NicmError::Invalid)?)
            .map_err(|_| NicmError::Invalid)?;
        self.srv.borrow_mut().request(1, self.conn, req);
        Ok(())
    }

    fn recv(&mut self) -> Option<Notify> {
        if self.queue.is_empty() {
            for d in self.srv.borrow_mut().drain_encoded(self.conn) {
                self.queue.push_back(Notify::decode(&d).unwrap());
            }
        }
        self.queue.pop_front()
    }
}

fn setup() -> (Rc<RefCell<S>>, Client<Loop>) {
    let mut server = Server::new(
        ServerConfig::default(),
        Engine::new(Config::default(), SimModem::new(), FakeNet::new()),
    );
    server.engine().qmi_mut().require_call = true;
    let srv = Rc::new(RefCell::new(server));
    let conn = srv.borrow_mut().accept(4242, 1001, LABEL).unwrap();
    let client = Client::new(Loop {
        srv: srv.clone(),
        conn,
        queue: VecDeque::new(),
        fail_sends: false,
    });
    (srv, client)
}

fn pump(srv: &Rc<RefCell<S>>, now: u64) {
    loop {
        let next = srv.borrow_mut().engine().qmi_mut().inbox.pop_front();
        match next {
            Some((c, b)) => srv.borrow_mut().on_qmi(now, c, &b),
            None => return,
        }
    }
}

fn modem_up(srv: &Rc<RefCell<S>>) {
    srv.borrow_mut().on_service_event(0, ServiceEvent::ModemUp);
    pump(srv, 0);
}

fn route(family: Family) -> RouteRequest {
    RouteRequest {
        slot: 0,
        family,
        apn: Some("internet.example".into()),
        apn_type: 1,
        apn_type_mask: 1,
    }
}

/// Send a request and run the modem until the reply is here.
fn ask(
    srv: &Rc<RefCell<S>>,
    c: &mut Client<Loop>,
    send: impl FnOnce(&mut Client<Loop>) -> Result<u32, NicmError>,
) -> Result<Reply, NicmError> {
    let txn = send(c)?;
    pump(srv, 1);
    c.poll();
    c.take_reply(txn).expect("the daemon answered")
}

#[test]
fn readiness_is_asked_with_hello_and_the_first_ready_is_not_a_restart() {
    let (srv, mut c) = setup();
    c.hello().unwrap();
    assert!(c.poll().is_empty());
    assert_eq!(c.ready(), Some(false));
    modem_up(&srv);
    assert!(
        c.poll().is_empty(),
        "first time ready: no restart to announce"
    );
    assert_eq!(c.ready(), Some(true));
}

#[test]
fn a_lookup_a_call_and_a_release_through_the_whole_stack() {
    let (srv, mut c) = setup();
    modem_up(&srv);
    c.hello().unwrap();
    c.poll();
    let r = ask(&srv, &mut c, |c| c.route_lookup(route(Family::V4))).unwrap();
    assert_eq!(
        r,
        Reply::Route {
            link: 0,
            existing: false,
            companion: false,
            ifname: "rmnet_data0".into()
        }
    );
    // the module's own call connects
    srv.borrow_mut().engine().qmi_mut().external_connect(1);
    pump(&srv, 2);
    let notices = c.poll();
    assert!(matches!(
        notices[0],
        Notice::Iface {
            link: 0,
            event: IfaceEvent::Up,
            ..
        }
    ));
    assert_eq!(
        notices.len(),
        2,
        "up and address, no MTU event at the first configuration: {notices:?}"
    );
    let mtu = ask(&srv, &mut c, |c| c.query_mtu(0)).unwrap();
    assert_eq!(mtu, Reply::Mtu { v4: 1400, v6: 1400 });
    // the call is up: the release is answered and the link stays
    assert_eq!(ask(&srv, &mut c, |c| c.link_release(0)), Ok(Reply::Done));
    assert_eq!(srv.borrow_mut().engine().free_links(), 14);
    // when the call has ended, the link is free at once and there is nothing left to release
    srv.borrow_mut()
        .engine()
        .qmi_mut()
        .external_disconnect(1, 3, 26);
    pump(&srv, 3);
    c.poll();
    assert_eq!(srv.borrow_mut().engine().free_links(), 15);
    assert_eq!(
        ask(&srv, &mut c, |c| c.link_release(0)),
        Err(NicmError::Refused(ResultCode::NoSuchLink))
    );
}

#[test]
fn what_the_daemon_refuses_comes_back_as_a_refusal_with_its_code() {
    let (srv, mut c) = setup();
    // not ready yet
    let r = ask(&srv, &mut c, |c| c.route_lookup(route(Family::V4)));
    assert_eq!(r, Err(NicmError::Refused(ResultCode::NotReady)));
    modem_up(&srv);
    let bad = RouteRequest {
        slot: 9,
        ..route(Family::V4)
    };
    assert_eq!(
        ask(&srv, &mut c, |c| c.route_lookup(bad)),
        Err(NicmError::Refused(ResultCode::Invalid))
    );
    assert_eq!(
        ask(&srv, &mut c, |c| c.screen_state(false)),
        Ok(Reply::Done)
    );
    assert_eq!(
        ask(&srv, &mut c, |c| c.link_release(3)),
        Err(NicmError::Refused(ResultCode::NoSuchLink))
    );
}

#[test]
fn a_modem_restart_is_announced_once_and_the_end_once() {
    let (srv, mut c) = setup();
    modem_up(&srv);
    c.hello().unwrap();
    c.poll();
    ask(&srv, &mut c, |c| c.route_lookup(route(Family::V4))).unwrap();
    srv.borrow_mut().engine().qmi_mut().external_connect(1);
    pump(&srv, 2);
    c.poll();
    srv.borrow_mut()
        .on_service_event(5, ServiceEvent::ModemDown);
    let n = c.poll();
    let start = n.iter().filter(|x| **x == Notice::RestartStart).count();
    assert_eq!(start, 1, "{n:?}");
    assert!(n.iter().any(|x| matches!(
        x,
        Notice::Iface {
            event: IfaceEvent::Down(EndReason::Local(LocalReason::ModemRestart)),
            ..
        }
    )));
    // a second down message does not announce it again
    srv.borrow_mut()
        .on_service_event(6, ServiceEvent::ModemDown);
    assert!(!c.poll().contains(&Notice::RestartStart));
    srv.borrow_mut().on_service_event(7, ServiceEvent::ModemUp);
    pump(&srv, 7);
    assert_eq!(c.poll(), vec![Notice::RestartDone]);
    assert!(c.poll().is_empty());
}

#[test]
fn losing_the_daemon_fails_what_waits_and_restarts_the_module() {
    let (srv, mut c) = setup();
    modem_up(&srv);
    c.hello().unwrap();
    c.poll();
    let txn = c.query_mtu(0).unwrap();
    // the daemon never answers: the connection is gone
    let n = c.transport_lost();
    assert_eq!(n, vec![Notice::RestartStart]);
    assert_eq!(c.take_reply(txn), Some(Err(NicmError::Transport)));
    assert_eq!(c.take_reply(txn), None, "an answer is handed out once");
    assert!(c.transport_lost().is_empty(), "and announced once");
    // a new connection: register again, and the daemon says it is ready
    let conn = srv.borrow_mut().accept(4242, 1001, LABEL).unwrap();
    c.transport_mut().conn = conn;
    c.transport_mut().queue.clear();
    c.reconnected().unwrap();
    assert_eq!(c.poll(), vec![Notice::RestartDone]);
}

#[test]
fn a_request_that_cannot_be_sent_leaves_nothing_waiting() {
    let (srv, mut c) = setup();
    modem_up(&srv);
    c.transport_mut().fail_sends = true;
    for _ in 0..20 {
        assert_eq!(c.query_mtu(0), Err(NicmError::Transport));
    }
    c.transport_mut().fail_sends = false;
    assert!(c.query_mtu(0).is_ok(), "the slots were not used up");
}

#[test]
fn only_a_few_requests_wait_at_a_time_and_a_late_answer_is_dropped() {
    let (srv, mut c) = setup();
    modem_up(&srv);
    let mut txns = Vec::new();
    for _ in 0..8 {
        txns.push(c.query_mtu(0).unwrap());
    }
    assert_eq!(c.query_mtu(0), Err(NicmError::TooMany));
    // the caller gave up on one, its late answer is not kept
    c.forget(txns[0]);
    assert!(c.query_mtu(0).is_ok());
    c.poll();
    assert_eq!(c.take_reply(txns[0]), None);
    assert_eq!(c.stale, 1, "the late answer matched nothing");
    for t in &txns[1..] {
        assert!(matches!(c.take_reply(*t), Some(Err(NicmError::Refused(_)))));
    }
}

#[test]
fn a_call_that_is_up_is_found_again_with_the_matching_call_request() {
    let (srv, mut c) = setup();
    modem_up(&srv);
    c.hello().unwrap();
    c.poll();
    ask(&srv, &mut c, |c| c.route_lookup(route(Family::V4))).unwrap();
    // a call that is not up is not found, and the refusal says so
    assert_eq!(
        ask(&srv, &mut c, |c| c
            .matching_call(route(Family::V4), MatchHint::default())),
        Err(NicmError::Refused(ResultCode::NoMatch))
    );
    srv.borrow_mut().engine().qmi_mut().external_connect(1);
    pump(&srv, 2);
    c.poll();
    srv.borrow_mut()
        .engine()
        .qmi_mut()
        .route_answers
        .insert(4, vec![(0x10, vec![0])]);
    assert_eq!(
        ask(&srv, &mut c, |c| c
            .matching_call(route(Family::V4), MatchHint::default())),
        Ok(Reply::Route {
            link: 0,
            existing: true,
            companion: false,
            ifname: "rmnet_data0".into()
        })
    );
    // the answer was the call's own, nothing new was taken
    assert_eq!(srv.borrow_mut().engine().free_links(), 14);
}

struct Feed(VecDeque<Notify>);

impl Transport for Feed {
    fn send(&mut self, _req: &Request) -> Result<(), NicmError> {
        Ok(())
    }
    fn recv(&mut self) -> Option<Notify> {
        self.0.pop_front()
    }
}

/// `drain` reads all the transport holds, `poll` only a bounded part of it.
#[test]
fn drain_reads_all_that_the_transport_holds_and_poll_a_bounded_part() {
    let event = |link| Notify::Event {
        link,
        slot: 0,
        event: IfaceEvent::Reconfigured,
    };
    let held: VecDeque<Notify> = (0..200).map(|l| event((l % 16) as u8)).collect();
    let mut c = Client::new(Feed(held.clone()));
    assert_eq!(c.poll().len(), dataos_nicm_compat::client::MAX_PER_POLL);
    assert_eq!(
        c.drain().len(),
        200 - dataos_nicm_compat::client::MAX_PER_POLL
    );
    let mut c = Client::new(Feed(held));
    assert_eq!(c.drain().len(), 200);
    assert!(c.drain().is_empty());
}

struct Shut {
    held: VecDeque<Notify>,
    /// What the daemon writes until its end is shut: it arrives while the connection is given up.
    late: Vec<Notify>,
    shut: bool,
}

impl Transport for Shut {
    fn send(&mut self, _req: &Request) -> Result<(), NicmError> {
        Ok(())
    }
    fn recv(&mut self) -> Option<Notify> {
        self.held.pop_front()
    }
    fn close_read(&mut self) {
        self.shut = true;
        self.held.extend(self.late.drain(..));
    }
}

/// F-B. The connection is given up in one call: the daemon is stopped from writing, what it wrote is read to the
/// end, and then the connection is lost. A Down among it reaches the module ahead of INIT_START.
#[test]
fn finish_stops_the_daemon_reads_to_the_end_and_then_loses_the_connection() {
    let down = Notify::Event {
        link: 3,
        slot: 0,
        event: IfaceEvent::Down(EndReason::Qmi(1)),
    };
    let mut c = Client::new(Shut {
        held: VecDeque::from([Notify::Ready { ready: true }, down.clone()]),
        late: vec![Notify::Event {
            link: 5,
            slot: 0,
            event: IfaceEvent::Down(EndReason::Qmi(2)),
        }],
        shut: false,
    });
    let txn = c.query_mtu(0).unwrap();
    let got = c.finish();
    assert!(c.transport().shut);
    let links: Vec<u8> = got
        .iter()
        .filter_map(|n| match n {
            Notice::Iface { link, .. } => Some(*link),
            _ => None,
        })
        .collect();
    assert_eq!(links, vec![3, 5], "both Downs, the one that came late too");
    assert_eq!(got.last(), Some(&Notice::RestartStart));
    // and the request that waited is failed
    assert_eq!(c.take_reply(txn), Some(Err(NicmError::Transport)));
}
