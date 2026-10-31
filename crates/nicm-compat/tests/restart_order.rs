// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The order in which the library hands the module what the daemon replays. DSI drops
//! every event but a few while it is not inited, and INIT_DONE comes with the daemon's readiness message,
//! so a replay must come after it. So must the Down a returning module is owed, and a Down the
//! daemon has written is read before the connection is given up.
#![allow(clippy::disallowed_methods)]
use dataos_datacore::engine::{Config, Engine, ServiceEvent};
use dataos_datacore::sim::SimModem;
use dataos_datad::server::{Server, ServerConfig};
use dataos_netcfg::SharedNet;
use dataos_nicm_compat::{Client, NicmError, Notice, Transport};
use dataos_wire::{Family, IfaceEvent, Notify, Request, RouteRequest};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

type S = Server<SimModem, SharedNet>;

struct Loop {
    srv: Rc<RefCell<S>>,
    conn: u32,
    now: u64,
    queue: VecDeque<Notify>,
}

impl Transport for Loop {
    fn send(&mut self, req: &Request) -> Result<(), NicmError> {
        let req = Request::decode(&req.encode().unwrap()).unwrap();
        self.srv.borrow_mut().request(self.now, self.conn, req);
        Ok(())
    }
    fn recv(&mut self) -> Option<Notify> {
        if self.queue.is_empty() {
            let mut srv = self.srv.borrow_mut();
            for d in srv.drain_encoded(self.conn) {
                let n = Notify::decode(&d).unwrap();
                // the socket took it
                if let Notify::Event {
                    link,
                    event: IfaceEvent::Down(_),
                    ..
                } = n
                {
                    srv.written(self.conn, link);
                }
                self.queue.push_back(n);
            }
        }
        self.queue.pop_front()
    }
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

fn request() -> RouteRequest {
    RouteRequest {
        slot: 0,
        family: Family::V4,
        apn: Some("internet.example".into()),
        apn_type: 1,
        apn_type_mask: 1,
    }
}

fn server(net: &SharedNet) -> Rc<RefCell<S>> {
    let mut server = Server::new(
        ServerConfig::default(),
        Engine::new(Config::default(), SimModem::new(), net.clone()),
    );
    server.engine().qmi_mut().require_call = true;
    Rc::new(RefCell::new(server))
}

fn is_down(n: &Notice) -> bool {
    matches!(
        n,
        Notice::Iface {
            event: IfaceEvent::Down(_),
            ..
        }
    )
}

/// The module had a call, the connection broke (INIT_START), the call came up while it was away. On the new
/// connection the library hands the module INIT_DONE first and the replayed events after it.
#[test]
fn the_replay_reaches_the_module_after_init_done() {
    let srv = server(&SharedNet::new());
    srv.borrow_mut().on_service_event(0, ServiceEvent::ModemUp);
    pump(&srv, 0);
    let conn = srv.borrow_mut().accept(4242, 1001, "u:r:rild:s0").unwrap();
    let mut c = Client::new(Loop {
        srv: srv.clone(),
        conn,
        now: 1,
        queue: VecDeque::new(),
    });
    c.hello().unwrap();
    c.poll();
    let txn = c.route_lookup(request()).unwrap();
    pump(&srv, 1);
    c.poll();
    c.take_reply(txn).unwrap().unwrap();
    // the connection breaks before the call is up: the module hears INIT_START
    srv.borrow_mut().close(2, conn);
    assert_eq!(c.transport_lost(), vec![Notice::RestartStart]);
    // the call comes up on the modem while the module is away: the events go nowhere
    srv.borrow_mut().engine().qmi_mut().external_connect(1);
    pump(&srv, 3);
    // the library reconnects
    let back = srv.borrow_mut().accept(4242, 1001, "u:r:rild:s0").unwrap();
    c.transport_mut().conn = back;
    c.reconnected().unwrap();
    let notices = c.poll();
    let up = notices
        .iter()
        .position(|n| {
            matches!(
                n,
                Notice::Iface {
                    event: IfaceEvent::Up,
                    ..
                }
            )
        })
        .unwrap();
    let done = notices
        .iter()
        .position(|n| *n == Notice::RestartDone)
        .unwrap();
    assert!(done < up, "{notices:?}");
}

/// The module had a call up, the connection broke, the call ended while it was away, and the daemon
/// restarted. The library reconnects before the new daemon is ready. The Down the module is owed comes after
/// INIT_DONE, because DSI drops it before.
#[test]
fn the_down_a_returning_module_is_owed_comes_after_init_done() {
    let net = SharedNet::new();
    let srv = server(&net);
    srv.borrow_mut().on_service_event(0, ServiceEvent::ModemUp);
    pump(&srv, 0);
    let conn = srv.borrow_mut().accept(4242, 1001, "u:r:rild:s0").unwrap();
    let mut c = Client::new(Loop {
        srv: srv.clone(),
        conn,
        now: 1,
        queue: VecDeque::new(),
    });
    c.hello().unwrap();
    c.poll();
    let txn = c.route_lookup(request()).unwrap();
    pump(&srv, 1);
    c.poll();
    c.take_reply(txn).unwrap().unwrap();
    srv.borrow_mut().engine().qmi_mut().external_connect(1);
    pump(&srv, 2);
    assert!(c.poll().iter().any(|n| matches!(
        n,
        Notice::Iface {
            event: IfaceEvent::Up,
            ..
        }
    )));
    // the connection breaks, the call ends while the module is away
    srv.borrow_mut().close(3, conn);
    assert_eq!(c.transport_lost(), vec![Notice::RestartStart]);
    srv.borrow_mut()
        .engine()
        .qmi_mut()
        .external_disconnect(1, 3, 26);
    pump(&srv, 4);
    // the daemon restarts and is not ready when the library comes back
    let b = server(&net);
    let back = b.borrow_mut().accept(4242, 1001, "u:r:rild:s0").unwrap();
    c.transport_mut().srv = b.clone();
    c.transport_mut().conn = back;
    c.transport_mut().now = 5;
    c.reconnected().unwrap();
    assert!(c.poll().is_empty(), "the answer says not ready");
    b.borrow_mut().on_service_event(10, ServiceEvent::ModemUp);
    pump(&b, 10);
    let notices = c.poll();
    let down = notices.iter().position(is_down).unwrap();
    let done = notices
        .iter()
        .position(|n| *n == Notice::RestartDone)
        .unwrap();
    assert!(done < down, "{notices:?}");
}

/// A Down the daemon has written is read before the library gives the connection up, as it does when
/// the module is slow: the daemon freed the number at the write and does not say it again.
#[test]
fn a_down_the_daemon_has_written_is_read_before_the_connection_is_given_up() {
    let srv = server(&SharedNet::new());
    srv.borrow_mut().on_service_event(0, ServiceEvent::ModemUp);
    pump(&srv, 0);
    let conn = srv.borrow_mut().accept(4242, 1001, "u:r:rild:s0").unwrap();
    let mut c = Client::new(Loop {
        srv: srv.clone(),
        conn,
        now: 1,
        queue: VecDeque::new(),
    });
    c.hello().unwrap();
    c.poll();
    let txn = c.route_lookup(request()).unwrap();
    pump(&srv, 1);
    c.poll();
    let link = match c.take_reply(txn).unwrap().unwrap() {
        dataos_nicm_compat::Reply::Route { link, .. } => link,
        other => panic!("{other:?}"),
    };
    srv.borrow_mut()
        .engine()
        .qmi_mut()
        .external_connect(link + 1);
    pump(&srv, 2);
    c.poll();
    // the call ends and the daemon writes the Down, which the library has not read
    srv.borrow_mut()
        .engine()
        .qmi_mut()
        .external_disconnect(link + 1, 3, 26);
    pump(&srv, 3);
    let held = c.drain();
    assert!(held.iter().any(is_down), "{held:?}");
    assert_eq!(c.transport_lost(), vec![Notice::RestartStart]);
}
