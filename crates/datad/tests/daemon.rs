// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The main loop over fake sockets, with the simulated modem behind the fake name service.
//! No modem, no phone. Made-up values only.
mod support;
use dataos_datad::daemon::{Clock, Poller};
use dataos_datad::ipc::IpcFault;
use dataos_datad::transport::Fault;
use dataos_wire::*;
use std::cell::Cell;
use std::os::fd::RawFd;
use support::*;

fn route(apn: &str) -> RouteRequest {
    RouteRequest {
        slot: 0,
        family: Family::V4,
        apn: Some(apn.into()),
        apn_type: 1,
        apn_type_mask: 1,
    }
}

fn events_of(heard: &[Notify]) -> Vec<(u8, IfaceEvent)> {
    heard
        .iter()
        .filter_map(|n| match n {
            Notify::Event { link, event, .. } => Some((*link, *event)),
            _ => None,
        })
        .collect()
}

#[test]
fn the_modem_announcing_itself_brings_the_data_path_up_and_the_module_is_told() {
    let mut d = rig();
    let m = module(&mut d, 4242, 0);
    assert!(d.server().engine().is_ready());
    say(&mut d, m, Request::Hello);
    settle(&mut d, 1);
    let got = heard(&mut d, m);
    assert!(got.contains(&Notify::HelloAck { ready: true }));
    // the bring-up asked the modem for the data format and the data port
    assert!(!sim(&mut d).sim.requests.is_empty());
    assert_eq!(d.stats().accepted, 1);
}

#[test]
fn a_module_that_connects_before_the_modem_is_told_when_the_data_path_is_ready() {
    let mut d = rig_without_modem(SimQrtr::new());
    let m = module(&mut d, 4242, 0);
    say(&mut d, m, Request::Hello);
    settle(&mut d, 1);
    assert_eq!(heard(&mut d, m), vec![Notify::HelloAck { ready: false }]);
    sim(&mut d).announce_modem();
    settle(&mut d, 2);
    assert_eq!(heard(&mut d, m), vec![Notify::Ready { ready: true }]);
}

#[test]
fn a_call_goes_through_the_whole_path_from_lookup_to_events() {
    let mut d = rig();
    let m = module(&mut d, 4242, 0);
    say(
        &mut d,
        m,
        Request::RouteLookup {
            txn: 7,
            req: route("internet.example"),
        },
    );
    settle(&mut d, 1);
    let got = heard(&mut d, m);
    assert!(got.iter().any(|n| matches!(
        n,
        Notify::RouteReply {
            txn: 7,
            code: ResultCode::Ok,
            link: 0,
            ..
        }
    )));
    // the module's own call connects on the mux ID of the link
    sim(&mut d).sim.external_connect(1);
    sim(&mut d).pump_sim();
    settle(&mut d, 2);
    let got = heard(&mut d, m);
    let events = events_of(&got);
    assert_eq!(events.first(), Some(&(0, IfaceEvent::Up)));
    assert!(events.iter().any(|(_, e)| matches!(
        e,
        IfaceEvent::NewAddr {
            family: Family::V4,
            prefix: 30,
            ..
        }
    )));
}

#[test]
fn a_modem_restart_ends_the_call_and_the_data_path_comes_back_when_the_modem_does() {
    let mut d = rig();
    let m = module(&mut d, 4242, 0);
    say(
        &mut d,
        m,
        Request::RouteLookup {
            txn: 7,
            req: route("internet.example"),
        },
    );
    settle(&mut d, 1);
    sim(&mut d).sim.external_connect(1);
    sim(&mut d).pump_sim();
    settle(&mut d, 2);
    heard(&mut d, m);
    // the modem goes: the name service says so, the engine ends the call and is not ready
    sim(&mut d).restart_modem(false);
    settle(&mut d, 3);
    let got = heard(&mut d, m);
    assert!(got.contains(&Notify::Ready { ready: false }));
    assert!(events_of(&got).iter().any(|(_, e)| matches!(
        e,
        IfaceEvent::Down(EndReason::Local(LocalReason::ModemRestart))
    )));
    assert!(!d.server().engine().is_ready());
    // and when it registers again, the data format is set again and the module hears of it
    sim(&mut d).announce_modem();
    settle(&mut d, 4);
    assert!(d.server().engine().is_ready());
    assert!(heard(&mut d, m).contains(&Notify::Ready { ready: true }));
    assert_eq!(d.link_stats().resets, 0);
}

#[test]
fn a_send_that_finds_no_room_goes_out_at_the_next_step_and_the_bring_up_still_ends() {
    // the first send finds no room, and so does its first retry for lack of buffers
    let mut q = SimQrtr::new();
    q.fake.send_faults.extend([Fault::Retry, Fault::Exhausted]);
    let mut d = rig_with(q);
    let m = module(&mut d, 4242, 0);
    say(&mut d, m, Request::Hello);
    settle(&mut d, 1);
    assert!(d.server().engine().is_ready());
    assert!(heard(&mut d, m).contains(&Notify::HelloAck { ready: true }));
    let stats = d.link_stats();
    assert_eq!(stats.queued, 1);
    assert_eq!(stats.exhausted, 1);
    assert_eq!(stats.send_dropped, 0);
}

#[test]
fn the_name_service_going_away_is_a_modem_restart_and_the_lookups_are_made_again() {
    let mut d = rig();
    let m = module(&mut d, 4242, 0);
    assert!(d.server().engine().is_ready());
    // the control socket is the first one the link opened
    let ctrl = sim(&mut d).fake.open_sockets()[0];
    sim(&mut d).fake.recv_faults.insert(ctrl, Fault::Reset);
    settle(&mut d, 1_000);
    assert!(heard(&mut d, m).contains(&Notify::Ready { ready: false }));
    assert!(!d.server().engine().is_ready());
    assert_eq!(d.link_stats().resets, 1);
    // after the wait, the lookups are made and the modem is up again
    settle(&mut d, 1_100);
    assert!(d.server().engine().is_ready());
    assert!(heard(&mut d, m).contains(&Notify::Ready { ready: true }));
}

#[test]
fn a_server_that_registers_on_the_local_node_is_not_the_modem() {
    let mut q = SimQrtr::new();
    q.fake.announce(1, 1, LOCAL, 7);
    q.fake.announce(0x1a, 1, LOCAL, 8);
    q.fake.announce(0x2f, 1, LOCAL, 9);
    let mut d = rig_without_modem(q);
    let m = module(&mut d, 4242, 0);
    say(&mut d, m, Request::Hello);
    settle(&mut d, 1);
    assert!(!d.server().engine().is_ready());
    assert_eq!(heard(&mut d, m), vec![Notify::HelloAck { ready: false }]);
    assert_eq!(
        d.server()
            .engine()
            .qmi_mut()
            .services()
            .stats()
            .local_refused,
        3
    );
}

#[test]
fn only_the_radio_process_is_kept() {
    let mut d = rig();
    let wrong_uid = d.ipc().connect(10, 2000, LABEL);
    let wrong_label = d.ipc().connect(11, 1001, "u:r:hal_radio_default:s0");
    let ok = d.ipc().connect(12, 1001, LABEL);
    settle(&mut d, 0);
    assert!(d.ipc().is_closed(wrong_uid));
    assert!(d.ipc().is_closed(wrong_label));
    assert!(!d.ipc().is_closed(ok));
    assert_eq!(d.stats().accepted, 1);
    assert_eq!(d.stats().rejected, 2);
    assert_eq!(d.connections(), 1);
}

#[test]
fn a_message_that_does_not_decode_closes_the_connection() {
    let mut d = rig();
    let m = module(&mut d, 4242, 0);
    d.ipc().push(m, &[1, 2, 3]);
    settle(&mut d, 1);
    assert!(d.ipc().is_closed(m));
    assert_eq!(d.stats().closed_protocol, 1);
    assert_eq!(d.connections(), 0);
}

#[test]
fn a_peer_that_hangs_up_or_breaks_is_closed_and_counted() {
    let mut d = rig();
    let a = module(&mut d, 1, 0);
    let b = module(&mut d, 2, 0);
    d.ipc().hang_up(a);
    d.ipc().break_conn(b);
    settle(&mut d, 1);
    assert!(d.ipc().is_closed(a) && d.ipc().is_closed(b));
    let s = d.stats();
    assert_eq!((s.closed_by_peer, s.closed_fault), (1, 1));
    assert_eq!(d.connections(), 0);
}

#[test]
fn a_connection_that_cannot_take_what_is_written_keeps_it_and_gets_it_later() {
    let mut d = rig();
    let m = module(&mut d, 4242, 0);
    heard(&mut d, m);
    d.ipc().block_writes(m, true);
    say(&mut d, m, Request::Hello);
    settle(&mut d, 1);
    assert!(heard(&mut d, m).is_empty());
    assert!(!d.ipc().is_closed(m));
    d.ipc().block_writes(m, false);
    settle(&mut d, 2);
    assert_eq!(heard(&mut d, m), vec![Notify::HelloAck { ready: true }]);
}

#[test]
fn a_module_that_does_not_read_for_ten_seconds_is_closed_and_its_calls_wait_for_it() {
    let mut d = rig();
    let m = module(&mut d, 4242, 0);
    say(
        &mut d,
        m,
        Request::RouteLookup {
            txn: 7,
            req: route("internet.example"),
        },
    );
    settle(&mut d, 1);
    heard(&mut d, m);
    sim(&mut d).sim.external_connect(1);
    sim(&mut d).pump_sim();
    d.ipc().block_writes(m, true);
    settle(&mut d, 2);
    // not yet at 9.9 s of waiting, gone at 10 s (the first message waited from time 2)
    settle(&mut d, 10_001);
    assert!(!d.ipc().is_closed(m));
    settle(&mut d, 10_002);
    assert!(d.ipc().is_closed(m));
    assert_eq!(d.stats().closed_blocked, 1);
    // the call is still there for a connection of the same process
    let again = module(&mut d, 4242, 10_003);
    say(&mut d, again, Request::Hello);
    settle(&mut d, 10_004);
    assert!(heard(&mut d, again).contains(&Notify::HelloAck { ready: true }));
}

#[test]
fn a_write_that_fails_closes_the_connection_and_the_next_step_comes_at_once() {
    let mut d = rig();
    let m = module(&mut d, 4242, 0);
    heard(&mut d, m);
    say(&mut d, m, Request::Hello);
    d.ipc().fail_writes(m);
    // the message is read, the answer cannot be written, the connection is closed, and a closed
    // connection can make the server say more, so the step says so
    assert!(d.step(1));
    assert!(d.ipc().is_closed(m));
    assert_eq!(d.connections(), 0);
    let s = d.stats();
    assert_eq!((s.closed_fault, s.closed_blocked), (1, 0));
    assert!(!d.step(2));
}

#[test]
fn a_flood_of_requests_is_read_in_bounded_steps() {
    let mut d = rig();
    let m = module(&mut d, 4242, 0);
    heard(&mut d, m);
    for _ in 0..20 {
        say(&mut d, m, Request::Hello);
    }
    // 8 per step: more to do after the first, and after the second, none after the third
    assert!(d.step(1));
    assert!(d.step(1));
    assert!(!d.step(1));
    assert_eq!(heard(&mut d, m).len(), 20);
    // exactly the number a step takes does not leave anything, and the step cannot tell
    for _ in 0..8 {
        say(&mut d, m, Request::Hello);
    }
    assert!(d.step(2));
    assert!(!d.step(2));
}

#[test]
fn connections_are_taken_in_bounded_steps() {
    let mut d = rig();
    for pid in 0..12 {
        d.ipc().connect(pid, 1001, LABEL);
    }
    // 8 per step: four are kept, the rest turned away by the server's limit of four
    assert!(d.step(0));
    assert_eq!(d.stats().accepted + d.stats().rejected, 8);
    assert!(!d.step(0));
    assert_eq!(d.stats().accepted, 4);
    assert_eq!(d.stats().rejected, 8);
    // a fault of the listener is counted and does not stop the loop
    d.ipc().accept_fault = Some(IpcFault::Gone);
    d.step(1);
    assert_eq!(d.stats().accept_faults, 1);
    d.step(2);
    assert_eq!(d.stats().accept_faults, 1);
}

#[test]
fn the_loop_sleeps_until_the_next_timer_and_not_longer_than_a_second() {
    let mut d = rig_without_modem(SimQrtr::new());
    settle(&mut d, 0);
    // nothing to wait for but the retry of the lookups, which are open
    assert_eq!(d.wait_ms(0), 1_000);
    // a bring-up deadline of the engine is a timer: the engine retries a failed bring-up
    sim(&mut d).announce_modem();
    sim(&mut d).sim.mute_service.push(dataos_qmi::wda::SERVICE);
    settle(&mut d, 100);
    let wait = d.wait_ms(100);
    assert!((1..=1_000).contains(&wait), "{wait}");
    let next = d.server().next_deadline().unwrap();
    assert_eq!(wait, (next - 100).clamp(1, 1_000));
    // a timer that is due waits one millisecond
    assert_eq!(d.wait_ms(next + 5_000), 1);
}

#[test]
fn some_output_that_waits_for_room_makes_the_loop_look_again_soon() {
    let mut d = rig();
    let m = module(&mut d, 4242, 0);
    assert_eq!(d.wait_ms(1), 1_000);
    d.ipc().block_writes(m, true);
    say(&mut d, m, Request::Hello);
    settle(&mut d, 1);
    assert_eq!(d.wait_ms(1), 25);
    // and so does a send toward the modem that waits for room
    d.ipc().block_writes(m, false);
    settle(&mut d, 2);
    assert_eq!(d.wait_ms(2), 1_000);
    let q = d.server().engine().qmi_mut();
    assert!(!q.blocked());
}

/// A clock that the poller moves: waiting for a time is what makes it pass.
struct Shared<'a>(&'a Cell<u64>);

impl Clock for Shared<'_> {
    fn now_ms(&mut self) -> u64 {
        self.0.get()
    }
}

struct SleepPoller<'a> {
    now: &'a Cell<u64>,
    waits: Vec<u64>,
    fail: bool,
}

impl Poller for SleepPoller<'_> {
    fn wait(&mut self, _fds: &[RawFd], timeout_ms: u64) -> std::io::Result<()> {
        self.waits.push(timeout_ms);
        self.now.set(self.now.get() + timeout_ms.max(1));
        if self.fail {
            Err(std::io::Error::other("poll"))
        } else {
            Ok(())
        }
    }
}

fn run_for(d: &mut Rig, steps: u32, fail: bool) -> Vec<u64> {
    let time = Cell::new(0u64);
    let mut poller = SleepPoller {
        now: &time,
        waits: Vec::new(),
        fail,
    };
    let mut clock = Shared(&time);
    let n = Cell::new(0);
    d.run(
        &mut clock,
        &mut poller,
        &|| {
            n.set(n.get() + 1);
            n.get() > steps
        },
        &mut |_| (),
        &mut |_| (),
    );
    poller.waits
}

#[test]
fn run_steps_waits_as_long_as_it_is_told_and_stops_when_asked() {
    let mut d = rig();
    let waits = run_for(&mut d, 6, false);
    assert_eq!(waits.len(), 6);
    // the fake sockets have no descriptors to wake the poller, so the loop sleeps as long as it may
    assert!(d.server().engine().is_ready());
    assert!(waits.iter().all(|w| *w <= 1_000));
    assert_eq!(*waits.last().unwrap(), 1_000);
    assert_eq!(d.stats().poll_errors, 0);
}

#[test]
fn a_failing_poll_is_counted_and_the_loop_goes_on() {
    let mut d = rig();
    run_for(&mut d, 3, true);
    assert_eq!(d.stats().poll_errors, 3);
}

#[test]
fn what_the_engine_wants_written_down_goes_to_the_note_callback() {
    let mut d = rig();
    // a boot ID that cannot be read is noted
    d.server().engine().net_mut().boot_id_unreadable = true;
    let time = Cell::new(0u64);
    let mut poller = SleepPoller {
        now: &time,
        waits: Vec::new(),
        fail: false,
    };
    let mut clock = Shared(&time);
    let n = Cell::new(0);
    let mut notes = Vec::new();
    d.run(
        &mut clock,
        &mut poller,
        &|| {
            n.set(n.get() + 1);
            n.get() > 8
        },
        &mut |note| notes.push(note),
        &mut |_| (),
    );
    assert!(!notes.is_empty());
    assert!(notes
        .iter()
        .all(|n| *n == dataos_datacore::Note::BootIdUnreadable));
    // and the notes were taken: none are left
    assert!(d.take_notes().is_empty());
}

#[test]
fn a_timer_fires_in_the_step_whose_time_it_is() {
    // a call the module started keeps its link when the module's connection closes, for 30 s
    let mut d = rig();
    let m = module(&mut d, 4242, 0);
    say(
        &mut d,
        m,
        Request::RouteLookup {
            txn: 7,
            req: route("internet.example"),
        },
    );
    settle(&mut d, 1_000);
    sim(&mut d).sim.external_connect(1);
    sim(&mut d).pump_sim();
    settle(&mut d, 1_001);
    let total = d.server().engine().link_total();
    assert_eq!(d.server().engine().free_links(), total - 1);
    d.ipc().hang_up(m);
    settle(&mut d, 2_000);
    let until = 2_000 + dataos_datad::server::ServerConfig::default().orphan_grace_ms;
    assert_eq!(d.server().next_deadline(), Some(until));
    // one millisecond early the link is still kept, and at the time it goes
    settle(&mut d, until - 1);
    assert_eq!(d.server().engine().free_links(), total - 1);
    settle(&mut d, until);
    assert_eq!(d.server().engine().free_links(), total);
}

#[test]
fn control_packets_are_read_a_step_at_a_time_in_bounded_numbers() {
    let mut d = rig();
    settle(&mut d, 0);
    let ctrl = sim(&mut d).fake.open_sockets()[0];
    let ns = sim(&mut d).fake.name_service();
    for _ in 0..40 {
        sim(&mut d).fake.deliver(ctrl, ns, &[1, 2, 3]);
    }
    assert!(d.step(1));
    assert_eq!(d.link_stats().bad_control, 32);
    assert!(!d.step(1));
    assert_eq!(d.link_stats().bad_control, 40);
}

#[test]
fn a_module_with_more_queued_for_it_than_the_server_keeps_is_closed() {
    let mut d = rig();
    let m = module(&mut d, 4242, 0);
    heard(&mut d, m);
    let hello = Request::Hello.encode().unwrap();
    // the server keeps 256 notifications for a connection, and marks it when it has to drop one
    for _ in 0..257 {
        d.server().on_datagram(1, 1, &hello).unwrap();
    }
    assert!(d.server().overflowed(1));
    d.step(1);
    assert!(d.ipc().is_closed(m));
    assert_eq!(d.stats().closed_blocked, 1);
}

#[test]
fn a_module_that_does_not_read_and_keeps_asking_is_closed_when_the_backlog_is_full() {
    let mut d = rig();
    let m = module(&mut d, 4242, 0);
    heard(&mut d, m);
    d.ipc().block_writes(m, true);
    let hello = Request::Hello.encode().unwrap();
    // 128 a step, drained into the daemon's backlog of 256, which is exactly full after the second
    for step in 0..2 {
        for _ in 0..128 {
            d.server().on_datagram(1, 1, &hello).unwrap();
        }
        d.step(1 + step);
        assert!(!d.ipc().is_closed(m), "step {step}");
    }
    // and one more does not fit
    d.server().on_datagram(1, 1, &hello).unwrap();
    d.step(3);
    assert!(d.ipc().is_closed(m));
    assert_eq!(d.stats().closed_blocked, 1);
}

#[test]
fn a_send_toward_the_modem_that_waits_for_room_makes_the_loop_look_again_soon() {
    let mut d = rig();
    module(&mut d, 4242, 0);
    assert_eq!(d.wait_ms(1), 1_000);
    // the next call the daemon makes toward the modem finds no room
    let q = sim(&mut d);
    q.fake.send_faults.push_back(Fault::Retry);
    let link = d.server().engine().qmi_mut();
    let client = dataos_datacore::Qmi::open_client(link, dataos_qmi::wds::SERVICE).unwrap();
    let request = dataos_qmi::frame::Builder::request(1, dataos_qmi::wds::id::STOP_NETWORK)
        .build()
        .unwrap();
    dataos_datacore::Qmi::send(link, client, &request).unwrap();
    assert!(link.blocked());
    assert_eq!(d.wait_ms(1), 25);
    // after its time (2 s) it is dropped, and the loop sleeps long again
    d.step(2_001);
    assert_eq!(d.wait_ms(2_001), 1_000);
}

#[test]
fn the_loop_does_not_sleep_while_there_is_more_to_read() {
    let mut d = rig();
    let m = module(&mut d, 4242, 0);
    heard(&mut d, m);
    for _ in 0..20 {
        say(&mut d, m, Request::Hello);
    }
    // 8 and 8 and 4 messages: two steps leave more, the third finds the end
    let waits = run_for(&mut d, 3, false);
    assert_eq!(&waits[..2], &[0, 0]);
    assert!(waits[2] > 0);
    assert_eq!(heard(&mut d, m).len(), 20);
}

/// A Down a process is owed stays owed, and its number held, until the socket took it. One that waits
/// in the output of a connection that cannot take it is not delivered.
#[test]
fn a_down_owed_stays_owed_until_the_socket_has_taken_it() {
    let mut d = rig();
    let m = module(&mut d, 4242, 0);
    say(&mut d, m, Request::Hello);
    say(
        &mut d,
        m,
        Request::RouteLookup {
            txn: 7,
            req: route("internet.example"),
        },
    );
    settle(&mut d, 1);
    sim(&mut d).sim.external_connect(1);
    sim(&mut d).pump_sim();
    settle(&mut d, 2);
    assert!(events_of(&heard(&mut d, m)).contains(&(0, IfaceEvent::Up)));
    // the connection breaks and the call ends while the module is away
    d.ipc().hang_up(m);
    settle(&mut d, 3);
    sim(&mut d).sim.external_disconnect(1, 3, 26);
    sim(&mut d).pump_sim();
    settle(&mut d, 4);
    assert_eq!(d.server().owed_downs(), 1);
    // it comes back on a socket that takes nothing
    let again = module(&mut d, 4242, 5);
    d.ipc().block_writes(again, true);
    say(&mut d, again, Request::Hello);
    settle(&mut d, 6);
    assert!(heard(&mut d, again).is_empty());
    assert_eq!(d.server().owed_downs(), 1, "queued is not delivered");
    let other = module(&mut d, 99, 7);
    say(
        &mut d,
        other,
        Request::RouteLookup {
            txn: 8,
            req: route("other.example"),
        },
    );
    settle(&mut d, 8);
    let got = heard(&mut d, other);
    assert!(
        got.iter().any(|n| matches!(
            n,
            Notify::RouteReply {
                txn: 8,
                code: ResultCode::Ok,
                link,
                ..
            } if *link != 0
        )),
        "the number is held: {got:?}"
    );
    // the socket takes it
    d.ipc().block_writes(again, false);
    settle(&mut d, 9);
    assert!(events_of(&heard(&mut d, again))
        .iter()
        .any(|(l, e)| *l == 0 && matches!(e, IfaceEvent::Down(_))));
    assert_eq!(d.server().owed_downs(), 0);
}

/// A new process with the number of an old one is not the old one: the Down the old one is owed is not for it,
/// and the process that is owed it gets it when it comes back.
#[test]
fn a_down_owed_is_not_given_to_a_process_with_the_same_number_and_another_identity() {
    let mut d = rig();
    let m = module(&mut d, 4242, 0);
    say(&mut d, m, Request::Hello);
    say(
        &mut d,
        m,
        Request::RouteLookup {
            txn: 7,
            req: route("internet.example"),
        },
    );
    settle(&mut d, 1);
    sim(&mut d).sim.external_connect(1);
    sim(&mut d).pump_sim();
    settle(&mut d, 2);
    heard(&mut d, m);
    d.ipc().hang_up(m);
    settle(&mut d, 3);
    sim(&mut d).sim.external_disconnect(1, 3, 26);
    sim(&mut d).pump_sim();
    settle(&mut d, 4);
    assert_eq!(d.server().owed_downs(), 1);
    let other = module_as(&mut d, 4242, 77, 5);
    say(&mut d, other, Request::Hello);
    settle(&mut d, 6);
    assert!(!events_of(&heard(&mut d, other))
        .iter()
        .any(|(_, e)| matches!(e, IfaceEvent::Down(_))));
    assert_eq!(d.server().owed_downs(), 1);
    let again = module(&mut d, 4242, 7);
    say(&mut d, again, Request::Hello);
    settle(&mut d, 8);
    assert!(events_of(&heard(&mut d, again))
        .iter()
        .any(|(_, e)| matches!(e, IfaceEvent::Down(_))));
    assert_eq!(d.server().owed_downs(), 0);
}

/// F-B. A Down for a connected module whose socket fails on the write is not lost: the connection is closed,
/// the Down stays owed with its number held, and the module has it again on its next connection.
#[test]
fn a_down_whose_write_fails_is_given_again_on_the_next_connection() {
    let mut d = rig();
    let m = module(&mut d, 4242, 0);
    say(&mut d, m, Request::Hello);
    say(
        &mut d,
        m,
        Request::RouteLookup {
            txn: 7,
            req: route("internet.example"),
        },
    );
    settle(&mut d, 1);
    sim(&mut d).sim.external_connect(1);
    sim(&mut d).pump_sim();
    settle(&mut d, 2);
    assert!(events_of(&heard(&mut d, m)).contains(&(0, IfaceEvent::Up)));
    d.ipc().fail_writes(m);
    sim(&mut d).sim.external_disconnect(1, 3, 26);
    sim(&mut d).pump_sim();
    settle(&mut d, 3);
    assert!(d.ipc().is_closed(m));
    assert_eq!(d.server().owed_downs(), 1);
    let other = module(&mut d, 99, 4);
    say(
        &mut d,
        other,
        Request::RouteLookup {
            txn: 8,
            req: route("other.example"),
        },
    );
    settle(&mut d, 5);
    assert!(heard(&mut d, other).iter().any(|n| matches!(
        n,
        Notify::RouteReply {
            txn: 8,
            code: ResultCode::Ok,
            link,
            ..
        } if *link != 0
    )));
    let again = module(&mut d, 4242, 6);
    say(&mut d, again, Request::Hello);
    settle(&mut d, 7);
    assert!(events_of(&heard(&mut d, again))
        .iter()
        .any(|(l, e)| *l == 0 && matches!(e, IfaceEvent::Down(_))));
    assert_eq!(d.server().owed_downs(), 0);
}
