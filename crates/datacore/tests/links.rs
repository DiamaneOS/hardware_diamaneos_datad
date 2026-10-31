// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! What the layer above asks of the links of the engine: whether the follower of a call has
//! seen it connected, a call on a link of its own, the reserve over links not on hold, and whether the
//! links of an earlier instance were kept.
use dataos_datacore::engine::ServiceEvent;
use dataos_datacore::sim::{pump, SimModem};
use dataos_datacore::*;
use dataos_netcfg::{FakeNet, SharedNet};
use dataos_qmi::wds;

type E = Engine<SimModem, FakeNet>;

fn up_with(cfg: Config) -> E {
    let mut e = Engine::new(cfg, SimModem::new(), FakeNet::new());
    // a call exists only when a module starts it
    e.qmi_mut().require_call = true;
    e.on_service_event(0, ServiceEvent::ModemUp);
    pump(&mut e, 0);
    assert!(e.is_ready());
    e
}

fn up() -> E {
    up_with(Config::default())
}

fn attach(e: &mut E) -> CallId {
    e.attach_call(1, 1, Priority::Normal, Family::V4).unwrap()
}

#[test]
fn a_follower_has_seen_the_call_connected_from_the_status_to_its_end() {
    // the settings never arrive, so the leg stays where it is after the status
    let mut e = up_with(Config {
        qmi_timeout_ms: 1_000_000,
        ..Config::default()
    });
    let id = attach(&mut e);
    pump(&mut e, 1);
    assert!(!e.call_seen_connected(id), "nothing is connected yet");
    assert!(!e.call_seen_connected(999));
    e.qmi_mut().mute.push(wds::id::GET_RUNTIME_SETTINGS);
    e.qmi_mut().external_connect(1);
    pump(&mut e, 2);
    assert!(e.call_up_families(id).is_empty(), "it is not up");
    assert!(e.call_seen_connected(id), "but it saw the status");
}

#[test]
fn a_follower_that_finished_has_seen_it_and_not_any_more_after_the_end() {
    let mut e = up();
    let id = attach(&mut e);
    pump(&mut e, 1);
    e.qmi_mut().external_connect(1);
    pump(&mut e, 2);
    assert_eq!(e.call_up_families(id), vec![Family::V4]);
    assert!(e.call_seen_connected(id));
    e.qmi_mut().external_disconnect(1, 3, 26);
    pump(&mut e, 3);
    assert!(e.call_up_families(id).is_empty());
    assert!(
        !e.call_seen_connected(id),
        "the flag is cleared at the disconnect"
    );
}

#[test]
fn a_follower_that_saw_the_status_and_could_not_get_the_settings_keeps_the_flag() {
    // The flag is nicmd's +0x28, which stays until the disconnect. The leg that saw the
    // status ended because the settings were refused, and the other family keeps the call open.
    let mut e = up();
    let id = attach(&mut e);
    e.attach_family(1, id, Family::V6).unwrap();
    pump(&mut e, 1);
    e.qmi_mut()
        .reject
        .push((wds::SERVICE, wds::id::GET_RUNTIME_SETTINGS));
    e.qmi_mut().external_connect(1);
    pump(&mut e, 2);
    assert!(e.call_up_families(id).is_empty(), "it never came up");
    assert!(!e.call_is_closed(id), "the other family still follows");
    assert!(e.call_seen_connected(id), "the flag outlives the leg");
}

#[test]
fn the_flag_goes_with_the_end_of_the_call_and_not_with_a_leg() {
    let mut e = up();
    let id = attach(&mut e);
    pump(&mut e, 1);
    e.qmi_mut().external_connect(1);
    pump(&mut e, 2);
    assert!(e.call_seen_connected(id));
    // a modem restart ends the call: the flag is gone with it
    e.on_service_event(5, ServiceEvent::ModemDown);
    assert!(!e.call_seen_connected(id));
}

#[test]
fn the_first_look_for_a_call_is_done_with_an_answer_and_failed_with_the_deadline() {
    let mut e = up_with(Config {
        qmi_timeout_ms: 1_000,
        ..Config::default()
    });
    let id = attach(&mut e);
    assert_eq!(e.call_look(id), Look::Pending, "nothing has been asked yet");
    assert_eq!(e.call_look(999), Look::Failed, "there is no such call");
    // the settings request gets no answer
    e.qmi_mut().mute.push(wds::id::GET_RUNTIME_SETTINGS);
    pump(&mut e, 1);
    assert_eq!(e.call_look(id), Look::Pending, "the look is under way");
    e.tick(5_000);
    pump(&mut e, 5_000);
    assert_eq!(e.call_look(id), Look::Failed, "no answer is no look");
    assert!(!e.call_seen_connected(id));
    // an answer that names no call is a look
    let mut f = up();
    let other = attach(&mut f);
    pump(&mut f, 1);
    assert_eq!(
        f.call_look(other),
        Look::Done,
        "no call on the modem is an answer"
    );
}

#[test]
fn a_leg_that_ended_does_not_keep_the_look_open() {
    let mut e = up();
    // the second binding of a mux is refused: the leg of the other family ends
    e.qmi_mut().reject_bind_mux_requests.push(1);
    let id = attach(&mut e);
    e.attach_family(1, id, Family::V6).unwrap();
    pump(&mut e, 1);
    assert_eq!(e.call_families(id), vec![Family::V4], "one leg is left");
    assert_eq!(e.call_look(id), Look::Done, "and it has looked");
}

/// A call with no leg alive has not looked, and a dual-stack call is looked at only when both legs have
/// answered, whatever the first one found.
#[test]
fn a_call_without_a_live_leg_or_with_a_leg_still_looking_has_not_looked() {
    let mut e = up();
    e.qmi_mut().reject_bind_mux_requests.push(0);
    let id = attach(&mut e);
    pump(&mut e, 1);
    assert!(e.call_families(id).is_empty(), "the only leg ended");
    assert_eq!(e.call_look(id), Look::Failed);
    // the leg of one family has looked and the other has not: the call has not looked yet, and when the
    // deadline of the second comes it has not looked at all
    let mut f = up_with(Config {
        qmi_timeout_ms: 1_000,
        ..Config::default()
    });
    f.qmi_mut().mute_settings_requests.push(1);
    let id = attach(&mut f);
    f.attach_family(1, id, Family::V6).unwrap();
    pump(&mut f, 1);
    assert_eq!(f.call_families(id).len(), 2);
    assert_eq!(f.call_look(id), Look::Pending);
    f.tick(5_000);
    pump(&mut f, 5_000);
    assert_eq!(f.call_look(id), Look::Failed);
}

/// An answer that says the request itself failed (a stack failure code) tells nothing about the call.
#[test]
fn an_answer_that_says_the_request_failed_is_no_look() {
    let mut e = up();
    e.qmi_mut()
        .reject
        .push((wds::SERVICE, wds::id::GET_RUNTIME_SETTINGS));
    let id = attach(&mut e);
    pump(&mut e, 1);
    assert_eq!(e.call_look(id), Look::Failed);
}

#[test]
fn a_call_found_by_the_first_look_has_been_looked_for() {
    let mut e = up();
    e.qmi_mut().external_connect(1);
    let id = attach(&mut e);
    pump(&mut e, 1);
    assert_eq!(e.call_up_families(id), vec![Family::V4]);
    assert_eq!(e.call_look(id), Look::Done);
    assert!(e.call_seen_connected(id));
}

#[test]
fn a_call_can_start_on_the_link_asked_for_and_on_no_other() {
    let mut e = up();
    let id = e
        .attach_call_at(1, 3, 1, Priority::Normal, Family::V4)
        .unwrap();
    assert_eq!(e.call_link(id), Some(3));
    assert_eq!(e.free_links(), 14);
    // a link in use, and one that is not there
    assert_eq!(
        e.attach_call_at(1, 3, 1, Priority::Normal, Family::V4),
        Err(StartError::NoLink)
    );
    assert_eq!(
        e.attach_call_at(1, 15, 1, Priority::Normal, Family::V4),
        Err(StartError::NoLink)
    );
    // the reserve does not stop it: the call is the module's, and it has the link already
    for n in 0..13usize {
        let l = if n >= 3 { n + 1 } else { n };
        e.attach_call_at(1, l, 1, Priority::Normal, Family::V4)
            .unwrap();
    }
    assert_eq!(e.free_links(), 1);
    assert!(e
        .attach_call_at(1, 14, 1, Priority::Normal, Family::V4)
        .is_ok());
    assert_eq!(e.free_links(), 0);
}

#[test]
fn a_call_of_the_module_can_attach_to_a_link_that_is_marked_broken() {
    // the call is the module's and runs on the link already, whatever the last try to make it said
    let mut e = Engine::new(
        Config {
            link_count: 2,
            reserve_links: 0,
            ..Config::default()
        },
        SimModem::new(),
        FakeNet::new(),
    );
    e.net_mut().mux_limit = 1;
    e.qmi_mut().require_call = true;
    e.on_service_event(0, ServiceEvent::ModemUp);
    pump(&mut e, 0);
    let first = e
        .attach_call_at(1, 0, 1, Priority::Normal, Family::V4)
        .unwrap();
    // an emergency start tries link 1, which cannot be made: it is broken now
    let sos = e
        .attach_call(2, 1, Priority::Emergency, Family::V4)
        .unwrap();
    pump(&mut e, 2);
    assert!(e.call_is_closed(sos));
    e.release_call(3, sos).unwrap();
    assert_eq!(
        e.attach_call(3, 1, Priority::Normal, Family::V4),
        Err(StartError::NoLink),
        "an ordinary call does not get a broken link"
    );
    assert!(e
        .attach_call_at(4, 1, 1, Priority::Normal, Family::V4)
        .is_ok());
    let _ = first;
}

#[test]
fn the_reserve_is_counted_over_links_that_are_not_on_hold() {
    let mut e = up_with(Config {
        link_count: 3,
        reserve_links: 1,
        ..Config::default()
    });
    assert_eq!(e.free_usable_links(), 3);
    e.hold_link(0, 1_000);
    e.hold_link(1, 1_000);
    assert_eq!(e.link_hold_until(0), 1_000);
    assert_eq!(e.link_hold_until(7), 0);
    assert_eq!(e.free_usable_links(), 1, "two are on hold");
    // one link is free and not on hold, and it is the reserve: an ordinary call is refused
    assert_eq!(
        e.attach_call(1, 1, Priority::Normal, Family::V4),
        Err(StartError::NoLink)
    );
    // an emergency call takes it
    assert!(e.attach_call(1, 1, Priority::Emergency, Family::V4).is_ok());
    // the hold ends with its time
    e.tick(1_000);
    assert_eq!(e.free_usable_links(), 2);
}

#[test]
fn links_kept_from_an_earlier_instance_are_told() {
    let net = SharedNet::new();
    let make = |net: &SharedNet| {
        let mut e = Engine::new(Config::default(), SimModem::new(), net.clone());
        assert!(!e.links_adopted());
        e.on_service_event(0, ServiceEvent::ModemUp);
        pump(&mut e, 0);
        e
    };
    let first = make(&net);
    assert!(
        !first.links_adopted(),
        "a device set up afresh keeps nothing"
    );
    assert!(first.adopted_links().is_empty());
    drop(first);
    let mut second = make(&net);
    assert!(second.links_adopted());
    assert_eq!(second.adopted_links(), (0..15).collect::<Vec<_>>());
    second.on_service_event(5, ServiceEvent::ModemDown);
    assert!(!second.links_adopted());
    assert!(second.adopted_links().is_empty());
}

#[test]
fn a_probe_that_is_waiting_is_no_sign_of_a_connected_call() {
    let mut e = up_with(Config {
        qmi_timeout_ms: 1_000_000,
        ..Config::default()
    });
    // the first request of the follower for the settings is not answered
    e.qmi_mut().mute.push(wds::id::GET_RUNTIME_SETTINGS);
    let id = attach(&mut e);
    pump(&mut e, 1);
    assert!(!e.call_seen_connected(id));
}
