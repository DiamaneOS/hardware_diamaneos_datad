// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The lookup for a call the modem has up already, against the simulated modem.
use dataos_datacore::engine::ServiceEvent;
use dataos_datacore::sim::{pump, SimModem};
use dataos_datacore::*;
use dataos_netcfg::FakeNet;
use dataos_qmi::wds;
use dataos_qmi::Frame;

type E = Engine<SimModem, FakeNet>;

fn up() -> E {
    let mut e = Engine::new(Config::default(), SimModem::new(), FakeNet::new());
    e.on_service_event(0, ServiceEvent::ModemUp);
    pump(&mut e, 0);
    assert!(e.is_ready());
    e
}

fn query(family: Family) -> LookupQuery {
    LookupQuery {
        subscription: 2,
        family,
        apn: Some("internet.example".into()),
        apn_type: Some(0x11),
        apn_type_mask: Some(0x21),
        hint: LookupHint::default(),
    }
}

fn answer(e: &mut E, family: u8, tlvs: &[(u8, &[u8])]) {
    e.qmi_mut()
        .route_answers
        .insert(family, tlvs.iter().map(|(t, v)| (*t, v.to_vec())).collect());
}

/// Run a lookup to its end and give back the one event it makes.
fn run(e: &mut E, q: LookupQuery) -> (Option<usize>, bool) {
    e.start_lookup(5, 7, q).unwrap();
    pump(e, 5);
    done(e)
}

fn done(e: &mut E) -> (Option<usize>, bool) {
    let evs = e.take_events();
    match evs.as_slice() {
        [Event::LookupDone {
            token: 7,
            link,
            companion,
            ..
        }] => (*link, *companion),
        other => panic!("one lookup event expected, got {other:?}"),
    }
}

fn asked(e: &mut E) -> Vec<u16> {
    e.qmi_mut().wds_requests.clone()
}

/// The IP family byte of every route lookup request that reached the modem.
fn families_asked(e: &mut E) -> Vec<u8> {
    e.qmi_mut()
        .route_frames
        .iter()
        .map(|(_, b)| Frame::parse(b).unwrap().tlv(0x19).unwrap()[0])
        .collect()
}

#[test]
fn a_lookup_binds_the_subscription_asks_for_the_family_and_gets_the_link() {
    let mut e = up();
    answer(&mut e, 4, &[(0x10, &[3])]);
    assert_eq!(run(&mut e, query(Family::V4)), (Some(3), false));
    assert_eq!(
        asked(&mut e),
        [wds::id::BIND_SUBSCRIPTION, wds::id::ROUTE_LOOKUP]
    );
    assert_eq!(e.qmi_mut().bound_subscriptions, [2]);
    assert_eq!(families_asked(&mut e), [4]);
    // the request is the stock one: lookup type, APN, family, origin, APN type and mask
    let (client, bytes) = e.qmi_mut().route_frames[0].clone();
    let f = Frame::parse(&bytes).unwrap();
    assert_eq!(f.tlv(0x14), Some(&b"internet.example"[..]));
    assert_eq!(f.tlv(0x38), Some(&[0x11u8, 0, 0, 0][..]));
    assert_eq!(f.tlv(0x3e), Some(&[0x21u8, 0, 0, 0, 0, 0, 0, 0][..]));
    // and the lookup's client is gone with it
    assert!(e.qmi_mut().closed.contains(&client));
    assert!(e.qmi_mut().client_ids(wds::SERVICE).is_empty());
}

#[test]
fn a_mux_id_names_the_link_it_belongs_to() {
    let mut e = up();
    let base = Config::default().base_mux_id;
    answer(&mut e, 6, &[(0x13, &[base + 4])]);
    assert_eq!(run(&mut e, query(Family::V6)), (Some(4), false));
    // below the first mux ID there is no link
    answer(&mut e, 6, &[(0x13, &[base - 1])]);
    answer(&mut e, 4, &[]);
    assert_eq!(run(&mut e, query(Family::V6)), (None, false));
}

#[test]
fn an_instance_and_a_mux_that_name_different_links_name_none() {
    let mut e = up();
    let base = Config::default().base_mux_id;
    answer(&mut e, 4, &[(0x10, &[2]), (0x13, &[base + 2])]);
    assert_eq!(run(&mut e, query(Family::V4)), (Some(2), false));
    answer(&mut e, 4, &[(0x10, &[2]), (0x13, &[base + 3])]);
    answer(&mut e, 6, &[]);
    assert_eq!(run(&mut e, query(Family::V4)), (None, false));
}

#[test]
fn a_link_the_engine_does_not_have_is_not_named() {
    let mut e = up();
    let n = Config::default().link_count;
    answer(&mut e, 4, &[(0x10, &[n - 1])]);
    assert_eq!(
        run(&mut e, query(Family::V4)),
        (Some(usize::from(n - 1)), false)
    );
    answer(&mut e, 4, &[(0x10, &[n])]);
    answer(&mut e, 6, &[]);
    assert_eq!(run(&mut e, query(Family::V4)), (None, false));
}

#[test]
fn a_call_on_another_data_transport_is_not_ours() {
    let mut e = up();
    let (ty, iface) = Config::default().endpoint;
    let ep = |t: u32, i: u32| [t.to_le_bytes(), i.to_le_bytes()].concat();
    answer(&mut e, 4, &[(0x10, &[1]), (0x12, &ep(ty, iface))]);
    assert_eq!(run(&mut e, query(Family::V4)), (Some(1), false));
    for other in [ep(ty, iface + 1), ep(ty + 1, iface)] {
        answer(&mut e, 4, &[(0x10, &[1]), (0x12, &other)]);
        answer(&mut e, 6, &[]);
        assert_eq!(run(&mut e, query(Family::V4)), (None, false));
    }
}

#[test]
fn the_companion_family_is_asked_when_the_family_finds_nothing() {
    let mut e = up();
    answer(&mut e, 6, &[(0x10, &[5])]);
    assert_eq!(run(&mut e, query(Family::V4)), (Some(5), true));
    assert_eq!(families_asked(&mut e), [4, 6]);
    // the other way round
    let mut e = up();
    answer(&mut e, 4, &[(0x10, &[5])]);
    assert_eq!(run(&mut e, query(Family::V6)), (Some(5), true));
    assert_eq!(families_asked(&mut e), [6, 4]);
    assert_eq!(
        asked(&mut e),
        [
            wds::id::BIND_SUBSCRIPTION,
            wds::id::ROUTE_LOOKUP,
            wds::id::ROUTE_LOOKUP
        ]
    );
}

#[test]
fn a_family_that_finds_a_link_does_not_ask_for_the_companion() {
    let mut e = up();
    answer(&mut e, 4, &[(0x10, &[0])]);
    answer(&mut e, 6, &[(0x10, &[9])]);
    assert_eq!(run(&mut e, query(Family::V4)), (Some(0), false));
    assert_eq!(families_asked(&mut e), [4]);
}

#[test]
fn nothing_found_for_either_family_is_no_link() {
    let mut e = up();
    assert_eq!(run(&mut e, query(Family::V4)), (None, false));
    assert_eq!(families_asked(&mut e), [4, 6]);
    assert_eq!(e.stats().lookup_bad, 0);
}

#[test]
fn a_refused_subscription_binding_ends_the_lookup_without_a_route_request() {
    let mut e = up();
    answer(&mut e, 4, &[(0x10, &[3])]);
    e.qmi_mut()
        .reject
        .push((wds::SERVICE, wds::id::BIND_SUBSCRIPTION));
    assert_eq!(run(&mut e, query(Family::V4)), (None, false));
    assert_eq!(asked(&mut e), [wds::id::BIND_SUBSCRIPTION]);
    assert_eq!(e.stats().lookup_bad, 1);
}

#[test]
fn a_refused_route_lookup_ends_it_without_the_companion_request() {
    let mut e = up();
    answer(&mut e, 6, &[(0x10, &[3])]);
    e.qmi_mut()
        .reject
        .push((wds::SERVICE, wds::id::ROUTE_LOOKUP));
    assert_eq!(run(&mut e, query(Family::V4)), (None, false));
    assert_eq!(
        asked(&mut e),
        [wds::id::BIND_SUBSCRIPTION, wds::id::ROUTE_LOOKUP]
    );
    assert_eq!(e.stats().lookup_bad, 1);
}

#[test]
fn an_answer_that_cannot_be_read_ends_the_lookup() {
    for tlv in [(0x10u8, vec![1u8, 2]), (0x13, vec![]), (0x12, vec![0; 7])] {
        let mut e = up();
        answer(&mut e, 4, &[(tlv.0, &tlv.1)]);
        assert_eq!(run(&mut e, query(Family::V4)), (None, false), "{tlv:?}");
        assert_eq!(e.stats().lookup_bad, 1);
        assert_eq!(families_asked(&mut e), [4], "no companion after bad data");
    }
}

#[test]
fn an_answer_without_the_block_of_tlv_1_ends_the_lookup() {
    let mut e = up();
    answer(&mut e, 4, &[(0x10, &[3])]);
    e.qmi_mut().route_no_block = true;
    assert_eq!(run(&mut e, query(Family::V4)), (None, false));
    assert_eq!(e.stats().lookup_bad, 1);
    assert_eq!(families_asked(&mut e), [4], "and no companion question");
}

#[test]
fn a_datagram_that_is_no_frame_is_counted_and_the_lookup_goes_on_to_its_deadline() {
    // the qcom QRTR module queues a zero-length datagram to a sender after a flow control resume
    let mut e = up();
    e.start_lookup(5, 7, query(Family::V4)).unwrap();
    let client = e.qmi_mut().client_ids(wds::SERVICE)[0];
    e.qmi_mut().inbox.clear();
    for bytes in [&[][..], &[0xff, 1, 2][..]] {
        e.on_qmi(5, client, bytes);
        assert!(e.take_events().is_empty(), "the question is still open");
    }
    let s = e.stats();
    assert_eq!((s.malformed, s.lookup_bad), (2, 0));
    // it ends at its deadline, unanswered
    e.tick(5 + 2_000);
    assert!(matches!(
        e.take_events().as_slice(),
        [Event::LookupDone {
            link: None,
            answered: false,
            ..
        }]
    ));
}

#[test]
fn a_question_nobody_answers_ends_at_its_deadline_unanswered() {
    let mut e = up();
    e.start_lookup(5, 7, query(Family::V4)).unwrap();
    e.qmi_mut().inbox.clear();
    e.tick(5 + 2_000);
    let evs = e.take_events();
    assert!(matches!(
        evs.as_slice(),
        [Event::LookupDone {
            token: 7,
            link: None,
            answered: false,
            ..
        }]
    ));
}

#[test]
fn a_well_formed_answer_that_names_no_call_is_an_answer() {
    let mut e = up();
    e.start_lookup(5, 7, query(Family::V4)).unwrap();
    pump(&mut e, 5);
    let evs = e.take_events();
    assert!(matches!(
        evs.as_slice(),
        [Event::LookupDone {
            token: 7,
            link: None,
            answered: true,
            ..
        }]
    ));
}

#[test]
fn an_unusable_answer_is_no_answer() {
    let mut e = up();
    // a failed result
    e.qmi_mut()
        .reject
        .push((wds::SERVICE, wds::id::ROUTE_LOOKUP));
    e.start_lookup(5, 7, query(Family::V4)).unwrap();
    pump(&mut e, 5);
    assert!(matches!(
        e.take_events().as_slice(),
        [Event::LookupDone {
            link: None,
            answered: false,
            ..
        }]
    ));
}

#[test]
fn an_answer_to_something_else_is_stale_and_the_lookup_goes_on() {
    let mut e = up();
    answer(&mut e, 4, &[(0x10, &[3])]);
    e.start_lookup(5, 7, query(Family::V4)).unwrap();
    let client = e.qmi_mut().client_ids(wds::SERVICE)[0];
    let txn = e.qmi_mut().last_txn[&client];
    let wrong_txn =
        dataos_qmi::frame::Builder::response(txn.wrapping_add(1), wds::id::BIND_SUBSCRIPTION)
            .ok()
            .unwrap()
            .build()
            .unwrap();
    let wrong_id = dataos_qmi::frame::Builder::response(txn, wds::id::ROUTE_LOOKUP)
        .ok()
        .unwrap()
        .build()
        .unwrap();
    e.on_qmi(5, client, &wrong_txn);
    e.on_qmi(5, client, &wrong_id);
    assert_eq!(e.stats().stale, 2);
    assert!(e.take_events().is_empty());
    pump(&mut e, 5);
    assert_eq!(done(&mut e), (Some(3), false));
}

#[test]
fn a_lookup_the_modem_does_not_answer_ends_at_its_deadline() {
    let mut e = up();
    e.qmi_mut().mute.push(wds::id::ROUTE_LOOKUP);
    let limit = Config::default().lookup_timeout_ms;
    e.start_lookup(5, 7, query(Family::V4)).unwrap();
    pump(&mut e, 5);
    assert_eq!(e.next_deadline(), Some(5 + limit));
    e.tick(5 + limit - 1);
    assert!(e.take_events().is_empty());
    e.tick(5 + limit);
    assert_eq!(done(&mut e), (None, false));
    assert_eq!(e.stats().lookup_timeouts, 1);
    assert_eq!(e.next_deadline(), None);
    assert!(e.qmi_mut().client_ids(wds::SERVICE).is_empty());
}

#[test]
fn the_deadline_is_for_the_whole_lookup_not_for_each_step() {
    let mut e = up();
    let limit = Config::default().lookup_timeout_ms;
    e.start_lookup(5, 7, query(Family::V4)).unwrap();
    // the modem answers the binding and the first family late, and the companion never
    for _ in 0..2 {
        let (client, bytes) = e.qmi_mut().inbox.pop_front().unwrap();
        e.on_qmi(1_000, client, &bytes);
    }
    assert_eq!(
        families_asked(&mut e),
        [4, 6],
        "the companion question is out"
    );
    e.qmi_mut().inbox.clear();
    assert_eq!(
        e.next_deadline(),
        Some(5 + limit),
        "the time did not start again"
    );
    e.tick(5 + limit - 1);
    assert!(e.take_events().is_empty());
    e.tick(5 + limit);
    assert_eq!(done(&mut e), (None, false));
}

#[test]
fn a_late_answer_after_the_end_is_nobodys() {
    let mut e = up();
    e.qmi_mut().mute.push(wds::id::ROUTE_LOOKUP);
    e.start_lookup(5, 7, query(Family::V4)).unwrap();
    pump(&mut e, 5);
    let client = e.qmi_mut().client_ids(wds::SERVICE)[0];
    e.tick(5 + Config::default().lookup_timeout_ms);
    done(&mut e);
    let late = dataos_qmi::frame::Builder::response(1, wds::id::ROUTE_LOOKUP)
        .ok()
        .unwrap()
        .u8(0x10, 3)
        .unwrap()
        .build()
        .unwrap();
    e.on_qmi(9999, client, &late);
    assert_eq!(e.stats().unknown_client, 1);
    assert!(e.take_events().is_empty());
}

#[test]
fn a_lookup_needs_a_ready_engine_a_free_place_and_a_new_token() {
    let mut e = Engine::new(Config::default(), SimModem::new(), FakeNet::new());
    assert_eq!(
        e.start_lookup(1, 7, query(Family::V4)),
        Err(StartError::Unavailable)
    );
    let mut e = up();
    e.qmi_mut().mute.push(wds::id::BIND_SUBSCRIPTION);
    e.start_lookup(1, 1, query(Family::V4)).unwrap();
    assert_eq!(
        e.start_lookup(1, 1, query(Family::V4)),
        Err(StartError::Unavailable),
        "a token in use"
    );
    assert_eq!(dataos_datacore::engine::MAX_LOOKUPS, 8);
    for token in 2..=8 {
        e.start_lookup(1, token, query(Family::V4)).unwrap();
    }
    assert_eq!(
        e.start_lookup(1, 9, query(Family::V4)),
        Err(StartError::Unavailable),
        "all eight places are taken"
    );
    // when one is over, there is room again
    e.tick(1 + Config::default().lookup_timeout_ms);
    assert_eq!(e.take_events().len(), 8);
    assert!(e.start_lookup(9999, 5, query(Family::V4)).is_ok());
}

#[test]
fn a_lookup_that_cannot_be_sent_opens_nothing() {
    let mut e = up();
    let bad = LookupQuery {
        subscription: 200,
        ..query(Family::V4)
    };
    assert_eq!(e.start_lookup(1, 7, bad), Err(StartError::Invalid));
    assert!(e.qmi_mut().client_ids(wds::SERVICE).is_empty());
    e.qmi_mut().refuse_service.push(wds::SERVICE);
    assert_eq!(
        e.start_lookup(1, 7, query(Family::V4)),
        Err(StartError::Unavailable)
    );
    // a client that was opened and then could not be written to is closed again
    e.qmi_mut().refuse_service.clear();
    e.qmi_mut().fail_sends = true;
    let closed = e.qmi_mut().closed.len();
    assert_eq!(
        e.start_lookup(1, 7, query(Family::V4)),
        Err(StartError::Unavailable)
    );
    assert_eq!(e.qmi_mut().closed.len(), closed + 1);
    assert!(e.qmi_mut().client_ids(wds::SERVICE).is_empty());
    assert!(e.take_events().is_empty());
    assert_eq!(e.next_deadline(), None);
}

#[test]
fn a_modem_restart_ends_every_lookup_and_a_cancelled_one_says_nothing() {
    let mut e = up();
    e.qmi_mut().mute.push(wds::id::ROUTE_LOOKUP);
    e.start_lookup(1, 1, query(Family::V4)).unwrap();
    e.start_lookup(1, 2, query(Family::V6)).unwrap();
    e.start_lookup(1, 3, query(Family::V6)).unwrap();
    pump(&mut e, 1);
    let before = e.qmi_mut().closed.len();
    e.cancel_lookup(2);
    e.cancel_lookup(99);
    assert_eq!(e.qmi_mut().closed.len(), before + 1);
    assert!(e.take_events().is_empty());
    e.on_service_event(2, ServiceEvent::ModemDown);
    let mut tokens: Vec<u32> = e
        .take_events()
        .into_iter()
        .filter_map(|ev| match ev {
            Event::LookupDone {
                token,
                link: None,
                companion: false,
                answered: false,
            } => Some(token),
            _ => None,
        })
        .collect();
    tokens.sort_unstable();
    assert_eq!(tokens, [1, 3]);
    assert_eq!(e.next_deadline(), None);
    // none of them counts as a timeout or as bad data
    let s = e.stats();
    assert_eq!((s.lookup_timeouts, s.lookup_bad), (0, 0));
}

#[test]
fn a_route_question_that_cannot_be_sent_ends_the_lookup_at_once() {
    let mut e = up();
    e.start_lookup(5, 7, query(Family::V4)).unwrap();
    e.qmi_mut().fail_sends = true;
    pump(&mut e, 5);
    assert_eq!(done(&mut e), (None, false));
    assert_eq!(e.stats().lookup_bad, 1);
    assert!(e.qmi_mut().client_ids(wds::SERVICE).is_empty());
}

#[test]
fn the_subscription_of_the_module_is_bound_as_given_including_dont_care() {
    for sub in [0u8, 1, 2, 3, 0xff] {
        let mut e = up();
        answer(&mut e, 4, &[(0x10, &[3])]);
        let q = LookupQuery {
            subscription: sub,
            ..query(Family::V4)
        };
        assert_eq!(run(&mut e, q), (Some(3), false), "{sub}");
        assert_eq!(e.qmi_mut().bound_subscriptions, [u32::from(sub)]);
    }
    // a value no SIM has is refused before anything is opened
    for sub in [4u8, 0x80, 0xfe] {
        let mut e = up();
        let q = LookupQuery {
            subscription: sub,
            ..query(Family::V4)
        };
        assert_eq!(e.start_lookup(1, 7, q), Err(StartError::Invalid), "{sub}");
    }
}

#[test]
fn the_other_values_of_the_request_go_to_the_modem() {
    let mut e = up();
    let q = LookupQuery {
        hint: LookupHint {
            profile_3gpp: Some(3),
            profile_3gpp2: Some(4),
            xt_pref: Some(0x0102),
            backup_name: Some(1),
            backup_type: Some(2),
        },
        ..query(Family::V4)
    };
    run(&mut e, q);
    let (_, bytes) = e.qmi_mut().route_frames[0].clone();
    let f = Frame::parse(&bytes).unwrap();
    assert_eq!(f.tlv(0x31), Some(&[3u8][..]));
    assert_eq!(f.tlv(0x32), Some(&[4u8][..]));
    assert_eq!(f.tlv(0x34), Some(&[2u8, 1][..]));
    assert_eq!(f.tlv(0x3c), Some(&[1u8][..]));
    assert_eq!(f.tlv(0x3d), Some(&[2u8][..]));
}
