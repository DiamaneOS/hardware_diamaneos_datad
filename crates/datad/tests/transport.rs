// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The QMI transport against the fake of the QRTR sockets and of the name service. No modem.
//! Made-up node and port numbers.
use dataos_datacore::{Qmi, QmiError, ServiceEvent};
use dataos_datad::fake::FakeQrtr;
use dataos_datad::qrtr::{Control, Peer, CTRL_PORT, NEW_SERVER};
use dataos_datad::transport::{Fault, QmiLink, MAX_CLIENTS};
use dataos_qmi::{dpm, wda, wds};

const LOCAL: u32 = 1;
const MODEM: u32 = 0;
const WDS_PORT: u32 = 100;
const WDA_PORT: u32 = 101;
const DPM_PORT: u32 = 102;

fn wds_at() -> Peer {
    Peer {
        node: MODEM,
        port: WDS_PORT,
    }
}

fn fake_with_modem() -> FakeQrtr {
    let mut f = FakeQrtr::new(LOCAL);
    f.announce(u32::from(wds::SERVICE), 1, MODEM, WDS_PORT);
    f.announce(u32::from(wda::SERVICE), 1, MODEM, WDA_PORT);
    f.announce(u32::from(dpm::SERVICE), 1, MODEM, DPM_PORT);
    f
}

/// A link whose modem is up already.
fn up_link() -> QmiLink<FakeQrtr> {
    let mut l = QmiLink::new(fake_with_modem());
    let (ev, _) = l.poll_control(0, 32);
    assert_eq!(ev, vec![ServiceEvent::ModemUp]);
    l
}

fn ctrl_sock(l: &QmiLink<FakeQrtr>) -> u32 {
    // the first socket the link opened
    l.io().open_sockets()[0]
}

#[test]
fn the_first_poll_registers_a_lookup_per_service_and_hears_the_modem() {
    let mut l = QmiLink::new(fake_with_modem());
    let (ev, more) = l.poll_control(0, 32);
    assert_eq!(ev, vec![ServiceEvent::ModemUp]);
    assert!(!more);
    assert_eq!(l.io().lookup_count(), 3);
    assert!(l.services().is_up());
    assert_eq!(l.io().opened, 1);
    // nothing is polled again
    let (ev, _) = l.poll_control(1, 32);
    assert!(ev.is_empty());
    assert_eq!(l.io().opened, 1);
}

#[test]
fn a_modem_that_is_not_there_yet_is_heard_when_it_comes() {
    let mut l = QmiLink::new(FakeQrtr::new(LOCAL));
    assert!(l.poll_control(0, 32).0.is_empty());
    l.io_mut()
        .announce(u32::from(wds::SERVICE), 1, MODEM, WDS_PORT);
    l.io_mut()
        .announce(u32::from(wda::SERVICE), 1, MODEM, WDA_PORT);
    assert!(l.poll_control(1, 32).0.is_empty());
    l.io_mut()
        .announce(u32::from(dpm::SERVICE), 1, MODEM, DPM_PORT);
    assert_eq!(l.poll_control(2, 32).0, vec![ServiceEvent::ModemUp]);
}

#[test]
fn services_that_are_not_wanted_are_not_looked_up() {
    let mut f = fake_with_modem();
    f.announce(0x30, 1, MODEM, 150);
    let mut l = QmiLink::new(f);
    assert_eq!(l.poll_control(0, 32).0, vec![ServiceEvent::ModemUp]);
    assert_eq!(l.services().stats().table_full, 0);
}

#[test]
fn a_modem_restart_is_a_down_and_an_up() {
    let mut l = up_link();
    l.io_mut().bye(MODEM);
    assert_eq!(l.poll_control(10, 32).0, vec![ServiceEvent::ModemDown]);
    assert!(!l.services().is_up());
    l.io_mut()
        .announce(u32::from(wds::SERVICE), 1, MODEM, WDS_PORT);
    l.io_mut()
        .announce(u32::from(wda::SERVICE), 1, MODEM, WDA_PORT);
    l.io_mut()
        .announce(u32::from(dpm::SERVICE), 1, MODEM, DPM_PORT);
    assert_eq!(l.poll_control(20, 32).0, vec![ServiceEvent::ModemUp]);
}

#[test]
fn a_packet_that_does_not_come_from_the_name_service_is_not_believed() {
    let mut l = QmiLink::new(FakeQrtr::new(LOCAL));
    l.poll_control(0, 32);
    let sock = ctrl_sock(&l);
    let fake = |port| NEW_SERVER_FOR(port);
    // from a port of a local process, in the form of a good packet
    for (from, bytes) in [
        (
            Peer {
                node: LOCAL,
                port: 0x5000,
            },
            fake(WDS_PORT),
        ),
        // from the right port of another node
        (
            Peer {
                node: MODEM,
                port: CTRL_PORT,
            },
            fake(WDS_PORT),
        ),
        // from the name service but not a packet
        (
            Peer {
                node: LOCAL,
                port: CTRL_PORT,
            },
            vec![1, 2, 3],
        ),
    ] {
        l.io_mut().deliver(sock, from, &bytes);
    }
    assert!(l.poll_control(1, 32).0.is_empty());
    assert_eq!(l.stats().bad_control, 3);
    assert!(!l.services().is_up());
}

#[allow(non_snake_case)]
fn NEW_SERVER_FOR(port: u32) -> Vec<u8> {
    Control {
        command: NEW_SERVER,
        words: [u32::from(wds::SERVICE), 1, MODEM, port],
    }
    .encode()
    .to_vec()
}

#[test]
fn the_control_budget_limits_a_pass_and_says_there_is_more() {
    let mut l = QmiLink::new(FakeQrtr::new(LOCAL));
    l.poll_control(0, 32);
    let sock = ctrl_sock(&l);
    let ns = Peer {
        node: LOCAL,
        port: CTRL_PORT,
    };
    for port in 1..=5 {
        l.io_mut().deliver(sock, ns, &NEW_SERVER_FOR(port));
    }
    let (_, more) = l.poll_control(1, 3);
    assert!(more);
    // a pass that uses its whole budget cannot know, so it says there may be more
    let (_, more) = l.poll_control(2, 2);
    assert!(more);
    // and one that finds the socket empty before the budget is used says there is not
    let (_, more) = l.poll_control(3, 3);
    assert!(!more);
}

#[test]
fn a_control_socket_that_cannot_be_opened_is_tried_again_with_a_longer_wait_each_time() {
    let mut f = fake_with_modem();
    f.open_faults
        .extend([Fault::Other, Fault::Other, Fault::Other]);
    let mut l = QmiLink::new(f);
    assert!(l.poll_control(0, 32).0.is_empty());
    assert_eq!(l.stats().lookup_failures, 1);
    assert_eq!(l.next_deadline(), Some(100));
    // not before its time
    l.poll_control(99, 32);
    assert_eq!(l.stats().lookup_failures, 1);
    l.poll_control(100, 32);
    assert_eq!(l.stats().lookup_failures, 2);
    assert_eq!(l.next_deadline(), Some(300));
    l.poll_control(300, 32);
    assert_eq!(l.stats().lookup_failures, 3);
    assert_eq!(l.next_deadline(), Some(700));
    // and then it works
    assert_eq!(l.poll_control(700, 32).0, vec![ServiceEvent::ModemUp]);
    assert_eq!(l.next_deadline(), None);
}

#[test]
fn the_wait_between_attempts_stops_growing_at_five_seconds() {
    let mut f = FakeQrtr::new(LOCAL);
    f.open_faults.extend(std::iter::repeat_n(Fault::Other, 9));
    let mut l = QmiLink::new(f);
    let mut now = 0;
    let mut waits = Vec::new();
    for _ in 0..9 {
        l.poll_control(now, 32);
        let next = l.next_deadline().unwrap();
        waits.push(next - now);
        now = next;
    }
    assert_eq!(
        waits,
        vec![100, 200, 400, 800, 1600, 3200, 5000, 5000, 5000]
    );
}

#[test]
fn lookups_that_cannot_be_sent_close_the_socket_again() {
    // any one of the three lookups can be the one that fails
    for failing in 0..3 {
        let mut f = fake_with_modem();
        f.control_faults
            .extend((0..=failing).map(|i| (i == failing).then_some(Fault::Retry)));
        let mut l = QmiLink::new(f);
        assert!(l.poll_control(0, 32).0.is_empty(), "{failing}");
        assert_eq!(l.stats().lookup_failures, 1);
        assert_eq!(l.io().open_sockets().len(), 0);
        assert_eq!(l.io().closed.len(), 1);
        assert_eq!(l.poll_control(100, 32).0, vec![ServiceEvent::ModemUp]);
        assert_eq!(l.io().open_sockets().len(), 1);
    }
}

#[test]
fn a_socket_that_does_not_know_its_address_is_not_used() {
    // the fake gives every socket an address, so a socket that was closed under us has none
    let mut l = QmiLink::new(FakeQrtr::new(LOCAL));
    l.io_mut().open_faults.push_back(Fault::Reset);
    assert!(l.poll_control(0, 32).0.is_empty());
    assert_eq!(l.stats().lookup_failures, 1);
}

#[test]
fn no_client_is_opened_while_the_modem_is_down() {
    let mut l = QmiLink::new(fake_with_modem());
    assert_eq!(l.open_client(wds::SERVICE), Err(QmiError::Unavailable));
    l.poll_control(0, 32);
    assert!(l.open_client(wds::SERVICE).is_ok());
    assert_eq!(l.open_client(0x55), Err(QmiError::Unavailable));
}

#[test]
fn a_client_sends_to_the_server_of_its_service_and_hears_only_that_one() {
    let mut l = up_link();
    let a = l.open_client(wds::SERVICE).unwrap();
    let b = l.open_client(wda::SERVICE).unwrap();
    assert_ne!(a, b);
    l.send(a, &[1, 2, 3]).unwrap();
    l.send(b, &[4]).unwrap();
    let sent = l.io().sent.clone();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].1, wds_at());
    assert_eq!(sent[0].2, vec![1, 2, 3]);
    assert_eq!(
        sent[1].1,
        Peer {
            node: MODEM,
            port: WDA_PORT
        }
    );
    // each client has a socket of its own
    assert_ne!(sent[0].0, sent[1].0);
    // the answer from the server arrives, one from anywhere else does not
    l.io_mut().deliver(sent[0].0, wds_at(), &[9, 9]);
    l.io_mut().deliver(
        sent[0].0,
        Peer {
            node: MODEM,
            port: WDA_PORT,
        },
        &[8],
    );
    l.io_mut().deliver(
        sent[0].0,
        Peer {
            node: LOCAL,
            port: WDS_PORT,
        },
        &[7],
    );
    let (got, more) = l.poll_clients(1);
    assert!(!more);
    assert_eq!(got, vec![(a, vec![9, 9])]);
    assert_eq!(l.stats().foreign, 2);
}

#[test]
fn an_unknown_client_cannot_send_and_a_closed_one_neither() {
    let mut l = up_link();
    assert_eq!(l.send(77, &[1]), Err(QmiError::Unavailable));
    let a = l.open_client(wds::SERVICE).unwrap();
    l.close_client(a);
    assert_eq!(l.send(a, &[1]), Err(QmiError::Unavailable));
    // closing twice is harmless, and the socket was closed once
    l.close_client(a);
    assert_eq!(l.io().closed.len(), 1);
    assert_eq!(l.client_count(), 0);
}

#[test]
fn client_numbers_are_not_used_twice() {
    let mut l = up_link();
    let a = l.open_client(wds::SERVICE).unwrap();
    l.close_client(a);
    let b = l.open_client(wds::SERVICE).unwrap();
    assert_ne!(a, b);
}

#[test]
fn at_most_48_clients_are_open() {
    let mut l = up_link();
    assert_eq!(MAX_CLIENTS, 48);
    for _ in 0..48 {
        l.open_client(wds::SERVICE).unwrap();
    }
    assert_eq!(l.open_client(wds::SERVICE), Err(QmiError::Unavailable));
    assert_eq!(l.client_count(), 48);
}

#[test]
fn a_socket_that_cannot_be_opened_is_no_client() {
    let mut l = up_link();
    l.io_mut().open_faults.push_back(Fault::Other);
    assert_eq!(l.open_client(wds::SERVICE), Err(QmiError::Unavailable));
    assert_eq!(l.client_count(), 0);
    // the transport is not reset by that
    assert!(l.services().is_up());
    // but a reset fault is
    l.io_mut().open_faults.push_back(Fault::Reset);
    assert_eq!(l.open_client(wds::SERVICE), Err(QmiError::Unavailable));
    assert_eq!(l.poll_control(5, 32).0, vec![ServiceEvent::ModemDown]);
}

#[test]
fn a_datagram_larger_than_a_qmi_message_is_refused() {
    let mut l = up_link();
    let a = l.open_client(wds::SERVICE).unwrap();
    assert!(l.send(a, &vec![0; 8192]).is_ok());
    assert_eq!(l.send(a, &vec![0; 8193]), Err(QmiError::Unavailable));
    assert_eq!(l.stats().send_failed, 1);
}

#[test]
fn a_send_without_room_waits_and_goes_out_later_in_the_same_order() {
    let mut l = up_link();
    let a = l.open_client(wds::SERVICE).unwrap();
    l.io_mut().send_faults.push_back(Fault::Retry);
    l.send(a, &[1]).unwrap();
    // the second does not overtake the first, though the socket would take it now
    l.send(a, &[2]).unwrap();
    assert!(l.io().sent.is_empty());
    assert!(l.blocked());
    assert_eq!(l.stats().queued, 2);
    l.flush(5);
    let bytes: Vec<Vec<u8>> = l.io().sent.iter().map(|s| s.2.clone()).collect();
    assert_eq!(bytes, vec![vec![1], vec![2]]);
    assert!(!l.blocked());
    // and the next goes straight out
    l.send(a, &[3]).unwrap();
    assert_eq!(l.io().sent.len(), 3);
    assert_eq!(l.stats().queued, 2);
}

#[test]
fn a_send_without_buffers_is_counted_and_waits_like_any_other() {
    let mut l = up_link();
    let a = l.open_client(wds::SERVICE).unwrap();
    l.io_mut().send_faults.push_back(Fault::Exhausted);
    l.send(a, &[1]).unwrap();
    assert_eq!(l.stats().exhausted, 1);
    assert_eq!(l.stats().queued, 1);
    l.flush(1);
    assert_eq!(l.io().sent.len(), 1);
    // a wait for room is no exhaustion
    l.io_mut().send_faults.push_back(Fault::Retry);
    l.send(a, &[2]).unwrap();
    assert_eq!(l.stats().exhausted, 1);
}

#[test]
fn a_destination_that_is_gone_fails_the_send_at_once() {
    let mut l = up_link();
    let a = l.open_client(wds::SERVICE).unwrap();
    for fault in [Fault::PeerGone, Fault::Other] {
        l.io_mut().send_faults.push_back(fault);
        assert_eq!(l.send(a, &[1]), Err(QmiError::Unavailable));
    }
    assert_eq!(l.stats().send_failed, 2);
    assert!(!l.blocked());
    // nothing is torn down for it
    assert!(l.services().is_up());
    assert_eq!(l.client_count(), 1);
}

#[test]
fn a_send_that_hits_a_reset_fails_and_resets_the_transport() {
    let mut l = up_link();
    let a = l.open_client(wds::SERVICE).unwrap();
    l.io_mut().send_faults.push_back(Fault::Reset);
    assert_eq!(l.send(a, &[1]), Err(QmiError::Unavailable));
    assert_eq!(l.stats().send_failed, 1);
    assert_eq!(l.poll_control(3, 32).0, vec![ServiceEvent::ModemDown]);
    assert_eq!(l.stats().resets, 1);
}

#[test]
fn a_client_that_stays_blocked_loses_what_waited_for_it() {
    let mut l = up_link();
    let a = l.open_client(wds::SERVICE).unwrap();
    let b = l.open_client(wda::SERVICE).unwrap();
    l.io_mut().send_faults.push_back(Fault::Retry);
    l.send(a, &[1]).unwrap();
    l.send(a, &[2]).unwrap();
    // the other client is not held up by it
    l.send(b, &[3]).unwrap();
    assert_eq!(l.io().sent.len(), 1);
    // still waiting at 1999 ms, still blocked
    l.io_mut().send_faults.push_back(Fault::Retry);
    l.flush(1999);
    assert_eq!(l.stats().send_dropped, 0);
    assert!(l.blocked());
    assert_eq!(l.next_deadline(), Some(2000));
    // gone at 2000 ms
    l.io_mut().send_faults.push_back(Fault::Retry);
    l.flush(2000);
    assert_eq!(l.stats().send_dropped, 1);
    assert!(!l.blocked());
    assert_eq!(l.next_deadline(), None);
    // the client itself is still there and can send again
    l.send(a, &[4]).unwrap();
    assert_eq!(l.io().sent.last().unwrap().2, vec![4]);
}

#[test]
fn the_queue_of_a_client_is_bounded() {
    let mut l = up_link();
    let a = l.open_client(wds::SERVICE).unwrap();
    l.io_mut().send_faults.extend([Fault::Retry; 1]);
    for i in 0..8 {
        l.send(a, &[i]).unwrap();
    }
    assert_eq!(l.send(a, &[9]), Err(QmiError::Unavailable));
    assert_eq!(l.stats().send_failed, 1);
    // by bytes as well: 16 KiB per client
    let mut l = up_link();
    let a = l.open_client(wds::SERVICE).unwrap();
    l.io_mut().send_faults.push_back(Fault::Retry);
    l.send(a, &vec![0; 8000]).unwrap();
    l.send(a, &vec![0; 8000]).unwrap();
    assert_eq!(l.send(a, &vec![0; 8000]), Err(QmiError::Unavailable));
    // what is left fits, up to the byte
    assert!(l.send(a, &vec![0; 384]).is_ok());
    assert_eq!(l.send(a, &[0]), Err(QmiError::Unavailable));
}

#[test]
fn a_waiting_send_for_a_client_that_was_closed_is_dropped_with_it() {
    let mut l = up_link();
    let a = l.open_client(wds::SERVICE).unwrap();
    l.io_mut().send_faults.push_back(Fault::Retry);
    l.send(a, &[1]).unwrap();
    l.close_client(a);
    assert!(!l.blocked());
    l.flush(1);
    assert!(l.io().sent.is_empty());
}

#[test]
fn a_waiting_send_whose_destination_is_gone_is_dropped() {
    let mut l = up_link();
    let a = l.open_client(wds::SERVICE).unwrap();
    l.io_mut().send_faults.push_back(Fault::Retry);
    l.send(a, &[1]).unwrap();
    l.io_mut().send_faults.push_back(Fault::PeerGone);
    l.flush(1);
    assert_eq!(l.stats().send_dropped, 1);
    assert!(!l.blocked());
    // a reset on the retry resets the transport
    let mut l = up_link();
    let a = l.open_client(wds::SERVICE).unwrap();
    l.io_mut().send_faults.push_back(Fault::Retry);
    l.send(a, &[1]).unwrap();
    l.io_mut().send_faults.push_back(Fault::Reset);
    l.flush(1);
    assert_eq!(l.poll_control(2, 32).0, vec![ServiceEvent::ModemDown]);
}

#[test]
fn every_client_is_read_in_every_pass_and_a_chatty_one_does_not_starve_the_rest() {
    let mut l = up_link();
    let a = l.open_client(wds::SERVICE).unwrap();
    let b = l.open_client(wds::SERVICE).unwrap();
    l.send(a, &[0]).unwrap();
    l.send(b, &[0]).unwrap();
    let socks: Vec<u32> = l.io().sent.iter().map(|s| s.0).collect();
    for i in 0..10 {
        l.io_mut().deliver(socks[0], wds_at(), &[i]);
    }
    l.io_mut().deliver(socks[1], wds_at(), &[99]);
    let (got, more) = l.poll_clients(1);
    // four from the first, then the one of the second, and the first may have more
    let ids: Vec<u32> = got.iter().map(|g| g.0).collect();
    assert_eq!(ids, vec![a, a, a, a, b]);
    assert!(more);
    // the rest follows on the next passes, in the order it came
    let (got, more) = l.poll_clients(2);
    let bytes: Vec<u8> = got.iter().map(|g| g.1[0]).collect();
    assert_eq!(bytes, vec![4, 5, 6, 7]);
    assert!(more);
    let (got, more) = l.poll_clients(3);
    assert_eq!(got.len(), 2);
    assert!(!more);
}

#[test]
fn a_pass_that_reads_its_whole_share_from_a_client_says_there_may_be_more() {
    let mut l = up_link();
    let a = l.open_client(wds::SERVICE).unwrap();
    l.send(a, &[0]).unwrap();
    let sock = l.io().sent[0].0;
    for i in 0..3 {
        l.io_mut().deliver(sock, wds_at(), &[i]);
    }
    let (got, more) = l.poll_clients(1);
    assert_eq!(got.len(), 3);
    assert!(!more);
    for i in 0..4 {
        l.io_mut().deliver(sock, wds_at(), &[i]);
    }
    let (got, more) = l.poll_clients(2);
    assert_eq!(got.len(), 4);
    assert!(more);
    let (got, more) = l.poll_clients(3);
    assert!(got.is_empty());
    assert!(!more);
}

#[test]
fn a_client_whose_socket_fails_on_receive_is_closed() {
    let mut l = up_link();
    let a = l.open_client(wds::SERVICE).unwrap();
    let b = l.open_client(wds::SERVICE).unwrap();
    let sock = l.io().open_sockets()[1];
    l.io_mut().recv_faults.insert(sock, Fault::PeerGone);
    let (got, _) = l.poll_clients(1);
    assert!(got.is_empty());
    assert_eq!(l.stats().recv_faults, 1);
    assert_eq!(l.client_count(), 1);
    assert_eq!(l.send(a, &[1]), Err(QmiError::Unavailable));
    assert!(l.send(b, &[1]).is_ok());
    // a wait for data is no fault
    let sock_b = l.io().open_sockets()[1];
    l.io_mut().recv_faults.insert(sock_b, Fault::Retry);
    l.poll_clients(2);
    assert_eq!(l.client_count(), 1);
    assert_eq!(l.stats().recv_faults, 1);
}

#[test]
fn a_reset_on_a_client_socket_resets_everything() {
    let mut l = up_link();
    l.open_client(wds::SERVICE).unwrap();
    let sock = l.io().open_sockets()[1];
    l.io_mut().recv_faults.insert(sock, Fault::Reset);
    l.poll_clients(1);
    // the client is still counted until the transport is polled for control
    assert_eq!(l.poll_control(2, 32).0, vec![ServiceEvent::ModemDown]);
    assert_eq!(l.client_count(), 0);
    assert_eq!(l.io().open_sockets().len(), 0);
}

#[test]
fn a_reset_of_the_control_socket_closes_everything_and_the_lookups_are_made_again() {
    let mut l = up_link();
    let a = l.open_client(wds::SERVICE).unwrap();
    l.send(a, &[1]).unwrap();
    let ctrl = ctrl_sock(&l);
    l.io_mut().recv_faults.insert(ctrl, Fault::Reset);
    let (ev, _) = l.poll_control(10, 32);
    assert_eq!(ev, vec![ServiceEvent::ModemDown]);
    assert_eq!(l.stats().resets, 1);
    assert_eq!(l.client_count(), 0);
    assert_eq!(l.io().open_sockets().len(), 0);
    assert_eq!(l.io().lookup_count(), 0);
    assert_eq!(l.send(a, &[2]), Err(QmiError::Unavailable));
    assert_eq!(l.open_client(wds::SERVICE), Err(QmiError::Unavailable));
    // the lookups come back after the wait, and the modem is up again
    assert_eq!(l.next_deadline(), Some(110));
    assert!(l.poll_control(109, 32).0.is_empty());
    assert_eq!(l.poll_control(110, 32).0, vec![ServiceEvent::ModemUp]);
    assert_eq!(l.io().lookup_count(), 3);
}

#[test]
fn any_other_fault_of_the_control_socket_resets_too_but_a_wait_does_not() {
    for (fault, resets) in [
        (Fault::Retry, 0),
        (Fault::Exhausted, 0),
        (Fault::PeerGone, 1),
        (Fault::Other, 1),
    ] {
        let mut l = up_link();
        let ctrl = ctrl_sock(&l);
        l.io_mut().recv_faults.insert(ctrl, fault);
        let (ev, _) = l.poll_control(1, 32);
        assert_eq!(l.stats().resets, resets, "{fault:?}");
        assert_eq!(ev.len(), resets as usize, "{fault:?}");
    }
}

#[test]
fn the_wait_after_a_reset_grows_unless_the_socket_was_healthy_for_a_while() {
    let mut l = up_link();
    // a reset soon after the open: the wait doubles from the first one
    let ctrl = ctrl_sock(&l);
    l.io_mut().recv_faults.insert(ctrl, Fault::Reset);
    l.poll_control(1_000, 32);
    assert_eq!(l.next_deadline(), Some(1_100));
    assert_eq!(l.poll_control(1_100, 32).0, vec![ServiceEvent::ModemUp]);
    let ctrl = l.io().open_sockets()[0];
    l.io_mut().recv_faults.insert(ctrl, Fault::Reset);
    l.poll_control(1_200, 32);
    // the first socket's wait (100) doubled to 200 for this one
    assert_eq!(l.next_deadline(), Some(1_400));
    l.poll_control(1_400, 32);
    // this socket lived for 29999 ms: still not healthy
    let ctrl = l.io().open_sockets()[0];
    l.io_mut().recv_faults.insert(ctrl, Fault::Reset);
    l.poll_control(31_399, 32);
    assert_eq!(l.next_deadline(), Some(31_399 + 400));
    l.poll_control(31_799, 32);
    // and one that lived for 30000 ms is
    let ctrl = l.io().open_sockets()[0];
    l.io_mut().recv_faults.insert(ctrl, Fault::Reset);
    l.poll_control(61_799, 32);
    assert_eq!(l.next_deadline(), Some(61_799 + 100));
}

#[test]
fn a_reset_while_the_modem_is_not_up_tells_nobody() {
    let mut l = QmiLink::new(FakeQrtr::new(LOCAL));
    l.poll_control(0, 32);
    let ctrl = ctrl_sock(&l);
    l.io_mut().recv_faults.insert(ctrl, Fault::Reset);
    assert!(l.poll_control(1, 32).0.is_empty());
    assert_eq!(l.stats().resets, 1);
}

#[test]
fn the_main_loop_is_told_when_to_come_back() {
    let mut l = QmiLink::new(fake_with_modem());
    // the control socket is to be opened at once
    assert_eq!(l.next_deadline(), Some(0));
    l.poll_control(0, 32);
    assert_eq!(l.next_deadline(), None);
    let a = l.open_client(wds::SERVICE).unwrap();
    l.io_mut().send_faults.push_back(Fault::Retry);
    l.send(a, &[1]).unwrap();
    assert_eq!(l.next_deadline(), Some(2000));
    assert!(l.fds().is_empty());
}

#[test]
fn a_reconnect_of_the_name_service_with_the_modem_unchanged_is_one_down_and_one_up() {
    let mut l = up_link();
    let ctrl = ctrl_sock(&l);
    l.io_mut().recv_faults.insert(ctrl, Fault::Reset);
    let mut events = l.poll_control(1, 32).0;
    events.extend(l.poll_control(101, 32).0);
    assert_eq!(events, vec![ServiceEvent::ModemDown, ServiceEvent::ModemUp]);
    // the same servers again do not make a second up
    assert!(l.poll_control(102, 32).0.is_empty());
}

#[test]
fn a_resume_notice_is_no_message_and_lets_the_waiting_sends_go() {
    let mut l = up_link();
    let a = l.open_client(wds::SERVICE).unwrap();
    // the destination takes one packet and holds the next back
    l.io_mut().flow_limit = Some(1);
    l.send(a, &[1]).unwrap();
    l.send(a, &[2]).unwrap();
    assert_eq!(l.io().sent.len(), 1);
    assert!(l.blocked());
    // the empty datagram from the server's address says it may go now
    l.io_mut().resume(wds_at());
    let (got, more) = l.poll_clients(5);
    assert!(got.is_empty(), "it is no message");
    assert!(!more);
    assert_eq!(l.stats().resumes, 1);
    let bytes: Vec<Vec<u8>> = l.io().sent.iter().map(|s| s.2.clone()).collect();
    assert_eq!(bytes, vec![vec![1], vec![2]]);
    assert!(!l.blocked());
}

#[test]
fn the_flow_of_a_destination_is_shared_by_every_sender_and_every_waiter_is_told() {
    let mut l = up_link();
    let a = l.open_client(wds::SERVICE).unwrap();
    let b = l.open_client(wds::SERVICE).unwrap();
    l.io_mut().flow_limit = Some(1);
    l.send(a, &[1]).unwrap();
    // the second sender finds the flow full although it sent nothing
    l.send(b, &[2]).unwrap();
    l.send(a, &[3]).unwrap();
    assert_eq!(l.io().sent.len(), 1);
    l.io_mut().resume(wds_at());
    let (got, _) = l.poll_clients(5);
    assert!(got.is_empty());
    assert_eq!(l.stats().resumes, 2, "both were told");
    // the flow allows one packet again: the first waiter's goes, the other stays held
    assert_eq!(l.io().sent.len(), 2);
    assert!(l.blocked());
}

#[test]
fn an_empty_datagram_from_anywhere_else_is_not_a_resume() {
    let mut l = up_link();
    let a = l.open_client(wds::SERVICE).unwrap();
    l.send(a, &[1]).unwrap();
    let sock = l.io().sent[0].0;
    l.io_mut().deliver(
        sock,
        Peer {
            node: MODEM,
            port: WDA_PORT,
        },
        &[],
    );
    let (got, _) = l.poll_clients(1);
    assert!(got.is_empty());
    assert_eq!(l.stats().resumes, 0);
    assert_eq!(l.stats().foreign, 1);
}

#[test]
fn a_resume_flushes_the_waiting_sends_of_other_clients_too() {
    let mut l = up_link();
    let a = l.open_client(wds::SERVICE).unwrap();
    let b = l.open_client(wda::SERVICE).unwrap();
    l.io_mut().send_faults.extend([Fault::Retry, Fault::Retry]);
    l.send(a, &[1]).unwrap();
    l.send(b, &[2]).unwrap();
    assert!(l.io().sent.is_empty());
    let sock_a = l.io().open_sockets()[1];
    l.io_mut().deliver(sock_a, wds_at(), &[]);
    l.poll_clients(2);
    assert_eq!(l.io().sent.len(), 2);
}
