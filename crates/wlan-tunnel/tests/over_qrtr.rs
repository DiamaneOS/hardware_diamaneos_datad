// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The main loop over the fake QRTR sockets and the name service: the modem is up when WDS and DFS are there.
use dataos_datad::fake::FakeQrtr;
use dataos_datad::qrtr::Peer;
use dataos_datad::transport::QmiLink;
use dataos_qmi::{dfs, reverse, wds, Builder, Frame, Kind};
use dataos_wlan_tunnel::daemon::Tunnel;
use dataos_wlan_tunnel::engine::{Config, Engine, MAX_CLIENTS, MAX_DATAGRAM, WANTED};
use dataos_wlan_tunnel::fake::FakeKernel;

const LOCAL: u32 = 1;
const MODEM: u32 = 0;
const WDS_PORT: u32 = 100;
const DFS_PORT: u32 = 101;

type Rig = Tunnel<FakeQrtr, FakeKernel>;

fn rig() -> (Rig, FakeKernel) {
    let k = FakeKernel::default();
    k.0.borrow_mut().device_present = true;
    let link = QmiLink::for_services(FakeQrtr::new(LOCAL), &WANTED, MAX_CLIENTS);
    (
        Tunnel::new(Engine::new(Config::default(), link, k.clone())),
        k,
    )
}

/// Answer every request that went out with success, until none is left. Returns how many.
fn answer_all(t: &mut Rig, now: u64) -> usize {
    let mut seen = 0;
    let mut total = 0;
    for _ in 0..50 {
        let sent: Vec<_> = t.engine().qmi_mut().io().sent[seen..].to_vec();
        seen += sent.len();
        for (sock, to, bytes) in sent {
            if to.port != WDS_PORT && to.port != DFS_PORT {
                continue;
            }
            total += 1;
            let f = Frame::parse(&bytes).unwrap();
            assert_eq!(f.kind, Kind::Request);
            let a = Builder::response(f.txn, f.id)
                .ok()
                .unwrap()
                .build()
                .unwrap();
            t.engine().qmi_mut().io_mut().deliver(sock, to, &a);
        }
        t.step(now);
    }
    total
}

#[test]
fn up_and_down_follow_the_two_services_and_a_new_modem_starts_over() {
    let (mut t, k) = rig();
    t.engine().start(1);
    t.step(1);
    assert!(k.0.borrow().links.is_empty());
    let io = t.engine().qmi_mut().io_mut();
    io.announce(u32::from(wds::SERVICE), 1, MODEM, WDS_PORT);
    t.step(2);
    assert!(k.0.borrow().links.is_empty(), "WDS alone is not enough");
    let io = t.engine().qmi_mut().io_mut();
    io.announce(u32::from(dfs::SERVICE), 1, MODEM, DFS_PORT);
    t.step(3);
    assert_eq!(k.0.borrow().links.len(), 4);
    // 4 requests per link and family and 2 for the ports
    assert_eq!(answer_all(&mut t, 4), 8 * 4 + 2);
    assert_eq!(t.engine().ready_clients(), 8);
    assert_eq!(t.engine().qmi_mut().client_count(), 17);

    // the modem restarts
    t.engine().qmi_mut().io_mut().withdraw(MODEM, DFS_PORT);
    t.step(5);
    assert_eq!(t.engine().ready_clients(), 0);
    assert_eq!(t.engine().qmi_mut().client_count(), 0);
    t.engine()
        .qmi_mut()
        .io_mut()
        .announce(u32::from(dfs::SERVICE), 1, MODEM, DFS_PORT);
    t.step(6);
    assert_eq!(t.engine().qmi_mut().client_count(), 8 + 1);
    let lines = t.engine().take_lines();
    assert!(lines.iter().any(|l| l == "modem services gone"));
    assert!(lines.iter().filter(|l| *l == "modem services up").count() == 2);
}

#[test]
fn a_connect_is_answered_through_the_socket_it_came_on() {
    let (mut t, k) = rig();
    k.0.borrow_mut().addrs = vec![("wlan0".into(), 30, "192.0.2.10".parse().unwrap())];
    t.engine().start(1);
    t.step(1);
    let io = t.engine().qmi_mut().io_mut();
    io.announce(u32::from(wds::SERVICE), 1, MODEM, WDS_PORT);
    io.announce(u32::from(dfs::SERVICE), 1, MODEM, DFS_PORT);
    t.step(2);
    answer_all(&mut t, 3);
    // the socket of the third link's IPv4 client is the one that bound mux 20
    let sent = t.engine().qmi_mut().io().sent.clone();
    let (sock, _, _) = sent
        .iter()
        .find(|(_, _, b)| {
            let f = Frame::parse(b).unwrap();
            f.id == reverse::id::BIND_CLIENT
                && f.tlv(0x13) == Some(&[20u8][..])
                && f.tlv(0x11) == Some(&[4u8][..])
        })
        .unwrap();
    let ind = Builder::indication(reverse::id::REVERSE_IND)
        .u32(0x01, 1)
        .unwrap()
        .u32(0x02, 77)
        .unwrap()
        .u16(0x10, reverse::tech::LOCAL_BREAKOUT)
        .unwrap()
        .u32(0x12, 0xc000_020a)
        .unwrap()
        .build()
        .unwrap();
    let from = Peer {
        node: MODEM,
        port: WDS_PORT,
    };
    t.engine().qmi_mut().io_mut().deliver(*sock, from, &ind);
    t.step(4);
    let sent = t.engine().qmi_mut().io().sent.clone();
    let (s, to, b) = sent.last().unwrap();
    assert_eq!((*s, *to), (*sock, from));
    let f = Frame::parse(b).unwrap();
    assert_eq!(f.id, reverse::id::REVERSE_ANSWER);
    assert_eq!(f.tlv(0x01), Some(&[1u8][..]));
    assert_eq!(f.tlv(0x02), Some(&[77, 0, 0, 0][..]));
    assert_eq!(t.engine().tunnels_up(), 1);
    assert!(t.wait_ms(4) >= 1);
}

const _: () = assert!(MAX_DATAGRAM == dfs::MAX_MESSAGE && MAX_CLIENTS >= 17);
