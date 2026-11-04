// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The engine against the simulated modem and the fake kernel. Documentation address ranges, made-up SPIs and keys.
use dataos_datacore::ServiceEvent;
use dataos_netcfg::xfrm::{Dir, Encap, SaId, Side};
use dataos_qmi::dfs::{self, PortKind};
use dataos_qmi::reverse::{self, tech};
use dataos_qmi::{wds, Builder, Frame};
use dataos_wlan_tunnel::engine::{Config, Engine};
use dataos_wlan_tunnel::fake::{FakeKernel, HeldSocket, KernelState, ModemState, SimModem};
use dataos_wlan_tunnel::KernelError;
use std::cell::{Ref, RefMut};
use std::net::IpAddr;

const WIFI4: &str = "192.0.2.10";
const WIFI6: &str = "2001:db8:1:2::10";
const EPDG4: &str = "198.51.100.20";
const INNER4: &str = "203.0.113.5";
const INNER6: &str = "2001:db8:aa:bb::5";
const RX_SPI: u32 = 0xc1c2_c3c4;
const TX_SPI: u32 = 0xd1d2_d3d4;
const RX_CRYPT: [u8; 16] = [0x11; 16];
const TX_CRYPT: [u8; 16] = [0x22; 16];
const RX_AUTH: [u8; 32] = [0x33; 32];
const TX_AUTH: [u8; 32] = [0x44; 32];
const LINK2_MUX: u8 = 20;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

struct Rig {
    e: Engine<SimModem, FakeKernel>,
    m: SimModem,
    k: FakeKernel,
    now: u64,
    lines: Vec<String>,
}

impl Rig {
    fn new() -> Rig {
        let (m, k) = (SimModem::default(), FakeKernel::default());
        {
            let mut s = k.0.borrow_mut();
            s.device_present = true;
            s.addrs = vec![
                ("wlan0".into(), 30, ip(WIFI4)),
                ("wlan0".into(), 30, ip(WIFI6)),
            ];
            s.sockets.clear();
        }
        let e = Engine::new(Config::default(), m.clone(), k.clone());
        Rig {
            e,
            m,
            k,
            now: 1_000,
            lines: Vec::new(),
        }
    }

    fn up() -> Rig {
        let mut r = Rig::new();
        r.e.start(r.now);
        r.modem_up();
        r
    }

    fn modem(&self) -> RefMut<'_, ModemState> {
        self.m.0.borrow_mut()
    }

    fn kernel(&self) -> Ref<'_, KernelState> {
        self.k.0.borrow()
    }

    fn kernel_mut(&self) -> RefMut<'_, KernelState> {
        self.k.0.borrow_mut()
    }

    fn modem_up(&mut self) {
        self.e.on_service(self.now, ServiceEvent::ModemUp);
        self.pump();
    }

    /// Deliver what the modem queued, until it has no more.
    fn pump(&mut self) {
        loop {
            let next = self.modem().inbox.pop_front();
            let Some((client, mut bytes)) = next else {
                break;
            };
            self.e.on_qmi(self.now, client, &mut bytes);
            assert!(bytes.iter().all(|b| *b == 0), "the datagram was not zeroed");
        }
        self.lines.extend(self.e.take_lines());
    }

    fn advance(&mut self, ms: u64) {
        self.now += ms;
        self.e.tick(self.now);
        self.pump();
    }

    fn indicate(&mut self, client: u32, bytes: Vec<u8>) {
        self.modem().inbox.push_back((client, bytes));
        self.pump();
    }

    fn wds_client(&self, mux: u8, family: u8) -> u32 {
        self.m.0.borrow().wds_client(mux, family).unwrap()
    }

    fn connect(&mut self, mux: u8, family: u8, t: u16, tid: u32, addr: &str) {
        let client = self.wds_client(mux, family);
        self.indicate(client, reverse_ind(reverse::STATUS_CONNECTED, tid, t, addr));
    }

    fn disconnect(&mut self, mux: u8, family: u8, t: u16, tid: u32, addr: &str) {
        let client = self.wds_client(mux, family);
        self.indicate(
            client,
            reverse_ind(reverse::STATUS_DISCONNECTED, tid, t, addr),
        );
    }

    /// The answers 0x90 so far: result and transaction ID.
    fn answers(&self) -> Vec<(u8, u32)> {
        self.m
            .0
            .borrow()
            .sent_of(wds::SERVICE, reverse::id::REVERSE_ANSWER)
            .iter()
            .map(|(_, b)| {
                let f = Frame::parse(b).unwrap();
                (
                    f.tlv(0x01).unwrap()[0],
                    u32::from_le_bytes(f.tlv(0x02).unwrap().try_into().unwrap()),
                )
            })
            .collect()
    }

    fn queue_sa(&mut self, nat: bool) {
        let mut m = self.modem();
        m.sa_id = 7;
        m.sa_segments = vec![whole_sa(7, nat)];
    }

    fn log_since(&self, from: usize) -> Vec<String> {
        self.kernel().log[from..].to_vec()
    }

    fn log_len(&self) -> usize {
        self.kernel().log.len()
    }
}

fn reverse_ind(status: u32, tid: u32, t: u16, addr: &str) -> Vec<u8> {
    let b = Builder::indication(reverse::id::REVERSE_IND)
        .u32(0x01, status)
        .unwrap()
        .u32(0x02, tid)
        .unwrap()
        .u16(0x10, t)
        .unwrap();
    let b = match ip(addr) {
        IpAddr::V4(a) => b.u32(0x12, u32::from(a)).unwrap(),
        IpAddr::V6(a) => {
            let mut v = a.octets().to_vec();
            v.push(64);
            b.tlv(0x14, &v).unwrap()
        }
    };
    b.build().unwrap()
}

fn tunnel_addr(addr: &str) -> Vec<u8> {
    match ip(addr) {
        IpAddr::V4(a) => {
            let mut v = vec![4, 0, 0, 0, 4];
            v.extend(a.octets().iter().rev());
            v
        }
        IpAddr::V6(a) => {
            let mut v = vec![6, 0, 0, 0, 16];
            v.extend(a.octets());
            v
        }
    }
}

fn counted(key: &[u8]) -> Vec<u8> {
    let mut v = vec![key.len() as u8];
    v.extend(key);
    v
}

fn counted16(key: &[u8]) -> Vec<u8> {
    let mut v = (key.len() as u16).to_le_bytes().to_vec();
    v.extend(key);
    v
}

fn sa_head(id: u16, size: u8, segment: u8) -> Builder {
    let mut h = id.to_le_bytes().to_vec();
    h.extend([size, segment]);
    Builder::indication(reverse::id::IPSEC_SA)
        .tlv(0x01, &h)
        .unwrap()
}

/// The fields of the states without the keys.
fn sa_plain(b: Builder, nat: bool) -> Builder {
    let b = b
        .u32(0x10, RX_SPI)
        .unwrap()
        .u32(0x11, TX_SPI)
        .unwrap()
        .u32(0x12, 3)
        .unwrap()
        .u32(0x13, 1)
        .unwrap()
        .tlv(0x14, &tunnel_addr(EPDG4))
        .unwrap()
        .tlv(0x15, &tunnel_addr(WIFI4))
        .unwrap()
        .u32(0x16, 6)
        .unwrap()
        .u32(0x17, 12)
        .unwrap();
    if nat {
        b.u8(0x1b, 1).unwrap().tlv(0x36, &[0x9c, 0x40]).unwrap()
    } else {
        b
    }
}

fn sa_keys(b: Builder) -> Builder {
    b.tlv(0x18, &counted(&RX_CRYPT))
        .unwrap()
        .tlv(0x19, &counted(&TX_CRYPT))
        .unwrap()
        .tlv(0x37, &counted16(&RX_AUTH))
        .unwrap()
        .tlv(0x38, &counted16(&TX_AUTH))
        .unwrap()
}

fn whole_sa(id: u16, nat: bool) -> Vec<u8> {
    sa_keys(sa_plain(sa_head(id, 1, 0), nat)).build().unwrap()
}

fn filter_entry(version: u8, spi: u32) -> Vec<u8> {
    let mut e = vec![0u8; 145];
    e[0] = version;
    e[75..79].copy_from_slice(&0x32u32.to_le_bytes());
    e[121] = 1;
    e[129..133].copy_from_slice(&spi.to_be_bytes());
    e
}

#[test]
fn bring_up_makes_the_links_and_registers_every_family() {
    let r = Rig::up();
    let k = r.kernel();
    let names: Vec<&String> = k.links.keys().collect();
    assert_eq!(
        names,
        [
            "r_rmnet_data0",
            "r_rmnet_data1",
            "r_rmnet_data2",
            "r_rmnet_data3"
        ]
    );
    for (i, (_, (mux, flags, up))) in k.links.iter().enumerate() {
        assert_eq!(*mux, 18 + i as u8);
        assert_eq!((flags.flags, flags.mask), (0xb400_0071, 0xffff_ffff));
        assert!(!up);
    }
    drop(k);
    assert_eq!(r.e.ready_clients(), 8);
    let m = r.m.0.borrow();
    assert_eq!(m.sent_of(wds::SERVICE, reverse::id::BIND_CLIENT).len(), 8);
    assert_eq!(m.sent_of(wds::SERVICE, reverse::id::REGISTER).len(), 8);
    // eight per link and family and one for the ports
    assert_eq!(m.sent_of(dfs::SERVICE, dfs::id::BIND_CLIENT).len(), 9);
    let regs = m.sent_of(dfs::SERVICE, dfs::id::INDICATION_REGISTER);
    assert_eq!(regs.len(), 9);
    let link_regs = regs
        .iter()
        .filter(|(_, b)| Frame::parse(b).unwrap().tlv(0x12) == Some(&[1u8][..]))
        .count();
    assert_eq!(link_regs, 8);
    let f_ports = regs
        .iter()
        .map(|(_, b)| b)
        .find(|b| Frame::parse(b).unwrap().tlv(0x13).is_some())
        .unwrap();
    assert_eq!(
        Frame::parse(f_ports).unwrap().tlv(0x14),
        Some(&[1, 0, 0, 0][..])
    );
    // the client for ports binds to mux 1, IPv4
    let info = m
        .clients
        .values()
        .find(|c| c.service == dfs::SERVICE && c.mux == 1)
        .unwrap();
    assert_eq!(info.family, 4);
    // a client of a link binds with its mux and the endpoint of the data port
    let (_, bytes) = &m.sent_of(wds::SERVICE, reverse::id::BIND_CLIENT)[0];
    let f = Frame::parse(bytes).unwrap();
    assert_eq!(f.tlv(0x12), Some(&[4, 0, 0, 0, 1, 0, 0, 0][..]));
}

#[test]
fn it_waits_for_the_device_of_the_data_daemon() {
    let mut r = Rig::new();
    r.kernel_mut().device_present = false;
    r.modem_up();
    assert!(r.kernel().links.is_empty());
    assert_eq!(r.e.ready_clients(), 0);
    r.advance(1_000);
    assert!(r.kernel().links.is_empty());
    r.kernel_mut().device_present = true;
    r.advance(1_000);
    assert_eq!(r.kernel().links.len(), 4);
    assert_eq!(r.e.ready_clients(), 8);
}

#[test]
fn a_refused_bind_is_tried_three_times_and_then_the_older_way() {
    let mut r = Rig::new();
    let bind = (wds::SERVICE, reverse::id::BIND_CLIENT);
    let binds = |r: &Rig| r.m.0.borrow().sent_of(bind.0, bind.1).len();
    r.modem().refuse.insert(bind, vec![0x0e; 24].into());
    r.modem_up();
    assert_eq!(binds(&r), 8);
    r.advance(99);
    assert_eq!(binds(&r), 8);
    r.advance(1);
    r.advance(100);
    assert_eq!(binds(&r), 24);
    let m = r.m.0.borrow();
    assert_eq!(
        m.sent_of(wds::SERVICE, wds::id::BIND_MUX_DATA_PORT).len(),
        8
    );
    assert_eq!(m.sent_of(wds::SERVICE, wds::id::SET_IP_FAMILY).len(), 8);
    drop(m);
    assert_eq!(r.e.ready_clients(), 8);
}

#[test]
fn error_0x47_goes_to_the_older_bind_at_once() {
    let mut r = Rig::new();
    let bind = (wds::SERVICE, reverse::id::BIND_CLIENT);
    r.modem().refuse.insert(bind, vec![0x47].into());
    r.modem_up();
    let m = r.m.0.borrow();
    let (_, old) = &m.sent_of(wds::SERVICE, wds::id::BIND_MUX_DATA_PORT)[0];
    assert_eq!(Frame::parse(old).unwrap().tlv(0x12), Some(&[1u8][..]));
    drop(m);
    assert_eq!(r.e.ready_clients(), 8);
}

#[test]
fn a_client_that_fails_starts_over_later_and_the_others_go_on() {
    let mut r = Rig::new();
    let reg = (wds::SERVICE, reverse::id::REGISTER);
    r.modem().refuse.insert(reg, vec![0x03].into());
    r.modem_up();
    assert_eq!(r.e.ready_clients(), 7);
    r.advance(1_000);
    assert_eq!(r.e.ready_clients(), 8);
    assert_eq!(r.modem().clients.len(), 17);
}

#[test]
fn the_well_known_ports_are_held_for_the_four_kinds_and_a_busy_one_keeps_its_tuple() {
    let mut r = Rig::new();
    r.kernel_mut().busy_ports = vec![7275];
    r.e.start(r.now);
    assert_eq!(r.e.ports_in_store(), 8);
    let k = r.kernel();
    assert_eq!(k.sockets.len(), 4);
    assert!(k
        .sockets
        .values()
        .all(|s| matches!(s, HeldSocket::Port(_, 5060))));
    drop(k);
    r.lines.extend(r.e.take_lines());
    assert!(r.lines.iter().any(|l| l.contains("bind failed")));
    // the port came free: the next modem start holds it
    r.kernel_mut().busy_ports.clear();
    r.modem_up();
    assert_eq!(r.kernel().sockets.len(), 8);
}

#[test]
fn an_s2b_tunnel_end_to_end() {
    let mut r = Rig::up();
    r.queue_sa(false);
    let mark = r.log_len();
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 0xabc, INNER4);
    assert_eq!(r.answers(), vec![(1, 0xabc)]);
    assert_eq!(r.e.tunnel_technologies(), vec![tech::IWLAN_S2B]);
    assert_eq!(
        r.log_since(mark),
        [
            "getaddr",
            "getaddr",
            "link up",
            "sysctls",
            "store state",
            "newsa",
            "newsa",
            "newpolicy Out",
            "newpolicy In",
            "newpolicy Fwd",
            "genl 1",
            "genl 5",
            "genl 3",
            "newrule",
        ]
    );
    {
        let k = r.kernel();
        assert_eq!(k.sysctls, ["r_rmnet_data2"]);
        assert!(k.links["r_rmnet_data2"].2);
        assert_eq!(k.states.len(), 2);
        let tx = &k.states[0];
        assert_eq!(tx.id.spi, TX_SPI);
        assert_eq!((tx.id.src, tx.id.dst), (ip(WIFI4), ip(EPDG4)));
        assert_eq!((tx.id.proto, tx.mode, tx.flags), (50, 1, 0x24));
        assert_eq!(tx.crypt_name, "cbc(aes)");
        assert_eq!(tx.crypt_key, TX_CRYPT);
        assert_eq!(
            (tx.auth_name.as_str(), tx.auth_trunc_bits),
            ("hmac(sha256)", 128)
        );
        assert_eq!(tx.auth_key, TX_AUTH);
        assert_eq!(tx.mark, Some(0x20000));
        assert_eq!(tx.encap, None);
        let rx = &k.states[1];
        assert_eq!(rx.id.spi, RX_SPI);
        assert_eq!((rx.id.src, rx.id.dst), (ip(EPDG4), ip(WIFI4)));
        assert_eq!((rx.flags, rx.mark), (0x20, None));
        assert_eq!(rx.crypt_key, RX_CRYPT);
        assert_eq!(rx.auth_key, RX_AUTH);
        assert_eq!(k.policies.len(), 3);
        let (sel, dir, t) = &k.policies[0];
        assert_eq!(*dir, Dir::Out);
        assert_eq!(
            (sel.addr, sel.prefix, sel.side),
            (ip(INNER4), 32, Side::Source)
        );
        assert_eq!((t.id, t.mode), (tx.id, 1));
        for (i, want) in [(1, Dir::In), (2, Dir::Fwd)] {
            let (sel, dir, t) = &k.policies[i];
            assert_eq!(*dir, want);
            assert_eq!(
                (sel.addr, sel.prefix, sel.side),
                (ip(INNER4), 32, Side::Destination)
            );
            assert_eq!(t.id, rx.id);
        }
        assert_eq!(k.device.as_deref(), Some("wlan0"));
        assert_eq!(k.forwards, [("r_rmnet_data2".to_string(), ip(INNER4))]);
        // the whole store: eight records of the two ports
        assert_eq!(k.tuples.len(), 8);
        let rule = &k.rules[0];
        assert_eq!(
            (rule.family, rule.mark, rule.mask, rule.table),
            (2, 0x20000, 0xfffff, 1030)
        );
    }
    let mark = r.log_len();
    r.disconnect(LINK2_MUX, 4, tech::IWLAN_S2B, 0xabd, INNER4);
    assert_eq!(r.answers(), vec![(1, 0xabc), (1, 0xabd)]);
    assert_eq!(
        r.log_since(mark),
        [
            "delrule",
            "genl 4",
            "genl 6",
            "delpolicy In",
            "delpolicy Fwd",
            "delpolicy Out",
            "delsa",
            "delsa",
            "link down",
            "store state",
        ]
    );
    assert!(r.kernel().is_clean());
    // no GETSA dump in any of it, and the tuples stay
    assert!(!r.kernel().log.iter().any(|l| l.contains("getsa")));
    assert_eq!(r.kernel().tuples.len(), 8);
    assert_eq!(r.e.tunnels_up(), 0);
}

#[test]
fn a_local_breakout_tunnel_end_to_end() {
    let mut r = Rig::up();
    let mark = r.log_len();
    r.connect(21, 4, tech::LOCAL_BREAKOUT, 5, WIFI4);
    assert_eq!(r.answers(), vec![(1, 5)]);
    assert_eq!(
        r.log_since(mark),
        ["getaddr", "link up", "sysctls", "genl 1", "genl 5", "genl 3"]
    );
    {
        let k = r.kernel();
        assert!(k.states.is_empty() && k.policies.is_empty() && k.rules.is_empty());
        assert_eq!(k.device.as_deref(), Some("wlan0"));
        assert_eq!(k.forwards, [("r_rmnet_data3".to_string(), ip(WIFI4))]);
    }
    let m = r.m.0.borrow();
    assert!(m.sent_of(wds::SERVICE, reverse::id::IPSEC_SA).is_empty());
    assert!(m.sent_of(dfs::SERVICE, dfs::id::GET_FILTERS).is_empty());
    drop(m);
    let mark = r.log_len();
    r.disconnect(21, 4, tech::LOCAL_BREAKOUT, 6, WIFI4);
    assert_eq!(r.log_since(mark), ["genl 4", "genl 6", "link down"]);
    assert_eq!(r.answers(), vec![(1, 5), (1, 6)]);
    assert!(r.kernel().is_clean());
}

#[test]
fn local_breakout_then_s2b_share_the_device_slot() {
    let mut r = Rig::up();
    r.connect(21, 4, tech::LOCAL_BREAKOUT, 1, WIFI4);
    r.queue_sa(false);
    let sets = |r: &Rig| r.kernel().wlan_log.iter().filter(|c| **c == 3).count();
    let before = sets(&r);
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 2, INNER4);
    assert_eq!(sets(&r), before, "the device is set by the first");
    // the first goes: the slot stays for the other, then the last unsets it
    r.disconnect(21, 4, tech::LOCAL_BREAKOUT, 3, WIFI4);
    assert_eq!(r.kernel().device.as_deref(), Some("wlan0"));
    r.disconnect(LINK2_MUX, 4, tech::IWLAN_S2B, 4, INNER4);
    assert!(r.kernel().is_clean());
}

#[test]
fn c_iwlan_and_unknown_technologies_are_refused_and_answered() {
    let mut r = Rig::up();
    r.connect(LINK2_MUX, 4, tech::CIWLAN, 1, INNER4);
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B_PROXY, 2, INNER4);
    r.connect(LINK2_MUX, 4, 0x8001, 3, INNER4);
    assert_eq!(r.answers(), vec![(0, 1), (0, 2), (0, 3)]);
    assert!(r.kernel().is_clean());
    assert!(r
        .lines
        .iter()
        .any(|l| l.contains("C-IWLAN is out of scope")));
}

#[test]
fn a_bad_status_a_wrong_family_and_no_transport_are_answered_with_0() {
    let mut r = Rig::up();
    let c = r.wds_client(LINK2_MUX, 4);
    r.indicate(c, reverse_ind(7, 1, tech::IWLAN_S2B, INNER4));
    // an IPv6 address on the IPv4 client
    r.connect(LINK2_MUX, 4, tech::LOCAL_BREAKOUT, 2, INNER6);
    // an address no interface has
    r.connect(LINK2_MUX, 4, tech::LOCAL_BREAKOUT, 3, "192.0.2.99");
    assert_eq!(r.answers(), vec![(0, 1), (0, 2), (0, 3)]);
    assert!(r.kernel().is_clean());
    // malformed with a readable ID, and malformed without one
    let bad = Builder::indication(reverse::id::REVERSE_IND)
        .u32(0x01, 1)
        .unwrap()
        .u32(0x02, 4)
        .unwrap()
        .u8(0x10, 1)
        .unwrap()
        .build()
        .unwrap();
    r.indicate(c, bad);
    assert_eq!(r.answers().last(), Some(&(0, 4)));
    let none = Builder::indication(reverse::id::REVERSE_IND)
        .build()
        .unwrap();
    r.indicate(c, none);
    assert_eq!(r.answers().len(), 4);
}

#[test]
fn a_disconnect_with_nothing_up_is_answered_by_its_technology() {
    let mut r = Rig::up();
    r.disconnect(LINK2_MUX, 4, tech::IWLAN_S2B, 1, INNER4);
    r.disconnect(LINK2_MUX, 4, 0x8001, 2, INNER4);
    assert_eq!(r.answers(), vec![(1, 1), (0, 2)]);
}

#[test]
fn any_failure_rolls_back_in_reverse_and_answers_0() {
    for op in [
        "getaddr",
        "link up",
        "newsa",
        "newpolicy Out",
        "newpolicy In",
        "newpolicy Fwd",
        "genl 1",
        "genl 5",
        "genl 3",
    ] {
        let mut r = Rig::up();
        r.queue_sa(false);
        r.kernel_mut()
            .fail
            .insert(op.into(), KernelError::Failed(13));
        r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 9, INNER4);
        assert_eq!(r.answers(), vec![(0, 9)], "{op}");
        assert!(r.kernel().is_clean(), "{op}");
        assert_eq!(r.e.tunnels_up(), 0, "{op}");
        assert!(r.lines.iter().any(|l| l.contains("rolled back")), "{op}");
        // the table is free again, so the next try works
        r.modem().sa_segments = vec![whole_sa(7, false)];
        r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 10, INNER4);
        assert_eq!(r.answers(), vec![(0, 9), (1, 10)], "{op}");
    }
}

#[test]
fn the_second_newsa_failing_takes_the_first_out_and_the_order_is_reversed() {
    let mut r = Rig::up();
    r.queue_sa(false);
    r.kernel_mut()
        .fail
        .insert("genl 3".into(), KernelError::Failed(1));
    let mark = r.log_len();
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 9, INNER4);
    let log = r.log_since(mark);
    let from = log.iter().position(|l| l == "genl 3").unwrap();
    assert_eq!(
        log[from + 1..],
        [
            "genl 6",
            "delpolicy Fwd",
            "delpolicy In",
            "delpolicy Out",
            "delsa",
            "delsa",
            "link down",
            "store state"
        ]
    );
}

#[test]
fn a_failed_rule_is_not_fatal_and_is_not_removed_later() {
    let mut r = Rig::up();
    r.queue_sa(false);
    r.kernel_mut()
        .fail
        .insert("newrule".into(), KernelError::Failed(1));
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 1, INNER4);
    assert_eq!(r.answers(), vec![(1, 1)]);
    r.disconnect(LINK2_MUX, 4, tech::IWLAN_S2B, 2, INNER4);
    assert!(!r.kernel().log.iter().any(|l| l == "delrule"));
    assert!(r.kernel().is_clean());
}

#[test]
fn two_families_on_one_tunnel_share_the_states() {
    let mut r = Rig::up();
    r.queue_sa(false);
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 1, INNER4);
    r.modem().sa_segments = vec![whole_sa(7, false)];
    let mark = r.log_len();
    r.connect(LINK2_MUX, 6, tech::IWLAN_S2B, 2, INNER6);
    assert_eq!(r.answers(), vec![(1, 1), (1, 2)]);
    assert_eq!(
        r.log_since(mark),
        [
            "getaddr",
            "getaddr",
            "store state",
            "newpolicy Out",
            "newpolicy In",
            "newpolicy Fwd",
            "genl 1",
            "genl 5",
            "newrule",
        ],
        "no second link up, no second NEWSA, no second set device"
    );
    {
        let k = r.kernel();
        assert_eq!(k.states.len(), 2);
        assert_eq!(k.policies.len(), 6);
        let v6: Vec<_> = k
            .policies
            .iter()
            .filter(|(s, _, _)| s.addr == ip(INNER6))
            .collect();
        assert!(v6.iter().all(|(s, _, _)| s.prefix == 64));
        assert_eq!(k.forwards.len(), 2);
        assert_eq!(k.rules.len(), 1, "the second family has the same rule");
    }
    // the first family goes: its policies and forward go, the states, the rule and the device stay
    let mark = r.log_len();
    r.disconnect(LINK2_MUX, 4, tech::IWLAN_S2B, 3, INNER4);
    assert_eq!(
        r.log_since(mark),
        [
            "genl 6",
            "delpolicy In",
            "delpolicy Fwd",
            "delpolicy Out",
            "store state"
        ]
    );
    {
        let k = r.kernel();
        assert_eq!((k.states.len(), k.policies.len(), k.rules.len()), (2, 3, 1));
        assert_eq!(k.device.as_deref(), Some("wlan0"));
        assert!(k.links["r_rmnet_data2"].2);
    }
    r.disconnect(LINK2_MUX, 6, tech::IWLAN_S2B, 4, INNER6);
    assert!(r.kernel().is_clean());
    assert_eq!(r.answers().last(), Some(&(1, 4)));
}

#[test]
fn a_connect_over_a_live_tunnel_replaces_it() {
    let mut r = Rig::up();
    r.queue_sa(false);
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 1, INNER4);
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 2, INNER4);
    assert_eq!(r.answers(), vec![(1, 1), (1, 2)]);
    assert_eq!(r.kernel().states.len(), 2);
    assert_eq!(r.e.tunnels_up(), 1);
    assert!(r.lines.iter().any(|l| l.contains("live tunnel")));
}

#[test]
fn segments_out_of_order_make_one_tunnel() {
    let mut r = Rig::up();
    let first = sa_plain(sa_head(7, 3, 2), false).build().unwrap();
    let second = sa_head(7, 3, 0)
        .tlv(0x18, &counted(&RX_CRYPT))
        .unwrap()
        .tlv(0x19, &counted(&TX_CRYPT))
        .unwrap()
        .build()
        .unwrap();
    let third = sa_head(7, 3, 1)
        .tlv(0x37, &counted16(&RX_AUTH))
        .unwrap()
        .tlv(0x38, &counted16(&TX_AUTH))
        .unwrap()
        .build()
        .unwrap();
    {
        let mut m = r.modem();
        m.sa_id = 7;
        m.sa_segments = vec![first, second, third];
    }
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 1, INNER4);
    assert_eq!(r.answers(), vec![(1, 1)]);
    let k = r.kernel();
    assert_eq!(k.states[0].crypt_key, TX_CRYPT);
    assert_eq!(k.states[1].auth_key, RX_AUTH);
}

#[test]
fn a_segment_before_the_response_waits_for_it() {
    let mut r = Rig::up();
    r.modem().silent.push((wds::SERVICE, reverse::id::IPSEC_SA));
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 1, INNER4);
    let c = r.wds_client(LINK2_MUX, 4);
    r.indicate(c, whole_sa(7, false));
    assert!(r.answers().is_empty());
    let txn = {
        let m = r.m.0.borrow();
        let (_, b) = &m.sent_of(wds::SERVICE, reverse::id::IPSEC_SA)[0];
        Frame::parse(b).unwrap().txn
    };
    let resp = Builder::response(txn, reverse::id::IPSEC_SA)
        .ok()
        .unwrap()
        .u32(0x10, 7)
        .unwrap()
        .build()
        .unwrap();
    r.indicate(c, resp);
    assert_eq!(r.answers(), vec![(1, 1)]);
}

#[test]
fn a_mismatch_drops_the_segments_and_the_connect_fails_at_its_deadline() {
    let mut r = Rig::up();
    let one = sa_plain(sa_head(7, 2, 0), false).build().unwrap();
    // another size for the same request
    let other = sa_keys(sa_head(7, 3, 1)).build().unwrap();
    {
        let mut m = r.modem();
        m.sa_id = 7;
        m.sa_segments = vec![one, other];
    }
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 4, INNER4);
    assert!(r.answers().is_empty());
    assert!(r.lines.iter().any(|l| l.contains("does not fit")));
    r.advance(4_999);
    assert!(r.answers().is_empty());
    r.advance(1);
    assert_eq!(r.answers(), vec![(0, 4)]);
    assert!(r.kernel().is_clean());
    assert!(r.kernel().states.is_empty());
}

#[test]
fn a_segment_of_another_request_does_not_count() {
    let mut r = Rig::up();
    {
        let mut m = r.modem();
        m.sa_id = 7;
        m.sa_segments = vec![whole_sa(8, false)];
    }
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 4, INNER4);
    r.advance(5_000);
    assert_eq!(r.answers(), vec![(0, 4)]);
}

#[test]
fn a_refused_sa_request_or_filter_request_or_incomplete_states_answer_0() {
    let mut r = Rig::up();
    r.modem()
        .refuse
        .insert((wds::SERVICE, reverse::id::IPSEC_SA), vec![0x0e].into());
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 1, INNER4);
    assert_eq!(r.answers(), vec![(0, 1)]);

    let mut r = Rig::up();
    r.queue_sa(false);
    r.modem()
        .refuse
        .insert((dfs::SERVICE, dfs::id::GET_FILTERS), vec![0x0e].into());
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 2, INNER4);
    assert_eq!(r.answers(), vec![(0, 2)]);
    assert!(r.kernel().is_clean());

    let mut r = Rig::up();
    {
        let mut m = r.modem();
        m.sa_id = 7;
        m.sa_segments = vec![sa_plain(sa_head(7, 1, 0), false).build().unwrap()];
    }
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 3, INNER4);
    assert_eq!(r.answers(), vec![(0, 3)]);
    assert!(r.lines.iter().any(|l| l.contains("crypto key")));
}

#[test]
fn no_answer_to_the_filter_request_fails_at_its_deadline() {
    let mut r = Rig::up();
    r.queue_sa(false);
    r.modem().silent.push((dfs::SERVICE, dfs::id::GET_FILTERS));
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 3, INNER4);
    assert!(r.answers().is_empty());
    r.advance(5_000);
    assert_eq!(r.answers(), vec![(0, 3)]);
}

#[test]
fn a_disconnect_during_a_connect_answers_both() {
    let mut r = Rig::up();
    r.modem().silent.push((wds::SERVICE, reverse::id::IPSEC_SA));
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 1, INNER4);
    r.disconnect(LINK2_MUX, 4, tech::IWLAN_S2B, 2, INNER4);
    assert_eq!(r.answers(), vec![(0, 1), (1, 2)]);
    r.advance(10_000);
    assert_eq!(r.answers().len(), 2);
}

#[test]
fn a_tunnel_over_udp_has_its_socket_and_keeps_it_until_the_modem_releases_the_port() {
    let mut r = Rig::up();
    r.queue_sa(true);
    let mark = r.log_len();
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 1, INNER4);
    let log = r.log_since(mark);
    let genl: Vec<&String> = log.iter().filter(|l| l.starts_with("genl")).collect();
    assert_eq!(genl, ["genl 7", "genl 10", "genl 1", "genl 5", "genl 3"]);
    let policy = log.iter().position(|l| l == "newpolicy Fwd").unwrap();
    assert_eq!(log[policy + 1], "encap socket");
    {
        let k = r.kernel();
        assert_eq!(
            k.states[0].encap,
            Some(Encap {
                sport: [0x9c, 0x40],
                dport: [0x11, 0x94]
            })
        );
        assert_eq!(
            k.states[1].encap,
            Some(Encap {
                sport: [0x11, 0x94],
                dport: [0x9c, 0x40]
            })
        );
        assert!(k.sockets.values().any(|s| *s == HeldSocket::Encap(40000)));
    }
    r.disconnect(LINK2_MUX, 4, tech::IWLAN_S2B, 2, INNER4);
    assert_eq!(r.e.encap_sockets(), 1, "not closed by the disconnect");
    // the same tunnel again uses it
    r.modem().sa_segments = vec![whole_sa(7, true)];
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 3, INNER4);
    assert_eq!(r.e.encap_sockets(), 1);
    // the modem releases the port
    let mut list = vec![1u8];
    list.extend(dfs::port_hash(40000, PortKind::V4Udp).to_le_bytes());
    let released = Builder::indication(dfs::id::PORTS_RELEASED)
        .tlv(0x10, &list)
        .unwrap()
        .build()
        .unwrap();
    let c = r.modem().dfs_client(1, 4).unwrap();
    r.indicate(c, released);
    assert_eq!(r.e.encap_sockets(), 0);
}

#[test]
fn the_port_requests_of_the_modem_are_held_answered_and_released() {
    let mut r = Rig::up();
    r.kernel_mut().wlan_log.clear();
    let c = r.modem().dfs_client(1, 4).unwrap();
    // a fixed UDP port on both families and a TCP port on IPv6, then one the AP picks
    let mut list = vec![3u8];
    list.extend([dfs::IP_BOTH, 17, 0, 0, 0]);
    list.extend(50000u16.to_le_bytes());
    list.extend([6, 6, 0, 0, 0]);
    list.extend(50001u16.to_le_bytes());
    list.extend([4, 17, 0, 0, 0, 0, 0]);
    let wanted = Builder::indication(dfs::id::PORTS_WANTED)
        .tlv(0x01, &list)
        .unwrap()
        .u16(0x10, 0x55)
        .unwrap()
        .build()
        .unwrap();
    r.indicate(c, wanted);
    assert_eq!(r.e.ports_in_store(), 8 + 4);
    assert_eq!(r.kernel().wlan_log, [1]);
    assert_eq!(r.kernel().tuples.len(), 4, "only the new ports");
    let answer = r.m.0.borrow().sent_of(dfs::SERVICE, dfs::id::PORTS_ANSWER)[0]
        .1
        .clone();
    let f = Frame::parse(&answer).unwrap();
    assert_eq!(f.tlv(0x10), Some(&[0x55, 0][..]));
    let v = f.tlv(0x01).unwrap();
    assert_eq!(v[0], 4);
    let entry = |n: usize| &v[1 + n * 16..1 + (n + 1) * 16];
    assert_eq!(&entry(0)[0..4], &[0; 4]);
    assert_eq!(
        &entry(0)[4..8],
        &dfs::port_hash(50000, PortKind::V4Udp).to_le_bytes()
    );
    assert_eq!((entry(0)[8], entry(0)[9]), (0, 4));
    assert_eq!(
        &entry(1)[4..8],
        &dfs::port_hash(50000, PortKind::V6Udp).to_le_bytes()
    );
    assert_eq!(entry(1)[9], 6);
    assert_eq!(&entry(2)[10..14], &[6, 0, 0, 0]);
    assert_eq!(&entry(2)[14..16], &50001u16.to_le_bytes());
    // the one the AP chose has the flag and the port the kernel gave
    assert_eq!(entry(3)[8], 1);
    let chosen = u16::from_le_bytes(entry(3)[14..16].try_into().unwrap());
    assert!(chosen >= 40_000);
    // release one: the socket closes and cmd 2 goes out
    let held = r.kernel().sockets.len();
    let mut rel = vec![1u8];
    rel.extend(dfs::port_hash(50001, PortKind::V6Tcp).to_le_bytes());
    let released = Builder::indication(dfs::id::PORTS_RELEASED)
        .tlv(0x10, &rel)
        .unwrap()
        .build()
        .unwrap();
    r.indicate(c, released);
    assert_eq!(r.kernel().sockets.len(), held - 1);
    assert_eq!(r.e.ports_in_store(), 8 + 3);
    assert_eq!(r.kernel().wlan_log, [1, 2]);
    assert_eq!(r.kernel().tuples.len(), 3);
    // the next connect sends the whole store, and a disconnect removes no tuple
    r.connect(21, 4, tech::LOCAL_BREAKOUT, 1, WIFI4);
    assert_eq!(r.kernel().tuples.len(), 8 + 3);
    r.disconnect(21, 4, tech::LOCAL_BREAKOUT, 2, WIFI4);
    assert_eq!(r.kernel().tuples.len(), 8 + 3);
}

#[test]
fn a_range_is_kept_a_symmetric_pick_is_one_port_and_a_failed_port_ends_the_answer() {
    let mut r = Rig::up();
    let c = r.modem().dfs_client(1, 4).unwrap();
    let mut range = dfs::PROPERTY_SYMMETRIC.to_le_bytes().to_vec();
    range.extend(45000u16.to_le_bytes());
    range.extend(45009u16.to_le_bytes());
    let wanted = Builder::indication(dfs::id::PORTS_WANTED)
        .tlv(0x01, &[1, dfs::IP_BOTH, 17, 0, 0, 0, 0, 0])
        .unwrap()
        .tlv(0x11, &range)
        .unwrap()
        .build()
        .unwrap();
    r.indicate(c, wanted);
    let answer = r.m.0.borrow().sent_of(dfs::SERVICE, dfs::id::PORTS_ANSWER)[0]
        .1
        .clone();
    let f = Frame::parse(&answer).unwrap();
    let v = f.tlv(0x01).unwrap();
    let a = u16::from_le_bytes(v[15..17].try_into().unwrap());
    let b = u16::from_le_bytes(v[31..33].try_into().unwrap());
    assert_eq!(a, b);
    assert!((45000..=45009).contains(&a));

    // every port of a range busy: the tries end and the answer has no entry
    let mut r = Rig::up();
    let c = r.modem().dfs_client(1, 4).unwrap();
    r.kernel_mut().busy_ports = (46000..=46001).collect();
    let mut range = 0u32.to_le_bytes().to_vec();
    range.extend(46000u16.to_le_bytes());
    range.extend(46001u16.to_le_bytes());
    let wanted = Builder::indication(dfs::id::PORTS_WANTED)
        .tlv(0x01, &[1, 4, 6, 0, 0, 0, 0, 0])
        .unwrap()
        .tlv(0x11, &range)
        .unwrap()
        .build()
        .unwrap();
    r.indicate(c, wanted);
    let answer = r.m.0.borrow().sent_of(dfs::SERVICE, dfs::id::PORTS_ANSWER)[0]
        .1
        .clone();
    let f = Frame::parse(&answer).unwrap();
    assert_eq!(f.tlv(0x01).unwrap(), &[0]);
    assert_eq!(r.e.ports_in_store(), 8);

    // a range that is no range gives an answer with no entry
    let mut r = Rig::up();
    let c = r.modem().dfs_client(1, 4).unwrap();
    let mut range = 0u32.to_le_bytes().to_vec();
    range.extend(9u16.to_le_bytes());
    range.extend(9u16.to_le_bytes());
    let wanted = Builder::indication(dfs::id::PORTS_WANTED)
        .tlv(0x01, &[1, 4, 6, 0, 0, 0, 0x50, 0xc3])
        .unwrap()
        .tlv(0x11, &range)
        .unwrap()
        .build()
        .unwrap();
    r.indicate(c, wanted);
    let answer = r.m.0.borrow().sent_of(dfs::SERVICE, dfs::id::PORTS_ANSWER)[0]
        .1
        .clone();
    let f = Frame::parse(&answer).unwrap();
    assert_eq!(f.tlv(0x01).unwrap(), &[0]);
}

#[test]
fn an_answer_that_cannot_be_sent_gives_the_new_ports_back() {
    let mut r = Rig::up();
    let held = r.kernel().sockets.len();
    r.modem().send_fails = true;
    let c = r.modem().dfs_client(1, 4).unwrap();
    let wanted = Builder::indication(dfs::id::PORTS_WANTED)
        .tlv(0x01, &[1, 4, 6, 0, 0, 0, 0x50, 0xc3])
        .unwrap()
        .build()
        .unwrap();
    r.indicate(c, wanted);
    assert_eq!(r.kernel().sockets.len(), held);
    assert_eq!(r.e.ports_in_store(), 8);
}

#[test]
fn the_encap_port_message_sends_its_two_commands() {
    let mut r = Rig::up();
    let c = r.modem().dfs_client(1, 4).unwrap();
    let msg = |value: u8| {
        Builder::indication(dfs::id::ENCAP_PORT)
            .u32(0x01, dfs::port_hash(40000, PortKind::V4Udp))
            .unwrap()
            .u8(0x10, value)
            .unwrap()
            .build()
            .unwrap()
    };
    r.kernel_mut().wlan_log.clear();
    r.indicate(c, msg(1));
    assert_eq!(r.kernel().wlan_log, [7, 11]);
    assert_eq!(r.kernel().encap_ports, [[0x9c, 0x40]]);
    r.kernel_mut().wlan_log.clear();
    r.indicate(c, msg(0));
    assert_eq!(r.kernel().wlan_log, [8, 10]);
    assert!(r.kernel().encap_ports.is_empty());
}

#[test]
fn esp_filters_become_tuples_at_connect_and_when_they_change() {
    let mut r = Rig::up();
    r.queue_sa(false);
    let mut list = vec![2u8];
    list.extend(filter_entry(4, 0x0102_0304));
    list.extend(filter_entry(6, 0x0506_0708));
    r.modem().filters = Some(list);
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 1, INNER4);
    assert_eq!(r.answers(), vec![(1, 1)]);
    {
        let k = r.kernel();
        assert!(k.tuples.contains(&[1, 2, 3, 4, 4, 50, 0, 0]));
        assert!(k.tuples.contains(&[5, 6, 7, 8, 6, 50, 0, 0]));
    }
    let c = r.modem().dfs_client(LINK2_MUX, 4).unwrap();
    let mut one = vec![1u8];
    one.extend(filter_entry(4, 0x0102_0304));
    let del = Builder::indication(dfs::id::FILTERS_CHANGED)
        .u32(0x01, dfs::FILTER_DELETE)
        .unwrap()
        .tlv(0x10, &one)
        .unwrap()
        .build()
        .unwrap();
    r.indicate(c, del);
    assert!(!r.kernel().tuples.contains(&[1, 2, 3, 4, 4, 50, 0, 0]));
    let add = Builder::indication(dfs::id::FILTERS_CHANGED)
        .u32(0x01, dfs::FILTER_ADD)
        .unwrap()
        .tlv(0x10, &one)
        .unwrap()
        .build()
        .unwrap();
    r.indicate(c, add);
    assert!(r.kernel().tuples.contains(&[1, 2, 3, 4, 4, 50, 0, 0]));
    let other = Builder::indication(dfs::id::FILTERS_CHANGED)
        .u32(0x01, 9)
        .unwrap()
        .tlv(0x10, &one)
        .unwrap()
        .build()
        .unwrap();
    let before = r.kernel().wlan_log.len();
    r.indicate(c, other);
    assert_eq!(r.kernel().wlan_log.len(), before);
}

#[test]
fn a_modem_restart_removes_everything_by_identifier_and_starts_over() {
    let mut r = Rig::up();
    r.queue_sa(true);
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 1, INNER4);
    r.connect(21, 4, tech::LOCAL_BREAKOUT, 2, WIFI4);
    let c = r.modem().dfs_client(1, 4).unwrap();
    let wanted = Builder::indication(dfs::id::PORTS_WANTED)
        .tlv(0x01, &[1, 4, 6, 0, 0, 0, 0x50, 0xc3])
        .unwrap()
        .build()
        .unwrap();
    r.indicate(c, wanted);
    assert_eq!(r.e.ports_in_store(), 9);
    assert_eq!(r.e.encap_sockets(), 1);

    // services gone: clients and in-flight work go, the kernel is not touched yet
    r.modem().silent.push((wds::SERVICE, reverse::id::IPSEC_SA));
    r.connect(LINK2_MUX, 6, tech::IWLAN_S2B, 3, INNER6);
    let mark = r.log_len();
    r.e.on_service(r.now, ServiceEvent::ModemDown);
    r.pump();
    assert!(r.modem().clients.is_empty());
    assert_eq!(r.e.ready_clients(), 0);
    assert_eq!(r.log_since(mark), Vec::<String>::new());
    assert_eq!(r.kernel().states.len(), 2);
    // the deadline of the connect that waited does nothing now
    r.advance(10_000);
    assert_eq!(r.answers().len(), 2);

    // services back
    r.modem().silent.clear();
    let mark = r.log_len();
    let links_before = r.kernel().links.len();
    r.modem_up();
    {
        let k = r.kernel();
        assert!(k.is_clean());
        assert_eq!(k.links.len(), links_before);
        assert_eq!(k.sockets.len(), 8, "the two ports of IMS stay held");
        assert!(k.tuples.is_empty());
        assert!(!k.log[mark..].iter().any(|l| l.starts_with("getsa")));
        assert!(k.log[mark..].iter().any(|l| l == "genl 9"));
    }
    assert_eq!(r.e.encap_sockets(), 0);
    assert_eq!(r.e.ports_in_store(), 8);
    assert_eq!(r.e.tunnels_up(), 0);
    assert_eq!(r.e.ready_clients(), 8);
    // and it works again
    r.modem().sa_segments = vec![whole_sa(7, true)];
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 4, INNER4);
    assert_eq!(r.answers().last(), Some(&(1, 4)));
}

#[test]
fn links_that_went_with_the_modem_are_made_again() {
    let mut r = Rig::up();
    r.e.on_service(r.now, ServiceEvent::ModemDown);
    r.kernel_mut().links.clear();
    r.modem_up();
    assert_eq!(r.kernel().links.len(), 4);
    assert_eq!(r.e.ready_clients(), 8);
}

#[test]
fn a_daemon_restart_removes_what_the_state_file_names_before_anything_else() {
    let mut old = Rig::up();
    old.queue_sa(false);
    old.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 1, INNER4);
    let file = old.kernel().state_file.clone().unwrap();
    let text = String::from_utf8(file.clone()).unwrap();
    assert!(text.contains(&format!("{TX_SPI:x}")));
    assert!(text.contains(WIFI4));
    for key in [RX_CRYPT.as_slice(), &TX_CRYPT, &RX_AUTH, &TX_AUTH] {
        assert!(!file.windows(key.len()).any(|w| w == key));
    }
    // a new engine on the same kernel: same state, no tables
    let m = SimModem::default();
    let mut new = Engine::new(Config::default(), m.clone(), old.k.clone());
    let mark = old.log_len();
    new.start(old.now);
    let log = old.log_since(mark);
    assert_eq!(
        log,
        [
            "link down",
            "link down",
            "link down",
            "link down",
            "genl 9",
            "delpolicy Out",
            "delpolicy In",
            "delpolicy Fwd",
            "delsa",
            "delsa",
            "delrule",
            "store state"
        ]
    );
    let k = old.kernel();
    assert!(k.states.is_empty() && k.policies.is_empty() && k.rules.is_empty());
    assert_eq!(k.state_file.as_deref(), Some(&b"wlantunnel-state 1\n"[..]));
    drop(k);
    new.on_service(old.now, ServiceEvent::ModemUp);
    assert!(old.kernel().is_clean());
}

#[test]
fn a_corrupt_state_file_is_dropped() {
    let mut r = Rig::new();
    r.kernel_mut().state_file = Some(b"sa 50 zz\n".to_vec());
    r.e.start(r.now);
    assert_eq!(
        r.kernel().state_file.as_deref(),
        Some(&b"wlantunnel-state 1\n"[..])
    );
    assert!(r.e.take_lines().iter().any(|l| l.contains("corrupt")));
}

#[test]
fn the_state_goes_to_the_file_before_the_first_state_goes_to_the_kernel() {
    let mut r = Rig::up();
    r.queue_sa(false);
    r.kernel_mut()
        .fail
        .insert("newsa".into(), KernelError::Failed(1));
    let mark = r.log_len();
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 1, INNER4);
    let log = r.log_since(mark);
    let store = log.iter().position(|l| l == "store state").unwrap();
    let newsa = log.iter().position(|l| l == "newsa").unwrap();
    assert!(store < newsa);
    assert_eq!(
        r.kernel().state_file.as_deref(),
        Some(&b"wlantunnel-state 1\n"[..]),
        "the rollback cleared it"
    );
}

#[test]
fn a_state_file_that_cannot_be_written_refuses_the_connect() {
    let mut r = Rig::up();
    r.queue_sa(false);
    r.kernel_mut()
        .fail
        .insert("store state".into(), KernelError::Failed(28));
    let mark = r.log_len();
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 1, INNER4);
    assert_eq!(r.answers(), vec![(0, 1)]);
    assert!(r.lines.iter().any(|l| l.contains("write failed")));
    assert!(!r.log_since(mark).iter().any(|l| l == "newsa"));
    assert!(r.kernel().is_clean());
}

#[test]
fn a_restart_stops_the_path_before_any_policy_goes() {
    // the modem comes back
    let mut r = Rig::up();
    r.queue_sa(false);
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 1, INNER4);
    let mark = r.log_len();
    r.e.on_service(r.now, ServiceEvent::ModemUp);
    let log = r.log_since(mark);
    let at = |name: &str| log.iter().position(|l| l == name).unwrap();
    assert!(at("link down") < at("genl 9"));
    assert!(at("genl 9") < at("delpolicy Out"));
    assert!(r.kernel().is_clean());

    // a new process, and the module cannot be flushed: the policies stay until it can
    let mut r = Rig::up();
    r.queue_sa(false);
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 1, INNER4);
    r.kernel_mut()
        .fail
        .insert("genl 9".into(), KernelError::Failed(5));
    let mut new = Engine::new(Config::default(), SimModem::default(), r.k.clone());
    new.start(r.now);
    assert_eq!(r.kernel().policies.len(), 3);
    assert_eq!(r.kernel().states.len(), 2);
    assert!(!r
        .kernel()
        .state_file
        .as_ref()
        .unwrap()
        .ends_with(b"state 1\n"));
    new.tick(new.next_deadline().unwrap());
    let k = r.kernel();
    assert!(k.policies.is_empty() && k.states.is_empty() && k.forwards.is_empty());
    assert_eq!(k.state_file.as_deref(), Some(&b"wlantunnel-state 1\n"[..]));
}

#[test]
fn an_inner_address_that_cannot_be_a_tunnel_of_the_modem_is_refused() {
    let mut r = Rig::up();
    for (n, bad) in [
        "0.0.0.0",
        "127.0.0.1",
        "224.0.0.1",
        "169.254.1.1",
        "255.255.255.255",
    ]
    .into_iter()
    .enumerate()
    {
        r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, n as u32, bad);
        assert_eq!(r.answers().last(), Some(&(0, n as u32)), "{bad}");
    }
    r.connect(LINK2_MUX, 6, tech::IWLAN_S2B, 9, "fe80::1");
    assert_eq!(r.answers().last(), Some(&(0, 9)));

    // on the transport
    r.queue_sa(false);
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 10, WIFI4);
    assert_eq!(r.answers().last(), Some(&(0, 10)));
    // on another interface
    r.kernel_mut().addrs.push(("tun0".into(), 40, ip(INNER4)));
    r.modem().sa_segments = vec![whole_sa(7, false)];
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 11, INNER4);
    assert_eq!(r.answers().last(), Some(&(0, 11)));
    assert!(r.kernel().is_clean());
    // on a forward link it is what a tunnel looks like
    r.kernel_mut().addrs.pop();
    r.kernel_mut()
        .addrs
        .push(("rmnet_data0".into(), 41, ip(INNER4)));
    r.modem().sa_segments = vec![whole_sa(7, false)];
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 12, INNER4);
    assert_eq!(r.answers().last(), Some(&(1, 12)));
}

#[test]
fn only_wifi_can_be_the_transport() {
    let mut r = Rig::up();
    r.kernel_mut().addrs = vec![("rmnet_data1".into(), 30, ip(WIFI4))];
    r.queue_sa(false);
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 1, INNER4);
    assert_eq!(r.answers(), vec![(0, 1)]);
    r.connect(21, 4, tech::LOCAL_BREAKOUT, 2, WIFI4);
    assert_eq!(r.answers().last(), Some(&(0, 2)));
    assert!(r.kernel().is_clean());
}

#[test]
fn a_new_family_with_other_states_than_the_first_is_refused() {
    let mut r = Rig::up();
    r.queue_sa(false);
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 1, INNER4);
    let other = sa_keys(
        sa_head(7, 1, 0)
            .u32(0x10, RX_SPI + 1)
            .unwrap()
            .u32(0x11, TX_SPI + 1)
            .unwrap()
            .u32(0x12, 3)
            .unwrap()
            .u32(0x13, 1)
            .unwrap()
            .tlv(0x14, &tunnel_addr(EPDG4))
            .unwrap()
            .tlv(0x15, &tunnel_addr(WIFI4))
            .unwrap()
            .u32(0x16, 6)
            .unwrap()
            .u32(0x17, 12)
            .unwrap(),
    )
    .build()
    .unwrap();
    r.modem().sa_segments = vec![other];
    r.connect(LINK2_MUX, 6, tech::IWLAN_S2B, 2, INNER6);
    assert_eq!(r.answers(), vec![(1, 1), (0, 2)]);
    assert_eq!(r.e.tunnels_up(), 1);
    assert_eq!(r.kernel().policies.len(), 3);
}

#[test]
fn an_incoming_state_has_a_replay_window_and_an_outgoing_one_has_none() {
    let mut r = Rig::up();
    r.queue_sa(false);
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 1, INNER4);
    let k = r.kernel();
    let of = |spi| {
        k.states
            .iter()
            .find(|s| s.id.spi == spi)
            .unwrap()
            .replay_window
    };
    assert_eq!((of(TX_SPI), of(RX_SPI)), (0, 32));
}

#[test]
fn a_delete_that_fails_stays_in_the_file_and_is_tried_again() {
    let mut r = Rig::up();
    r.queue_sa(false);
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 1, INNER4);
    r.kernel_mut()
        .fail
        .insert("delsa".into(), KernelError::Failed(5));
    r.kernel_mut()
        .fail
        .insert("delpolicy In".into(), KernelError::Failed(5));
    r.disconnect(LINK2_MUX, 4, tech::IWLAN_S2B, 2, INNER4);
    assert_eq!(r.answers().last(), Some(&(0, 2)));
    {
        let k = r.kernel();
        assert_eq!((k.states.len(), k.policies.len()), (1, 1));
        let file = String::from_utf8(k.state_file.clone().unwrap()).unwrap();
        assert!(file.contains("sa ") && file.contains("pol in"));
    }
    let due = r.e.next_deadline().unwrap();
    r.advance(due - r.now);
    let k = r.kernel();
    assert!(k.is_clean());
    assert_eq!(k.state_file.as_deref(), Some(&b"wlantunnel-state 1\n"[..]));
}

#[test]
fn a_forward_that_cannot_be_removed_holds_the_policies_back() {
    let mut r = Rig::up();
    r.queue_sa(false);
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 1, INNER4);
    r.kernel_mut()
        .fail
        .insert("genl 6".into(), KernelError::Failed(5));
    r.disconnect(LINK2_MUX, 4, tech::IWLAN_S2B, 2, INNER4);
    assert_eq!(r.answers().last(), Some(&(0, 2)));
    assert_eq!(r.kernel().policies.len(), 3);
    // no new tunnel while it may still be there: the retry before it clears the way
    r.queue_sa(false);
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 3, INNER4);
    assert_eq!(r.answers().last(), Some(&(1, 3)));
    assert_eq!(r.kernel().policies.len(), 3);
}

#[test]
fn no_line_has_an_address_an_spi_or_a_key() {
    let mut r = Rig::up();
    r.queue_sa(true);
    r.connect(LINK2_MUX, 4, tech::IWLAN_S2B, 0x4242_4242, INNER4);
    r.modem().sa_segments = vec![whole_sa(7, true)];
    r.connect(LINK2_MUX, 6, tech::IWLAN_S2B, 2, INNER6);
    r.disconnect(LINK2_MUX, 4, tech::IWLAN_S2B, 3, INNER4);
    r.e.on_service(r.now, ServiceEvent::ModemDown);
    r.modem_up();
    assert!(r.lines.len() > 20);
    let spi = |v: u32| [format!("{v:x}"), format!("{v:#x}"), format!("{v}")];
    let mut banned: Vec<String> = [WIFI4, WIFI6, EPDG4, INNER4, INNER6]
        .iter()
        .map(|s| s.to_string())
        .collect();
    banned.extend(spi(RX_SPI));
    banned.extend(spi(TX_SPI));
    banned.extend(spi(0x4242_4242));
    for l in &r.lines {
        for b in &banned {
            assert!(!l.contains(b.as_str()), "{l:?} has {b}");
        }
        assert!(!l.contains(';'), "{l:?} has a semicolon");
    }
}

#[test]
fn a_state_id_debug_has_no_address() {
    let id = SaId {
        proto: 50,
        spi: 1,
        src: ip(WIFI4),
        dst: ip(EPDG4),
    };
    assert!(!format!("{id:?}").contains("192"));
}

#[test]
fn messages_from_a_stranger_or_not_qmi_change_nothing() {
    let mut r = Rig::up();
    let mut junk = vec![1, 2, 3];
    r.e.on_qmi(r.now, 999, &mut junk);
    assert_eq!(junk, [0, 0, 0]);
    let c = r.wds_client(LINK2_MUX, 4);
    let mut junk = vec![9; 40];
    r.e.on_qmi(r.now, c, &mut junk);
    assert_eq!(junk, [0; 40]);
    let late = whole_sa(1, false);
    r.indicate(c, late);
    assert!(r.kernel().is_clean());
}

#[test]
fn the_links_of_the_data_daemon_never_take_a_mux_of_the_reverse_links() {
    let data = dataos_datacore::Config::default();
    let last = u16::from(data.base_mux_id) + u16::from(data.link_count) - 1;
    let ours = Config::default();
    assert_eq!(ours.first_mux, 18);
    assert!(last < u16::from(ours.first_mux), "last mux {last}");
    assert_eq!(data.reserve_links, 2);
    assert_eq!(ours.links, 4);
    assert!(data.link_count <= 17);
}

#[test]
fn the_answer_of_a_port_request_ends_at_the_first_port_that_cannot_be_had() {
    let mut r = Rig::up();
    let c = r.modem().dfs_client(1, 4).unwrap();
    r.kernel_mut().busy_ports = vec![500];
    let mut entries = vec![3u8];
    for port in [40000u16, 500, 40001] {
        entries.extend([4u8, 17, 0, 0, 0]);
        entries.extend(port.to_le_bytes());
    }
    let wanted = Builder::indication(dfs::id::PORTS_WANTED)
        .tlv(0x01, &entries)
        .unwrap()
        .build()
        .unwrap();
    r.indicate(c, wanted);
    let answer = r.m.0.borrow().sent_of(dfs::SERVICE, dfs::id::PORTS_ANSWER)[0]
        .1
        .clone();
    let f = Frame::parse(&answer).unwrap();
    let v = f.tlv(0x01).unwrap();
    assert_eq!((v[0], &v[1..5]), (1, &[0u8, 0, 0, 0][..]));
    assert_eq!(r.e.ports_in_store(), 9);
    let said = r
        .lines
        .iter()
        .any(|l| l.contains("port 500") && l.contains("bind failed"));
    assert!(said);
    assert!(r
        .lines
        .iter()
        .any(|l| l.contains("first ports [40000, 500, 40001]")));
}

#[test]
fn local_breakout_is_taken_as_soon_as_the_client_is_registered() {
    let mut r = Rig::new();
    r.e.start(r.now);
    // the answers of the DFS client stay away, so the client stops short of ready
    r.modem().silent.push((dfs::SERVICE, dfs::id::BIND_CLIENT));
    r.modem_up();
    r.connect(18, 4, tech::LOCAL_BREAKOUT, 1, WIFI4);
    assert_eq!(r.answers(), vec![(1, 1)]);
    r.connect(18, 6, tech::IWLAN_S2B, 2, INNER6);
    assert_eq!(r.answers().last(), Some(&(0, 2)));
}

/// The module compares the tuple with the SPI field of the packet, so the bytes of the modem must reach it unchanged.
#[test]
fn an_esp_filter_reaches_the_module_in_the_byte_order_of_the_packet() {
    let mut r = Rig::up();
    r.queue_sa(false);
    r.connect(LINK2_MUX, 6, tech::IWLAN_S2B, 1, INNER6);
    let mut entry = vec![0u8; 145];
    entry[0] = 6;
    entry[75..79].copy_from_slice(&0x32u32.to_le_bytes());
    entry[121] = 1;
    entry[129..133].copy_from_slice(&[0xc1, 0xc2, 0xc3, 0xc4]);
    let mut list = vec![1u8];
    list.extend(entry);
    let c = r.modem().dfs_client(LINK2_MUX, 6).unwrap();
    let changed = Builder::indication(dfs::id::FILTERS_CHANGED)
        .u32(0x01, 0)
        .unwrap()
        .tlv(0x10, &list)
        .unwrap()
        .build()
        .unwrap();
    r.indicate(c, changed);
    assert!(r
        .kernel()
        .tuples
        .contains(&[0xc1, 0xc2, 0xc3, 0xc4, 6, 50, 0, 0]));
}
