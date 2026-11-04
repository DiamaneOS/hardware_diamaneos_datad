// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! QRTR: the control packets of the name service, the table of modem services they build, and the transport that
//! reads them and the datagrams of the clients from sockets.
#![no_main]
use dataos_datacore::{Qmi, ServiceEvent};
use dataos_datad::fake::FakeQrtr;
use dataos_datad::qrtr::{Control, Peer, Services, CTRL_PORT, DEL_SERVER, NEW_SERVER, WANTED};
use dataos_datad::transport::QmiLink;
use dataos_fuzz::Input;
use libfuzzer_sys::fuzz_target;

const LOCAL: u32 = 1;

/// A control packet: raw, or one the table acts on.
fn packet(inp: &mut Input<'_>) -> [u8; Control::LEN] {
    if inp.one_in(4) {
        let mut b = [0u8; Control::LEN];
        b.copy_from_slice(&inp.exact(Control::LEN));
        return b;
    }
    let command = match inp.u8() % 8 {
        0..=3 => NEW_SERVER,
        4..=6 => DEL_SERVER,
        _ => inp.u32(),
    };
    let service = match inp.pick(&WANTED) {
        Some(s) if !inp.one_in(8) => u32::from(s),
        _ => inp.u32(),
    };
    let instance = u32::from(inp.u8() % 4);
    let node = match inp.u8() % 8 {
        0 => LOCAL,
        1 => inp.u32(),
        n => u32::from(n % 3) * 2,
    };
    let port = match inp.u8() % 8 {
        0 => 0,
        1 => inp.u32(),
        n => 100 + u32::from(n),
    };
    Control {
        command,
        words: [service, instance, node, port],
    }
    .encode()
}

/// The modem goes up only from down and down only from up, and a target is a remote server.
fn check(up: &mut bool, events: &[ServiceEvent], is_up: bool, target: impl Fn(u8) -> Option<Peer>) {
    for ev in events {
        match ev {
            ServiceEvent::ModemUp => {
                assert!(!*up, "up twice");
                *up = true;
            }
            ServiceEvent::ModemDown => {
                assert!(*up, "down twice");
                *up = false;
            }
        }
    }
    assert_eq!(*up, is_up);
    for s in WANTED {
        match target(s) {
            Some(p) => {
                assert!(is_up);
                assert_ne!(p.port, 0);
            }
            None => assert!(!is_up),
        }
    }
}

fn table(inp: &mut Input<'_>) {
    let mut s = Services::new(LOCAL);
    let mut up = false;
    let mut last = s.stats();
    for _ in 0..256 {
        if inp.is_empty() {
            break;
        }
        let ev = if inp.one_in(32) {
            s.clear()
        } else {
            let b = packet(inp);
            let Some(c) = Control::decode(&b) else {
                panic!("20 bytes did not decode");
            };
            assert_eq!(c.encode(), b);
            s.apply(c)
        };
        check(&mut up, &ev, s.is_up(), |x| s.target(x));
        for x in WANTED {
            assert!(s.target(x).is_none_or(|p| p.node != LOCAL));
        }
        let now = s.stats();
        assert!(now.local_refused >= last.local_refused);
        assert!(now.table_full >= last.table_full);
        assert!(now.stale_removals >= last.stale_removals);
        last = now;
    }
}

fn link(inp: &mut Input<'_>) {
    let mut l = QmiLink::new(FakeQrtr::new(LOCAL));
    let mut now = 0u64;
    let (ev, _) = l.poll_control(now, 8);
    assert!(ev.is_empty());
    let Some(ctrl) = l.io().open_sockets().first().copied() else {
        return;
    };
    let ns = Peer {
        node: LOCAL,
        port: CTRL_PORT,
    };
    let mut up = false;
    let mut client = None;
    for _ in 0..128 {
        if inp.is_empty() {
            break;
        }
        match inp.u8() % 8 {
            // the name service, or someone else on the control port
            0..=3 => {
                let from = if inp.one_in(8) {
                    Peer {
                        node: inp.u32(),
                        port: inp.u32(),
                    }
                } else {
                    ns
                };
                let n = if inp.one_in(8) {
                    usize::from(inp.u8() % 40)
                } else {
                    Control::LEN
                };
                let b = if n == Control::LEN {
                    packet(inp).to_vec()
                } else {
                    inp.exact(n)
                };
                l.io_mut().deliver(ctrl, from, &b);
                let budget = 1 + inp.below(4);
                let (ev, _) = l.poll_control(now, budget);
                check(&mut up, &ev, l.services().is_up(), |x| {
                    l.services().target(x)
                });
                if !up {
                    client = None;
                }
            }
            // a datagram for a client, from its server or not
            4..=6 => {
                if client.is_none() && up {
                    let service = inp.pick(&WANTED).unwrap_or(WANTED[0]);
                    let before = l.io().open_sockets();
                    if let Ok(id) = l.open_client(service) {
                        let sock = l
                            .io()
                            .open_sockets()
                            .into_iter()
                            .find(|s| !before.contains(s));
                        let target = l.services().target(service);
                        if let (Some(sock), Some(target)) = (sock, target) {
                            client = Some((id, sock, target));
                        }
                    }
                }
                let Some((id, sock, target)) = client else {
                    continue;
                };
                let from = if inp.one_in(4) {
                    Peer {
                        node: inp.u32(),
                        port: inp.u32(),
                    }
                } else {
                    target
                };
                let n = usize::from(inp.u16() % 9000);
                let b = inp.exact(n);
                l.io_mut().deliver(sock, from, &b);
                let (got, _) = l.poll_clients(now);
                if from == target && !b.is_empty() {
                    assert_eq!(got, vec![(id, b)]);
                } else {
                    assert!(got.is_empty());
                }
            }
            _ => {
                now = now.saturating_add(u64::from(inp.u16()));
                let (ev, _) = l.poll_control(now, 4);
                check(&mut up, &ev, l.services().is_up(), |x| {
                    l.services().target(x)
                });
                if !up {
                    client = None;
                }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut inp = Input(data);
    if inp.bool() {
        table(&mut inp);
    } else {
        link(&mut inp);
    }
});
