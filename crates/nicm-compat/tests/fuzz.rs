// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Random requests against a daemon that sends random things. Nothing may
//! panic, and the books must stay straight.
#![allow(clippy::disallowed_methods)] // test code, the list is for the shipped crates
use dataos_nicm_compat::client::MAX_WAITING;
use dataos_nicm_compat::{Client, NicmError, Notice, Transport};
use dataos_wire::*;
use std::collections::VecDeque;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0.max(1);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn chance(&mut self, p: usize) -> bool {
        self.below(100) < p
    }
}

#[derive(Default)]
struct Script {
    inbox: VecDeque<Notify>,
    sent: Vec<Request>,
    fail: bool,
}

impl Transport for Script {
    fn send(&mut self, req: &Request) -> Result<(), NicmError> {
        if self.fail {
            return Err(NicmError::Transport);
        }
        self.sent.push(req.clone());
        Ok(())
    }
    fn recv(&mut self) -> Option<Notify> {
        self.inbox.pop_front()
    }
}

fn code(rng: &mut Rng) -> ResultCode {
    [
        ResultCode::Ok,
        ResultCode::Ok,
        ResultCode::Invalid,
        ResultCode::NoLink,
        ResultCode::NotReady,
        ResultCode::Unsupported,
    ][rng.below(6)]
}

fn notify(rng: &mut Rng, known: &[u32]) -> Notify {
    // mostly answers to requests that were sent, some to others
    let txn = if !known.is_empty() && rng.chance(80) {
        known[rng.below(known.len())]
    } else {
        rng.below(40) as u32
    };
    match rng.below(7) {
        0 => Notify::HelloAck {
            ready: rng.chance(50),
        },
        1 => Notify::Ready {
            ready: rng.chance(50),
        },
        2 => Notify::RouteReply {
            txn,
            code: code(rng),
            link: rng.below(16) as u8,
            existing: rng.chance(50),
            companion: rng.chance(50),
            ifname: "rmnet_data1".into(),
        },
        3 | 4 => Notify::Done {
            txn,
            code: code(rng),
        },
        5 => Notify::MtuReply {
            txn,
            code: code(rng),
            v4: 1400,
            v6: 1300,
        },
        _ => Notify::Event {
            link: rng.below(16) as u8,
            slot: 0,
            event: IfaceEvent::Reconfigured,
        },
    }
}

#[test]
fn random_calls_and_answers_never_panic_and_keep_their_promises() {
    let mut rng = Rng(0x0dd_ba11);
    let (mut restarts, mut done, mut refused, mut events) = (0u32, 0u32, 0u32, 0u32);
    for _ in 0..1500 {
        let mut c = Client::new(Script::default());
        let mut txns: Vec<u32> = Vec::new();
        let mut open: Vec<u32> = Vec::new();
        for _ in 0..120 {
            match rng.below(12) {
                0 => {
                    let _ = c.hello();
                }
                1..=4 => {
                    let r = match rng.below(4) {
                        0 => c.query_mtu(1),
                        1 => c.link_release(1),
                        2 => c.screen_state(rng.chance(50)),
                        _ => c.route_lookup(RouteRequest {
                            slot: 0,
                            family: Family::V4,
                            apn: Some("x.example".into()),
                            apn_type: 1,
                            apn_type_mask: 1,
                        }),
                    };
                    if let Ok(t) = r {
                        txns.push(t);
                        open.push(t);
                    }
                }
                5 => {
                    if !open.is_empty() {
                        let t = open.swap_remove(rng.below(open.len()));
                        c.forget(t);
                    }
                }
                6 => {
                    for n in c.transport_lost() {
                        if n == Notice::RestartStart {
                            restarts += 1;
                        }
                    }
                    let _ = c.reconnected();
                }
                7 => c.transport_mut().fail = !c.transport_mut().fail,
                _ => {
                    for _ in 0..1 + rng.below(4) {
                        let n = notify(&mut rng, &txns);
                        c.transport_mut().inbox.push_back(n);
                    }
                }
            }
            for n in c.poll() {
                match n {
                    Notice::RestartStart => restarts += 1,
                    Notice::Iface { .. } => events += 1,
                    Notice::RestartDone => {}
                }
            }
            // an answer comes out once, and at most the bound of requests wait
            let mut still = Vec::new();
            for t in open.drain(..) {
                match c.take_reply(t) {
                    Some(r) => {
                        assert!(c.take_reply(t).is_none());
                        if r.is_ok() {
                            done += 1;
                        } else {
                            refused += 1;
                        }
                    }
                    None => still.push(t),
                }
            }
            open = still;
            assert!(open.len() <= MAX_WAITING, "{}", open.len());
        }
    }
    // the sequences reached the interesting paths
    assert!(
        restarts > 500 && done > 500 && refused > 500 && events > 500,
        "{restarts} {done} {refused} {events}"
    );
}

fn script_client() -> Client<Script> {
    Client::new(Script::default())
}

#[test]
fn an_answer_of_another_kind_is_not_the_answer() {
    let mut c = script_client();
    let t = c.query_mtu(1).unwrap();
    // a plain "done" for a request that wants the MTUs, and a route reply
    for n in [
        Notify::Done {
            txn: t,
            code: ResultCode::Ok,
        },
        Notify::RouteReply {
            txn: t,
            code: ResultCode::Ok,
            link: 1,
            existing: false,
            companion: false,
            ifname: "rmnet_data1".into(),
        },
    ] {
        c.transport_mut().inbox.push_back(n);
    }
    c.poll();
    assert_eq!(c.take_reply(t), None);
    assert_eq!(c.stale, 2);
    c.transport_mut().inbox.push_back(Notify::MtuReply {
        txn: t,
        code: ResultCode::Ok,
        v4: 1400,
        v6: 1380,
    });
    c.poll();
    assert_eq!(
        c.take_reply(t),
        Some(Ok(dataos_nicm_compat::Reply::Mtu { v4: 1400, v6: 1380 }))
    );
    // a second answer for a request that was answered is late
    c.transport_mut().inbox.push_back(Notify::MtuReply {
        txn: t,
        code: ResultCode::Ok,
        v4: 1,
        v6: 1,
    });
    c.poll();
    assert_eq!(c.stale, 3);
}

#[test]
fn transaction_numbers_skip_zero_and_the_ones_that_wait() {
    let mut c = script_client();
    c.set_next_txn_for_tests(u32::MAX);
    assert_eq!(c.query_mtu(1), Ok(u32::MAX));
    assert_eq!(c.query_mtu(1), Ok(1), "after the largest comes 1, never 0");
    // the number the counter is at waits already
    c.set_next_txn_for_tests(1);
    assert_eq!(c.query_mtu(1), Ok(2));
    c.set_next_txn_for_tests(0);
    assert_eq!(c.query_mtu(1), Ok(3));
}

#[test]
fn one_poll_handles_a_bounded_number_of_messages() {
    let mut c = script_client();
    for _ in 0..200 {
        c.transport_mut().inbox.push_back(Notify::Event {
            link: 1,
            slot: 0,
            event: IfaceEvent::Reconfigured,
        });
    }
    let sizes: Vec<usize> = std::iter::from_fn(|| {
        let n = c.poll().len();
        (n > 0).then_some(n)
    })
    .collect();
    assert_eq!(sizes, vec![64, 64, 64, 8]);
}
