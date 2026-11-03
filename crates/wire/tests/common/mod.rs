// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Shared test helpers: a deterministic generator and message samples.
#![allow(dead_code, clippy::disallowed_methods)]
use dataos_wire::limits::*;
use dataos_wire::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// xorshift64, no dependencies.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0.max(1);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    pub fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }

    pub fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
}

pub fn gen_ip(rng: &mut Rng, fam: Family) -> IpAddr {
    match fam {
        Family::V4 => IpAddr::V4(Ipv4Addr::from(rng.next() as u32)),
        Family::V6 => IpAddr::V6(Ipv6Addr::from(
            (u128::from(rng.next()) << 64) | u128::from(rng.next()),
        )),
    }
}

pub fn gen_name(rng: &mut Rng, max: usize) -> String {
    let n = rng.below(max + 1);
    (0..n).map(|_| (b'a' + (rng.byte() % 26)) as char).collect()
}

pub fn gen_family(rng: &mut Rng) -> Family {
    if rng.chance(50) {
        Family::V4
    } else {
        Family::V6
    }
}

pub fn gen_reason(rng: &mut Rng) -> EndReason {
    match rng.below(4) {
        0 => EndReason::Network {
            kind: rng.next() as u16,
            reason: rng.next() as i16,
        },
        1 => EndReason::NetworkBasic(rng.next() as u16),
        2 => EndReason::Qmi(rng.next() as u16),
        _ => EndReason::Local(match rng.below(9) {
            0 => LocalReason::UserRequested,
            1 => LocalReason::ModemRestart,
            2 => LocalReason::NoQmiClient,
            3 => LocalReason::Timeout,
            4 => LocalReason::BindFailed,
            5 => LocalReason::LinkFailed,
            6 => LocalReason::BadSettings,
            7 => LocalReason::Malformed,
            _ => LocalReason::DaemonLost,
        }),
    }
}

pub fn gen_code(rng: &mut Rng) -> ResultCode {
    [
        ResultCode::Ok,
        ResultCode::Invalid,
        ResultCode::NoLink,
        ResultCode::NoSuchLink,
        ResultCode::TooMany,
        ResultCode::BadState,
        ResultCode::NotReady,
        ResultCode::Unsupported,
        ResultCode::NoMatch,
    ][rng.below(9)]
}

pub fn gen_route(rng: &mut Rng) -> RouteRequest {
    RouteRequest {
        slot: rng.byte(),
        family: gen_family(rng),
        apn: rng.chance(70).then(|| gen_name(rng, MAX_APN)),
        apn_type: rng.next() as u32,
        apn_type_mask: rng.next(),
    }
}

pub fn gen_event(rng: &mut Rng) -> IfaceEvent {
    let fam = gen_family(rng);
    let max_prefix = if fam == Family::V4 { 32 } else { 128 };
    match rng.below(7) {
        0 => IfaceEvent::Up,
        1 => IfaceEvent::Down(gen_reason(rng)),
        2 => IfaceEvent::Reconfigured,
        3 => IfaceEvent::NewAddr {
            family: fam,
            addr: gen_ip(rng, fam),
            prefix: rng.below(max_prefix + 1) as u8,
        },
        4 => IfaceEvent::DelAddr {
            family: fam,
            addr: gen_ip(rng, fam),
            prefix: rng.below(max_prefix + 1) as u8,
        },
        5 => IfaceEvent::MtuUpdate {
            family: fam,
            mtu: rng.next() as u32,
        },
        _ => IfaceEvent::OpFailed(gen_reason(rng)),
    }
}

pub fn gen_request(rng: &mut Rng) -> Request {
    let txn = rng.next() as u32;
    let link = rng.byte();
    match rng.below(7) {
        0 => Request::Hello,
        1 => Request::RouteLookup {
            txn,
            req: gen_route(rng),
        },
        6 => Request::RouteLookupPref {
            txn,
            req: gen_route(rng),
            xt_pref: rng.next() as u16,
        },
        2 => Request::LinkRelease { txn, link },
        3 => Request::QueryMtu { txn, link },
        4 => Request::ScreenState {
            txn,
            on: rng.chance(50),
        },
        _ => Request::MatchingCall {
            txn,
            req: gen_route(rng),
            hint: MatchHint {
                profile_3gpp: rng.chance(50).then(|| rng.byte()),
                profile_3gpp2: rng.chance(50).then(|| rng.byte()),
                xt_pref: rng.chance(50).then(|| rng.next() as u16),
                backup_name: rng.chance(50).then(|| rng.byte()),
                backup_type: rng.chance(50).then(|| rng.byte()),
            },
        },
    }
}

pub fn gen_notify(rng: &mut Rng) -> Notify {
    let txn = rng.next() as u32;
    match rng.below(6) {
        0 => Notify::HelloAck {
            ready: rng.chance(50),
        },
        1 => Notify::Ready {
            ready: rng.chance(50),
        },
        2 => Notify::RouteReply {
            txn,
            code: gen_code(rng),
            link: rng.byte(),
            existing: rng.chance(50),
            companion: rng.chance(50),
            ifname: gen_name(rng, MAX_IFNAME),
            tech: rng.next() as u16,
        },
        3 => Notify::Done {
            txn,
            code: gen_code(rng),
        },
        4 => Notify::MtuReply {
            txn,
            code: gen_code(rng),
            v4: rng.next() as u32,
            v6: rng.next() as u32,
        },
        _ => Notify::Event {
            link: rng.byte(),
            slot: rng.byte(),
            event: gen_event(rng),
        },
    }
}

pub fn sample_route() -> RouteRequest {
    RouteRequest {
        slot: 1,
        family: Family::V6,
        apn: Some("internet.example".into()),
        apn_type: 5,
        apn_type_mask: 0x201,
    }
}

pub fn all_requests() -> Vec<Request> {
    vec![
        Request::Hello,
        Request::RouteLookupPref {
            txn: 7,
            req: sample_route(),
            xt_pref: 0x8021,
        },
        Request::RouteLookup {
            txn: 7,
            req: sample_route(),
        },
        Request::RouteLookup {
            txn: u32::MAX,
            req: RouteRequest {
                apn: None,
                ..sample_route()
            },
        },
        Request::LinkRelease { txn: 8, link: 3 },
        Request::QueryMtu { txn: 9, link: 14 },
        Request::ScreenState { txn: 12, on: false },
        Request::MatchingCall {
            txn: 14,
            req: sample_route(),
            hint: MatchHint::default(),
        },
        Request::MatchingCall {
            txn: 15,
            req: sample_route(),
            hint: MatchHint {
                profile_3gpp: Some(3),
                profile_3gpp2: Some(4),
                xt_pref: Some(0x0102),
                backup_name: Some(1),
                backup_type: Some(2),
            },
        },
    ]
}

pub fn all_notifies() -> Vec<Notify> {
    vec![
        Notify::HelloAck { ready: true },
        Notify::Ready { ready: false },
        Notify::RouteReply {
            txn: 7,
            code: ResultCode::Ok,
            link: 3,
            existing: true,
            companion: true,
            ifname: "rmnet_data3".into(),
            tech: 0x8021,
        },
        Notify::RouteReply {
            txn: 7,
            code: ResultCode::NoLink,
            link: 0,
            existing: false,
            companion: false,
            ifname: String::new(),
            tech: 0,
        },
        Notify::Done {
            txn: 8,
            code: ResultCode::Unsupported,
        },
        Notify::MtuReply {
            txn: 9,
            code: ResultCode::Ok,
            v4: 1400,
            v6: 1380,
        },
        Notify::Event {
            link: 3,
            slot: 0,
            event: IfaceEvent::Up,
        },
        Notify::Event {
            link: 3,
            slot: 1,
            event: IfaceEvent::NewAddr {
                family: Family::V4,
                addr: "192.0.2.10".parse().unwrap(),
                prefix: 30,
            },
        },
        Notify::Event {
            link: 3,
            slot: 1,
            event: IfaceEvent::DelAddr {
                family: Family::V6,
                addr: "2001:db8::5".parse().unwrap(),
                prefix: 64,
            },
        },
        Notify::Event {
            link: 3,
            slot: 0,
            event: IfaceEvent::MtuUpdate {
                family: Family::V6,
                mtu: 1280,
            },
        },
        Notify::Event {
            link: 255,
            slot: 0,
            event: IfaceEvent::Down(EndReason::Network {
                kind: 3,
                reason: -26,
            }),
        },
        Notify::Event {
            link: 0,
            slot: 0,
            event: IfaceEvent::Reconfigured,
        },
        Notify::Event {
            link: 0,
            slot: 0,
            event: IfaceEvent::OpFailed(EndReason::Local(LocalReason::BindFailed)),
        },
    ]
}

/// The largest request: an APN at its bound.
pub fn largest_request() -> Request {
    Request::MatchingCall {
        txn: 1,
        req: RouteRequest {
            apn: Some("a".repeat(MAX_APN)),
            ..sample_route()
        },
        hint: MatchHint {
            profile_3gpp: Some(255),
            profile_3gpp2: Some(255),
            xt_pref: Some(u16::MAX),
            backup_name: Some(255),
            backup_type: Some(255),
        },
    }
}
