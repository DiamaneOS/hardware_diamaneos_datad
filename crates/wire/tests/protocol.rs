// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The protocol: round trips, strictness and the bounds, at the bound and one past it.
//! Made-up values only (documentation address ranges).
#![allow(clippy::disallowed_methods)] // test code, the list is for the shipped crates
use dataos_wire::limits::*;
use dataos_wire::*;

mod common;
use common::*;

fn bytes(ty: u8, number: u32, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![VERSION, ty];
    b.extend_from_slice(&number.to_le_bytes());
    b.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    b.extend_from_slice(payload);
    b
}

#[test]
fn requests_round_trip() {
    for r in all_requests() {
        assert_eq!(Request::decode(&r.encode().unwrap()).unwrap(), r);
    }
}

#[test]
fn notifications_round_trip() {
    for n in all_notifies() {
        assert_eq!(Notify::decode(&n.encode().unwrap()).unwrap(), n);
    }
}

#[test]
fn every_encodable_message_decodes_to_itself() {
    let mut rng = Rng(0x5eed);
    for _ in 0..5000 {
        let n = gen_notify(&mut rng);
        assert_eq!(Notify::decode(&n.encode().unwrap()).unwrap(), n);
        let r = gen_request(&mut rng);
        assert_eq!(Request::decode(&r.encode().unwrap()).unwrap(), r);
    }
}

#[test]
fn strict_decoding() {
    let good = Request::RouteLookup {
        txn: 1,
        req: sample_route(),
    }
    .encode()
    .unwrap();
    // trailing byte, version, type, truncation
    let mut b = good.clone();
    b.push(0);
    assert_eq!(Request::decode(&b).unwrap_err(), DecodeError::Length);
    let mut b = good.clone();
    b[0] = 9;
    assert_eq!(Request::decode(&b).unwrap_err(), DecodeError::Version);
    let mut b = good.clone();
    b[1] = 0x7f;
    assert_eq!(Request::decode(&b).unwrap_err(), DecodeError::Type);
    assert_eq!(
        Request::decode(&good[..5]).unwrap_err(),
        DecodeError::Truncated
    );
    // no notification decodes as a request and no request as a notification
    for n in all_notifies() {
        assert!(Request::decode(&n.encode().unwrap()).is_err(), "{n:?}");
    }
    for r in all_requests() {
        assert!(Notify::decode(&r.encode().unwrap()).is_err(), "{r:?}");
    }
    // a reply type is not a request and the other way round
    assert_eq!(
        Request::decode(&Notify::Ready { ready: true }.encode().unwrap()).unwrap_err(),
        DecodeError::Type
    );
    assert_eq!(Notify::decode(&good).unwrap_err(), DecodeError::Type);
    // NUL inside the APN, bad enum values
    let mut b = good.clone();
    let at = HEADER_LEN + 4;
    assert_eq!(b[at], b'i');
    b[at] = 0;
    assert_eq!(Request::decode(&b).unwrap_err(), DecodeError::Value);
    assert_eq!(
        Request::decode(&bytes(2, 1, &[0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])).unwrap_err(),
        DecodeError::Value,
        "family 2"
    );
    // a flag byte is 0 or 1
    assert_eq!(
        Request::decode(&bytes(7, 1, &[2])).unwrap_err(),
        DecodeError::Value
    );
    let mut r = Notify::Ready { ready: true }.encode().unwrap();
    r[HEADER_LEN] = 2;
    assert_eq!(Notify::decode(&r).unwrap_err(), DecodeError::Value);
    // a result code and an event kind that do not exist
    assert_eq!(
        Notify::decode(&bytes(0x83, 1, &[9])).unwrap_err(),
        DecodeError::Value
    );
    assert_eq!(
        Notify::decode(&bytes(0x86, 1, &[0, 7])).unwrap_err(),
        DecodeError::Value
    );
    // Hello carries no number
    let mut h = Request::Hello.encode().unwrap();
    h[2] = 1;
    assert_eq!(Request::decode(&h).unwrap_err(), DecodeError::Value);
    // a message over the bound is refused before it is read
    let mut huge = vec![VERSION, 1, 0, 0, 0, 0, 0, 0];
    huge.resize(MAX_MESSAGE + 1, 0);
    assert_eq!(Request::decode(&huge).unwrap_err(), DecodeError::Length);
}

#[test]
fn the_apn_is_bounded_and_never_cut() {
    let route = |apn: String| Request::RouteLookup {
        txn: 1,
        req: RouteRequest {
            apn: Some(apn),
            ..sample_route()
        },
    };
    assert!(route("a".repeat(MAX_APN)).encode().is_ok());
    assert_eq!(
        route("a".repeat(MAX_APN + 1)).encode().unwrap_err(),
        EncodeError::TooLong
    );
    assert_eq!(
        route("a\0b".into()).encode().unwrap_err(),
        EncodeError::Value
    );
    // and a hand-made one over the bound is refused by the decoder
    let mut p = vec![0, 0, 1, (MAX_APN + 1) as u8];
    p.extend(std::iter::repeat_n(b'a', MAX_APN + 1));
    p.extend_from_slice(&[0; 12]);
    assert_eq!(
        Request::decode(&bytes(2, 1, &p)).unwrap_err(),
        DecodeError::Length
    );
}

#[test]
fn the_interface_name_is_bounded_both_ways() {
    let reply = |ifname: String| Notify::RouteReply {
        txn: 1,
        code: ResultCode::Ok,
        link: 1,
        existing: false,
        companion: false,
        ifname,
    };
    assert!(reply("n".repeat(MAX_IFNAME)).encode().is_ok());
    assert_eq!(
        reply("n".repeat(MAX_IFNAME + 1)).encode().unwrap_err(),
        EncodeError::TooLong
    );
    let mut p = vec![0, 1, 0, (MAX_IFNAME + 1) as u8];
    p.extend(std::iter::repeat_n(b'n', MAX_IFNAME + 1));
    assert_eq!(
        Notify::decode(&bytes(0x82, 1, &p)).unwrap_err(),
        DecodeError::Length
    );
}

#[test]
fn the_flags_of_a_route_reply_are_two_bits() {
    for (flags, ok) in [
        (0u8, true),
        (1, true),
        (2, true),
        (3, true),
        (4, false),
        (0xff, false),
    ] {
        let p = vec![0, 1, flags, 0];
        let r = Notify::decode(&bytes(0x82, 1, &p));
        assert_eq!(r.is_ok(), ok, "flags {flags}");
        if !ok {
            assert_eq!(r.unwrap_err(), DecodeError::Value);
        }
    }
}

#[test]
fn a_prefix_and_an_address_stay_inside_their_family() {
    let ev = |family, addr: &str, prefix| Notify::Event {
        link: 1,
        slot: 0,
        event: IfaceEvent::NewAddr {
            family,
            addr: addr.parse().unwrap(),
            prefix,
        },
    };
    assert!(ev(Family::V4, "192.0.2.1", 32).encode().is_ok());
    assert_eq!(
        ev(Family::V4, "192.0.2.1", 33).encode().unwrap_err(),
        EncodeError::Value
    );
    assert!(ev(Family::V6, "2001:db8::1", 128).encode().is_ok());
    assert_eq!(
        ev(Family::V6, "2001:db8::1", 129).encode().unwrap_err(),
        EncodeError::Value
    );
    assert_eq!(
        ev(Family::V4, "2001:db8::1", 8).encode().unwrap_err(),
        EncodeError::Value
    );
    // hand-made: prefix 33 for v4, a v6 address in a v4 slot
    let mut p = vec![0, 3, 0, 4, 192, 0, 2, 1, 33];
    assert_eq!(
        Notify::decode(&bytes(0x86, 1, &p)).unwrap_err(),
        DecodeError::Value
    );
    p[7] = 1;
    p[8] = 32;
    assert!(Notify::decode(&bytes(0x86, 1, &p)).is_ok());
    let mut p = vec![0, 3, 0, 6];
    p.extend_from_slice(&[0; 16]);
    p.push(8);
    assert_eq!(
        Notify::decode(&bytes(0x86, 1, &p)).unwrap_err(),
        DecodeError::Value
    );
    // a link above 255 cannot be an event
    assert_eq!(
        Notify::decode(&bytes(0x86, 256, &[0, 0])).unwrap_err(),
        DecodeError::Value
    );
}

#[test]
fn the_largest_message_fits_the_bound_and_one_byte_more_is_refused() {
    let big = largest_request().encode().unwrap();
    assert_eq!(big.len() - HEADER_LEN, MAX_LARGEST_PAYLOAD);
    assert!(big.len() <= MAX_MESSAGE);
    // a header that claims the whole bound plus one
    let mut over = vec![VERSION, 1, 0, 0, 0, 0];
    over.extend_from_slice(&((MAX_PAYLOAD + 1) as u16).to_le_bytes());
    over.resize(MAX_MESSAGE + 1, 0);
    assert_eq!(Request::decode(&over).unwrap_err(), DecodeError::Length);
    assert_eq!(Notify::decode(&over).unwrap_err(), DecodeError::Length);
    // and the exact bound is not refused for its size (this one fails on its type)
    let mut exact = vec![VERSION, 0x7f, 0, 0, 0, 0];
    exact.extend_from_slice(&(MAX_PAYLOAD as u16).to_le_bytes());
    exact.resize(MAX_MESSAGE, 0);
    assert_eq!(Request::decode(&exact).unwrap_err(), DecodeError::Type);
}

#[test]
fn debug_hides_the_apn_and_the_addresses() {
    let r = Request::RouteLookup {
        txn: 1,
        req: sample_route(),
    };
    assert!(!format!("{r:?}").contains("internet.example"));
    for n in all_notifies() {
        let s = format!("{n:?}");
        assert!(!s.contains("192.0.2") && !s.contains("2001:db8"), "{s}");
    }
}

#[test]
fn the_version_and_the_bytes_of_a_route_reply_are_pinned() {
    // A daemon and a library of different builds must not read each other's layouts: the
    // version changes with every layout, and these bytes change with it.
    assert_eq!(VERSION, 4);
    let reply = Notify::RouteReply {
        txn: 7,
        code: ResultCode::Ok,
        link: 3,
        existing: true,
        companion: false,
        ifname: "rmnet_data3".into(),
    };
    let mut want = vec![4, 0x82, 7, 0, 0, 0, 15, 0, 0, 3, 1, 11];
    want.extend_from_slice(b"rmnet_data3");
    assert_eq!(reply.encode().unwrap(), want);
    let both = Notify::RouteReply {
        txn: 7,
        code: ResultCode::Ok,
        link: 3,
        existing: false,
        companion: true,
        ifname: "rmnet_data3".into(),
    };
    assert_eq!(both.encode().unwrap().get(10), Some(&2));
}

#[test]
fn the_matching_call_is_a_route_request_of_its_own_type() {
    let req = sample_route();
    let lookup = Request::RouteLookup {
        txn: 5,
        req: req.clone(),
    }
    .encode()
    .unwrap();
    let matching = Request::MatchingCall {
        txn: 5,
        req,
        hint: MatchHint::default(),
    }
    .encode()
    .unwrap();
    assert_eq!((lookup.get(1), matching.get(1)), (Some(&2), Some(&9)));
    // the same request, then the hint: five values, none present
    let n = matching.len();
    assert_eq!(lookup.get(8..), matching.get(8..n - 5));
    assert_eq!(matching.get(n - 5..), Some(&[0u8, 0, 0, 0, 0][..]));
    // and with all of them, the u16 little endian
    let full = Request::MatchingCall {
        txn: 5,
        req: sample_route(),
        hint: MatchHint {
            profile_3gpp: Some(3),
            profile_3gpp2: Some(4),
            xt_pref: Some(0x0102),
            backup_name: Some(1),
            backup_type: Some(2),
        },
    }
    .encode()
    .unwrap();
    let m = full.len();
    assert_eq!(
        full.get(m - 11..),
        Some(&[1u8, 3, 1, 4, 1, 2, 1, 1, 1, 1, 2][..])
    );
    // a presence byte is 0 or 1
    let mut bad = matching.clone();
    bad[n - 5] = 2;
    assert_eq!(Request::decode(&bad).unwrap_err(), DecodeError::Value);
}

#[test]
fn the_result_codes_have_the_numbers_the_libraries_carry() {
    let all = [
        (ResultCode::Ok, 0),
        (ResultCode::Invalid, 1),
        (ResultCode::NoLink, 2),
        (ResultCode::NoSuchLink, 3),
        (ResultCode::TooMany, 4),
        (ResultCode::BadState, 5),
        (ResultCode::NotReady, 6),
        (ResultCode::Unsupported, 7),
        (ResultCode::NoMatch, 8),
    ];
    for (code, n) in all {
        assert_eq!((code.code(), ResultCode::from_code(n)), (n, Some(code)));
    }
    assert_eq!(ResultCode::from_code(9), None);
}

#[test]
fn the_requests_the_daemon_never_did_are_no_types_any_more() {
    // 5 the network handle, 6 port forwarding, 8 the OEM proxy
    for ty in [5u8, 6, 8] {
        for payload in [&[][..], &[0][..], &[0, 1][..]] {
            assert_eq!(
                Request::decode(&bytes(ty, 1, payload)).unwrap_err(),
                DecodeError::Type,
                "type {ty}"
            );
        }
    }
}
