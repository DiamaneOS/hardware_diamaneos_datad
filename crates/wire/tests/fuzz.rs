// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Garbage that gets past the header. Random bytes almost never carry the
//! right version and length, so these tests build the header themselves and
//! count how far the inputs got. A fuzz test that only exercises the header
//! checks would pass for any payload decoder, so each test asserts its reach.
#![allow(clippy::disallowed_methods)] // test code, the list is for the shipped crates
use dataos_wire::limits::*;
use dataos_wire::*;
use std::collections::BTreeMap;

mod common;
use common::*;

fn framed(ty: u8, number: u32, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![VERSION, ty];
    b.extend_from_slice(&number.to_le_bytes());
    b.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    b.extend_from_slice(payload);
    b
}

/// Write the real payload length into a mutated message so the header passes.
fn refit(mut b: Vec<u8>) -> Vec<u8> {
    if b.len() >= HEADER_LEN {
        let n = (b.len() - HEADER_LEN) as u16;
        b[6..8].copy_from_slice(&n.to_le_bytes());
    }
    b
}

// 5, 6 and 8 are no types any more and must be refused as such
const REQUEST_TYPES: [u8; 9] = [1, 2, 3, 4, 5, 6, 7, 8, 9];
const NOTIFY_TYPES: [u8; 6] = [0x81, 0x82, 0x83, 0x84, 0x85, 0x86];

#[derive(Default)]
struct Reach {
    ok: BTreeMap<u8, u32>,
    err: BTreeMap<String, u32>,
}

impl Reach {
    fn record<T>(&mut self, ty: u8, r: Result<T, DecodeError>) {
        match r {
            Ok(_) => *self.ok.entry(ty).or_default() += 1,
            Err(e) => *self.err.entry(format!("{e:?}")).or_default() += 1,
        }
    }
}

#[test]
fn random_payloads_behind_a_valid_header_reach_every_decoder() {
    let mut rng = Rng(0xfeed_beef);
    let mut reach = Reach::default();
    let mut total = 0u32;
    for _ in 0..80_000 {
        let ty = if rng.chance(8) {
            rng.byte()
        } else if rng.chance(50) {
            REQUEST_TYPES[rng.below(9)]
        } else {
            NOTIFY_TYPES[rng.below(6)]
        };
        // short payloads are the ones that can parse, long ones test the bounds
        let len = match rng.below(100) {
            0..=59 => rng.below(5),
            60..=84 => rng.below(24),
            _ => rng.below(130),
        };
        let payload: Vec<u8> = (0..len).map(|_| rng.byte() % 3).collect();
        let number = if rng.chance(30) {
            0
        } else {
            rng.below(300) as u32
        };
        let msg = framed(ty, number, &payload);
        total += 1;
        reach.record(ty, Request::decode(&msg));
        reach.record(ty, Notify::decode(&msg));
    }
    // errors can only come from the payload decoders: the header is valid by construction
    for kind in ["Truncated", "Value", "Length", "Type"] {
        assert!(
            reach.err.get(kind).copied().unwrap_or(0) > 100,
            "{kind} was hardly reached: {:?}",
            reach.err
        );
    }
    // and inputs get through the whole decoder for the small messages
    for ty in [1u8, 3, 4, 7, 0x81, 0x83, 0x84, 0x85, 0x86] {
        assert!(
            reach.ok.get(&ty).copied().unwrap_or(0) > 20,
            "type {ty:#x} never decoded: {:?}",
            reach.ok
        );
    }
    let oks: u32 = reach.ok.values().sum();
    assert!(oks > total / 50, "{oks} of {total}");
}

#[test]
fn route_lookups_with_random_fields_hit_the_field_decoders() {
    let mut rng = Rng(0x5e7);
    let (mut ok, mut family_err, mut flag_err, mut len_err) = (0u32, 0u32, 0u32, 0u32);
    for _ in 0..40_000 {
        let mut payload = vec![rng.byte()];
        payload.push(if rng.chance(85) {
            rng.below(2) as u8
        } else {
            rng.byte()
        });
        let has_apn = if rng.chance(90) {
            rng.below(2) as u8
        } else {
            rng.byte()
        };
        payload.push(has_apn);
        if has_apn == 1 {
            let n = if rng.chance(90) {
                rng.below(20)
            } else {
                rng.below(MAX_APN + 100)
            };
            payload.push(n as u8);
            payload.extend((0..n).map(|_| b'a' + rng.byte() % 26));
        }
        payload.extend((0..12).map(|_| rng.byte()));
        match Request::decode(&framed(2, 1, &payload)) {
            Ok(Request::RouteLookup { .. }) => ok += 1,
            Ok(_) => unreachable!("type 2 is RouteLookup"),
            Err(DecodeError::Value) if payload[1] > 1 => family_err += 1,
            Err(DecodeError::Value) => flag_err += 1,
            Err(_) => len_err += 1,
        }
    }
    assert!(ok > 5000, "{ok}");
    assert!(
        family_err > 500 && flag_err > 500 && len_err > 500,
        "{family_err} {flag_err} {len_err}"
    );
}

/// Cut, change, insert and stretch valid messages, then fix the length.
fn mutate(rng: &mut Rng, mut b: Vec<u8>) -> Vec<u8> {
    for _ in 0..1 + rng.below(3) {
        if b.len() <= HEADER_LEN {
            break;
        }
        let at = HEADER_LEN + rng.below(b.len() - HEADER_LEN);
        match rng.below(6) {
            0 => b[at] = rng.byte(),
            1 => b[at] ^= 1 << rng.below(8),
            2 => b.truncate(at),
            3 => b.insert(at, rng.byte()),
            4 => {
                let end = (at + 1 + rng.below(6)).min(b.len());
                b.drain(at..end);
            }
            _ => {
                let n = 1 + rng.below(20);
                b.extend((0..n).map(|_| rng.byte()));
            }
        }
    }
    refit(b)
}

#[test]
fn mutated_valid_messages_decode_or_fail_cleanly_and_stay_stable() {
    let mut rng = Rng(0xabcd);
    let (mut n_ok, mut n_err, mut r_ok, mut r_err) = (0, 0, 0, 0);
    let mut kinds: BTreeMap<String, u32> = BTreeMap::new();
    for _ in 0..40_000 {
        let n = gen_notify(&mut rng);
        let msg = mutate(&mut rng, n.encode().unwrap());
        match Notify::decode(&msg) {
            Ok(back) => {
                // anything the decoder accepts must encode again and decode to the same value
                let again = back.encode().expect("a decoded message can be encoded");
                assert_eq!(Notify::decode(&again).unwrap(), back);
                n_ok += 1;
            }
            Err(e) => {
                *kinds.entry(format!("{e:?}")).or_default() += 1;
                n_err += 1;
            }
        }
        let r = gen_request(&mut rng);
        let msg = mutate(&mut rng, r.encode().unwrap());
        match Request::decode(&msg) {
            Ok(back) => {
                let again = back.encode().expect("a decoded request can be encoded");
                assert_eq!(Request::decode(&again).unwrap(), back);
                r_ok += 1;
            }
            Err(_) => r_err += 1,
        }
    }
    assert!(n_ok > 1000 && n_err > 1000, "{n_ok} {n_err}");
    assert!(r_ok > 1000 && r_err > 1000, "{r_ok} {r_err}");
    for kind in ["Truncated", "Value", "Length"] {
        assert!(kinds.get(kind).copied().unwrap_or(0) > 100, "{kinds:?}");
    }
}

#[test]
fn every_prefix_and_every_single_byte_change_of_the_largest_message() {
    let msg = largest_request().encode().unwrap();
    // every prefix, with the length field fixed so the header passes
    let mut cut_ok = 0;
    for n in HEADER_LEN..msg.len() {
        if Request::decode(&refit(msg[..n].to_vec())).is_ok() {
            cut_ok += 1;
        }
    }
    assert_eq!(cut_ok, 0, "a shorter payload of this message never parses");
    // every byte set to three other values
    let (mut changed_ok, mut changed) = (0, 0);
    for at in HEADER_LEN..msg.len() {
        for v in [0u8, 1, 0xff] {
            let mut m = msg.clone();
            m[at] = v;
            changed += 1;
            if Request::decode(&m).is_ok() {
                changed_ok += 1;
            }
        }
    }
    // most bytes are APN text: 1 still decodes there, 0 (NUL) and 0xff (not UTF-8) do not
    assert!(
        changed_ok > changed / 4 && changed_ok < changed - changed / 4,
        "{changed_ok} of {changed}"
    );
}

#[test]
fn arbitrary_bytes_with_a_bad_header_are_refused_quickly() {
    let mut rng = Rng(99);
    for _ in 0..20_000 {
        let n = rng.below(300);
        let buf: Vec<u8> = (0..n).map(|_| rng.byte()).collect();
        let _ = Request::decode(&buf);
        let _ = Notify::decode(&buf);
    }
}
