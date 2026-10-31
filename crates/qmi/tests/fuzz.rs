// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Garbage that passes the framing checks. Random bytes are almost never a
//! frame (a 7-byte header whose length field matches and a TLV chain that
//! ends exactly), so the old fuzz test only ever exercised the header
//! check. These tests build frames that parse, with the tags the parsers look
//! for and values of the right and the wrong width, and count how far the
//! inputs got.
use dataos_qmi::wds::{self, id, IpFamily};
use dataos_qmi::{wda, Error, Frame};
use std::collections::BTreeMap;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
}

const TAGS: [u8; 29] = [
    0x01, 0x02, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1e, 0x1f, 0x20, 0x21,
    0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x30, 0x31,
];
const IDS: [u16; 8] = [
    id::START_NETWORK,
    id::STOP_NETWORK,
    id::PACKET_SERVICE_STATUS,
    id::GET_RUNTIME_SETTINGS,
    id::EXTENDED_IP_CONFIG,
    id::BIND_MUX_DATA_PORT,
    id::BIND_SUBSCRIPTION,
    id::INDICATION_REGISTER,
];

/// A value of a plausible width for the tag, or a random one.
fn value(rng: &mut Rng, tag: u8) -> Vec<u8> {
    let right = rng.below(100) < 85;
    if right {
        match tag {
            0x02 => {
                // the result: mostly success
                return if rng.below(100) < 80 {
                    vec![0, 0, 0, 0]
                } else {
                    vec![1, 0, 14, 0]
                };
            }
            0x23 => {
                let n = rng.below(10);
                let mut v = vec![n as u8];
                for _ in 0..n {
                    v.extend_from_slice(&(rng.next() as u32).to_le_bytes());
                }
                return v;
            }
            0x24 | 0x2a => {
                let n = rng.below(10);
                let mut v = vec![n as u8];
                for _ in 0..n {
                    let len = if rng.below(10) == 0 {
                        250 + rng.below(8)
                    } else {
                        1 + rng.below(20)
                    };
                    v.extend_from_slice(&(len as u16).to_le_bytes());
                    v.extend((0..len).map(|_| b'a' + rng.byte() % 26));
                }
                return v;
            }
            0x25 | 0x26 => {
                let mut v: Vec<u8> = (0..16).map(|_| rng.byte()).collect();
                v.push(if rng.below(10) == 0 {
                    rng.byte()
                } else {
                    rng.byte() % 129
                });
                return v;
            }
            _ => {}
        }
    }
    let n = match (right, tag) {
        (false, _) => rng.below(40),
        (true, 0x01) => 2,
        (true, 0x14 | 0x17 | 0x18) => 1 + rng.below(8),
        (true, 0x10 | 0x11 | 0x13 | 0x15 | 0x16 | 0x1e | 0x20 | 0x21 | 0x29) => 4,
        (true, 0x27 | 0x28) => 16,
        (true, 0x12 | 0x2b) => 1,
        (true, _) => 1 + rng.below(3),
    };
    (0..n)
        .map(|_| {
            if rng.below(3) == 0 {
                rng.byte()
            } else {
                rng.byte() % 4
            }
        })
        .collect()
}

/// The TLVs a message of this kind carries, each present most of the time.
fn targeted_tags(mid: u16) -> &'static [u8] {
    match mid {
        // 0x20 is also WDA Set Data Format, so it carries both messages' TLVs
        id::START_NETWORK => &[0x02, 0x01, 0x10, 0x11, 0x12, 0x13, 0x16],
        id::PACKET_SERVICE_STATUS => &[0x01, 0x10, 0x11, 0x12, 0x14],
        id::GET_RUNTIME_SETTINGS => &[
            0x02, 0x15, 0x16, 0x1e, 0x20, 0x21, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
            0x2b,
        ],
        id::EXTENDED_IP_CONFIG => &[0x10],
        _ => &[0x02],
    }
}

/// A frame that passes `Frame::parse`.
fn frame(rng: &mut Rng) -> Vec<u8> {
    let kind = [0u8, 2, 2, 4, 4][rng.below(5)];
    let mid = if rng.below(10) == 0 {
        rng.next() as u16
    } else {
        IDS[rng.below(IDS.len())]
    };
    let mut body = Vec::new();
    let mut used = Vec::new();
    // half of the frames carry what their message kind is made of
    let tags: Vec<u8> = if rng.below(2) == 0 {
        targeted_tags(mid)
            .iter()
            .copied()
            .filter(|_| rng.below(100) < 85)
            .collect()
    } else {
        (0..rng.below(9))
            .map(|_| {
                if rng.below(10) == 0 {
                    rng.byte()
                } else {
                    TAGS[rng.below(TAGS.len())]
                }
            })
            .collect()
    };
    for tag in tags {
        if used.contains(&tag) {
            continue;
        }
        used.push(tag);
        let v = value(rng, tag);
        body.push(tag);
        body.extend_from_slice(&(v.len() as u16).to_le_bytes());
        body.extend_from_slice(&v);
    }
    let mut out = vec![kind];
    out.extend_from_slice(&(rng.next() as u16).to_le_bytes());
    out.extend_from_slice(&mid.to_le_bytes());
    out.extend_from_slice(&(body.len() as u16).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

#[derive(Default)]
struct Tally {
    parsed: u32,
    ok: BTreeMap<&'static str, u32>,
    err: BTreeMap<String, u32>,
}

impl Tally {
    fn note<T>(&mut self, name: &'static str, r: Result<T, Error>) {
        match r {
            Ok(_) => *self.ok.entry(name).or_default() += 1,
            Err(e) => *self.err.entry(format!("{e:?}")).or_default() += 1,
        }
    }
}

fn run_all_parsers(f: &Frame<'_>, t: &mut Tally) {
    t.note("start", wds::parse_start_network_response(f));
    t.note("status", f.status());
    t.note("pkt", wds::parse_packet_service_status(f));
    t.note("v4", wds::parse_runtime_settings(f, IpFamily::V4));
    t.note("v6", wds::parse_runtime_settings(f, IpFamily::V6));
    t.note("ext", wds::parse_extended_ip_config(f));
    t.note("wda", wda::parse_set_data_format_response(f));
    for tag in TAGS {
        let _ = f.tlv(tag);
    }
    assert!(f.tlvs().count() < 20);
}

#[test]
fn frames_that_parse_reach_every_message_parser() {
    let mut rng = Rng(0xc0ffee);
    let mut t = Tally::default();
    let n = 80_000u32;
    for _ in 0..n {
        let bytes = frame(&mut rng);
        if let Ok(f) = Frame::parse(&bytes) {
            t.parsed += 1;
            run_all_parsers(&f, &mut t);
        }
    }
    // the framing check lets nearly everything through, unlike random bytes
    assert!(t.parsed > n * 9 / 10, "{} of {n} parsed", t.parsed);
    // every parser accepted some inputs, so its field decoding ran to the end
    for p in ["start", "status", "pkt", "v4", "v6", "ext", "wda"] {
        assert!(
            t.ok.get(p).copied().unwrap_or(0) > 300,
            "{p} hardly accepted anything: {:?}",
            t.ok
        );
    }
    // and rejected others in several ways (framing errors cannot occur here:
    // the frames parsed)
    for e in ["Missing", "Length", "Value"] {
        assert!(
            t.err.get(e).copied().unwrap_or(0) > 300,
            "{e} hardly happened: {:?}",
            t.err
        );
    }
}

fn valid_settings() -> Vec<u8> {
    let mut v6 = "2001:db8:1:2::5"
        .parse::<std::net::Ipv6Addr>()
        .unwrap()
        .octets()
        .to_vec();
    v6.push(64);
    let mut names = vec![2u8];
    for n in [&b"ims.example"[..], &b"b.example"[..]] {
        names.extend_from_slice(&(n.len() as u16).to_le_bytes());
        names.extend_from_slice(n);
    }
    dataos_qmi::Builder::response(4, id::GET_RUNTIME_SETTINGS)
        .ok()
        .unwrap()
        .u32(0x15, 0xc000_0235)
        .unwrap()
        .u32(0x1e, 0xc000_020a)
        .unwrap()
        .u32(0x20, 0xc000_0209)
        .unwrap()
        .u32(0x21, 0xffff_fffc)
        .unwrap()
        .tlv(0x23, &[1, 7, 100, 51, 198])
        .unwrap()
        .tlv(0x24, &names)
        .unwrap()
        .tlv(0x25, &v6)
        .unwrap()
        .tlv(0x2a, &names)
        .unwrap()
        .u32(0x29, 1400)
        .unwrap()
        .u8(0x2b, 4)
        .unwrap()
        .build()
        .unwrap()
}

/// Fix the body length after a change.
fn refit(mut b: Vec<u8>) -> Vec<u8> {
    let n = (b.len() - 7) as u16;
    b[5..7].copy_from_slice(&n.to_le_bytes());
    b
}

#[test]
fn every_prefix_and_every_byte_change_of_a_real_settings_answer() {
    let good = valid_settings();
    let ok = |b: &[u8], fam| {
        Frame::parse(b)
            .and_then(|f| wds::parse_runtime_settings(&f, fam))
            .is_ok()
    };
    assert!(ok(&good, IpFamily::V4) && ok(&good, IpFamily::V6));
    // cut the body anywhere (length field fixed): either the framing or the
    // parser says no, or the cut fell between two TLVs and the rest parses
    let mut survived = 0;
    for n in 7..good.len() {
        let cut = refit(good[..n].to_vec());
        if ok(&cut, IpFamily::V4) {
            survived += 1;
        }
    }
    assert!(survived > 0 && survived < good.len() / 2, "{survived}");
    // each byte of the body set to 0, 1, 0xff
    let mut parsed = 0;
    let mut total = 0;
    let mut dropped_somewhere = 0;
    for at in 7..good.len() {
        for v in [0u8, 1, 0xff] {
            let mut b = good.clone();
            b[at] = v;
            total += 1;
            if let Ok(f) = Frame::parse(&b) {
                parsed += 1;
                if let Ok(s) = wds::parse_runtime_settings(&f, IpFamily::V4) {
                    if s.dropped > 0 {
                        dropped_somewhere += 1;
                    }
                }
            }
        }
    }
    assert!(parsed > total / 2, "{parsed} of {total}");
    // optional fields hit by a change are dropped and counted, not fatal
    assert!(dropped_somewhere > 5, "{dropped_somewhere}");
}

#[test]
fn big_and_empty_inputs_are_refused_or_parsed_without_trouble() {
    for len in [0usize, 1, 6, 7, 8, 9, 8191, 8192, 8193, 70_000] {
        let b = vec![2u8; len];
        let _ = Frame::parse(&b);
    }
    // the largest legal body
    let mut b = vec![2u8, 1, 0, 0x2d, 0];
    let body = 8192 - 7;
    b.extend_from_slice(&(body as u16).to_le_bytes());
    b.push(0x50);
    b.extend_from_slice(&((body - 3) as u16).to_le_bytes());
    b.resize(8192, 0);
    assert!(Frame::parse(&b).is_ok());
}
