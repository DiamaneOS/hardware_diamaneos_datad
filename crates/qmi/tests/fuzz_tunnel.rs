// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Garbage that passes the framing checks, for the two big indications of the tunnel: the ESP states and the
//! filter list. Values of the right and the wrong width, and a count of how far the inputs got.
use dataos_qmi::dfs;
use dataos_qmi::reverse;
use dataos_qmi::{Builder, Frame};

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
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }
}

fn sa_value(rng: &mut Rng, tag: u8) -> Vec<u8> {
    if rng.below(100) >= 85 {
        let n = rng.below(40);
        return rng.bytes(n);
    }
    match tag {
        0x01 => vec![1, 0, 1, 0],
        0x14 | 0x15 => {
            if rng.below(2) == 0 {
                let mut v = vec![4, 0, 0, 0, 4];
                v.extend(rng.bytes(4));
                v
            } else {
                let mut v = vec![6, 0, 0, 0, 16];
                v.extend(rng.bytes(16));
                v
            }
        }
        0x18 | 0x19 => {
            let n = rng.below(129);
            let mut v = vec![n as u8];
            v.extend(rng.bytes(n));
            v
        }
        0x37 | 0x38 => {
            let n = rng.below(200);
            let mut v = (n as u16).to_le_bytes().to_vec();
            v.extend(rng.bytes(n));
            v
        }
        0x1b => vec![rng.byte()],
        0x36 => rng.bytes(2),
        _ => rng.bytes(4),
    }
}

#[test]
fn the_sa_indication_parser_takes_anything_and_reads_good_input() {
    const TAGS: [u8; 16] = [
        0x01, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1b, 0x35, 0x36, 0x37,
        0x38,
    ];
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let (mut good, mut bad) = (0u32, 0u32);
    for _ in 0..20_000 {
        let mut b = Builder::indication(reverse::id::IPSEC_SA);
        for tag in TAGS {
            if tag == 0x01 || rng.below(100) < 70 {
                let v = sa_value(&mut rng, tag);
                b = b.tlv(tag, &v).unwrap();
            }
        }
        let bytes = b.build().unwrap();
        match reverse::parse_sa_segment(&Frame::parse(&bytes).unwrap()) {
            Ok(_) => good += 1,
            Err(_) => bad += 1,
        }
    }
    assert!(good > 100, "{good} good");
    assert!(bad > 100, "{bad} bad");
}

fn filter_list(rng: &mut Rng) -> Vec<u8> {
    let n = rng.below(8);
    let mut v = vec![n as u8];
    for _ in 0..n {
        v.extend(rng.bytes(145));
    }
    if rng.below(100) < 10 {
        let extra = rng.below(5);
        v.extend(rng.bytes(extra));
    }
    v
}

#[test]
fn the_filter_list_parser_takes_anything_and_reads_good_input() {
    let mut rng = Rng(0x0fed_cba9_8765_4321);
    let (mut good, mut bad) = (0u32, 0u32);
    for _ in 0..20_000 {
        let list = filter_list(&mut rng);
        let b = Builder::indication(dfs::id::FILTERS_CHANGED)
            .u32(0x01, (rng.below(3)) as u32)
            .unwrap()
            .tlv(0x10, &list)
            .unwrap()
            .build()
            .unwrap();
        match dfs::parse_filters_changed(&Frame::parse(&b).unwrap()) {
            Ok(_) => good += 1,
            Err(_) => bad += 1,
        }
    }
    assert!(good > 100, "{good} good");
    assert!(bad > 100, "{bad} bad");
}

#[test]
fn the_other_tunnel_parsers_take_anything() {
    let mut rng = Rng(0x1111_2222_3333_4445);
    for _ in 0..20_000 {
        let mut b = Builder::indication(reverse::id::REVERSE_IND);
        for tag in [0x01, 0x02, 0x10, 0x11, 0x12, 0x14, 0x32] {
            if rng.below(100) < 80 {
                let n = rng.below(20);
                b = b.tlv(tag, &rng.bytes(n)).unwrap();
            }
        }
        let bytes = b.build().unwrap();
        let f = Frame::parse(&bytes).unwrap();
        let _ = reverse::parse_reverse_ind(&f);
        let _ = reverse::reverse_tid(&f);
        for id in [
            dfs::id::PORTS_WANTED,
            dfs::id::PORTS_RELEASED,
            dfs::id::ENCAP_PORT,
        ] {
            let n = rng.below(40);
            let b = Builder::indication(id)
                .tlv(0x01, &rng.bytes(n))
                .unwrap()
                .tlv(0x10, &rng.bytes(n / 2))
                .unwrap()
                .build()
                .unwrap();
            let f = Frame::parse(&b).unwrap();
            let _ = dfs::parse_ports_wanted(&f);
            let _ = dfs::parse_ports_released(&f);
            let _ = dfs::parse_encap_port(&f);
        }
    }
}
