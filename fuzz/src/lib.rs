// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! What the fuzz targets share: a reader of the input bytes, and builders of QMI messages and netlink replies that
//! pass the framing checks, so the input reaches the parsers of the fields and not only the header check.
use dataos_qmi::frame::HEADER_LEN;

pub mod esp;
pub mod parsers;

/// The input of one run, read from the front. Reads past the end give zeros, so every input is a whole run.
pub struct Input<'a>(pub &'a [u8]);

impl<'a> Input<'a> {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn u8(&mut self) -> u8 {
        match self.0.split_first() {
            Some((b, rest)) => {
                self.0 = rest;
                *b
            }
            None => 0,
        }
    }

    pub fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.u8(), self.u8()])
    }

    pub fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }

    /// True one time in `n`, from one byte.
    pub fn one_in(&mut self, n: u8) -> bool {
        self.u8().is_multiple_of(n.max(1))
    }

    pub fn bool(&mut self) -> bool {
        self.u8() & 1 != 0
    }

    /// A number below `n`, 0 when `n` is 0.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        if n <= 256 {
            usize::from(self.u8()) % n
        } else {
            usize::from(self.u16()) % n
        }
    }

    pub fn pick<T: Copy>(&mut self, from: &[T]) -> Option<T> {
        if from.is_empty() {
            return None;
        }
        let i = self.below(from.len());
        from.get(i).copied()
    }

    /// Up to `n` bytes, fewer when the input ends.
    pub fn bytes(&mut self, n: usize) -> &'a [u8] {
        let (a, b) = self.0.split_at(n.min(self.0.len()));
        self.0 = b;
        a
    }

    /// Exactly `n` bytes, zeros after the end of the input.
    pub fn exact(&mut self, n: usize) -> Vec<u8> {
        let mut v = self.bytes(n).to_vec();
        v.resize(n, 0);
        v
    }
}

/// The shape of the value of one TLV, as the parser that reads it expects it.
#[derive(Clone, Copy, Debug)]
pub enum Shape {
    /// A fixed width.
    W(usize),
    /// The result TLV, success most of the time.
    Result,
    /// A one byte count and that many entries of this width.
    List(usize),
    /// A one byte count and entries with a 16-bit length (domain names).
    Names,
    /// A one byte count and a key.
    KeyU8,
    /// A 16-bit count and a key.
    KeyU16,
    /// `{u32 family, u8 len, bytes}`, the tunnel addresses of `0x11c`.
    Addr,
    /// The DFS filter list: a count and entries of 145 bytes.
    Filters,
}

/// Grow a length a little, or shrink it, now and then: an off by one is what a parser gets wrong.
fn skew(inp: &mut Input<'_>, n: usize) -> usize {
    match inp.u8() % 16 {
        0 => n.saturating_add(1),
        1 => n.saturating_sub(1),
        2 => n.saturating_add(usize::from(inp.u8())),
        _ => n,
    }
}

/// A value of this shape, mostly well formed.
pub fn value(inp: &mut Input<'_>, shape: Shape) -> Vec<u8> {
    match inp.u8() % 16 {
        // anything at all
        0 => {
            let n = usize::from(inp.u8());
            return inp.exact(n);
        }
        1 => return Vec::new(),
        _ => {}
    }
    match shape {
        Shape::W(n) => {
            let n = skew(inp, n);
            inp.exact(n)
        }
        Shape::Result => {
            if inp.one_in(4) {
                let e = inp.u16().to_le_bytes();
                vec![1, 0, e[0], e[1]]
            } else {
                vec![0, 0, 0, 0]
            }
        }
        Shape::List(width) => {
            let count = inp.u8();
            let n = skew(inp, usize::from(count).saturating_mul(width));
            let mut v = vec![count];
            v.extend(inp.exact(n));
            v
        }
        Shape::Names => {
            let count = inp.u8() % 16;
            let mut v = vec![count];
            for _ in 0..count {
                let len = match inp.u8() % 8 {
                    0 => 250 + usize::from(inp.u8() % 8),
                    1 => usize::from(inp.u16()) % 600,
                    _ => usize::from(inp.u8() % 32),
                };
                let declared = skew(inp, len);
                v.extend(u16::try_from(declared).unwrap_or(u16::MAX).to_le_bytes());
                v.extend(inp.exact(len));
            }
            v
        }
        Shape::KeyU8 => {
            let len = match inp.u8() % 4 {
                0 => usize::from(inp.u8()),
                _ => *[16usize, 20, 24, 28, 32, 36]
                    .get(inp.below(6))
                    .unwrap_or(&16),
            };
            let mut v = vec![u8::try_from(skew(inp, len)).unwrap_or(u8::MAX)];
            v.extend(inp.exact(len));
            v
        }
        Shape::KeyU16 => {
            let len = match inp.u8() % 4 {
                0 => usize::from(inp.u16()) % 1100,
                _ => *[16usize, 20, 32, 48, 64].get(inp.below(5)).unwrap_or(&16),
            };
            let declared = u16::try_from(skew(inp, len)).unwrap_or(u16::MAX);
            let mut v = declared.to_le_bytes().to_vec();
            v.extend(inp.exact(len));
            v
        }
        Shape::Addr => {
            let family: u32 = match inp.u8() % 8 {
                0 => inp.u32(),
                1..=4 => 4,
                _ => 6,
            };
            let len = match family {
                4 => 4,
                6 => 16,
                _ => usize::from(inp.u8() % 20),
            };
            let len = skew(inp, len);
            let mut v = family.to_le_bytes().to_vec();
            v.push(u8::try_from(len).unwrap_or(u8::MAX));
            v.extend(inp.exact(len));
            v
        }
        Shape::Filters => {
            let count = inp.u8() % 8;
            let mut v = vec![count];
            for _ in 0..count {
                let mut e = inp.exact(145);
                if !inp.one_in(4) {
                    if let Some(b) = e.get_mut(0) {
                        *b = if inp.bool() { 4 } else { 6 };
                    }
                    if let Some(p) = e.get_mut(75..79) {
                        p.copy_from_slice(&0x32u32.to_le_bytes());
                    }
                    if let Some(b) = e.get_mut(121) {
                        *b |= 1;
                    }
                }
                v.extend(e);
            }
            let n = v.len();
            let n = skew(inp, n);
            v.resize(n, 0);
            v
        }
    }
}

/// One QMI message as the modem would send it: the header and these TLVs, in this order. No checks, so a test can
/// say what the parser must do with what it gets.
pub fn encode(kind: u8, txn: u16, id: u16, tlvs: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (tag, v) in tlvs {
        body.push(*tag);
        body.extend(u16::try_from(v.len()).unwrap_or(u16::MAX).to_le_bytes());
        body.extend(v.iter().take(usize::from(u16::MAX)));
    }
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.push(kind);
    out.extend(txn.to_le_bytes());
    out.extend(id.to_le_bytes());
    out.extend(u16::try_from(body.len()).unwrap_or(u16::MAX).to_le_bytes());
    out.extend(body);
    out
}

/// The TLVs of one message: mostly tags of `known` with their shapes, now and then another tag, each tag once, and
/// the whole no larger than `max` bytes with its header.
pub fn tlvs(inp: &mut Input<'_>, known: &[(u8, Shape)], max: usize) -> Vec<(u8, Vec<u8>)> {
    let mut out: Vec<(u8, Vec<u8>)> = Vec::new();
    let mut size = HEADER_LEN;
    let n = inp.u8() % 24;
    for _ in 0..n {
        let (tag, shape) = if inp.one_in(8) {
            (inp.u8(), Shape::W(usize::from(inp.u8() % 24)))
        } else {
            match inp.pick(known) {
                Some(k) => k,
                None => (inp.u8(), Shape::W(4)),
            }
        };
        if out.iter().any(|(t, _)| *t == tag) {
            continue;
        }
        let v = value(inp, shape);
        let grown = size.saturating_add(3).saturating_add(v.len());
        if grown > max || v.len() > usize::from(u16::MAX) {
            continue;
        }
        size = grown;
        out.push((tag, v));
    }
    out
}

pub const REQUEST: u8 = 0;
pub const RESPONSE: u8 = 2;
pub const INDICATION: u8 = 4;

/// The tags and shapes of every message of the modem that a parser reads, by kind and message ID.
pub mod messages {
    use super::Shape::{self, *};
    use super::{INDICATION, RESPONSE};
    use dataos_qmi::{dfs, reverse, wda, wds};

    pub struct Message {
        pub kind: u8,
        pub id: u16,
        pub tlvs: &'static [(u8, Shape)],
    }

    pub const SA_SEGMENT: &[(u8, Shape)] = &[
        (0x01, W(4)),
        (0x10, W(4)),
        (0x11, W(4)),
        (0x12, W(4)),
        (0x13, W(4)),
        (0x14, Addr),
        (0x15, Addr),
        (0x16, W(4)),
        (0x17, W(4)),
        (0x18, KeyU8),
        (0x19, KeyU8),
        (0x1b, W(1)),
        (0x35, W(4)),
        (0x36, W(2)),
        (0x37, KeyU16),
        (0x38, KeyU16),
    ];

    pub const ALL: &[Message] = &[
        Message {
            kind: RESPONSE,
            id: wds::id::START_NETWORK,
            tlvs: &[(0x02, Result), (0x01, W(4)), (0x10, W(2)), (0x11, W(4))],
        },
        Message {
            kind: INDICATION,
            id: wds::id::PACKET_SERVICE_STATUS,
            tlvs: &[
                (0x01, W(2)),
                (0x10, W(2)),
                (0x11, W(4)),
                (0x12, W(1)),
                (0x14, W(1)),
            ],
        },
        Message {
            kind: INDICATION,
            id: wds::id::EXTENDED_IP_CONFIG,
            tlvs: &[(0x10, W(4)), (0x11, W(4))],
        },
        Message {
            kind: RESPONSE,
            id: wds::id::GET_RUNTIME_SETTINGS,
            tlvs: &[
                (0x02, Result),
                (0x15, W(4)),
                (0x16, W(4)),
                (0x1e, W(4)),
                (0x20, W(4)),
                (0x21, W(4)),
                (0x23, List(4)),
                (0x24, Names),
                (0x25, W(17)),
                (0x26, W(17)),
                (0x27, W(16)),
                (0x28, W(16)),
                (0x29, W(4)),
                (0x2a, Names),
                (0x2b, W(1)),
            ],
        },
        Message {
            kind: RESPONSE,
            id: wds::id::ROUTE_LOOKUP,
            tlvs: &[
                (0x02, Result),
                (0x01, W(10)),
                (0x10, W(1)),
                (0x12, W(8)),
                (0x13, W(1)),
            ],
        },
        Message {
            kind: RESPONSE,
            id: wda::SET_DATA_FORMAT,
            tlvs: &[
                (0x02, Result),
                (0x11, W(4)),
                (0x12, W(4)),
                (0x13, W(4)),
                (0x16, W(4)),
            ],
        },
        Message {
            kind: INDICATION,
            id: reverse::id::REVERSE_IND,
            tlvs: &[
                (0x01, W(4)),
                (0x02, W(4)),
                (0x10, W(2)),
                (0x12, W(4)),
                (0x14, W(17)),
            ],
        },
        Message {
            kind: RESPONSE,
            id: reverse::id::IPSEC_SA,
            tlvs: &[(0x02, Result), (0x10, W(4))],
        },
        Message {
            kind: INDICATION,
            id: reverse::id::IPSEC_SA,
            tlvs: SA_SEGMENT,
        },
        Message {
            kind: RESPONSE,
            id: reverse::id::REVERSE_ANSWER,
            tlvs: &[(0x02, Result)],
        },
        Message {
            kind: RESPONSE,
            id: dfs::id::GET_FILTERS,
            tlvs: &[(0x02, Result), (0x10, Filters)],
        },
        Message {
            kind: INDICATION,
            id: dfs::id::FILTERS_CHANGED,
            tlvs: &[(0x01, W(4)), (0x10, Filters)],
        },
        Message {
            kind: INDICATION,
            id: dfs::id::PORTS_WANTED,
            tlvs: &[(0x01, List(7)), (0x10, W(2)), (0x11, W(8))],
        },
        Message {
            kind: RESPONSE,
            id: dfs::id::PORTS_ANSWER,
            tlvs: &[(0x02, Result)],
        },
        Message {
            kind: INDICATION,
            id: dfs::id::PORTS_RELEASED,
            tlvs: &[(0x10, List(4))],
        },
        Message {
            kind: INDICATION,
            id: dfs::id::ENCAP_PORT,
            tlvs: &[(0x01, W(4)), (0x10, W(1))],
        },
    ];
}

/// One netlink message: the header with this length, type, flags, sequence number and port, then the payload.
pub fn nlmsg(len: u32, ty: u16, flags: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(16 + payload.len());
    v.extend(len.to_ne_bytes());
    v.extend(ty.to_ne_bytes());
    v.extend(flags.to_ne_bytes());
    v.extend(seq.to_ne_bytes());
    v.extend(0u32.to_ne_bytes());
    v.extend(payload);
    v
}

/// One netlink attribute with its padding.
pub fn nlattr(len: u16, ty: u16, value: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + value.len() + 3);
    v.extend(len.to_ne_bytes());
    v.extend(ty.to_ne_bytes());
    v.extend(value);
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
    v
}
