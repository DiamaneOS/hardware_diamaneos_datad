// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Data Filter Service (QMI service 0x30, libqmi's number). The modem asks the AP to keep ports free for it and
//! says which ESP SPIs belong to it. Layouts are those of the stock IDL tables (`tests/idl/idl-expected.txt`).
use crate::frame::{u16_value, u32_value, u8_value, Builder, Error, Frame, Kind};

pub const SERVICE: u8 = 0x30;

pub mod id {
    pub const INDICATION_REGISTER: u16 = 0x0003;
    pub const BIND_CLIENT: u16 = 0x0021;
    pub const GET_FILTERS: u16 = 0x0030;
    pub const FILTERS_CHANGED: u16 = 0x0031;
    pub const PORTS_WANTED: u16 = 0x0032;
    pub const PORTS_ANSWER: u16 = 0x0033;
    pub const PORTS_RELEASED: u16 = 0x0034;
    pub const ENCAP_PORT: u16 = 0x0035;
}

/// The largest message of the service, a filter list of 255 entries with its header and result.
pub const MAX_MESSAGE: usize = 36986 + crate::frame::HEADER_LEN;

const FILTER_LEN: usize = 145;
const FILTER_PROTO_AT: usize = 75;
const FILTER_IPSEC_VALID_AT: usize = 121;
const FILTER_SPI_AT: usize = 129;
const PROTO_ESP: u32 = 0x32;

/// One port on one family and protocol. The numbers are what the hash of the modem's messages is made of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PortKind {
    V4Udp = 0,
    V6Udp = 1,
    V4Tcp = 2,
    V6Tcp = 3,
}

impl PortKind {
    pub const ALL: [PortKind; 4] = [
        PortKind::V4Udp,
        PortKind::V6Udp,
        PortKind::V4Tcp,
        PortKind::V6Tcp,
    ];

    pub fn ip(self) -> u8 {
        match self {
            PortKind::V4Udp | PortKind::V4Tcp => 4,
            PortKind::V6Udp | PortKind::V6Tcp => 6,
        }
    }

    /// The IP protocol number.
    pub fn proto(self) -> u8 {
        match self {
            PortKind::V4Udp | PortKind::V6Udp => 17,
            PortKind::V4Tcp | PortKind::V6Tcp => 6,
        }
    }

    pub fn is_udp(self) -> bool {
        self.proto() == 17
    }
}

/// The modem keeps this number and names the port with it later. It looks into it nowhere that is known.
pub fn port_hash(port: u16, kind: PortKind) -> u32 {
    (u32::from(port) << 2)
        .saturating_add(0x1_0000)
        .saturating_add(kind as u32)
}

pub fn port_of_hash(hash: u32) -> Option<(u16, PortKind)> {
    let v = hash.checked_sub(0x1_0000)?;
    let port = u16::try_from(v >> 2).ok()?;
    let kind = match v & 3 {
        0 => PortKind::V4Udp,
        1 => PortKind::V6Udp,
        2 => PortKind::V4Tcp,
        _ => PortKind::V6Tcp,
    };
    Some((port, kind))
}

fn endpoint(ep: (u32, u32)) -> [u8; 8] {
    let mut v = [0u8; 8];
    let (a, b) = v.split_at_mut(4);
    a.copy_from_slice(&ep.0.to_le_bytes());
    b.copy_from_slice(&ep.1.to_le_bytes());
    v
}

/// Bind a client to a mux and an IP family (4 or 6).
pub fn bind_client(txn: u16, family: u8, ep: (u32, u32), mux: u8) -> Result<Vec<u8>, Error> {
    Builder::request(txn, id::BIND_CLIENT)
        .u8(0x11, family)?
        .tlv(0x12, &endpoint(ep))?
        .u8(0x13, mux)?
        .build()
}

/// The registration of the client of a reverse link.
pub fn register_link(txn: u16) -> Result<Vec<u8>, Error> {
    Builder::request(txn, id::INDICATION_REGISTER)
        .u8(0x12, 1)?
        .build()
}

/// The registration of the client that hears about ports.
pub fn register_ports(txn: u16) -> Result<Vec<u8>, Error> {
    Builder::request(txn, id::INDICATION_REGISTER)
        .u8(0x13, 1)?
        .u32(0x14, 1)?
        .build()
}

pub fn get_filters(txn: u16) -> Result<Vec<u8>, Error> {
    Builder::request(txn, id::GET_FILTERS).build()
}

/// An ESP filter, as far as it is used: the IP version and the SPI.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EspFilter {
    pub version: u8,
    pub spi: u32,
}

impl std::fmt::Debug for EspFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EspFilter")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

fn word_at(entry: &[u8], at: usize) -> Option<u32> {
    let b = entry.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(b.try_into().ok()?))
}

/// The ESP entries of a filter list. Entries of other protocols are left out.
fn esp_filters(v: &[u8]) -> Result<Vec<EspFilter>, Error> {
    let [count, entries @ ..] = v else {
        return Err(Error::Length);
    };
    if usize::from(*count).checked_mul(FILTER_LEN) != Some(entries.len()) {
        return Err(Error::Length);
    }
    let mut out = Vec::new();
    for e in entries.chunks_exact(FILTER_LEN) {
        let valid = word_at(e, FILTER_IPSEC_VALID_AT).ok_or(Error::Length)? & 1 != 0;
        let proto = word_at(e, FILTER_PROTO_AT).ok_or(Error::Length)?;
        let spi = word_at(e, FILTER_SPI_AT).ok_or(Error::Length)?;
        match e.first() {
            Some(&version @ (4 | 6)) if proto == PROTO_ESP && valid => {
                out.push(EspFilter { version, spi });
            }
            _ => {}
        }
    }
    Ok(out)
}

/// The filters in the response to `0x30`. A refusal is an error, and a response without a list has none.
pub fn parse_get_filters(f: &Frame<'_>) -> Result<Vec<EspFilter>, Error> {
    if f.kind != Kind::Response || f.id != id::GET_FILTERS {
        return Err(Error::Value);
    }
    if !f.status()?.is_ok() {
        return Err(Error::Value);
    }
    f.tlv(0x10).map_or(Ok(Vec::new()), esp_filters)
}

pub const FILTER_ADD: u32 = 0;
pub const FILTER_DELETE: u32 = 1;

/// `0x31`: the action and the filters it is for.
pub fn parse_filters_changed(f: &Frame<'_>) -> Result<(u32, Vec<EspFilter>), Error> {
    if f.kind != Kind::Indication || f.id != id::FILTERS_CHANGED {
        return Err(Error::Value);
    }
    let action = u32_value(f.required(0x01)?)?;
    Ok((action, f.tlv(0x10).map_or(Ok(Vec::new()), esp_filters)?))
}

pub const IP_BOTH: u8 = 0x10;
pub const PROTO_BOTH: u32 = 0xff;
pub const PROPERTY_ADJACENT: u32 = 1;
pub const PROPERTY_SYMMETRIC: u32 = 2;

/// One entry of `0x32`: IP version 4, 6 or `IP_BOTH`, protocol 6, 17 or `PROTO_BOTH`, and the port, 0
/// when the AP picks it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortWish {
    pub ip: u8,
    pub proto: u32,
    pub port: u16,
}

/// The ports the modem wants kept free.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortsWanted {
    pub wishes: Vec<PortWish>,
    pub transaction: Option<u16>,
    /// The property and the lowest and highest port the AP may pick from.
    pub range: Option<(u32, u16, u16)>,
}

pub fn parse_ports_wanted(f: &Frame<'_>) -> Result<PortsWanted, Error> {
    if f.kind != Kind::Indication || f.id != id::PORTS_WANTED {
        return Err(Error::Value);
    }
    let [count, entries @ ..] = f.required(0x01)? else {
        return Err(Error::Length);
    };
    if usize::from(*count).checked_mul(7) != Some(entries.len()) {
        return Err(Error::Length);
    }
    let mut wishes = Vec::with_capacity(usize::from(*count));
    for e in entries.chunks_exact(7) {
        let [ip, p0, p1, p2, p3, o0, o1]: [u8; 7] = e.try_into().map_err(|_| Error::Length)?;
        wishes.push(PortWish {
            ip,
            proto: u32::from_le_bytes([p0, p1, p2, p3]),
            port: u16::from_le_bytes([o0, o1]),
        });
    }
    let range = match f.tlv(0x11) {
        None => None,
        Some(v) => {
            let [a, b, c, d, l0, l1, h0, h1]: [u8; 8] = v.try_into().map_err(|_| Error::Length)?;
            Some((
                u32::from_le_bytes([a, b, c, d]),
                u16::from_le_bytes([l0, l1]),
                u16::from_le_bytes([h0, h1]),
            ))
        }
    };
    Ok(PortsWanted {
        wishes,
        transaction: f.tlv(0x10).map(u16_value).transpose()?,
        range,
    })
}

/// One entry of the answer `0x33`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortAnswer {
    pub status: u32,
    pub kind: PortKind,
    pub port: u16,
    /// The AP chose the port.
    pub chosen: bool,
}

/// The most entries of an answer, by the table.
pub const MAX_PORT_ANSWERS: usize = 255;

pub fn ports_answer(
    txn: u16,
    entries: &[PortAnswer],
    transaction: Option<u16>,
) -> Result<Vec<u8>, Error> {
    let count = u8::try_from(entries.len()).map_err(|_| Error::TooLarge)?;
    let mut v = Vec::with_capacity(entries.len().saturating_mul(16).saturating_add(1));
    v.push(count);
    for e in entries {
        v.extend_from_slice(&e.status.to_le_bytes());
        v.extend_from_slice(&port_hash(e.port, e.kind).to_le_bytes());
        v.push(u8::from(e.chosen));
        v.push(e.kind.ip());
        v.extend_from_slice(&u32::from(e.kind.proto()).to_le_bytes());
        v.extend_from_slice(&e.port.to_le_bytes());
    }
    let b = Builder::request(txn, id::PORTS_ANSWER).tlv(0x01, &v)?;
    match transaction {
        Some(t) => b.u16(0x10, t)?.build(),
        None => b.build(),
    }
}

/// `0x34`: the hashes of the ports that are no longer needed.
pub fn parse_ports_released(f: &Frame<'_>) -> Result<Vec<u32>, Error> {
    if f.kind != Kind::Indication || f.id != id::PORTS_RELEASED {
        return Err(Error::Value);
    }
    let Some(v) = f.tlv(0x10) else {
        return Ok(Vec::new());
    };
    let [count, entries @ ..] = v else {
        return Err(Error::Length);
    };
    if usize::from(*count).checked_mul(4) != Some(entries.len()) {
        return Err(Error::Length);
    }
    entries.chunks_exact(4).map(u32_value).collect()
}

/// `0x35`: the hash of a port and whether it is an encapsulation port that drops, 0 when the TLV is absent.
pub fn parse_encap_port(f: &Frame<'_>) -> Result<(u32, u8), Error> {
    if f.kind != Kind::Indication || f.id != id::ENCAP_PORT {
        return Err(Error::Value);
    }
    Ok((
        u32_value(f.required(0x01)?)?,
        f.tlv(0x10).map(u8_value).transpose()?.unwrap_or(0),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(b: &[u8]) -> Frame<'_> {
        Frame::parse(b).unwrap()
    }

    #[test]
    fn the_hash_is_port_and_kind() {
        assert_eq!(port_hash(5060, PortKind::V4Udp), (5060 << 2) + 0x10000);
        assert_eq!(port_hash(5060, PortKind::V6Tcp), (5060 << 2) + 0x10000 + 3);
        for kind in PortKind::ALL {
            for port in [0, 1, 5060, 65535] {
                assert_eq!(port_of_hash(port_hash(port, kind)), Some((port, kind)));
            }
        }
        assert_eq!(port_of_hash(5), None);
        assert_eq!(port_of_hash(u32::MAX), None);
    }

    #[test]
    fn the_bind_and_the_registrations() {
        let b = bind_client(1, 4, (4, 1), 1).unwrap();
        let f = frame(&b);
        assert_eq!(f.id, 0x21);
        assert_eq!(f.tlv(0x10), None);
        assert_eq!(f.tlv(0x11), Some(&[4u8][..]));
        assert_eq!(f.tlv(0x12), Some(&[4, 0, 0, 0, 1, 0, 0, 0][..]));
        assert_eq!(f.tlv(0x13), Some(&[1u8][..]));
        let b = register_link(2).unwrap();
        assert_eq!(frame(&b).tlv(0x12), Some(&[1u8][..]));
        assert_eq!(frame(&b).tlvs().count(), 1);
        let b = register_ports(3).unwrap();
        assert_eq!(frame(&b).tlv(0x13), Some(&[1u8][..]));
        assert_eq!(frame(&b).tlv(0x14), Some(&[1, 0, 0, 0][..]));
    }

    fn filter(version: u8, proto: u32, valid: u64, spi: u32) -> Vec<u8> {
        let mut e = vec![0u8; FILTER_LEN];
        e[0] = version;
        e[FILTER_PROTO_AT..FILTER_PROTO_AT + 4].copy_from_slice(&proto.to_le_bytes());
        e[FILTER_IPSEC_VALID_AT..FILTER_IPSEC_VALID_AT + 8].copy_from_slice(&valid.to_le_bytes());
        e[FILTER_SPI_AT..FILTER_SPI_AT + 4].copy_from_slice(&spi.to_le_bytes());
        e
    }

    #[test]
    fn only_esp_filters_with_a_valid_spi_count() {
        let mut v = vec![4u8];
        v.extend(filter(4, 0x32, 1, 0xaabb));
        v.extend(filter(6, 0x32, 1, 0xccdd));
        v.extend(filter(4, 17, 1, 1));
        v.extend(filter(4, 0x32, 0, 2));
        let got = esp_filters(&v).unwrap();
        assert_eq!(
            got,
            vec![
                EspFilter {
                    version: 4,
                    spi: 0xaabb
                },
                EspFilter {
                    version: 6,
                    spi: 0xccdd
                }
            ]
        );
        assert_eq!(esp_filters(&[]), Err(Error::Length));
        assert_eq!(esp_filters(&[1, 0]), Err(Error::Length));
        assert_eq!(esp_filters(&[0]), Ok(Vec::new()));
    }

    #[test]
    fn a_get_filters_answer_may_refuse_or_have_no_list() {
        let ok = Builder::response(1, id::GET_FILTERS)
            .ok()
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(parse_get_filters(&frame(&ok)), Ok(Vec::new()));
        let bad = Builder::response(1, id::GET_FILTERS)
            .fail(3)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(parse_get_filters(&frame(&bad)), Err(Error::Value));
    }

    #[test]
    fn a_ports_message_reads_with_its_range() {
        let mut list = vec![2u8];
        list.extend([IP_BOTH, 0xff, 0, 0, 0, 0, 0]);
        list.extend([4, 17, 0, 0, 0, 0xc4, 0x13]);
        let mut range = 2u32.to_le_bytes().to_vec();
        range.extend(40000u16.to_le_bytes());
        range.extend(41000u16.to_le_bytes());
        let b = Builder::indication(id::PORTS_WANTED)
            .tlv(0x01, &list)
            .unwrap()
            .u16(0x10, 77)
            .unwrap()
            .tlv(0x11, &range)
            .unwrap()
            .build()
            .unwrap();
        let p = parse_ports_wanted(&frame(&b)).unwrap();
        assert_eq!(
            p.wishes,
            vec![
                PortWish {
                    ip: IP_BOTH,
                    proto: PROTO_BOTH,
                    port: 0
                },
                PortWish {
                    ip: 4,
                    proto: 17,
                    port: 5060
                }
            ]
        );
        assert_eq!(p.transaction, Some(77));
        assert_eq!(p.range, Some((2, 40000, 41000)));
    }

    #[test]
    fn the_answer_has_the_layout_of_the_table() {
        let b = ports_answer(
            1,
            &[PortAnswer {
                status: 0,
                kind: PortKind::V6Tcp,
                port: 0x1234,
                chosen: true,
            }],
            Some(9),
        )
        .unwrap();
        let f = frame(&b);
        let v = f.tlv(0x01).unwrap();
        assert_eq!(v.len(), 17);
        assert_eq!(v[0], 1);
        assert_eq!(&v[1..5], &[0, 0, 0, 0]);
        assert_eq!(&v[5..9], &port_hash(0x1234, PortKind::V6Tcp).to_le_bytes());
        assert_eq!(v[9], 1);
        assert_eq!(v[10], 6);
        assert_eq!(&v[11..15], &[6, 0, 0, 0]);
        assert_eq!(&v[15..17], &[0x34, 0x12]);
        assert_eq!(f.tlv(0x10), Some(&[9, 0][..]));
        let many = vec![
            PortAnswer {
                status: 0,
                kind: PortKind::V4Udp,
                port: 1,
                chosen: false
            };
            256
        ];
        assert_eq!(ports_answer(1, &many, None).err(), Some(Error::TooLarge));
    }

    #[test]
    fn released_and_encap_ports_read() {
        let mut v = vec![2u8];
        v.extend(7u32.to_le_bytes());
        v.extend(8u32.to_le_bytes());
        let b = Builder::indication(id::PORTS_RELEASED)
            .tlv(0x10, &v)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(parse_ports_released(&frame(&b)), Ok(vec![7, 8]));
        let none = Builder::indication(id::PORTS_RELEASED).build().unwrap();
        assert_eq!(parse_ports_released(&frame(&none)), Ok(Vec::new()));
        let b = Builder::indication(id::ENCAP_PORT)
            .u32(0x01, 5)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(parse_encap_port(&frame(&b)), Ok((5, 0)));
    }
}
