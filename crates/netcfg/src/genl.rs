// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Generic netlink messages of the kernel module `rmnet_wlan`, which steers the packets of a Wi-Fi tunnel between
//! the Wi-Fi interface and a reverse link, and the lookup of its family number. Commands and attributes
//! are those of `rmnet_wlan_genl`. Its policy is strict, so nested attributes carry `NLA_F_NESTED`.
use crate::rtnl::{name_attr, parse_ack, Ack, BuildError, Msg, NLM_F_ACK, NLM_F_REQUEST};
use std::net::IpAddr;

pub const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const CTRL_VERSION: u8 = 1;

pub const WLAN_FAMILY: &str = "RMNET_WLAN";
const WLAN_VERSION: u8 = 1;
const NLA_F_NESTED: u16 = 0x8000;
const NLMSG_HEADER_LEN: usize = 16;
const GENL_HEADER_LEN: usize = 4;

const ATTR_TUPLES: u16 = 1;
const ATTR_DEVICE: u16 = 2;
const ATTR_ADDRESS: u16 = 3;
const ATTR_FORWARD_DEVICE: u16 = 4;
const ATTR_ENCAP_PORT: u16 = 5;
const ATTR_NET_TYPE: u16 = 6;
const TUPLE_ENTRY: u16 = 1;
const TUPLE_RECORD: u16 = 1;

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ESP: u8 = 50;

/// What a tuple matches: a port, or an ESP SPI.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TupleKey {
    Port(u16),
    Spi(u32),
}

/// One packet match of the module: 8 bytes with the key in network order, the IP version and the protocol.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Tuple {
    pub key: TupleKey,
    pub version: u8,
    pub proto: u8,
}

impl std::fmt::Debug for Tuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tuple")
            .field("version", &self.version)
            .field("proto", &self.proto)
            .finish_non_exhaustive()
    }
}

impl Tuple {
    pub fn bytes(&self) -> [u8; 8] {
        let mut b = [0, 0, 0, 0, self.version, self.proto, 0, 0];
        match self.key {
            TupleKey::Port(p) => {
                let [h, l] = p.to_be_bytes();
                b[0] = h;
                b[1] = l;
            }
            TupleKey::Spi(s) => {
                let [a, c, d, e] = s.to_be_bytes();
                b[0] = a;
                b[1] = c;
                b[2] = d;
                b[3] = e;
            }
        }
        b
    }
}

/// The net type attribute. S2B and local breakout share the device slot of the module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetType {
    S2b = 0,
    Ciwlan = 1,
    LocalBreakout = 2,
}

/// The commands of the module this code uses, by number in `number`.
#[derive(Clone, PartialEq, Eq)]
pub enum WlanRequest {
    AddTuples(Vec<Tuple>),
    DelTuples(Vec<Tuple>),
    SetDevice {
        net: NetType,
        device: String,
    },
    UnsetDevice {
        net: NetType,
        device: String,
    },
    AddForward {
        net: NetType,
        device: String,
        addr: IpAddr,
    },
    DelForward {
        net: NetType,
        device: String,
        addr: IpAddr,
    },
    SetEncapPort([u8; 2]),
    UnsetEncapPort([u8; 2]),
    Flush,
    EncapPass([u8; 2]),
    EncapDrop([u8; 2]),
}

impl std::fmt::Debug for WlanRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WlanRequest({})", self.number())
    }
}

impl WlanRequest {
    pub fn number(&self) -> u8 {
        match self {
            WlanRequest::AddTuples(_) => 1,
            WlanRequest::DelTuples(_) => 2,
            WlanRequest::SetDevice { .. } => 3,
            WlanRequest::UnsetDevice { .. } => 4,
            WlanRequest::AddForward { .. } => 5,
            WlanRequest::DelForward { .. } => 6,
            WlanRequest::SetEncapPort(_) => 7,
            WlanRequest::UnsetEncapPort(_) => 8,
            WlanRequest::Flush => 9,
            WlanRequest::EncapPass(_) => 10,
            WlanRequest::EncapDrop(_) => 11,
        }
    }
}

fn begin_genl(family: u16, seq: u32, cmd: u8, version: u8) -> Msg {
    let mut m = Msg::new(family, NLM_F_REQUEST | NLM_F_ACK, seq);
    m.raw(&[cmd, version, 0, 0]);
    m
}

/// The message of a request for the family with this number.
pub fn wlan_message(seq: u32, family: u16, req: &WlanRequest) -> Result<Vec<u8>, BuildError> {
    let mut m = begin_genl(family, seq, req.number(), WLAN_VERSION);
    match req {
        WlanRequest::AddTuples(tuples) | WlanRequest::DelTuples(tuples) => {
            let all = m.begin(ATTR_TUPLES | NLA_F_NESTED);
            for t in tuples {
                let entry = m.begin(TUPLE_ENTRY | NLA_F_NESTED);
                m.attr(TUPLE_RECORD, &t.bytes());
                m.end(entry);
            }
            m.end(all);
        }
        WlanRequest::SetDevice { net, device } | WlanRequest::UnsetDevice { net, device } => {
            m.attr(ATTR_NET_TYPE, &[*net as u8]);
            m.attr(ATTR_DEVICE, &name_attr(device)?);
        }
        WlanRequest::AddForward { net, device, addr }
        | WlanRequest::DelForward { net, device, addr } => {
            m.attr(ATTR_NET_TYPE, &[*net as u8]);
            m.attr(ATTR_FORWARD_DEVICE, &name_attr(device)?);
            let mut text = addr.to_string().into_bytes();
            text.push(0);
            m.attr(ATTR_ADDRESS, &text);
        }
        WlanRequest::SetEncapPort(p)
        | WlanRequest::UnsetEncapPort(p)
        | WlanRequest::EncapPass(p)
        | WlanRequest::EncapDrop(p) => m.attr(ATTR_ENCAP_PORT, p),
        WlanRequest::Flush => {}
    }
    Ok(m.finish())
}

/// `CTRL_CMD_GETFAMILY` by name. The answer is a message with the number.
pub fn get_family(seq: u32, name: &str) -> Vec<u8> {
    let mut m = begin_genl(GENL_ID_CTRL, seq, CTRL_CMD_GETFAMILY, CTRL_VERSION);
    let mut text = name.as_bytes().to_vec();
    text.push(0);
    m.attr(CTRL_ATTR_FAMILY_NAME, &text);
    m.finish()
}

/// What came back for a family lookup. None: this datagram is not about it.
pub fn parse_family(buf: &[u8], seq: u32) -> Option<Result<u16, i32>> {
    match parse_ack(buf, seq) {
        Some(Ack::Errno(e)) => return Some(Err(e)),
        // the acknowledgement of a lookup that also answered, read the answer instead
        Some(Ack::Ok) => return None,
        None => {}
    }
    let head = buf.get(..NLMSG_HEADER_LEN)?;
    let ty = u16::from_ne_bytes(head.get(4..6)?.try_into().ok()?);
    let got = u32::from_ne_bytes(head.get(8..12)?.try_into().ok()?);
    if ty != GENL_ID_CTRL || got != seq {
        return None;
    }
    let len = usize::try_from(u32::from_ne_bytes(head.get(0..4)?.try_into().ok()?)).ok()?;
    let mut rest = buf.get(NLMSG_HEADER_LEN.checked_add(GENL_HEADER_LEN)?..len)?;
    while rest.len() >= 4 {
        let n = usize::from(u16::from_ne_bytes(rest.get(0..2)?.try_into().ok()?));
        let kind = u16::from_ne_bytes(rest.get(2..4)?.try_into().ok()?);
        let value = rest.get(4..n)?;
        if kind == CTRL_ATTR_FAMILY_ID {
            return Some(Ok(u16::from_ne_bytes(value.try_into().ok()?)));
        }
        rest = rest.get(crate::rtnl::padded(n)..)?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtnl::testutil::attrs;

    fn head(m: &[u8]) -> (usize, u16, u16, u8, u8) {
        (
            u32::from_ne_bytes(m[0..4].try_into().unwrap()) as usize,
            u16::from_ne_bytes(m[4..6].try_into().unwrap()),
            u16::from_ne_bytes(m[6..8].try_into().unwrap()),
            m[16],
            m[17],
        )
    }

    #[test]
    fn a_tuple_is_eight_bytes_with_the_key_in_network_order() {
        let t = Tuple {
            key: TupleKey::Port(5060),
            version: 4,
            proto: PROTO_UDP,
        };
        assert_eq!(t.bytes(), [0x13, 0xc4, 0, 0, 4, 17, 0, 0]);
        let t = Tuple {
            key: TupleKey::Spi(0x0102_0304),
            version: 6,
            proto: PROTO_ESP,
        };
        assert_eq!(t.bytes(), [1, 2, 3, 4, 6, 50, 0, 0]);
    }

    #[test]
    fn tuples_are_a_nested_array_of_one_record_each() {
        let t = Tuple {
            key: TupleKey::Port(7275),
            version: 6,
            proto: PROTO_TCP,
        };
        let m = wlan_message(2, 33, &WlanRequest::AddTuples(vec![t, t])).unwrap();
        let (len, ty, flags, cmd, ver) = head(&m);
        assert_eq!((len, ty, flags, cmd, ver), (m.len(), 33, 5, 1, 1));
        let top = attrs(&m, 20);
        assert_eq!(top[0].0, 1 | 0x8000);
        let entries = attrs(&top[0].1, 0);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, 1 | 0x8000);
        let record = attrs(&entries[1].1, 0);
        assert_eq!(record, vec![(1, t.bytes().to_vec())]);
        let del = wlan_message(2, 33, &WlanRequest::DelTuples(vec![t])).unwrap();
        assert_eq!(head(&del).3, 2);
    }

    #[test]
    fn the_device_and_forward_commands_carry_their_attributes_in_order() {
        let m = wlan_message(
            1,
            33,
            &WlanRequest::SetDevice {
                net: NetType::LocalBreakout,
                device: "wlan0".into(),
            },
        )
        .unwrap();
        assert_eq!(head(&m).3, 3);
        assert_eq!(attrs(&m, 20), vec![(6, vec![2]), (2, b"wlan0\0".to_vec())]);
        let m = wlan_message(
            1,
            33,
            &WlanRequest::UnsetDevice {
                net: NetType::S2b,
                device: "wlan0".into(),
            },
        )
        .unwrap();
        assert_eq!(head(&m).3, 4);
        assert_eq!(attrs(&m, 20)[0], (6, vec![0]));
        let m = wlan_message(
            1,
            33,
            &WlanRequest::AddForward {
                net: NetType::S2b,
                device: "r_rmnet_data2".into(),
                addr: "2001:db8::5".parse().unwrap(),
            },
        )
        .unwrap();
        assert_eq!(head(&m).3, 5);
        assert_eq!(
            attrs(&m, 20),
            vec![
                (6, vec![0]),
                (4, b"r_rmnet_data2\0".to_vec()),
                (3, b"2001:db8::5\0".to_vec())
            ]
        );
        let m = wlan_message(
            1,
            33,
            &WlanRequest::DelForward {
                net: NetType::S2b,
                device: "r_rmnet_data2".into(),
                addr: "192.0.2.1".parse().unwrap(),
            },
        )
        .unwrap();
        assert_eq!(head(&m).3, 6);
    }

    #[test]
    fn the_port_commands_and_the_flush() {
        for (req, cmd) in [
            (WlanRequest::SetEncapPort([0x11, 0x94]), 7),
            (WlanRequest::UnsetEncapPort([0x11, 0x94]), 8),
            (WlanRequest::EncapPass([0x11, 0x94]), 10),
            (WlanRequest::EncapDrop([0x11, 0x94]), 11),
        ] {
            let m = wlan_message(1, 33, &req).unwrap();
            assert_eq!(head(&m).3, cmd);
            assert_eq!(attrs(&m, 20), vec![(5, vec![0x11, 0x94])]);
        }
        let m = wlan_message(1, 33, &WlanRequest::Flush).unwrap();
        assert_eq!(head(&m).3, 9);
        assert_eq!(m.len(), 20);
    }

    #[test]
    fn a_bad_device_name_is_refused() {
        assert!(wlan_message(
            1,
            33,
            &WlanRequest::SetDevice {
                net: NetType::S2b,
                device: "a/b".into()
            }
        )
        .is_err());
    }

    #[test]
    fn the_family_lookup_and_its_answer() {
        let m = get_family(5, WLAN_FAMILY);
        let (_, ty, flags, cmd, ver) = head(&m);
        assert_eq!((ty, flags, cmd, ver), (0x10, 5, 3, 1));
        assert_eq!(attrs(&m, 20), vec![(2, b"RMNET_WLAN\0".to_vec())]);

        let mut reply = vec![0u8; 16];
        reply[4..6].copy_from_slice(&0x10u16.to_ne_bytes());
        reply[8..12].copy_from_slice(&5u32.to_ne_bytes());
        reply.extend([1, 2, 0, 0]);
        // the name first, then the number
        reply.extend(15u16.to_ne_bytes());
        reply.extend(2u16.to_ne_bytes());
        reply.extend(b"RMNET_WLAN\0\0");
        reply.extend(6u16.to_ne_bytes());
        reply.extend(1u16.to_ne_bytes());
        reply.extend(33u16.to_ne_bytes());
        reply.extend([0, 0]);
        let n = reply.len() as u32;
        reply[0..4].copy_from_slice(&n.to_ne_bytes());
        assert_eq!(parse_family(&reply, 5), Some(Ok(33)));
        assert_eq!(parse_family(&reply, 6), None);
        assert_eq!(parse_family(&[], 5), None);

        let mut err = vec![0u8; 36];
        err[0..4].copy_from_slice(&36u32.to_ne_bytes());
        err[4..6].copy_from_slice(&2u16.to_ne_bytes());
        err[8..12].copy_from_slice(&5u32.to_ne_bytes());
        err[16..20].copy_from_slice(&(-2i32).to_ne_bytes());
        assert_eq!(parse_family(&err, 5), Some(Err(2)));
    }
}
