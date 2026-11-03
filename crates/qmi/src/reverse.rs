// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The reverse transport of WDS: how a modem that keeps IKE to itself hands a Wi-Fi tunnel to the AP. The AP
//! binds a client to a reverse link, registers, and hears `0x8e` for each tunnel. It answers with `0x90`.
//! For an S2B tunnel it asks for the ESP states with `0x11c`, which come back as indications in segments.
//!
//! Layouts are those of the stock IDL tables (`tests/idl/idl-expected.txt`). Types that carry addresses
//! or keys have no derived Debug, and keys are `Secret`s.
use crate::frame::{u16_value, u32_value, u8_value, Builder, Error, Frame, Kind};
use crate::secret::Secret;
use crate::wds::{self, IpFamily};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub mod id {
    pub const REGISTER: u16 = 0x008d;
    pub const REVERSE_IND: u16 = 0x008e;
    pub const REVERSE_ANSWER: u16 = 0x0090;
    pub const BIND_CLIENT: u16 = 0x0118;
    pub const IPSEC_SA: u16 = 0x011c;
}

/// The technology TLV of `0x8e`, and the values a route lookup can name for a Wi-Fi call.
pub mod tech {
    pub const LOCAL_BREAKOUT: u16 = 0x8020;
    pub const IWLAN_S2B: u16 = 0x8021;
    pub const IWLAN_S2B_PROXY: u16 = 0x8040;
    pub const CIWLAN: u16 = 0x8080;

    pub fn is_iwlan(t: u16) -> bool {
        matches!(t, LOCAL_BREAKOUT | IWLAN_S2B | IWLAN_S2B_PROXY | CIWLAN)
    }
}

pub const STATUS_DISCONNECTED: u32 = 0;
pub const STATUS_CONNECTED: u32 = 1;

/// Longest crypto and auth key of the table, without their count.
pub const MAX_CRYPT_KEY: usize = 128;
pub const MAX_AUTH_KEY: usize = 1024;

fn endpoint(ep: (u32, u32)) -> [u8; 8] {
    let mut v = [0u8; 8];
    let (a, b) = v.split_at_mut(4);
    a.copy_from_slice(&ep.0.to_le_bytes());
    b.copy_from_slice(&ep.1.to_le_bytes());
    v
}

/// Bind a client to the reverse link with this mux, for one IP family and any subscription.
pub fn bind_client(txn: u16, family: IpFamily, ep: (u32, u32), mux: u8) -> Result<Vec<u8>, Error> {
    if family == IpFamily::Unspecified {
        return Err(Error::Value);
    }
    Builder::request(txn, id::BIND_CLIENT)
        .u32(0x10, wds::DONT_CARE_SUBS)?
        .u8(0x11, family.to_u8())?
        .tlv(0x12, &endpoint(ep))?
        .u8(0x13, mux)?
        .u8(0x14, 1)?
        .build()
}

/// The older way to bind: Bind Mux Data Port with the reverse flag. Set IP Family follows it.
pub fn bind_mux_reverse(txn: u16, ep: (u32, u32), mux: u8) -> Result<Vec<u8>, Error> {
    Builder::request(txn, wds::id::BIND_MUX_DATA_PORT)
        .tlv(0x10, &endpoint(ep))?
        .u8(0x11, mux)?
        .u8(0x12, 1)?
        .build()
}

/// Ask for the `0x8e` indications of this client.
pub fn register(txn: u16) -> Result<Vec<u8>, Error> {
    Builder::request(txn, id::REGISTER).u8(0x01, 1)?.build()
}

/// The answer to a `0x8e`, with its transaction ID.
pub fn reverse_answer(txn: u16, ok: bool, tid: u32) -> Result<Vec<u8>, Error> {
    Builder::request(txn, id::REVERSE_ANSWER)
        .u8(0x01, u8::from(ok))?
        .u32(0x02, tid)?
        .build()
}

/// Ask for the ESP states of the tunnel of this client. It has no TLVs.
pub fn ipsec_sa_request(txn: u16) -> Result<Vec<u8>, Error> {
    Builder::request(txn, id::IPSEC_SA).build()
}

/// What `0x8e` says.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReverseInd {
    pub status: u32,
    pub tid: u32,
    pub tech: Option<u16>,
    pub inner_v4: Option<Ipv4Addr>,
    pub inner_v6: Option<(Ipv6Addr, u8)>,
}

impl std::fmt::Debug for ReverseInd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReverseInd")
            .field("status", &self.status)
            .field("tech", &self.tech)
            .finish_non_exhaustive()
    }
}

impl ReverseInd {
    /// The inner address: IPv4 when there is one.
    pub fn address(&self) -> Option<IpAddr> {
        self.inner_v4
            .map(IpAddr::V4)
            .or(self.inner_v6.map(|(a, _)| IpAddr::V6(a)))
    }
}

/// The transaction ID alone, so that a message that is otherwise unusable can still be answered.
pub fn reverse_tid(f: &Frame<'_>) -> Option<u32> {
    f.tlv(0x02).and_then(|v| u32_value(v).ok())
}

/// Read `0x8e`. TLVs that are not needed, `0x13`, `0x15` and `0x16` among them, are left alone.
pub fn parse_reverse_ind(f: &Frame<'_>) -> Result<ReverseInd, Error> {
    if f.kind != Kind::Indication || f.id != id::REVERSE_IND {
        return Err(Error::Value);
    }
    let inner_v6 = match f.tlv(0x14) {
        None => None,
        Some(v) => {
            let (addr, prefix) = v.split_at_checked(16).ok_or(Error::Length)?;
            let a: [u8; 16] = addr.try_into().map_err(|_| Error::Length)?;
            Some((Ipv6Addr::from(a), u8_value(prefix)?))
        }
    };
    Ok(ReverseInd {
        status: u32_value(f.required(0x01)?)?,
        tid: u32_value(f.required(0x02)?)?,
        tech: f.tlv(0x10).map(u16_value).transpose()?,
        // a number in host order, so its high byte is the first one of the address
        inner_v4: f.tlv(0x12).map(u32_value).transpose()?.map(Ipv4Addr::from),
        inner_v6,
    })
}

/// The request ID in the response to `0x11c`. A refusal is an error.
pub fn parse_ipsec_sa_response(f: &Frame<'_>) -> Result<u32, Error> {
    if f.kind != Kind::Response || f.id != id::IPSEC_SA {
        return Err(Error::Value);
    }
    if !f.status()?.is_ok() {
        return Err(Error::Value);
    }
    u32_value(f.required(0x10)?)
}

/// The fields of the ESP states. A segment has some of them, and all the segments together have all.
#[derive(Default)]
pub struct SaFields {
    pub rx_spi: Option<u32>,
    pub tx_spi: Option<u32>,
    pub proto: Option<u32>,
    pub mode: Option<u32>,
    pub remote: Option<IpAddr>,
    pub local: Option<IpAddr>,
    pub auth_alg: Option<u32>,
    pub crypt_alg: Option<u32>,
    pub rx_crypt: Option<Secret>,
    pub tx_crypt: Option<Secret>,
    pub udp_encap: Option<u8>,
    pub aes_mode: Option<u32>,
    /// Network order on the wire, kept as those two bytes.
    pub encap_port: Option<[u8; 2]>,
    pub rx_auth: Option<Secret>,
    pub tx_auth: Option<Secret>,
}

/// Two segments give different values for one field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mismatch;

fn take<T: PartialEq>(into: &mut Option<T>, from: Option<T>) -> Result<(), Mismatch> {
    match (into.as_ref(), from) {
        (_, None) => Ok(()),
        (None, Some(v)) => {
            *into = Some(v);
            Ok(())
        }
        (Some(a), Some(b)) if *a == b => Ok(()),
        _ => Err(Mismatch),
    }
}

fn take_secret(into: &mut Option<Secret>, from: Option<Secret>) -> Result<(), Mismatch> {
    match (into.as_ref(), from) {
        (_, None) => Ok(()),
        (None, Some(v)) => {
            *into = Some(v);
            Ok(())
        }
        (Some(a), Some(b)) if a.same(&b) => Ok(()),
        _ => Err(Mismatch),
    }
}

impl SaFields {
    /// Add a segment's fields. A field two segments give must be the same in both.
    pub fn merge(&mut self, o: SaFields) -> Result<(), Mismatch> {
        take(&mut self.rx_spi, o.rx_spi)?;
        take(&mut self.tx_spi, o.tx_spi)?;
        take(&mut self.proto, o.proto)?;
        take(&mut self.mode, o.mode)?;
        take(&mut self.remote, o.remote)?;
        take(&mut self.local, o.local)?;
        take(&mut self.auth_alg, o.auth_alg)?;
        take(&mut self.crypt_alg, o.crypt_alg)?;
        take_secret(&mut self.rx_crypt, o.rx_crypt)?;
        take_secret(&mut self.tx_crypt, o.tx_crypt)?;
        take(&mut self.udp_encap, o.udp_encap)?;
        take(&mut self.aes_mode, o.aes_mode)?;
        take(&mut self.encap_port, o.encap_port)?;
        take_secret(&mut self.rx_auth, o.rx_auth)?;
        take_secret(&mut self.tx_auth, o.tx_auth)
    }
}

/// The head of a segment: the ID of the request, how many segments there are, and which this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SaHead {
    pub id: u16,
    pub size: u8,
    pub segment: u8,
}

pub struct SaSegment {
    pub head: SaHead,
    pub fields: SaFields,
}

/// `{u32 family, u8 len, bytes}`. An IPv4 address is reversed in its bytes.
fn tunnel_address(v: &[u8]) -> Result<IpAddr, Error> {
    let (family, rest) = v.split_at_checked(4).ok_or(Error::Length)?;
    let [len, data @ ..] = rest else {
        return Err(Error::Length);
    };
    if usize::from(*len) != data.len() {
        return Err(Error::Length);
    }
    match (u32_value(family)?, data) {
        (4, [d, c, b, a]) => Ok(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
        (6, bytes) => {
            let a: [u8; 16] = bytes.try_into().map_err(|_| Error::Length)?;
            Ok(IpAddr::V6(Ipv6Addr::from(a)))
        }
        _ => Err(Error::Value),
    }
}

fn key_u8(v: &[u8], max: usize) -> Result<Secret, Error> {
    let [n, data @ ..] = v else {
        return Err(Error::Length);
    };
    if usize::from(*n) != data.len() {
        return Err(Error::Length);
    }
    if data.len() > max {
        return Err(Error::TooLarge);
    }
    Ok(Secret::copy_of(data))
}

fn key_u16(v: &[u8], max: usize) -> Result<Secret, Error> {
    let [l0, l1, data @ ..] = v else {
        return Err(Error::Length);
    };
    if usize::from(u16::from_le_bytes([*l0, *l1])) != data.len() {
        return Err(Error::Length);
    }
    if data.len() > max {
        return Err(Error::TooLarge);
    }
    Ok(Secret::copy_of(data))
}

/// Read one segment of the `0x11c` indication. TLVs not needed are left alone.
pub fn parse_sa_segment(f: &Frame<'_>) -> Result<SaSegment, Error> {
    if f.kind != Kind::Indication || f.id != id::IPSEC_SA {
        return Err(Error::Value);
    }
    let [i0, i1, size, segment]: [u8; 4] =
        f.required(0x01)?.try_into().map_err(|_| Error::Length)?;
    let word = |t| f.tlv(t).map(u32_value).transpose();
    let encap_port = match f.tlv(0x36) {
        None => None,
        Some(v) => Some(<[u8; 2]>::try_from(v).map_err(|_| Error::Length)?),
    };
    Ok(SaSegment {
        head: SaHead {
            id: u16::from_le_bytes([i0, i1]),
            size,
            segment,
        },
        fields: SaFields {
            rx_spi: word(0x10)?,
            tx_spi: word(0x11)?,
            proto: word(0x12)?,
            mode: word(0x13)?,
            remote: f.tlv(0x14).map(tunnel_address).transpose()?,
            local: f.tlv(0x15).map(tunnel_address).transpose()?,
            auth_alg: word(0x16)?,
            crypt_alg: word(0x17)?,
            rx_crypt: f.tlv(0x18).map(|v| key_u8(v, MAX_CRYPT_KEY)).transpose()?,
            tx_crypt: f.tlv(0x19).map(|v| key_u8(v, MAX_CRYPT_KEY)).transpose()?,
            udp_encap: f.tlv(0x1b).map(u8_value).transpose()?,
            aes_mode: word(0x35)?,
            encap_port,
            rx_auth: f.tlv(0x37).map(|v| key_u16(v, MAX_AUTH_KEY)).transpose()?,
            tx_auth: f.tlv(0x38).map(|v| key_u16(v, MAX_AUTH_KEY)).transpose()?,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(b: &[u8]) -> Frame<'_> {
        Frame::parse(b).unwrap()
    }

    #[test]
    fn the_bind_carries_family_endpoint_mux_and_the_reverse_flag() {
        let b = bind_client(1, IpFamily::V6, (4, 1), 20).unwrap();
        let f = frame(&b);
        assert_eq!(f.id, 0x118);
        assert_eq!(f.tlv(0x10), Some(&[0xff, 0, 0, 0][..]));
        assert_eq!(f.tlv(0x11), Some(&[6u8][..]));
        assert_eq!(f.tlv(0x12), Some(&[4, 0, 0, 0, 1, 0, 0, 0][..]));
        assert_eq!(f.tlv(0x13), Some(&[20u8][..]));
        assert_eq!(f.tlv(0x14), Some(&[1u8][..]));
        assert!(bind_client(1, IpFamily::Unspecified, (4, 1), 20).is_err());
    }

    #[test]
    fn the_older_bind_has_the_reverse_flag_in_0x12() {
        let b = bind_mux_reverse(1, (4, 1), 18).unwrap();
        let f = frame(&b);
        assert_eq!(f.id, 0xa2);
        assert_eq!(f.tlv(0x11), Some(&[18u8][..]));
        assert_eq!(f.tlv(0x12), Some(&[1u8][..]));
        assert_eq!(f.tlv(0x13), None);
    }

    #[test]
    fn register_and_answer() {
        let b = register(2).unwrap();
        assert_eq!(frame(&b).tlv(0x01), Some(&[1u8][..]));
        assert_eq!(frame(&b).tlv(0x10), None);
        let b = reverse_answer(3, false, 0x0102_0304).unwrap();
        let f = frame(&b);
        assert_eq!(f.id, 0x90);
        assert_eq!(f.tlv(0x01), Some(&[0u8][..]));
        assert_eq!(f.tlv(0x02), Some(&[4, 3, 2, 1][..]));
        assert_eq!(frame(&ipsec_sa_request(4).unwrap()).tlvs().count(), 0);
    }

    #[test]
    fn a_reverse_indication_reads_with_unknown_tlvs_and_0x16() {
        let b = Builder::indication(id::REVERSE_IND)
            .u32(0x01, STATUS_CONNECTED)
            .unwrap()
            .u32(0x02, 9)
            .unwrap()
            .u16(0x10, tech::IWLAN_S2B)
            .unwrap()
            .u32(0x12, 0xc000_0201)
            .unwrap()
            .tlv(0x16, &[0; 17])
            .unwrap()
            .u8(0x77, 1)
            .unwrap()
            .build()
            .unwrap();
        let r = parse_reverse_ind(&frame(&b)).unwrap();
        assert_eq!((r.status, r.tid, r.tech), (1, 9, Some(0x8021)));
        assert_eq!(r.address(), Some("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn a_v6_inner_address_comes_with_its_prefix() {
        let a: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let mut v = a.octets().to_vec();
        v.push(64);
        let b = Builder::indication(id::REVERSE_IND)
            .u32(0x01, 0)
            .unwrap()
            .u32(0x02, 1)
            .unwrap()
            .tlv(0x14, &v)
            .unwrap()
            .build()
            .unwrap();
        let r = parse_reverse_ind(&frame(&b)).unwrap();
        assert_eq!(r.inner_v6, Some((a, 64)));
        assert_eq!(r.address(), Some(IpAddr::V6(a)));
    }

    #[test]
    fn a_reverse_indication_with_a_wrong_width_is_refused_and_its_id_still_reads() {
        let b = Builder::indication(id::REVERSE_IND)
            .u32(0x01, 1)
            .unwrap()
            .u32(0x02, 7)
            .unwrap()
            .u8(0x10, 1)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(parse_reverse_ind(&frame(&b)).unwrap_err(), Error::Length);
        assert_eq!(reverse_tid(&frame(&b)), Some(7));
    }

    #[test]
    fn the_debug_of_an_indication_has_no_address() {
        let r = ReverseInd {
            status: 1,
            tid: 2,
            tech: None,
            inner_v4: Some(Ipv4Addr::new(192, 0, 2, 1)),
            inner_v6: None,
        };
        assert!(!format!("{r:?}").contains("192"));
    }

    fn addr_v4(a: [u8; 4]) -> Vec<u8> {
        let mut v = 4u32.to_le_bytes().to_vec();
        v.push(4);
        v.extend(a.iter().rev());
        v
    }

    #[test]
    fn a_segment_reads_reversed_v4_addresses_network_order_port_and_keys() {
        let mut crypt = vec![3u8];
        crypt.extend([9, 9, 9]);
        let mut auth = vec![2u8, 0];
        auth.extend([8, 8]);
        let b = Builder::indication(id::IPSEC_SA)
            .tlv(0x01, &[0x34, 0x12, 2, 1])
            .unwrap()
            .u32(0x10, 0x1111)
            .unwrap()
            .tlv(0x14, &addr_v4([192, 0, 2, 1]))
            .unwrap()
            .tlv(0x18, &crypt)
            .unwrap()
            .tlv(0x37, &auth)
            .unwrap()
            .tlv(0x36, &[0x11, 0x94])
            .unwrap()
            .build()
            .unwrap();
        let s = parse_sa_segment(&frame(&b)).unwrap();
        assert_eq!(
            s.head,
            SaHead {
                id: 0x1234,
                size: 2,
                segment: 1
            }
        );
        assert_eq!(s.fields.rx_spi, Some(0x1111));
        assert_eq!(s.fields.remote, Some("192.0.2.1".parse().unwrap()));
        assert_eq!(s.fields.rx_crypt.unwrap().bytes(), &[9, 9, 9]);
        assert_eq!(s.fields.rx_auth.unwrap().bytes(), &[8, 8]);
        assert_eq!(s.fields.encap_port, Some([0x11, 0x94]));
    }

    #[test]
    fn bad_addresses_and_counts_are_refused() {
        for bad in [
            vec![],
            vec![4, 0, 0, 0],
            vec![4, 0, 0, 0, 3, 1, 2, 3],
            vec![4, 0, 0, 0, 5, 1, 2, 3, 4],
            vec![6, 0, 0, 0, 4, 1, 2, 3, 4],
            vec![9, 0, 0, 0, 4, 1, 2, 3, 4],
        ] {
            assert!(tunnel_address(&bad).is_err(), "{bad:?}");
        }
        assert_eq!(key_u8(&[], 4).err(), Some(Error::Length));
        assert_eq!(key_u8(&[2, 1], 4).err(), Some(Error::Length));
        assert_eq!(key_u8(&[5, 1, 2, 3, 4, 5], 4).err(), Some(Error::TooLarge));
        assert_eq!(key_u16(&[1], 4).err(), Some(Error::Length));
        assert_eq!(key_u16(&[1, 1, 0], 4).err(), Some(Error::Length));
    }

    #[test]
    fn merging_takes_what_is_missing_and_refuses_a_difference() {
        let mut a = SaFields {
            rx_spi: Some(1),
            rx_crypt: Some(Secret::copy_of(&[1])),
            ..SaFields::default()
        };
        a.merge(SaFields {
            rx_spi: Some(1),
            tx_spi: Some(2),
            ..SaFields::default()
        })
        .unwrap();
        assert_eq!((a.rx_spi, a.tx_spi), (Some(1), Some(2)));
        assert_eq!(
            a.merge(SaFields {
                tx_spi: Some(3),
                ..SaFields::default()
            }),
            Err(Mismatch)
        );
        assert_eq!(
            a.merge(SaFields {
                rx_crypt: Some(Secret::copy_of(&[2])),
                ..SaFields::default()
            }),
            Err(Mismatch)
        );
    }
}
