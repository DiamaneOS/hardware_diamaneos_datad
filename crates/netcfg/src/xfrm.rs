// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! XFRM message builders for the ESP states and policies of a Wi-Fi tunnel. Pure byte building, host endianness
//! where the UAPI has host order. Layouts are those of linux/xfrm.h on a 64-bit kernel, checked by the offsets in the
//! tests. The message that holds a key is allocated at its exact size, so it is never moved, and the caller zeroes it.
use crate::rtnl::{BuildError, Msg, AF_INET, AF_INET6, NLM_F_ACK, NLM_F_REQUEST};
use std::net::IpAddr;

pub const XFRM_MSG_NEWSA: u16 = 0x10;
pub const XFRM_MSG_DELSA: u16 = 0x11;
pub const XFRM_MSG_NEWPOLICY: u16 = 0x13;
pub const XFRM_MSG_DELPOLICY: u16 = 0x14;

const XFRMA_ALG_CRYPT: u16 = 2;
const XFRMA_ENCAP: u16 = 4;
const XFRMA_TMPL: u16 = 5;
const XFRMA_SRCADDR: u16 = 13;
const XFRMA_ALG_AUTH_TRUNC: u16 = 20;
const XFRMA_SET_MARK: u16 = 29;

pub const IPPROTO_ESP: u8 = 50;
pub const IPPROTO_AH: u8 = 51;
pub const MODE_TRANSPORT: u8 = 0;
pub const MODE_TUNNEL: u8 = 1;
pub const STATE_NOPMTUDISC: u8 = 4;
pub const STATE_AF_UNSPEC: u8 = 32;
const UDP_ENCAP_ESPINUDP: u16 = 2;
const POLICY_PRIORITY: u32 = 100;

const SELECTOR_LEN: usize = 56;
const LIFETIME_LEN: usize = 64;
const STATE_LEN: usize = 224;
const POLICY_LEN: usize = 168;
const TMPL_LEN: usize = 64;
const POLICY_ID_LEN: usize = 64;
const STATE_ID_LEN: usize = 24;
const ALG_NAME_LEN: usize = 64;
const HEADER_LEN: usize = 16;
const ATTR_HEADER_LEN: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    In = 0,
    Out = 1,
    Fwd = 2,
}

/// What names a state: protocol, SPI (a number here, network order in the message) and both addresses.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SaId {
    pub proto: u8,
    pub spi: u32,
    pub src: IpAddr,
    pub dst: IpAddr,
}

impl std::fmt::Debug for SaId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SaId")
            .field("proto", &self.proto)
            .finish_non_exhaustive()
    }
}

/// UDP encapsulation of a state: the two ports as their network order bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Encap {
    pub sport: [u8; 2],
    pub dport: [u8; 2],
}

/// A new state. No Debug: it holds the keys.
pub struct NewState<'a> {
    pub id: SaId,
    pub mode: u8,
    pub flags: u8,
    /// In packets. 0 turns replay protection off, which only suits an outgoing state.
    pub replay_window: u8,
    pub crypt_name: &'a str,
    pub crypt_key: &'a [u8],
    pub auth_name: &'a str,
    pub auth_trunc_bits: u32,
    pub auth_key: &'a [u8],
    pub encap: Option<Encap>,
    pub mark: Option<u32>,
}

/// Which side of a policy selector holds the address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Source,
    Destination,
}

/// A policy selector with one address. The other side is empty.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Selector {
    pub addr: IpAddr,
    pub prefix: u8,
    pub side: Side,
}

impl std::fmt::Debug for Selector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Selector")
            .field("prefix", &self.prefix)
            .field("side", &self.side)
            .finish_non_exhaustive()
    }
}

/// The template of a policy: the state it uses and its mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tmpl {
    pub id: SaId,
    pub mode: u8,
}

fn family_of(a: IpAddr) -> u16 {
    u16::from(match a {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    })
}

/// `xfrm_address_t`: an IPv4 address takes the first four bytes.
fn addr16(a: IpAddr) -> [u8; 16] {
    let mut out = [0u8; 16];
    match a {
        IpAddr::V4(v) => {
            for (d, s) in out.iter_mut().zip(v.octets()) {
                *d = s;
            }
        }
        IpAddr::V6(v) => out = v.octets(),
    }
    out
}

fn put(buf: &mut [u8], at: usize, bytes: &[u8]) {
    if let Some(d) = buf.get_mut(at..at.saturating_add(bytes.len())) {
        d.copy_from_slice(bytes);
    }
}

fn selector(s: &Selector) -> [u8; SELECTOR_LEN] {
    let mut b = [0u8; SELECTOR_LEN];
    let a = addr16(s.addr);
    put(
        &mut b,
        match s.side {
            Side::Destination => 0,
            Side::Source => 16,
        },
        &a,
    );
    put(&mut b, 40, &family_of(s.addr).to_ne_bytes());
    // the prefix of the daddr at 42, of the saddr at 43
    put(
        &mut b,
        match s.side {
            Side::Destination => 42,
            Side::Source => 43,
        },
        &[s.prefix],
    );
    b
}

/// `xfrm_lifetime_cfg`: no limit in bytes or packets, no expiry.
fn no_limits() -> [u8; LIFETIME_LEN] {
    let mut b = [0u8; LIFETIME_LEN];
    put(&mut b, 0, &[0xff; 32]);
    b
}

fn check_id(id: &SaId) -> Result<(), BuildError> {
    if family_of(id.src) == family_of(id.dst) {
        Ok(())
    } else {
        Err(BuildError::FamilyMismatch)
    }
}

/// `struct xfrm_id`: the destination, the SPI in network order and the protocol.
fn put_id(b: &mut [u8], at: usize, id: &SaId) {
    put(b, at, &addr16(id.dst));
    put(b, at.saturating_add(16), &id.spi.to_be_bytes());
    put(b, at.saturating_add(20), &[id.proto]);
}

fn alg_name(name: &str) -> Result<[u8; ALG_NAME_LEN], BuildError> {
    let n = name.as_bytes();
    if n.is_empty() || n.len() >= ALG_NAME_LEN || n.contains(&0) {
        return Err(BuildError::BadName);
    }
    let mut out = [0u8; ALG_NAME_LEN];
    put(&mut out, 0, n);
    Ok(out)
}

fn attr_size(payload: usize) -> usize {
    crate::rtnl::padded(ATTR_HEADER_LEN.saturating_add(payload))
}

/// `XFRM_MSG_NEWSA`, in one allocation of the exact size.
pub fn new_state(seq: u32, s: &NewState<'_>) -> Result<Vec<u8>, BuildError> {
    check_id(&s.id)?;
    let crypt = alg_name(s.crypt_name)?;
    let auth = alg_name(s.auth_name)?;
    let bits = |key: &[u8]| {
        u32::try_from(key.len())
            .ok()
            .and_then(|n| n.checked_mul(8))
            .ok_or(BuildError::BadName)
    };
    let (crypt_bits, auth_bits) = (bits(s.crypt_key)?, bits(s.auth_key)?);
    let size = HEADER_LEN
        + STATE_LEN
        + attr_size(ALG_NAME_LEN + 4 + s.crypt_key.len())
        + attr_size(ALG_NAME_LEN + 8 + s.auth_key.len())
        + s.encap.map_or(0, |_| attr_size(24))
        + s.mark.map_or(0, |_| attr_size(4));
    let mut m = Msg::sized(XFRM_MSG_NEWSA, NLM_F_REQUEST | NLM_F_ACK, seq, size);
    let mut info = [0u8; STATE_LEN];
    put_id(&mut info, 56, &s.id);
    put(&mut info, 80, &addr16(s.id.src));
    put(&mut info, 96, &no_limits());
    put(&mut info, 212, &family_of(s.id.src).to_ne_bytes());
    put(&mut info, 214, &[s.mode]);
    put(&mut info, 215, &[s.replay_window]);
    put(&mut info, 216, &[s.flags]);
    m.raw(&info);
    let a = m.begin(XFRMA_ALG_CRYPT);
    m.raw(&crypt);
    m.raw(&crypt_bits.to_ne_bytes());
    m.raw(s.crypt_key);
    m.end(a);
    let a = m.begin(XFRMA_ALG_AUTH_TRUNC);
    m.raw(&auth);
    m.raw(&auth_bits.to_ne_bytes());
    m.raw(&s.auth_trunc_bits.to_ne_bytes());
    m.raw(s.auth_key);
    m.end(a);
    if let Some(e) = s.encap {
        let mut t = [0u8; 24];
        put(&mut t, 0, &UDP_ENCAP_ESPINUDP.to_ne_bytes());
        put(&mut t, 2, &e.sport);
        put(&mut t, 4, &e.dport);
        m.attr(XFRMA_ENCAP, &t);
    }
    if let Some(mark) = s.mark {
        m.attr(XFRMA_SET_MARK, &mark.to_ne_bytes());
    }
    Ok(m.finish())
}

/// `XFRM_MSG_DELSA` by exact identifier: `xfrm_usersa_id` and the source address.
pub fn del_state(seq: u32, id: &SaId) -> Result<Vec<u8>, BuildError> {
    check_id(id)?;
    let mut m = Msg::new(XFRM_MSG_DELSA, NLM_F_REQUEST | NLM_F_ACK, seq);
    let mut b = [0u8; STATE_ID_LEN];
    put(&mut b, 0, &addr16(id.dst));
    put(&mut b, 16, &id.spi.to_be_bytes());
    put(&mut b, 20, &family_of(id.src).to_ne_bytes());
    put(&mut b, 22, &[id.proto]);
    m.raw(&b);
    m.attr(XFRMA_SRCADDR, &addr16(id.src));
    Ok(m.finish())
}

/// `XFRM_MSG_NEWPOLICY`: priority 100, allow, one template that takes any algorithm.
pub fn new_policy(seq: u32, sel: &Selector, dir: Dir, t: &Tmpl) -> Result<Vec<u8>, BuildError> {
    check_id(&t.id)?;
    let mut m = Msg::new(XFRM_MSG_NEWPOLICY, NLM_F_REQUEST | NLM_F_ACK, seq);
    let mut info = [0u8; POLICY_LEN];
    put(&mut info, 0, &selector(sel));
    put(&mut info, 56, &no_limits());
    put(&mut info, 152, &POLICY_PRIORITY.to_ne_bytes());
    put(&mut info, 160, &[dir as u8]);
    m.raw(&info);
    let mut tmpl = [0u8; TMPL_LEN];
    put_id(&mut tmpl, 0, &t.id);
    put(&mut tmpl, 24, &family_of(t.id.src).to_ne_bytes());
    put(&mut tmpl, 28, &addr16(t.id.src));
    put(&mut tmpl, 48, &[t.mode]);
    put(&mut tmpl, 52, &[0xff; 12]);
    m.attr(XFRMA_TMPL, &tmpl);
    Ok(m.finish())
}

/// `XFRM_MSG_DELPOLICY` by selector and direction.
pub fn del_policy(seq: u32, sel: &Selector, dir: Dir) -> Vec<u8> {
    let mut m = Msg::new(XFRM_MSG_DELPOLICY, NLM_F_REQUEST | NLM_F_ACK, seq);
    let mut b = [0u8; POLICY_ID_LEN];
    put(&mut b, 0, &selector(sel));
    put(&mut b, 60, &[dir as u8]);
    m.raw(&b);
    m.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtnl::testutil::attrs;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn id() -> SaId {
        SaId {
            proto: IPPROTO_ESP,
            spi: 0x0102_0304,
            src: ip("192.0.2.10"),
            dst: ip("198.51.100.20"),
        }
    }

    fn state<'a>() -> NewState<'a> {
        NewState {
            id: id(),
            mode: MODE_TUNNEL,
            flags: STATE_AF_UNSPEC | STATE_NOPMTUDISC,
            replay_window: 0,
            crypt_name: "cbc(aes)",
            crypt_key: &[0xaa; 16],
            auth_name: "hmac(sha256)",
            auth_trunc_bits: 128,
            auth_key: &[0xbb; 32],
            encap: Some(Encap {
                sport: [0x11, 0x94],
                dport: [0x11, 0x95],
            }),
            mark: Some(0x20000),
        }
    }

    fn hdr(m: &[u8]) -> (usize, u16, u16, u32) {
        (
            u32::from_ne_bytes(m[0..4].try_into().unwrap()) as usize,
            u16::from_ne_bytes(m[4..6].try_into().unwrap()),
            u16::from_ne_bytes(m[6..8].try_into().unwrap()),
            u32::from_ne_bytes(m[8..12].try_into().unwrap()),
        )
    }

    #[test]
    fn a_state_has_the_fields_of_xfrm_usersa_info() {
        let m = new_state(7, &state()).unwrap();
        let (len, ty, flags, seq) = hdr(&m);
        assert_eq!((len, ty, flags, seq), (m.len(), 0x10, 5, 7));
        let p = &m[16..16 + 224];
        // the selector stays zero
        assert_eq!(&p[..56], &[0; 56]);
        // id: daddr, SPI in network order, protocol
        assert_eq!(&p[56..60], &[198, 51, 100, 20]);
        assert_eq!(&p[72..76], &[1, 2, 3, 4]);
        assert_eq!(p[76], 50);
        // saddr
        assert_eq!(&p[80..84], &[192, 0, 2, 10]);
        // limits all ones, expiry zero
        assert_eq!(&p[96..128], &[0xff; 32]);
        assert_eq!(&p[128..160], &[0; 32]);
        // seq, reqid, family, mode, replay window, flags
        assert_eq!(&p[204..212], &[0; 8]);
        assert_eq!(u16::from_ne_bytes(p[212..214].try_into().unwrap()), 2);
        assert_eq!((p[214], p[215], p[216]), (1, 0, 0x24));
    }

    #[test]
    fn a_state_carries_its_replay_window() {
        let mut s = state();
        s.replay_window = 32;
        let m = new_state(1, &s).unwrap();
        assert_eq!(m[16 + 215], 32);
    }

    #[test]
    fn a_state_has_its_attributes_in_order_and_is_built_in_its_exact_size() {
        let m = new_state(1, &state()).unwrap();
        let a = attrs(&m, 16 + 224);
        let kinds: Vec<u16> = a.iter().map(|(t, _)| *t).collect();
        assert_eq!(kinds, vec![2, 20, 4, 29]);
        let crypt = &a[0].1;
        assert_eq!(&crypt[..8], b"cbc(aes)");
        assert_eq!(crypt[8], 0);
        assert_eq!(u32::from_ne_bytes(crypt[64..68].try_into().unwrap()), 128);
        assert_eq!(&crypt[68..], &[0xaa; 16]);
        let auth = &a[1].1;
        assert_eq!(&auth[..12], b"hmac(sha256)");
        assert_eq!(u32::from_ne_bytes(auth[64..68].try_into().unwrap()), 256);
        assert_eq!(u32::from_ne_bytes(auth[68..72].try_into().unwrap()), 128);
        assert_eq!(&auth[72..], &[0xbb; 32]);
        let encap = &a[2].1;
        assert_eq!(encap.len(), 24);
        assert_eq!(u16::from_ne_bytes(encap[..2].try_into().unwrap()), 2);
        assert_eq!(&encap[2..4], &[0x11, 0x94]);
        assert_eq!(&encap[4..6], &[0x11, 0x95]);
        assert_eq!(&encap[8..], &[0; 16]);
        assert_eq!(a[3].1, 0x20000u32.to_ne_bytes());
        // the size worked out before the allocation is what was written, so it never grew
        let n = 16 + 224 + attr_size(64 + 4 + 16) + attr_size(64 + 8 + 32) + attr_size(24) + 8;
        assert_eq!(m.len(), n);
    }

    #[test]
    fn a_state_without_encap_and_mark_leaves_them_out() {
        let mut s = state();
        s.encap = None;
        s.mark = None;
        let m = new_state(1, &s).unwrap();
        let kinds: Vec<u16> = attrs(&m, 16 + 224).iter().map(|(t, _)| *t).collect();
        assert_eq!(kinds, vec![2, 20]);
    }

    #[test]
    fn a_state_with_bad_names_or_mixed_families_is_refused() {
        let mut s = state();
        s.crypt_name = "";
        assert_eq!(new_state(1, &s).unwrap_err(), BuildError::BadName);
        let long = "x".repeat(64);
        let mut s = state();
        s.auth_name = &long;
        assert_eq!(new_state(1, &s).unwrap_err(), BuildError::BadName);
        let mut s = state();
        s.id.dst = ip("2001:db8::1");
        assert_eq!(new_state(1, &s).unwrap_err(), BuildError::FamilyMismatch);
    }

    #[test]
    fn a_state_is_removed_by_its_exact_identifier() {
        let m = del_state(9, &id()).unwrap();
        let (len, ty, flags, seq) = hdr(&m);
        assert_eq!((len, ty, flags, seq), (m.len(), 0x11, 5, 9));
        let p = &m[16..16 + 24];
        assert_eq!(&p[..4], &[198, 51, 100, 20]);
        assert_eq!(&p[16..20], &[1, 2, 3, 4]);
        assert_eq!(u16::from_ne_bytes(p[20..22].try_into().unwrap()), 2);
        assert_eq!(p[22], 50);
        let a = attrs(&m, 16 + 24);
        assert_eq!(a[0].0, 13);
        assert_eq!(&a[0].1[..4], &[192, 0, 2, 10]);
        assert_eq!(a[0].1.len(), 16);
    }

    #[test]
    fn a_policy_has_the_fields_of_xfrm_userpolicy_info_and_a_template() {
        let inner = ip("2001:db8::5");
        let sel = Selector {
            addr: inner,
            prefix: 64,
            side: Side::Source,
        };
        let tmpl = Tmpl {
            id: id(),
            mode: MODE_TUNNEL,
        };
        let m = new_policy(3, &sel, Dir::Out, &tmpl).unwrap();
        let (len, ty, flags, _) = hdr(&m);
        assert_eq!((len, ty, flags), (m.len(), 0x13, 5));
        let p = &m[16..16 + 168];
        // the selector: saddr at 16, family at 40, prefix of the saddr at 43
        assert_eq!(&p[..16], &[0; 16]);
        assert_eq!(p[16], 0x20);
        assert_eq!(u16::from_ne_bytes(p[40..42].try_into().unwrap()), 10);
        assert_eq!((p[42], p[43], p[44]), (0, 64, 0));
        assert_eq!(&p[48..56], &[0; 8]);
        assert_eq!(&p[56..88], &[0xff; 32]);
        assert_eq!(u32::from_ne_bytes(p[152..156].try_into().unwrap()), 100);
        assert_eq!((p[160], p[161], p[162], p[163]), (1, 0, 0, 0));
        let a = attrs(&m, 16 + 168);
        assert_eq!(a[0].0, 5);
        let t = &a[0].1;
        assert_eq!(t.len(), 64);
        assert_eq!(&t[..4], &[198, 51, 100, 20]);
        assert_eq!(&t[16..20], &[1, 2, 3, 4]);
        assert_eq!(t[20], 50);
        assert_eq!(u16::from_ne_bytes(t[24..26].try_into().unwrap()), 2);
        assert_eq!(&t[28..32], &[192, 0, 2, 10]);
        assert_eq!(&t[44..48], &[0; 4]);
        assert_eq!(t[48], 1);
        assert_eq!(&t[52..], &[0xff; 12]);
    }

    #[test]
    fn a_policy_selector_with_the_destination_has_its_prefix_at_42() {
        let sel = Selector {
            addr: ip("192.0.2.1"),
            prefix: 32,
            side: Side::Destination,
        };
        let m = del_policy(4, &sel, Dir::Fwd);
        let (len, ty, flags, _) = hdr(&m);
        assert_eq!((len, ty, flags), (16 + 64, 0x14, 5));
        let p = &m[16..];
        assert_eq!(&p[..4], &[192, 0, 2, 1]);
        assert_eq!(&p[16..32], &[0; 16]);
        assert_eq!((p[42], p[43]), (32, 0));
        assert_eq!(p[60], 2);
    }

    #[test]
    fn debug_shows_no_address_or_spi() {
        let s = format!(
            "{:?} {:?}",
            id(),
            Selector {
                addr: ip("192.0.2.1"),
                prefix: 32,
                side: Side::Source
            }
        );
        assert!(!s.contains("192") && !s.contains("198") && !s.contains("spi"));
    }
}
