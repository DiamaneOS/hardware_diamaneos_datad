// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The layouts of the closed data module, as offsets into byte buffers. Everything
//! here is safe code over slices, so the parsers are total and tested without
//! pointers. Each offset was read from `libnicm_dsi.so` and `libdsi_netctrl.so` of
//! the FP6 vendor generation 23400.
//!
//! A field read with `rd_*` is checked against the length of the buffer. A field
//! written with `wr_*` is too. Nothing here can panic.

/// Size of a `NicmEventInfo`, and of the buffers the module hands to the exports
/// for a route lookup, a port forwarding request and an OEM proxy query.
pub const INFO_LEN: usize = 0x3c0;
/// Size of the route lookup request the module builds.
pub const REQUEST_LEN: usize = 0xd0;
/// Size of the answer of the link MTU query: link, IPv4 MTU, IPv6 MTU.
pub const MTU_OUT_LEN: usize = 12;
/// Size of the answer of the link-local network handle query.
pub const HANDLE_OUT_LEN: usize = 8;
/// Size of the input of the OEM proxy query.
pub const OEM_IN_LEN: usize = 16;

/// The route lookup request the module builds (`dsi_prepare_route_lookup_params`)
/// and `dsiNicmRouteLookup` reads. The names are those of the stock log line.
pub mod request {
    /// u32, always 1 when the module builds the request.
    pub const VALID: usize = 0x00;
    /// u64, which of the fields below are present.
    pub const MASK: usize = 0x08;
    /// u8, `pi`, with `MASK_PROFILE_3GPP`.
    pub const PROFILE_3GPP: usize = 0x10;
    /// u8, `pi3gpp2`, with `MASK_PROFILE_3GPP2`.
    pub const PROFILE_3GPP2: usize = 0x11;
    /// u8, `tpref`, with `MASK_TECH_PREF`.
    pub const TECH_PREF: usize = 0x12;
    /// u32, `xt_t_pref`, with `MASK_XT_TECH_PREF`.
    pub const XT_TECH_PREF: usize = 0x14;
    /// u32, `ippref`, the IP family (4 or 6), with `MASK_IP_FAMILY`.
    pub const IP_FAMILY: usize = 0x18;
    /// Text, NUL terminated, `apn`, with `MASK_APN`.
    pub const APN: usize = 0x1c;
    pub const APN_LEN: usize = 0x97;
    /// u32, `datagin` of the stock log line. The module never sets it.
    pub const DATAGIN: usize = 0xb4;
    /// u32, `bu_apn_name`, with `MASK_BU_APN_NAME`.
    pub const BU_APN_NAME: usize = 0xb8;
    /// u32, `bu_apn_type`, with `MASK_BU_APN_TYPE`.
    pub const BU_APN_TYPE: usize = 0xbc;
    /// u32, `apn_type`, 0x80000001 when `MASK_APN_TYPE` is not set.
    pub const APN_TYPE: usize = 0xc0;
    /// u64, `apn_type_mask`, 0 when `MASK_APN_TYPE_MASK` is not set.
    pub const APN_TYPE_MASK: usize = 0xc8;

    pub const MASK_TECH_PREF: u64 = 0x1;
    pub const MASK_PROFILE_3GPP: u64 = 0x2;
    pub const MASK_APN: u64 = 0x4;
    pub const MASK_IP_FAMILY: u64 = 0x8;
    pub const MASK_PROFILE_3GPP2: u64 = 0x10;
    pub const MASK_XT_TECH_PREF: u64 = 0x20;
    pub const MASK_APN_TYPE: u64 = 0x80;
    pub const MASK_APN_TYPE_MASK: u64 = 0x100;
    pub const MASK_BU_APN_NAME: u64 = 0x200;
    pub const MASK_BU_APN_TYPE: u64 = 0x400;
}

/// What the module reads from its 960 byte buffer after a route lookup that
/// succeeded (`dsi_mm_iface_look_up`).
pub mod route_out {
    /// u32, not zero when a route was found.
    pub const VALID: usize = 0x368;
    /// u32, 1 when the link is the companion of a call on the other IP family.
    pub const COMPANION: usize = 0x36c;
    /// u32, the link (also the interface number of the module, below 34).
    pub const LINK: usize = 0x370;
    /// u32, `modem` of the stock log line about the preferred technology.
    pub const MODEM: usize = 0x378;
    /// u32, the technology the data system determination prefers (0x8880 and
    /// its neighbours, compared with the technology the user asked for).
    pub const TECH: usize = 0x37c;
    /// 17 bytes, the matching-call query only: the device name, NUL terminated.
    pub const MATCH_NAME: usize = 0x3a0;
    pub const MATCH_NAME_LEN: usize = 17;
    /// u32, the matching-call query only: 1 when the name is there.
    pub const MATCH_VALID: usize = 0x3b4;
}

/// The two route lookup kinds (the fifth argument of `dsiNicmRouteLookup`).
pub const LOOKUP_ROUTE: u32 = 5;
pub const LOOKUP_MATCHING_CALL: u32 = 0xb;

/// Links the module can name: its interface table has 34 entries and the link map
/// of the stock library is the identity from 0 to 32.
pub const MAX_LINK: u32 = 32;

/// The event the module's translation function fills (`dsiTranslateNicmEvent`),
/// 960 bytes, zeroed by the caller.
pub mod event {
    /// u32, which fields are present.
    pub const MASK: usize = 0x00;
    /// u32, the event ID of the module (`ID_*`).
    pub const ID: usize = 0x04;
    /// u32, the link.
    pub const LINK: usize = 0x08;
    /// u16, the address family (2 or 10) of the address block.
    pub const ADDR_FAMILY: usize = 0x20;
    /// 16 bytes, the address (4 bytes for IPv4) directly after the family.
    pub const ADDR: usize = 0x22;
    /// u32, the prefix length of the address.
    pub const PREFIX: usize = 0xa0;
    /// u32 x 3, the link MTU, the IPv4 MTU and the IPv6 MTU, with `MASK_MTU`. The module keeps the first
    /// as the MTU of the interface and answers `dsi_get_link_mtu` with it.
    pub const MTU_IFACE: usize = 0x258;
    pub const MTU_V4: usize = 0x25c;
    pub const MTU_V6: usize = 0x260;
    /// u32, the subscription the event is for.
    pub const SUB: usize = 0x384;
    /// u8, 1 when `RESTART_STATE` is present.
    pub const RESTART_PRESENT: usize = 0x388;
    /// u32, 0 start, 1 ongoing, 2 done.
    pub const RESTART_STATE: usize = 0x38c;

    pub const MASK_LINK: u32 = 0x1;
    /// Address family and address (`MASK_ADDR` is both bits, the module tests both).
    pub const MASK_ADDR: u32 = 0x1004;
    pub const MASK_MTU: u32 = 0x200;

    pub const ID_UP: u32 = 1;
    pub const ID_DOWN: u32 = 2;
    pub const ID_RECONFIGURED: u32 = 3;
    pub const ID_NEW_ADDR: u32 = 0xb;
    pub const ID_DEL_ADDR: u32 = 0xc;
    pub const ID_USER_CMD: u32 = 0xf;
    pub const ID_MTU_UPDATE: u32 = 0x10;

    /// The kind the module acts on (the third argument of the translation).
    pub const KIND_UP: u32 = 1;
    pub const KIND_DOWN: u32 = 2;
    pub const KIND_RECONFIGURED: u32 = 5;
    pub const KIND_NEW_ADDR: u32 = 7;
    pub const KIND_DEL_ADDR: u32 = 8;
    pub const KIND_MTU_UPDATE: u32 = 0x13;

    pub const RESTART_START: u32 = 0;
    pub const RESTART_DONE: u32 = 2;
}

/// Address families as the module's address block spells them.
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

// The sizes are those of the module's allocations, not relations.
const _: () = assert!(INFO_LEN == 0x3c0);
const _: () = assert!(REQUEST_LEN == 0xd0);
const _: () = assert!(MTU_OUT_LEN == 12);
const _: () = assert!(HANDLE_OUT_LEN == 8);
const _: () = assert!(OEM_IN_LEN == 16);

// The layouts have to fit their buffers and must not overlap where the module
// keeps two things apart.
const _: () = assert!(request::APN + request::APN_LEN <= request::DATAGIN);
const _: () = assert!(request::APN_TYPE_MASK + 8 == REQUEST_LEN);
const _: () = assert!(route_out::MATCH_NAME + route_out::MATCH_NAME_LEN <= route_out::MATCH_VALID);
const _: () = assert!(event::RESTART_STATE + 4 <= route_out::MATCH_NAME);
const _: () = assert!(route_out::MATCH_VALID + 4 <= INFO_LEN);
const _: () = assert!(route_out::TECH + 4 <= event::SUB);
const _: () = assert!(route_out::TECH + 4 <= INFO_LEN);
const _: () = assert!(event::RESTART_STATE + 4 <= INFO_LEN);
const _: () = assert!(event::ADDR + 16 <= event::PREFIX);
const _: () = assert!(event::PREFIX + 4 <= event::MTU_IFACE);
const _: () = assert!(event::MTU_V6 + 4 <= event::SUB);

fn range(off: usize, len: usize) -> Option<core::ops::Range<usize>> {
    Some(off..off.checked_add(len)?)
}

pub fn rd_u8(b: &[u8], off: usize) -> Option<u8> {
    b.get(off).copied()
}

pub fn rd_u16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(range(off, 2)?)?.try_into().ok()?))
}

pub fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(range(off, 4)?)?.try_into().ok()?))
}

pub fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(range(off, 8)?)?.try_into().ok()?))
}

/// Write bytes at an offset. False: they do not fit.
pub fn wr_bytes(b: &mut [u8], off: usize, v: &[u8]) -> bool {
    let Some(r) = range(off, v.len()) else {
        return false;
    };
    let Some(dst) = b.get_mut(r) else {
        return false;
    };
    for (d, s) in dst.iter_mut().zip(v) {
        *d = *s;
    }
    true
}

pub fn wr_u8(b: &mut [u8], off: usize, v: u8) -> bool {
    wr_bytes(b, off, &[v])
}

pub fn wr_u16(b: &mut [u8], off: usize, v: u16) -> bool {
    wr_bytes(b, off, &v.to_le_bytes())
}

pub fn wr_u32(b: &mut [u8], off: usize, v: u32) -> bool {
    wr_bytes(b, off, &v.to_le_bytes())
}

pub fn wr_u64(b: &mut [u8], off: usize, v: u64) -> bool {
    wr_bytes(b, off, &v.to_le_bytes())
}

/// What the module asked for in a route lookup, with every value checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub ip_family: u32,
    pub apn: Option<String>,
    pub apn_type: u32,
    pub apn_type_mask: u64,
    /// The other values nicmd passes on to the modem (TLVs 0x31, 0x32, 0x34, 0x3c, 0x3d), each only
    /// when the module marked it present.
    pub profile_3gpp: Option<u8>,
    pub profile_3gpp2: Option<u8>,
    pub xt_tech_pref: Option<u32>,
    pub bu_apn_name: Option<u32>,
    pub bu_apn_type: Option<u32>,
}

/// Why a request was refused before anything was sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bad {
    /// Shorter than a request, or not marked valid.
    Shape,
    /// The IP family is missing or is not 4 or 6.
    Family,
    /// The APN has no end, is not text, or is longer than the daemon takes.
    Apn,
}

/// Read the request the module built.
pub fn read_request(b: &[u8]) -> Result<Request, Bad> {
    if b.len() < REQUEST_LEN || rd_u32(b, request::VALID) != Some(1) {
        return Err(Bad::Shape);
    }
    let mask = rd_u64(b, request::MASK).ok_or(Bad::Shape)?;
    // The module always gives the family. Without it nicmd takes the request for IPv4,
    // and so does this.
    let ip_family = if mask & request::MASK_IP_FAMILY == 0 {
        4
    } else {
        rd_u32(b, request::IP_FAMILY).ok_or(Bad::Shape)?
    };
    if ip_family != 4 && ip_family != 6 {
        return Err(Bad::Family);
    }
    let apn = if mask & request::MASK_APN == 0 {
        None
    } else {
        let raw = b
            .get(range(request::APN, request::APN_LEN).ok_or(Bad::Shape)?)
            .ok_or(Bad::Shape)?;
        let end = raw.iter().position(|c| *c == 0).ok_or(Bad::Apn)?;
        let text = raw.get(..end).ok_or(Bad::Apn)?;
        if text.is_empty() {
            None
        } else if text.len() > dataos_nicm_abi::MAX_APN {
            return Err(Bad::Apn);
        } else {
            Some(String::from_utf8(text.to_vec()).map_err(|_| Bad::Apn)?)
        }
    };
    let apn_type = rd_u32(b, request::APN_TYPE).ok_or(Bad::Shape)?;
    let apn_type_mask = if mask & request::MASK_APN_TYPE_MASK == 0 {
        0
    } else {
        rd_u64(b, request::APN_TYPE_MASK).ok_or(Bad::Shape)?
    };
    let present = |bit: u64| mask & bit != 0;
    Ok(Request {
        ip_family,
        apn,
        apn_type,
        apn_type_mask,
        profile_3gpp: if present(request::MASK_PROFILE_3GPP) {
            Some(rd_u8(b, request::PROFILE_3GPP).ok_or(Bad::Shape)?)
        } else {
            None
        },
        profile_3gpp2: if present(request::MASK_PROFILE_3GPP2) {
            Some(rd_u8(b, request::PROFILE_3GPP2).ok_or(Bad::Shape)?)
        } else {
            None
        },
        xt_tech_pref: if present(request::MASK_XT_TECH_PREF) {
            Some(rd_u32(b, request::XT_TECH_PREF).ok_or(Bad::Shape)?)
        } else {
            None
        },
        bu_apn_name: if present(request::MASK_BU_APN_NAME) {
            Some(rd_u32(b, request::BU_APN_NAME).ok_or(Bad::Shape)?)
        } else {
            None
        },
        bu_apn_type: if present(request::MASK_BU_APN_TYPE) {
            Some(rd_u32(b, request::BU_APN_TYPE).ok_or(Bad::Shape)?)
        } else {
            None
        },
    })
}

/// The technology that `route_out::TECH` carries until the stock logs give the
/// real values: the one that satisfies the module's checks for the radio
/// technologies of a 4G and 5G phone (UMTS, LTE, CDMA and TD-SCDMA accept it).
/// Inferred, not read from a stock log.
pub const TECH_DEFAULT: u32 = 0x8880;

/// What `route_out::TECH` carries: a technology of a Wi-Fi call as the modem named it, and `TECH_DEFAULT` for anything
/// else, so a cellular value stays what it always was.
pub fn route_tech(tech: u32) -> u32 {
    match tech {
        0x8020 | 0x8021 | 0x8040 | 0x8080 => tech,
        _ => TECH_DEFAULT,
    }
}

/// Write the answer of a route lookup into the module's 960 byte buffer. `existing` is nicmd's "the
/// modem returned an instance" (the field the module reads as "route found", 0 for a new call) and
/// `companion` its "the instance is the other family's". The buffer
/// is zeroed first, as the stock function does. False: the link is not one the
/// module can name, or the buffer is too short.
pub fn write_route(out: &mut [u8], link: u32, existing: bool, companion: bool, tech: u32) -> bool {
    for b in out.iter_mut() {
        *b = 0;
    }
    if out.len() < INFO_LEN || link > MAX_LINK {
        return false;
    }
    wr_u32(out, route_out::VALID, u32::from(existing))
        && wr_u32(out, route_out::COMPANION, u32::from(companion))
        && wr_u32(out, route_out::LINK, link)
        && wr_u32(out, route_out::MODEM, 0)
        && wr_u32(out, route_out::TECH, route_tech(tech))
}

/// Write the answer of a matching-call query: the device name and the mark that it is there. The
/// buffer is zeroed first. False: the name is empty, has a NUL or does not fit with its
/// terminator in 17 bytes, or the buffer is too short. Nothing is marked valid then.
pub fn write_matching(out: &mut [u8], name: &str) -> bool {
    for b in out.iter_mut() {
        *b = 0;
    }
    let bytes = name.as_bytes();
    if out.len() < INFO_LEN
        || bytes.is_empty()
        || bytes.len() >= route_out::MATCH_NAME_LEN
        || bytes.contains(&0)
    {
        return false;
    }
    wr_bytes(out, route_out::MATCH_NAME, bytes) && wr_u32(out, route_out::MATCH_VALID, 1)
}

/// Write the answer of the link MTU query: the link MTU, the IPv4 MTU, the IPv6 MTU.
pub fn write_mtu(out: &mut [u8], v4: u32, v6: u32) -> bool {
    out.len() >= MTU_OUT_LEN
        && wr_u32(out, 0, dataos_nicm_abi::link_mtu(v4, v6))
        && wr_u32(out, 4, v4)
        && wr_u32(out, 8, v6)
}

/// The fields of an event the module needs, for one event of ours.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Translated {
    /// The kind (third argument of the translation), 0 when the event has none.
    pub kind: u32,
}

/// What an event of ours stands for, before it is written.
pub enum Ev {
    Up {
        link: u32,
        sub: u32,
        addr: Option<(u16, [u8; 16], u32)>,
    },
    Down {
        link: u32,
        sub: u32,
    },
    Reconfigured {
        link: u32,
        sub: u32,
        addr: Option<(u16, [u8; 16], u32)>,
    },
    NewAddr {
        link: u32,
        sub: u32,
        family: u16,
        addr: [u8; 16],
        prefix: u32,
    },
    DelAddr {
        link: u32,
        sub: u32,
        family: u16,
        addr: [u8; 16],
        prefix: u32,
    },
    Mtu {
        link: u32,
        sub: u32,
        v4: u32,
        v6: u32,
    },
    /// A call that could not be followed: the module hears "no net" for the link.
    OpFailed {
        link: u32,
        sub: u32,
    },
    /// The restart notice: start or done.
    Restart {
        done: bool,
    },
}

fn put_addr(out: &mut [u8], addr: (u16, [u8; 16], u32)) -> bool {
    let (family, bytes, prefix) = addr;
    let len = if family == AF_INET {
        4
    } else if family == AF_INET6 {
        16
    } else {
        return false;
    };
    let Some(used) = bytes.get(..len) else {
        return false;
    };
    let mask = rd_u32(out, event::MASK).unwrap_or(0) | event::MASK_ADDR;
    wr_u16(out, event::ADDR_FAMILY, family)
        && wr_bytes(out, event::ADDR, used)
        && wr_u32(out, event::PREFIX, prefix)
        && wr_u32(out, event::MASK, mask)
}

/// Write an event into the module's zeroed 960 byte buffer. None: the buffer is
/// too short or a value is outside what the module takes.
pub fn write_event(out: &mut [u8], ev: &Ev) -> Option<Translated> {
    if out.len() < INFO_LEN {
        return None;
    }
    let head = |out: &mut [u8], id: u32, link: u32, sub: u32| {
        link <= MAX_LINK
            && wr_u32(out, event::MASK, event::MASK_LINK)
            && wr_u32(out, event::ID, id)
            && wr_u32(out, event::LINK, link)
            && wr_u32(out, event::SUB, sub)
    };
    let ok = match *ev {
        Ev::Up { link, sub, addr } => {
            head(out, event::ID_UP, link, sub) && addr.is_none_or(|a| put_addr(out, a))
        }
        Ev::Reconfigured { link, sub, addr } => {
            head(out, event::ID_RECONFIGURED, link, sub) && addr.is_none_or(|a| put_addr(out, a))
        }
        Ev::NewAddr {
            link,
            sub,
            family,
            addr,
            prefix,
        } => head(out, event::ID_RECONFIGURED, link, sub) && put_addr(out, (family, addr, prefix)),
        Ev::DelAddr {
            link,
            sub,
            family,
            addr,
            prefix,
        } => head(out, event::ID_DEL_ADDR, link, sub) && put_addr(out, (family, addr, prefix)),
        Ev::Down { link, sub } => head(out, event::ID_DOWN, link, sub),
        Ev::OpFailed { link, sub } => {
            // the stock translation leaves the event ID of a failed operation at 0
            head(out, 0, link, sub)
        }
        Ev::Mtu { link, sub, v4, v6 } => {
            head(out, event::ID_MTU_UPDATE, link, sub)
                && wr_u32(out, event::MTU_IFACE, dataos_nicm_abi::link_mtu(v4, v6))
                && wr_u32(out, event::MTU_V4, v4)
                && wr_u32(out, event::MTU_V6, v6)
                && wr_u32(out, event::MASK, event::MASK_LINK | event::MASK_MTU)
        }
        Ev::Restart { done } => {
            wr_u32(out, event::MASK, event::MASK_LINK)
                && wr_u32(out, event::ID, event::ID_USER_CMD)
                && wr_u8(out, event::RESTART_PRESENT, 1)
                && wr_u32(
                    out,
                    event::RESTART_STATE,
                    if done {
                        event::RESTART_DONE
                    } else {
                        event::RESTART_START
                    },
                )
        }
    };
    if !ok {
        return None;
    }
    let kind = match ev {
        Ev::Up { .. } => event::KIND_UP,
        Ev::Down { .. } | Ev::OpFailed { .. } => event::KIND_DOWN,
        Ev::Reconfigured { .. } => event::KIND_RECONFIGURED,
        Ev::NewAddr { .. } => event::KIND_RECONFIGURED,
        Ev::DelAddr { .. } => event::KIND_DEL_ADDR,
        Ev::Mtu { .. } => event::KIND_MTU_UPDATE,
        Ev::Restart { .. } => 0,
    };
    Some(Translated { kind })
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    fn request_bytes(mask: u64, family: u32, apn: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; REQUEST_LEN];
        assert!(wr_u32(&mut b, request::VALID, 1));
        assert!(wr_u64(&mut b, request::MASK, mask));
        assert!(wr_u32(&mut b, request::IP_FAMILY, family));
        assert!(wr_bytes(&mut b, request::APN, apn));
        assert!(wr_u32(&mut b, request::APN_TYPE, 0x8000_0001));
        b
    }

    #[test]
    fn the_request_is_read_with_every_value_checked() {
        let m = request::MASK_IP_FAMILY | request::MASK_APN;
        let r = read_request(&request_bytes(m, 6, b"internet.example")).unwrap();
        assert_eq!(r.ip_family, 6);
        assert_eq!(r.apn.as_deref(), Some("internet.example"));
        assert_eq!(r.apn_type, 0x8000_0001);
        assert_eq!(r.apn_type_mask, 0);
        // the mask decides what is read
        let mut b = request_bytes(m | request::MASK_APN_TYPE_MASK, 4, b"");
        assert!(wr_u64(&mut b, request::APN_TYPE_MASK, 0x200));
        let r = read_request(&b).unwrap();
        assert_eq!((r.apn, r.apn_type_mask), (None, 0x200));
        let mut b = request_bytes(request::MASK_IP_FAMILY, 4, b"ignored");
        assert!(wr_u64(&mut b, request::APN_TYPE_MASK, 0x200));
        let r = read_request(&b).unwrap();
        assert_eq!((r.apn, r.apn_type_mask), (None, 0));
        // refused
        assert_eq!(read_request(&[0; 8]), Err(Bad::Shape));
        let mut b = request_bytes(m, 4, b"x");
        assert!(wr_u32(&mut b, request::VALID, 0));
        assert_eq!(read_request(&b), Err(Bad::Shape));
        for family in [0, 1, 5, 8, 10, 0xffff_ffff] {
            assert_eq!(
                read_request(&request_bytes(m, family, b"x")),
                Err(Bad::Family)
            );
        }
        // no family given: nicmd treats anything but IPv6 as IPv4 (its companion lookup swaps 6 for
        // 4 and everything else for 6), so the lookup is for IPv4
        let r = read_request(&request_bytes(request::MASK_APN, 0, b"x")).unwrap();
        assert_eq!(r.ip_family, 4);
        // an APN without its end, not text, longer than the daemon takes
        let unended = vec![b'a'; request::APN_LEN];
        assert_eq!(read_request(&request_bytes(m, 4, &unended)), Err(Bad::Apn));
        assert_eq!(
            read_request(&request_bytes(m, 4, &[0xff, 0xfe])),
            Err(Bad::Apn)
        );
        let long = vec![b'a'; dataos_nicm_abi::MAX_APN + 1];
        assert_eq!(read_request(&request_bytes(m, 4, &long)), Err(Bad::Apn));
        let longest = vec![b'a'; dataos_nicm_abi::MAX_APN];
        assert!(read_request(&request_bytes(m, 4, &longest)).is_ok());
    }

    #[test]
    fn a_wifi_technology_goes_through_and_any_other_keeps_the_default() {
        let mut out = vec![0u8; INFO_LEN];
        for tech in [0x8020, 0x8021, 0x8040, 0x8080] {
            assert!(write_route(&mut out, 3, false, false, tech));
            assert_eq!(rd_u32(&out, route_out::TECH), Some(tech));
        }
        for tech in [0, 0x8880, 0x8001, 0x8004, 0x8840, 1] {
            assert!(write_route(&mut out, 3, false, false, tech));
            assert_eq!(rd_u32(&out, route_out::TECH), Some(TECH_DEFAULT));
        }
    }

    #[test]
    fn the_route_answer_lands_where_the_module_reads_it() {
        let mut out = vec![0xaau8; INFO_LEN];
        assert!(write_route(&mut out, 3, false, false, 0));
        assert_eq!(
            rd_u32(&out, route_out::VALID),
            Some(0),
            "a new call, not one the modem has"
        );
        assert_eq!(rd_u32(&out, route_out::COMPANION), Some(0));
        assert_eq!(rd_u32(&out, route_out::LINK), Some(3));
        assert_eq!(rd_u32(&out, route_out::MODEM), Some(0));
        assert_eq!(rd_u32(&out, route_out::TECH), Some(TECH_DEFAULT));
        assert_eq!(rd_u8(&out, 0), Some(0), "the rest is zeroed");
        assert_eq!(rd_u8(&out, INFO_LEN - 1), Some(0));
        // a link the module cannot name, and a buffer that is too short
        let mut out = vec![0xaau8; INFO_LEN];
        assert!(write_route(&mut out, MAX_LINK, false, false, 0));
        assert!(!write_route(&mut out, MAX_LINK + 1, true, true, 0));
        assert_eq!(rd_u32(&out, route_out::VALID), Some(0));
        assert!(!write_route(
            &mut vec![0u8; INFO_LEN - 1],
            0,
            false,
            false,
            0
        ));
        // the other family of a call that is up: the instance exists and it is the companion's
        assert!(write_route(&mut out, 4, true, true, 0));
        assert_eq!(rd_u32(&out, route_out::VALID), Some(1));
        assert_eq!(rd_u32(&out, route_out::COMPANION), Some(1));
        assert_eq!(rd_u32(&out, route_out::LINK), Some(4));
        assert!(write_route(&mut out, 4, true, false, 0));
        assert_eq!(rd_u32(&out, route_out::COMPANION), Some(0));
    }

    #[test]
    fn the_mtu_answer_is_link_then_the_two_mtus() {
        let mut out = [0u8; MTU_OUT_LEN];
        assert!(write_mtu(&mut out, 1500, 1280));
        assert_eq!(
            rd_u32(&out, 0),
            Some(1280),
            "the link MTU, not the link number"
        );
        assert_eq!(rd_u32(&out, 4), Some(1500));
        assert_eq!(rd_u32(&out, 8), Some(1280));
        assert!(!write_mtu(&mut [0u8; 11], 1, 2));
    }

    fn event_buf() -> Vec<u8> {
        vec![0u8; INFO_LEN]
    }

    #[test]
    fn an_address_event_carries_the_family_the_address_and_the_prefix() {
        let mut v4 = [0u8; 16];
        v4[..4].copy_from_slice(&[10, 1, 2, 3]);
        let mut b = event_buf();
        let t = write_event(
            &mut b,
            &Ev::NewAddr {
                link: 2,
                sub: 1,
                family: AF_INET,
                addr: v4,
                prefix: 30,
            },
        )
        .unwrap();
        assert_eq!(t.kind, event::KIND_RECONFIGURED);
        assert_eq!(rd_u32(&b, event::ID), Some(event::ID_RECONFIGURED));
        assert_eq!(rd_u32(&b, event::LINK), Some(2));
        assert_eq!(rd_u32(&b, event::SUB), Some(1));
        let mask = rd_u32(&b, event::MASK).unwrap();
        assert_eq!(mask & event::MASK_ADDR, event::MASK_ADDR);
        assert_eq!(mask & event::MASK_LINK, event::MASK_LINK);
        assert_eq!(rd_u16(&b, event::ADDR_FAMILY), Some(AF_INET));
        assert_eq!(
            b.get(event::ADDR..event::ADDR + 4),
            Some(&[10, 1, 2, 3][..])
        );
        assert_eq!(
            rd_u8(&b, event::ADDR + 4),
            Some(0),
            "an IPv4 address is 4 bytes"
        );
        assert_eq!(rd_u32(&b, event::PREFIX), Some(30));
        // IPv6 fills all sixteen
        let v6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];
        let mut b = event_buf();
        let t = write_event(
            &mut b,
            &Ev::DelAddr {
                link: 2,
                sub: 0,
                family: AF_INET6,
                addr: v6,
                prefix: 64,
            },
        )
        .unwrap();
        assert_eq!(t.kind, event::KIND_DEL_ADDR);
        assert_eq!(rd_u16(&b, event::ADDR_FAMILY), Some(AF_INET6));
        assert_eq!(b.get(event::ADDR..event::ADDR + 16), Some(&v6[..]));
        // a family the module does not know is refused
        let mut b = event_buf();
        assert!(write_event(
            &mut b,
            &Ev::NewAddr {
                link: 2,
                sub: 0,
                family: 7,
                addr: v6,
                prefix: 1
            }
        )
        .is_none());
    }

    #[test]
    fn the_other_events_have_their_ids_kinds_and_fields() {
        let cases = [
            (
                Ev::Up {
                    link: 1,
                    sub: 0,
                    addr: None,
                },
                event::ID_UP,
                event::KIND_UP,
            ),
            (
                Ev::Down { link: 1, sub: 0 },
                event::ID_DOWN,
                event::KIND_DOWN,
            ),
            (
                Ev::Reconfigured {
                    link: 1,
                    sub: 0,
                    addr: None,
                },
                event::ID_RECONFIGURED,
                event::KIND_RECONFIGURED,
            ),
            (Ev::OpFailed { link: 1, sub: 0 }, 0, event::KIND_DOWN),
        ];
        for (ev, id, kind) in cases {
            let mut b = event_buf();
            let t = write_event(&mut b, &ev).unwrap();
            assert_eq!((rd_u32(&b, event::ID), t.kind), (Some(id), kind));
            assert_eq!(rd_u32(&b, event::LINK), Some(1));
        }
        let mut b = event_buf();
        let t = write_event(
            &mut b,
            &Ev::Mtu {
                link: 4,
                sub: 0,
                v4: 1500,
                v6: 1400,
            },
        )
        .unwrap();
        assert_eq!(t.kind, event::KIND_MTU_UPDATE);
        assert_eq!(
            rd_u32(&b, event::MTU_IFACE),
            Some(1400),
            "the link MTU: the smaller of the two"
        );
        assert_eq!(rd_u32(&b, event::MTU_V4), Some(1500));
        assert_eq!(rd_u32(&b, event::MTU_V6), Some(1400));
        assert_eq!(
            rd_u32(&b, event::MASK).unwrap() & event::MASK_MTU,
            event::MASK_MTU
        );
        // the restart notices carry the state and nothing else
        for (done, state) in [(false, 0), (true, 2)] {
            let mut b = event_buf();
            let t = write_event(&mut b, &Ev::Restart { done }).unwrap();
            assert_eq!(t.kind, 0);
            assert_eq!(rd_u32(&b, event::ID), Some(event::ID_USER_CMD));
            assert_eq!(rd_u8(&b, event::RESTART_PRESENT), Some(1));
            assert_eq!(rd_u32(&b, event::RESTART_STATE), Some(state));
        }
        // a link the module cannot name, and a buffer that is too short
        let mut b = event_buf();
        assert!(write_event(&mut b, &Ev::Down { link: 33, sub: 0 }).is_none());
        assert!(write_event(&mut vec![0u8; INFO_LEN - 1], &Ev::Restart { done: true }).is_none());
    }

    /// Every number of the layout tables, once more, as literals. The other tests read
    /// and write through the constants, so a wrong constant would pass them.
    #[test]
    fn the_other_values_of_a_request_are_read_only_when_marked_present() {
        let mut r = vec![0u8; REQUEST_LEN];
        assert!(wr_u32(&mut r, request::VALID, 1));
        assert!(wr_u8(&mut r, request::PROFILE_3GPP, 3));
        assert!(wr_u8(&mut r, request::PROFILE_3GPP2, 4));
        assert!(wr_u32(&mut r, request::XT_TECH_PREF, 0x0102));
        assert!(wr_u32(&mut r, request::BU_APN_NAME, 1));
        assert!(wr_u32(&mut r, request::BU_APN_TYPE, 2));
        let none = read_request(&r).unwrap();
        assert_eq!(
            (none.profile_3gpp, none.profile_3gpp2, none.xt_tech_pref),
            (None, None, None)
        );
        assert_eq!((none.bu_apn_name, none.bu_apn_type), (None, None));
        for (bit, pick) in [
            (request::MASK_PROFILE_3GPP, 0),
            (request::MASK_PROFILE_3GPP2, 1),
            (request::MASK_XT_TECH_PREF, 2),
            (request::MASK_BU_APN_NAME, 3),
            (request::MASK_BU_APN_TYPE, 4),
        ] {
            assert!(wr_u64(&mut r, request::MASK, bit));
            let q = read_request(&r).unwrap();
            let got = [
                q.profile_3gpp.map(u32::from),
                q.profile_3gpp2.map(u32::from),
                q.xt_tech_pref,
                q.bu_apn_name,
                q.bu_apn_type,
            ];
            let want = [Some(3), Some(4), Some(0x0102), Some(1), Some(2)];
            for (i, g) in got.iter().enumerate() {
                assert_eq!(*g, if i == pick { want[i] } else { None }, "{bit:#x} {i}");
            }
        }
    }

    #[test]
    fn the_matching_answer_is_a_name_and_a_mark() {
        let mut out = vec![0xaau8; INFO_LEN];
        assert!(write_matching(&mut out, "rmnet_data3"));
        assert_eq!(out.get(0x3a0..0x3a0 + 12), Some(&b"rmnet_data3\0"[..]));
        assert_eq!(rd_u32(&out, 0x3b4), Some(1));
        // everything else was cleared, as the stock function does
        assert_eq!(rd_u32(&out, route_out::VALID), Some(0));
        assert_eq!(out.iter().filter(|b| **b != 0).count(), 11 + 1);
        // 16 bytes and the terminator fit, 17 do not
        let mut out = vec![0u8; INFO_LEN];
        assert!(write_matching(&mut out, "abcdefghijklmnop"));
        assert_eq!(out.get(0x3a0 + 16), Some(&0));
        let mut out = vec![0xaau8; INFO_LEN];
        assert!(!write_matching(&mut out, "abcdefghijklmnopq"));
        assert_eq!(rd_u32(&out, 0x3b4), Some(0), "not marked");
        assert!(out.iter().all(|b| *b == 0));
        assert!(!write_matching(&mut out, ""));
        assert!(!write_matching(&mut out, "a\0b"));
        assert!(!write_matching(&mut vec![0u8; INFO_LEN - 1], "rmnet_data3"));
    }

    #[test]
    fn every_offset_width_id_and_kind_is_the_number_of_the_design_tables() {
        let sizes = [
            (INFO_LEN, 0x3c0),
            (REQUEST_LEN, 0xd0),
            (MTU_OUT_LEN, 12),
            (HANDLE_OUT_LEN, 8),
            (OEM_IN_LEN, 16),
            (request::APN_LEN, 0x97),
            (MAX_LINK as usize, 32),
        ];
        for (got, want) in sizes {
            assert_eq!(got, want);
        }
        let request_at = [
            (request::VALID, 0x00),
            (request::MASK, 0x08),
            (request::PROFILE_3GPP, 0x10),
            (request::PROFILE_3GPP2, 0x11),
            (request::TECH_PREF, 0x12),
            (request::XT_TECH_PREF, 0x14),
            (request::IP_FAMILY, 0x18),
            (request::APN, 0x1c),
            (request::DATAGIN, 0xb4),
            (request::BU_APN_NAME, 0xb8),
            (request::BU_APN_TYPE, 0xbc),
            (request::APN_TYPE, 0xc0),
            (request::APN_TYPE_MASK, 0xc8),
            (route_out::VALID, 0x368),
            (route_out::COMPANION, 0x36c),
            (route_out::MATCH_NAME, 0x3a0),
            (route_out::MATCH_NAME_LEN, 17),
            (route_out::MATCH_VALID, 0x3b4),
            (route_out::LINK, 0x370),
            (route_out::MODEM, 0x378),
            (route_out::TECH, 0x37c),
            (event::MASK, 0x00),
            (event::ID, 0x04),
            (event::LINK, 0x08),
            (event::ADDR_FAMILY, 0x20),
            (event::ADDR, 0x22),
            (event::PREFIX, 0xa0),
            (event::MTU_IFACE, 0x258),
            (event::MTU_V4, 0x25c),
            (event::MTU_V6, 0x260),
            (event::SUB, 0x384),
            (event::RESTART_PRESENT, 0x388),
            (event::RESTART_STATE, 0x38c),
        ];
        for (got, want) in request_at {
            assert_eq!(got, want);
        }
        let masks: [(u64, u64); 10] = [
            (request::MASK_TECH_PREF, 0x1),
            (request::MASK_PROFILE_3GPP, 0x2),
            (request::MASK_APN, 0x4),
            (request::MASK_IP_FAMILY, 0x8),
            (request::MASK_PROFILE_3GPP2, 0x10),
            (request::MASK_XT_TECH_PREF, 0x20),
            (request::MASK_APN_TYPE, 0x80),
            (request::MASK_APN_TYPE_MASK, 0x100),
            (request::MASK_BU_APN_NAME, 0x200),
            (request::MASK_BU_APN_TYPE, 0x400),
        ];
        for (got, want) in masks {
            assert_eq!(got, want);
        }
        let words: [(u32, u32); 20] = [
            (event::MASK_LINK, 0x1),
            (event::MASK_ADDR, 0x1004),
            (event::MASK_MTU, 0x200),
            (event::ID_UP, 1),
            (event::ID_DOWN, 2),
            (event::ID_RECONFIGURED, 3),
            (event::ID_NEW_ADDR, 0xb),
            (event::ID_DEL_ADDR, 0xc),
            (event::ID_USER_CMD, 0xf),
            (event::ID_MTU_UPDATE, 0x10),
            (event::KIND_UP, 1),
            (event::KIND_DOWN, 2),
            (event::KIND_RECONFIGURED, 5),
            (event::KIND_NEW_ADDR, 7),
            (event::KIND_DEL_ADDR, 8),
            (event::KIND_MTU_UPDATE, 0x13),
            (event::RESTART_START, 0),
            (event::RESTART_DONE, 2),
            (LOOKUP_ROUTE, 5),
            (LOOKUP_MATCHING_CALL, 0xb),
        ];
        for (got, want) in words {
            assert_eq!(got, want);
        }
        assert_eq!((AF_INET, AF_INET6), (2, 10));
        assert_eq!(TECH_DEFAULT, 0x8880);
    }

    #[test]
    fn the_readers_and_writers_refuse_what_does_not_fit() {
        let mut b = [0u8; 4];
        assert!(!wr_u32(&mut b, 1, 7));
        assert!(!wr_u32(&mut b, usize::MAX, 7));
        assert!(wr_u32(&mut b, 0, 0x0102_0304));
        assert_eq!(rd_u32(&b, 0), Some(0x0102_0304));
        assert_eq!(rd_u32(&b, 1), None);
        assert_eq!(rd_u64(&b, 0), None);
        assert_eq!(rd_u16(&b, usize::MAX), None);
        assert_eq!(rd_u8(&b, 4), None);
    }
}
