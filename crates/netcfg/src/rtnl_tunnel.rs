// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The route socket messages of the Wi-Fi tunnel daemon: its policy rule, and the dump of the interface addresses
//! that tells which interface has a tunnel's local address. In a file of their own, because the
//! messages of `rtnl.rs` are held to the policy of the data daemon, which allows none of these.
use crate::rtnl::{
    padded, BuildError, Msg, AF_INET, AF_INET6, NLMSG_DONE, NLMSG_ERROR, NLM_F_ACK, NLM_F_CREATE,
    NLM_F_EXCL, NLM_F_REQUEST,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const RTM_NEWADDR: u16 = 20;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWRULE: u16 = 32;
pub const RTM_DELRULE: u16 = 33;
const NLM_F_DUMP: u16 = 0x300;

const FRA_PRIORITY: u16 = 6;
const FRA_FWMARK: u16 = 10;
const FRA_TABLE: u16 = 15;
const FRA_FWMASK: u16 = 16;
/// `FR_ACT_TO_TBL`, in the last byte of the header.
const ACTION_TO_TABLE: u8 = 1;
/// `RTPROT_BOOT`, in the byte of the header where `rtmsg` has its protocol.
const PROTOCOL_BOOT: u8 = 3;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;

/// The priority of the rule of a tunnel.
pub const RULE_PRIORITY: u32 = 9999;

/// One rule: packets with this mark look in this table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    pub family: u8,
    pub mark: u32,
    pub mask: u32,
    pub table: u32,
}

fn rule_message(ty: u16, flags: u16, seq: u32, r: &Rule) -> Result<Vec<u8>, BuildError> {
    if r.family != AF_INET && r.family != AF_INET6 {
        return Err(BuildError::FamilyMismatch);
    }
    let mut m = Msg::new(ty, flags, seq);
    let mut h = [0u8; 12];
    h[0] = r.family;
    h[5] = PROTOCOL_BOOT;
    h[7] = ACTION_TO_TABLE;
    m.raw(&h);
    m.attr(FRA_PRIORITY, &RULE_PRIORITY.to_ne_bytes());
    m.attr(FRA_FWMARK, &r.mark.to_ne_bytes());
    m.attr(FRA_FWMASK, &r.mask.to_ne_bytes());
    m.attr(FRA_TABLE, &r.table.to_ne_bytes());
    Ok(m.finish())
}

pub fn new_rule(seq: u32, r: &Rule) -> Result<Vec<u8>, BuildError> {
    rule_message(
        RTM_NEWRULE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        seq,
        r,
    )
}

pub fn del_rule(seq: u32, r: &Rule) -> Result<Vec<u8>, BuildError> {
    rule_message(RTM_DELRULE, NLM_F_REQUEST | NLM_F_ACK, seq, r)
}

/// The dump of the addresses of one family.
pub fn get_addrs(seq: u32, family: u8) -> Vec<u8> {
    let mut m = Msg::new(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, seq);
    m.raw(&[family, 0, 0, 0, 0, 0, 0, 0]);
    m.finish()
}

/// An address of an interface. No derived Debug.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IfAddr {
    pub index: i32,
    pub addr: IpAddr,
}

impl std::fmt::Debug for IfAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IfAddr")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

/// How a datagram of a dump ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DumpStep {
    More,
    Done,
    Failed(i32),
}

fn one_addr(payload: &[u8]) -> Option<IfAddr> {
    let family = *payload.first()?;
    let index = i32::from_ne_bytes(payload.get(4..8)?.try_into().ok()?);
    let (mut local, mut address) = (None, None);
    let mut rest = payload.get(8..)?;
    while rest.len() >= 4 {
        let n = usize::from(u16::from_ne_bytes(rest.get(0..2)?.try_into().ok()?));
        let kind = u16::from_ne_bytes(rest.get(2..4)?.try_into().ok()?);
        let value = rest.get(4..n)?;
        match kind {
            IFA_LOCAL => local = Some(value),
            IFA_ADDRESS => address = Some(value),
            _ => {}
        }
        rest = rest.get(padded(n)..)?;
    }
    let bytes = local.or(address)?;
    let addr = match family {
        AF_INET => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?)),
        AF_INET6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?)),
        _ => return None,
    };
    Some(IfAddr { index, addr })
}

/// Read one datagram of the dump with this sequence number into `out`, at most `max` entries in all.
pub fn parse_addrs(mut buf: &[u8], seq: u32, out: &mut Vec<IfAddr>, max: usize) -> DumpStep {
    while buf.len() >= 16 {
        let word = |at: usize| {
            buf.get(at..at.saturating_add(4))
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map(u32::from_ne_bytes)
        };
        let half = |at: usize| {
            buf.get(at..at.saturating_add(2))
                .and_then(|b| <[u8; 2]>::try_from(b).ok())
                .map(u16::from_ne_bytes)
        };
        let (Some(len), Some(ty), Some(got)) = (word(0), half(4), word(8)) else {
            return DumpStep::Failed(0);
        };
        let Some(len) = usize::try_from(len).ok().filter(|n| *n >= 16) else {
            return DumpStep::Failed(0);
        };
        let Some(payload) = buf.get(16..len) else {
            return DumpStep::Failed(0);
        };
        if got == seq {
            match ty {
                NLMSG_DONE => return DumpStep::Done,
                NLMSG_ERROR => {
                    let e = payload
                        .get(..4)
                        .and_then(|b| <[u8; 4]>::try_from(b).ok())
                        .map_or(0, i32::from_ne_bytes);
                    return DumpStep::Failed(e.saturating_neg());
                }
                RTM_NEWADDR if out.len() < max => {
                    if let Some(a) = one_addr(payload) {
                        out.push(a);
                    }
                }
                _ => {}
            }
        }
        let Some(after) = buf.get(padded(len)..) else {
            return DumpStep::More;
        };
        buf = after;
    }
    DumpStep::More
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtnl::testutil::attrs;

    fn rule() -> Rule {
        Rule {
            family: AF_INET6,
            mark: 0x20000,
            mask: 0xfffff,
            table: 1030,
        }
    }

    /// The message types the policy allows for the tunnel daemon are what the code sends, no more and no fewer.
    #[test]
    fn the_policy_allows_the_message_types_that_are_sent_and_no_other() {
        let te = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../android/sepolicy/vendor/wlantunnel.te"
        ))
        .unwrap();
        let allowed = |rule: &str| -> Vec<String> {
            let line = te.lines().find(|l| l.starts_with(rule)).unwrap();
            let inside = line.split('{').nth(1).unwrap().split('}').next().unwrap();
            let mut v: Vec<String> = inside.split_whitespace().map(str::to_owned).collect();
            v.sort();
            v
        };
        assert_eq!(
            allowed("allowxperm diamaneos_wlantunnel self:netlink_route_socket nlmsg {"),
            ["RTM_DELRULE", "RTM_GETADDR", "RTM_NEWLINK", "RTM_NEWRULE"]
        );
        assert_eq!(
            allowed("allowxperm diamaneos_wlantunnel self:netlink_xfrm_socket nlmsg {"),
            [
                "XFRM_MSG_DELPOLICY",
                "XFRM_MSG_DELSA",
                "XFRM_MSG_NEWPOLICY",
                "XFRM_MSG_NEWSA"
            ]
        );
        // the numbers of the file that builds them, and only RTM_NEWLINK comes from `rtnl.rs`
        assert_eq!(
            (
                RTM_GETADDR,
                RTM_NEWRULE,
                RTM_DELRULE,
                crate::rtnl::RTM_NEWLINK
            ),
            (22, 32, 33, 16)
        );
        use crate::xfrm::*;
        assert_eq!(
            (
                XFRM_MSG_NEWSA,
                XFRM_MSG_DELSA,
                XFRM_MSG_NEWPOLICY,
                XFRM_MSG_DELPOLICY
            ),
            (0x10, 0x11, 0x13, 0x14)
        );
    }

    #[test]
    fn a_rule_has_the_header_and_attributes_of_a_tunnel() {
        let m = new_rule(4, &rule()).unwrap();
        assert_eq!(
            u32::from_ne_bytes(m[0..4].try_into().unwrap()) as usize,
            m.len()
        );
        assert_eq!(u16::from_ne_bytes(m[4..6].try_into().unwrap()), 32);
        assert_eq!(u16::from_ne_bytes(m[6..8].try_into().unwrap()), 0x605);
        let h = &m[16..28];
        assert_eq!(h, &[10, 0, 0, 0, 0, 3, 0, 1, 0, 0, 0, 0]);
        assert_eq!(
            attrs(&m, 28),
            vec![
                (6, 9999u32.to_ne_bytes().to_vec()),
                (10, 0x20000u32.to_ne_bytes().to_vec()),
                (16, 0xfffffu32.to_ne_bytes().to_vec()),
                (15, 1030u32.to_ne_bytes().to_vec()),
            ]
        );
        let d = del_rule(5, &rule()).unwrap();
        assert_eq!(u16::from_ne_bytes(d[4..6].try_into().unwrap()), 33);
        assert_eq!(u16::from_ne_bytes(d[6..8].try_into().unwrap()), 5);
        let mut bad = rule();
        bad.family = 9;
        assert!(new_rule(1, &bad).is_err());
    }

    #[test]
    fn the_dump_asks_for_one_family() {
        let m = get_addrs(3, AF_INET);
        assert_eq!(m.len(), 24);
        assert_eq!(u16::from_ne_bytes(m[4..6].try_into().unwrap()), 22);
        assert_eq!(u16::from_ne_bytes(m[6..8].try_into().unwrap()), 0x301);
        assert_eq!(m[16], AF_INET);
    }

    fn addr_msg(seq: u32, family: u8, index: i32, attr: &[(u16, &[u8])]) -> Vec<u8> {
        let mut m = vec![0u8; 16];
        m[4..6].copy_from_slice(&RTM_NEWADDR.to_ne_bytes());
        m[8..12].copy_from_slice(&seq.to_ne_bytes());
        m.extend([family, 64, 0, 0]);
        m.extend(index.to_ne_bytes());
        for (ty, v) in attr {
            m.extend(((v.len() + 4) as u16).to_ne_bytes());
            m.extend(ty.to_ne_bytes());
            m.extend(*v);
            while !m.len().is_multiple_of(4) {
                m.push(0);
            }
        }
        let n = m.len() as u32;
        m[0..4].copy_from_slice(&n.to_ne_bytes());
        m
    }

    fn done(seq: u32) -> Vec<u8> {
        let mut m = vec![0u8; 20];
        m[0..4].copy_from_slice(&20u32.to_ne_bytes());
        m[4..6].copy_from_slice(&NLMSG_DONE.to_ne_bytes());
        m[8..12].copy_from_slice(&seq.to_ne_bytes());
        m
    }

    #[test]
    fn the_local_address_wins_and_ipv6_has_only_the_address() {
        let v4 = addr_msg(
            1,
            AF_INET,
            3,
            &[(IFA_ADDRESS, &[10, 0, 0, 9]), (IFA_LOCAL, &[192, 0, 2, 1])],
        );
        let a6: [u8; 16] = "2001:db8::5".parse::<Ipv6Addr>().unwrap().octets();
        let v6 = addr_msg(1, AF_INET6, 4, &[(IFA_ADDRESS, &a6)]);
        let mut buf = v4;
        buf.extend(&v6);
        let mut out = Vec::new();
        assert_eq!(parse_addrs(&buf, 1, &mut out, 8), DumpStep::More);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].index, 3);
        assert_eq!(out[0].addr, "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(out[1].addr, "2001:db8::5".parse::<IpAddr>().unwrap());
        assert_eq!(parse_addrs(&done(1), 1, &mut out, 8), DumpStep::Done);
    }

    #[test]
    fn the_list_is_bounded_and_other_sequences_are_skipped() {
        let one = addr_msg(1, AF_INET, 3, &[(IFA_LOCAL, &[192, 0, 2, 1])]);
        let mut buf = Vec::new();
        for _ in 0..5 {
            buf.extend(&one);
        }
        let mut out = Vec::new();
        parse_addrs(&buf, 1, &mut out, 2);
        assert_eq!(out.len(), 2);
        let mut out = Vec::new();
        assert_eq!(parse_addrs(&buf, 9, &mut out, 8), DumpStep::More);
        assert!(out.is_empty());
    }

    #[test]
    fn errors_and_short_input_end_the_walk() {
        let mut e = vec![0u8; 36];
        e[0..4].copy_from_slice(&36u32.to_ne_bytes());
        e[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        e[8..12].copy_from_slice(&1u32.to_ne_bytes());
        e[16..20].copy_from_slice(&(-13i32).to_ne_bytes());
        let mut out = Vec::new();
        assert_eq!(parse_addrs(&e, 1, &mut out, 8), DumpStep::Failed(13));
        // a length that overruns, and one below the header
        let mut long = done(1);
        long[0..4].copy_from_slice(&999u32.to_ne_bytes());
        assert_eq!(parse_addrs(&long, 1, &mut out, 8), DumpStep::Failed(0));
        let mut small = done(1);
        small[0..4].copy_from_slice(&4u32.to_ne_bytes());
        assert_eq!(parse_addrs(&small, 1, &mut out, 8), DumpStep::Failed(0));
    }

    #[test]
    fn any_bytes_are_safe() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut byte = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        };
        for _ in 0..5_000 {
            let n = usize::from(byte()) % 64;
            let mut b: Vec<u8> = (0..n).map(|_| byte()).collect();
            if b.len() >= 8 {
                b[0] = n as u8;
                b[1] = 0;
                b[2] = 0;
                b[3] = 0;
                b[4] = 20;
                b[5] = 0;
            }
            let mut out = Vec::new();
            let _ = parse_addrs(&b, 0, &mut out, 8);
            let _ = one_addr(&b);
            let _ = crate::genl::parse_family(&b, 0);
        }
    }
}
