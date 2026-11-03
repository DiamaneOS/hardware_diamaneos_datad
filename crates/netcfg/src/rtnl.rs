// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! rtnetlink message builders for the operations a data call needs. Pure byte
//! building, host endianness as the kernel expects. Kernel UAPI constants:
//! linux/netlink.h, linux/rtnetlink.h, linux/if_link.h, linux/if_addr.h.
//! The rmnet attributes are the ones of the rmnet driver (mux ID and flags).
use std::net::IpAddr;

pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLM_F_REQUEST: u16 = 0x1;
pub const NLM_F_ACK: u16 = 0x4;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;

pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;

const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_LINK: u16 = 5;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const IFLA_RMNET_MUX_ID: u16 = 1;
const IFLA_RMNET_FLAGS: u16 = 2;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_FLAGS: u16 = 8;

pub const IFF_UP: u32 = 1;
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

pub const IFA_F_NODAD: u32 = 0x02;
pub const IFA_F_NOPREFIXROUTE: u32 = 0x200;

/// Longest interface name the kernel accepts, without the terminating NUL.
pub const IFNAME_MAX: usize = 15;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    BadName,
    BadPrefix,
    FamilyMismatch,
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

pub(crate) struct Msg {
    buf: Vec<u8>,
}

impl Msg {
    pub(crate) fn new(ty: u16, flags: u16, seq: u32) -> Self {
        Self::sized(ty, flags, seq, 128)
    }

    /// A message with room for this many bytes from the start.
    pub(crate) fn sized(ty: u16, flags: u16, seq: u32, room: usize) -> Self {
        let mut buf = Vec::with_capacity(room);
        buf.extend_from_slice(&0u32.to_ne_bytes()); // length, patched in finish
        buf.extend_from_slice(&ty.to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // port ID, kernel fills
        Msg { buf }
    }

    pub(crate) fn raw(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    /// Open a nested attribute. Returns the offset to pass to `end`.
    pub(crate) fn begin(&mut self, ty: u16) -> usize {
        let at = self.buf.len();
        self.buf.extend_from_slice(&0u16.to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        at
    }

    pub(crate) fn end(&mut self, at: usize) {
        let len = u16::try_from(self.buf.len().saturating_sub(at)).unwrap_or(u16::MAX);
        if let Some(dst) = self.buf.get_mut(at..at.saturating_add(2)) {
            dst.copy_from_slice(&len.to_ne_bytes());
        }
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
    }

    pub(crate) fn attr(&mut self, ty: u16, payload: &[u8]) {
        let at = self.begin(ty);
        self.buf.extend_from_slice(payload);
        self.end(at);
    }

    pub(crate) fn finish(mut self) -> Vec<u8> {
        let len = u32::try_from(self.buf.len()).unwrap_or(u32::MAX);
        if let Some(dst) = self.buf.get_mut(0..4) {
            dst.copy_from_slice(&len.to_ne_bytes());
        }
        self.buf
    }
}

fn ifinfomsg(index: i32, flags: u32, change: u32) -> [u8; 16] {
    let mut b = [0u8; 16];
    // family, pad, type(2) stay zero
    b[4..8].copy_from_slice(&index.to_ne_bytes());
    b[8..12].copy_from_slice(&flags.to_ne_bytes());
    b[12..16].copy_from_slice(&change.to_ne_bytes());
    b
}

pub(crate) fn name_attr(name: &str) -> Result<Vec<u8>, BuildError> {
    let b = name.as_bytes();
    if b.is_empty()
        || b.len() > IFNAME_MAX
        || !b
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-')
    {
        return Err(BuildError::BadName);
    }
    let mut v = b.to_vec();
    v.push(0);
    Ok(v)
}

/// rmnet flags: the `ifla_rmnet_flags` pair (flags, mask).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct RmnetFlagsRaw {
    pub flags: u32,
    pub mask: u32,
}

/// RTM_NEWLINK creating an rmnet virtual device on top of `parent_index`.
pub fn new_rmnet_link(
    seq: u32,
    parent_index: i32,
    name: &str,
    mux_id: u16,
    flags: RmnetFlagsRaw,
) -> Result<Vec<u8>, BuildError> {
    let mut m = Msg::new(
        RTM_NEWLINK,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        seq,
    );
    m.raw(&ifinfomsg(0, 0, 0));
    m.attr(IFLA_IFNAME, &name_attr(name)?);
    m.attr(IFLA_LINK, &parent_index.to_ne_bytes());
    let info = m.begin(IFLA_LINKINFO);
    m.attr(IFLA_INFO_KIND, b"rmnet\0");
    let data = m.begin(IFLA_INFO_DATA);
    m.attr(IFLA_RMNET_MUX_ID, &mux_id.to_ne_bytes());
    let mut f = [0u8; 8];
    f[..4].copy_from_slice(&flags.flags.to_ne_bytes());
    f[4..].copy_from_slice(&flags.mask.to_ne_bytes());
    m.attr(IFLA_RMNET_FLAGS, &f);
    m.end(data);
    m.end(info);
    Ok(m.finish())
}

pub fn del_link(seq: u32, index: i32) -> Vec<u8> {
    let mut m = Msg::new(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, seq);
    m.raw(&ifinfomsg(index, 0, 0));
    m.finish()
}

/// RTM_DELLINK for the link with this name. The kernel looks the name up itself,
/// so no interface index is needed and a name that does not exist cannot make it
/// try to load a module (`dev_load()` does that for the ioctl lookup).
pub fn del_link_by_name(seq: u32, name: &str) -> Result<Vec<u8>, BuildError> {
    let mut m = Msg::new(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, seq);
    m.raw(&ifinfomsg(0, 0, 0));
    m.attr(IFLA_IFNAME, &name_attr(name)?);
    Ok(m.finish())
}

/// RTM_NEWLINK that sets the administrative state and optionally the MTU.
pub fn set_link(seq: u32, index: i32, up: bool, mtu: Option<u32>) -> Vec<u8> {
    let mut m = Msg::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, seq);
    m.raw(&ifinfomsg(index, if up { IFF_UP } else { 0 }, IFF_UP));
    if let Some(mtu) = mtu {
        m.attr(IFLA_MTU, &mtu.to_ne_bytes());
    }
    m.finish()
}

fn addr_message(
    ty: u16,
    flags: u16,
    seq: u32,
    index: i32,
    addr: IpAddr,
    prefix: u8,
    addr_flags: u32,
) -> Result<Vec<u8>, BuildError> {
    let (family, bytes, max): (u8, Vec<u8>, u8) = match addr {
        IpAddr::V4(a) => (AF_INET, a.octets().to_vec(), 32),
        IpAddr::V6(a) => (AF_INET6, a.octets().to_vec(), 128),
    };
    if prefix > max {
        return Err(BuildError::BadPrefix);
    }
    let mut m = Msg::new(ty, flags, seq);
    let mut h = [0u8; 8];
    h[0] = family;
    h[1] = prefix;
    // flags byte left zero, the 32-bit IFA_FLAGS attribute carries them
    h[2] = 0;
    h[3] = 0; // RT_SCOPE_UNIVERSE
    h[4..8].copy_from_slice(&(index as u32).to_ne_bytes());
    m.raw(&h);
    m.attr(IFA_LOCAL, &bytes);
    m.attr(IFA_ADDRESS, &bytes);
    if addr_flags != 0 {
        m.attr(IFA_FLAGS, &addr_flags.to_ne_bytes());
    }
    Ok(m.finish())
}

pub fn add_addr(
    seq: u32,
    index: i32,
    addr: IpAddr,
    prefix: u8,
    addr_flags: u32,
) -> Result<Vec<u8>, BuildError> {
    addr_message(
        RTM_NEWADDR,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        seq,
        index,
        addr,
        prefix,
        addr_flags,
    )
}

pub fn del_addr(seq: u32, index: i32, addr: IpAddr, prefix: u8) -> Result<Vec<u8>, BuildError> {
    addr_message(
        RTM_DELADDR,
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
        index,
        addr,
        prefix,
        0,
    )
}

/// Result of reading one kernel reply datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ack {
    Ok,
    /// Positive errno value reported by the kernel.
    Errno(i32),
}

/// Parse a reply datagram that must hold an NLMSG_ERROR for `seq`.
pub fn parse_ack(buf: &[u8], seq: u32) -> Option<Ack> {
    if buf.len() < 20 {
        return None;
    }
    let len = u32::from_ne_bytes(buf[0..4].try_into().ok()?) as usize;
    let ty = u16::from_ne_bytes(buf[4..6].try_into().ok()?);
    let got_seq = u32::from_ne_bytes(buf[8..12].try_into().ok()?);
    if ty != NLMSG_ERROR || len < 20 || len > buf.len() || got_seq != seq {
        return None;
    }
    let err = i32::from_ne_bytes(buf[16..20].try_into().ok()?);
    Some(if err == 0 { Ack::Ok } else { Ack::Errno(-err) })
}

pub fn padded(n: usize) -> usize {
    align4(n)
}

#[cfg(test)]
pub(crate) mod testutil {
    /// Walk rtattrs after `skip` bytes of header and return (type, payload).
    pub fn attrs(buf: &[u8], skip: usize) -> Vec<(u16, Vec<u8>)> {
        let mut out = Vec::new();
        let mut at = skip;
        while at + 4 <= buf.len() {
            let len = u16::from_ne_bytes([buf[at], buf[at + 1]]) as usize;
            let ty = u16::from_ne_bytes([buf[at + 2], buf[at + 3]]);
            assert!(len >= 4 && at + len <= buf.len(), "attribute overruns");
            out.push((ty, buf[at + 4..at + len].to_vec()));
            at += (len + 3) & !3;
        }
        assert_eq!(at, buf.len(), "trailing bytes");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::attrs;
    use super::*;

    /// The message types the policy allows for the daemon's route socket (`datad.te`) are the ones this file
    /// sends, no more and no fewer. A new request here makes this fail until the policy has it.
    #[test]
    fn the_policy_allows_the_message_types_that_are_sent_and_no_other() {
        let code = include_str!("rtnl.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let mut sent: Vec<&str> = Vec::new();
        for line in code.lines().map(str::trim) {
            if line.starts_with("//") || line.starts_with("pub const") {
                continue;
            }
            for word in line.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
                if word.starts_with("RTM_") && !sent.contains(&word) {
                    sent.push(word);
                }
            }
        }
        sent.sort_unstable();
        let te = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../android/sepolicy/vendor/datad.te"
        ))
        .unwrap();
        let rule = te
            .lines()
            .find(|l| l.starts_with("allowxperm diamaneos_datad self:netlink_route_socket nlmsg {"))
            .unwrap();
        let inside = rule.split('{').nth(1).unwrap().split('}').next().unwrap();
        let mut allowed: Vec<&str> = inside.split_whitespace().collect();
        allowed.sort_unstable();
        assert!(!sent.is_empty());
        assert_eq!(sent, allowed);
    }

    fn hdr(buf: &[u8]) -> (u32, u16, u16, u32) {
        (
            u32::from_ne_bytes(buf[0..4].try_into().unwrap()),
            u16::from_ne_bytes(buf[4..6].try_into().unwrap()),
            u16::from_ne_bytes(buf[6..8].try_into().unwrap()),
            u32::from_ne_bytes(buf[8..12].try_into().unwrap()),
        )
    }

    #[test]
    fn rmnet_link_layout() {
        let m = new_rmnet_link(
            11,
            3,
            "rmnet_data0",
            1,
            RmnetFlagsRaw {
                flags: 0x1,
                mask: 0x1f,
            },
        )
        .unwrap();
        let (len, ty, flags, seq) = hdr(&m);
        assert_eq!(len as usize, m.len());
        assert_eq!(m.len() % 4, 0);
        assert_eq!(ty, RTM_NEWLINK);
        assert_eq!(flags, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
        assert_eq!(seq, 11);
        let a = attrs(&m, 32);
        assert_eq!(a[0], (IFLA_IFNAME, b"rmnet_data0\0".to_vec()));
        assert_eq!(a[1], (IFLA_LINK, 3i32.to_ne_bytes().to_vec()));
        assert_eq!(a[2].0, IFLA_LINKINFO);
        let nested = attrs(&a[2].1, 0);
        assert_eq!(nested[0], (IFLA_INFO_KIND, b"rmnet\0".to_vec()));
        assert_eq!(nested[1].0, IFLA_INFO_DATA);
        let data = attrs(&nested[1].1, 0);
        assert_eq!(data[0], (IFLA_RMNET_MUX_ID, 1u16.to_ne_bytes().to_vec()));
        assert_eq!(data[1].0, IFLA_RMNET_FLAGS);
        assert_eq!(data[1].1.len(), 8);
    }

    #[test]
    fn names_are_checked() {
        for bad in [
            "",
            "a/b",
            "name with space",
            "sixteen_chars_xx",
            "a\0b",
            "né",
        ] {
            assert_eq!(
                new_rmnet_link(1, 1, bad, 1, RmnetFlagsRaw::default()).unwrap_err(),
                BuildError::BadName,
                "{bad:?}"
            );
        }
        assert!(new_rmnet_link(1, 1, "fifteen_chars_x", 1, RmnetFlagsRaw::default()).is_ok());
    }

    #[test]
    fn delete_by_name_carries_the_name_and_no_index() {
        let m = del_link_by_name(8, "rmnet_data3").unwrap();
        let (len, ty, flags, seq) = hdr(&m);
        assert_eq!((len as usize, ty, seq), (m.len(), RTM_DELLINK, 8));
        assert_eq!(flags, NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(i32::from_ne_bytes(m[20..24].try_into().unwrap()), 0);
        assert_eq!(
            attrs(&m, 32),
            vec![(IFLA_IFNAME, b"rmnet_data3\0".to_vec())]
        );
        for bad in ["", "a/b", "sixteen_chars_xx"] {
            assert_eq!(del_link_by_name(1, bad).unwrap_err(), BuildError::BadName);
        }
    }

    #[test]
    fn set_link_up_with_mtu() {
        let m = set_link(5, 9, true, Some(1400));
        let (len, ty, _, _) = hdr(&m);
        assert_eq!((len as usize, ty), (m.len(), RTM_NEWLINK));
        assert_eq!(i32::from_ne_bytes(m[20..24].try_into().unwrap()), 9);
        assert_eq!(u32::from_ne_bytes(m[24..28].try_into().unwrap()), IFF_UP);
        assert_eq!(u32::from_ne_bytes(m[28..32].try_into().unwrap()), IFF_UP);
        assert_eq!(
            attrs(&m, 32),
            vec![(IFLA_MTU, 1400u32.to_ne_bytes().to_vec())]
        );
        let down = set_link(6, 9, false, None);
        assert_eq!(down.len(), 32);
        assert_eq!(u32::from_ne_bytes(down[24..28].try_into().unwrap()), 0);
    }

    #[test]
    fn address_messages() {
        let a: IpAddr = "192.0.2.10".parse().unwrap();
        let m = add_addr(1, 4, a, 30, 0).unwrap();
        assert_eq!(m[16], AF_INET);
        assert_eq!(m[17], 30);
        let at = attrs(&m, 24);
        assert_eq!(at[0], (IFA_LOCAL, vec![192, 0, 2, 10]));
        assert_eq!(at.len(), 2, "no flags attribute when flags are zero");

        let v6: IpAddr = "2001:db8:1:2::5".parse().unwrap();
        let m = add_addr(2, 4, v6, 64, IFA_F_NODAD | IFA_F_NOPREFIXROUTE).unwrap();
        assert_eq!(m[16], AF_INET6);
        let at = attrs(&m, 24);
        assert_eq!(at[2].0, IFA_FLAGS);
        assert_eq!(u32::from_ne_bytes(at[2].1[..4].try_into().unwrap()), 0x202);

        assert_eq!(add_addr(1, 1, a, 33, 0).unwrap_err(), BuildError::BadPrefix);
        assert_eq!(
            add_addr(1, 1, v6, 129, 0).unwrap_err(),
            BuildError::BadPrefix
        );
        let d = del_addr(3, 4, a, 30).unwrap();
        assert_eq!(hdr(&d).1, RTM_DELADDR);
    }

    #[test]
    fn ack_parsing() {
        let mut ok = vec![0u8; 36];
        ok[0..4].copy_from_slice(&36u32.to_ne_bytes());
        ok[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        ok[8..12].copy_from_slice(&7u32.to_ne_bytes());
        assert_eq!(parse_ack(&ok, 7), Some(Ack::Ok));
        assert_eq!(parse_ack(&ok, 8), None, "wrong sequence");
        ok[16..20].copy_from_slice(&(-17i32).to_ne_bytes());
        assert_eq!(parse_ack(&ok, 7), Some(Ack::Errno(17)));
        assert_eq!(parse_ack(&ok[..10], 7), None);
    }
}
