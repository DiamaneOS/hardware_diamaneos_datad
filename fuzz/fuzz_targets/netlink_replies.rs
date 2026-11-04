// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! What the kernel answers on a netlink socket: the acknowledgement of a request, the answer to a generic netlink
//! family lookup, and a datagram of an address dump.
#![no_main]
use dataos_fuzz::{nlattr, nlmsg, Input};
use dataos_netcfg::genl::{self, GENL_ID_CTRL};
use dataos_netcfg::rtnl::{self, Ack, AF_INET, AF_INET6, NLMSG_DONE, NLMSG_ERROR, RTM_NEWADDR};
use dataos_netcfg::rtnl_tunnel::{self, IfAddr};
use libfuzzer_sys::fuzz_target;

/// A datagram of whole netlink messages, most of them well formed, some for another request.
fn datagram(inp: &mut Input<'_>, seq: u32) -> Vec<u8> {
    let mut out = Vec::new();
    for _ in 0..1 + inp.below(6) {
        let ty = match inp.u8() % 8 {
            0 => NLMSG_ERROR,
            1 => NLMSG_DONE,
            2 | 3 => RTM_NEWADDR,
            4 | 5 => GENL_ID_CTRL,
            _ => inp.u16(),
        };
        let mut payload = match ty {
            NLMSG_ERROR => {
                let e: i32 = match inp.u8() % 4 {
                    0 => 0,
                    1 => i32::MIN,
                    _ => -i32::from(inp.u8()),
                };
                let mut p = e.to_ne_bytes().to_vec();
                // the request that failed, or part of it
                let n = usize::from(inp.u8() % 40);
                p.extend(inp.exact(n));
                p
            }
            RTM_NEWADDR => {
                let family = match inp.u8() % 4 {
                    0 => inp.u8(),
                    1 => AF_INET6,
                    _ => AF_INET,
                };
                let mut p = vec![family, inp.u8(), 0, 0];
                p.extend(inp.u32().to_ne_bytes());
                for _ in 0..inp.below(4) {
                    let kind = match inp.u8() % 4 {
                        0 => inp.u16(),
                        1 => 1,
                        _ => 2,
                    };
                    let n = match inp.u8() % 4 {
                        0 => usize::from(inp.u8() % 24),
                        1 => 16,
                        _ => 4,
                    };
                    let v = inp.exact(n);
                    let len = if inp.one_in(8) {
                        inp.u16()
                    } else {
                        (4 + n) as u16
                    };
                    p.extend(nlattr(len, kind, &v));
                }
                p
            }
            GENL_ID_CTRL => {
                let mut p = vec![1, 2, 0, 0];
                for _ in 0..inp.below(4) {
                    let kind = match inp.u8() % 4 {
                        0 => inp.u16(),
                        1 => 2,
                        _ => 1,
                    };
                    let n = match inp.u8() % 4 {
                        0 => usize::from(inp.u8() % 24),
                        _ => 2,
                    };
                    let v = inp.exact(n);
                    let len = if inp.one_in(8) {
                        inp.u16()
                    } else {
                        (4 + n) as u16
                    };
                    p.extend(nlattr(len, kind, &v));
                }
                p
            }
            _ => {
                let n = usize::from(inp.u8());
                inp.exact(n)
            }
        };
        let got = if inp.one_in(4) { inp.u32() } else { seq };
        let exact = 16 + payload.len() as u32;
        let len = match inp.u8() % 16 {
            0 => inp.u32(),
            1 => exact.saturating_sub(u32::from(inp.u8() % 20)),
            2 => exact.saturating_add(u32::from(inp.u8() % 20)),
            _ => exact,
        };
        while !payload.len().is_multiple_of(4) {
            payload.push(0);
        }
        out.extend(nlmsg(len, ty, 0, got, &payload));
    }
    if inp.one_in(8) {
        let n = out.len().saturating_sub(inp.below(32));
        out.truncate(n);
    }
    out
}

fn header(buf: &[u8]) -> Option<(u16, u32)> {
    let ty = u16::from_ne_bytes(buf.get(4..6)?.try_into().ok()?);
    let seq = u32::from_ne_bytes(buf.get(8..12)?.try_into().ok()?);
    Some((ty, seq))
}

fuzz_target!(|data: &[u8]| {
    let mut inp = Input(data);
    let seq = inp.u32();
    let max = inp.below(20);
    let buf = if inp.bool() {
        inp.0.to_vec()
    } else {
        datagram(&mut inp, seq)
    };

    let ack = rtnl::parse_ack(&buf, seq);
    if ack.is_some() {
        assert_eq!(header(&buf), Some((NLMSG_ERROR, seq)));
    }
    match (ack, genl::parse_family(&buf, seq)) {
        (Some(Ack::Errno(e)), f) => assert_eq!(f, Some(Err(e))),
        (Some(Ack::Ok), f) => assert_eq!(f, None),
        (None, Some(Err(_))) => panic!("an error that is no acknowledgement"),
        (None, Some(Ok(_))) => assert_eq!(header(&buf), Some((GENL_ID_CTRL, seq))),
        (None, None) => {}
    }

    // a dump read over several datagrams, as the tunnel daemon reads it
    let mut out: Vec<IfAddr> = Vec::new();
    for chunk in [&buf[..], &buf[..buf.len() / 2]] {
        let before = out.len();
        let _ = rtnl_tunnel::parse_addrs(chunk, seq, &mut out, max);
        assert!(out.len() >= before && out.len() <= max);
    }
});
