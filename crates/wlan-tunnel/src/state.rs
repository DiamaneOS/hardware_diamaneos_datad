// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! What is installed in the kernel, as a small text file in the tmpfs directory of the daemon, so that a new
//! instance can remove what an old one left. It names states, policies and rules. It never holds a key.
use dataos_netcfg::rtnl_tunnel::Rule;
use dataos_netcfg::xfrm::{Dir, SaId, Selector, Side};
use std::net::IpAddr;

/// The most bytes and lines a file may have. Four links of two families each fit many times over.
pub const MAX_FILE: usize = 8192;
const MAX_LINES: usize = 64;
const HEADER: &str = "wlantunnel-state 1";

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Ledger {
    pub states: Vec<SaId>,
    pub policies: Vec<(Selector, Dir)>,
    pub rules: Vec<Rule>,
}

fn dir_name(d: Dir) -> &'static str {
    match d {
        Dir::In => "in",
        Dir::Out => "out",
        Dir::Fwd => "fwd",
    }
}

impl Ledger {
    pub fn is_empty(&self) -> bool {
        self.states.is_empty() && self.policies.is_empty() && self.rules.is_empty()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut t = String::from(HEADER);
        t.push('\n');
        for s in &self.states {
            t.push_str(&format!("sa {} {:x} {} {}\n", s.proto, s.spi, s.src, s.dst));
        }
        for (sel, dir) in &self.policies {
            let side = match sel.side {
                Side::Source => "src",
                Side::Destination => "dst",
            };
            t.push_str(&format!(
                "pol {} {side} {} {}\n",
                dir_name(*dir),
                sel.addr,
                sel.prefix
            ));
        }
        for r in &self.rules {
            t.push_str(&format!(
                "rule {} {:x} {:x} {}\n",
                r.family, r.mark, r.mask, r.table
            ));
        }
        t.into_bytes()
    }

    /// Read a file. Anything that is not exactly what `encode` writes is None, and the file is dropped.
    pub fn parse(bytes: &[u8]) -> Option<Ledger> {
        if bytes.len() > MAX_FILE {
            return None;
        }
        let text = std::str::from_utf8(bytes).ok()?;
        let body = text.strip_suffix('\n')?;
        let mut lines = body.split('\n');
        if lines.next()? != HEADER {
            return None;
        }
        let mut out = Ledger::default();
        for (n, line) in lines.enumerate() {
            if n >= MAX_LINES {
                return None;
            }
            let words: Vec<&str> = line.split(' ').collect();
            match words.as_slice() {
                ["sa", proto, spi, src, dst] => {
                    let (src, dst): (IpAddr, IpAddr) = (src.parse().ok()?, dst.parse().ok()?);
                    if src.is_ipv4() != dst.is_ipv4() {
                        return None;
                    }
                    out.states.push(SaId {
                        proto: proto.parse().ok()?,
                        spi: u32::from_str_radix(spi, 16).ok()?,
                        src,
                        dst,
                    });
                }
                ["pol", dir, side, addr, prefix] => {
                    let dir = match *dir {
                        "in" => Dir::In,
                        "out" => Dir::Out,
                        "fwd" => Dir::Fwd,
                        _ => return None,
                    };
                    let side = match *side {
                        "src" => Side::Source,
                        "dst" => Side::Destination,
                        _ => return None,
                    };
                    out.policies.push((
                        Selector {
                            addr: addr.parse().ok()?,
                            prefix: prefix.parse().ok()?,
                            side,
                        },
                        dir,
                    ));
                }
                ["rule", family, mark, mask, table] => out.rules.push(Rule {
                    family: family.parse().ok()?,
                    mark: u32::from_str_radix(mark, 16).ok()?,
                    mask: u32::from_str_radix(mask, 16).ok()?,
                    table: table.parse().ok()?,
                }),
                _ => return None,
            }
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Ledger {
        Ledger {
            states: vec![SaId {
                proto: 50,
                spi: 0xdead_beef,
                src: "192.0.2.1".parse().unwrap(),
                dst: "198.51.100.1".parse().unwrap(),
            }],
            policies: vec![
                (
                    Selector {
                        addr: "2001:db8::5".parse().unwrap(),
                        prefix: 64,
                        side: Side::Source,
                    },
                    Dir::Out,
                ),
                (
                    Selector {
                        addr: "2001:db8::5".parse().unwrap(),
                        prefix: 64,
                        side: Side::Destination,
                    },
                    Dir::Fwd,
                ),
            ],
            rules: vec![Rule {
                family: 2,
                mark: 0x20000,
                mask: 0xfffff,
                table: 1030,
            }],
        }
    }

    #[test]
    fn a_file_round_trips() {
        let l = sample();
        assert!(Ledger::parse(&l.encode()) == Some(l));
        let empty = Ledger::default();
        assert!(empty.is_empty());
        assert!(Ledger::parse(&empty.encode()) == Some(empty));
    }

    #[test]
    fn a_corrupt_file_is_refused() {
        let good = String::from_utf8(sample().encode()).unwrap();
        let cases = [
            String::new(),
            "wlantunnel-state 2\n".to_string(),
            good.replace("sa 50", "sa 500"),
            good.replace("sa 50", "sa"),
            good.replace("deadbeef", "xyz"),
            good.replace("192.0.2.1", "192.0.2"),
            good.replace("198.51.100.1", "2001:db8::9"),
            good.replace("pol out", "pol up"),
            good.replace("src", "left"),
            good.replace("rule 2", "rule x"),
            good.trim_end().to_string(),
            format!("{good}junk\n"),
            format!("{good}\n"),
        ];
        for bad in cases {
            assert!(Ledger::parse(bad.as_bytes()).is_none(), "{bad:?}");
        }
        assert!(Ledger::parse(&[0xff, 0xfe]).is_none());
        assert!(Ledger::parse(&vec![b'a'; MAX_FILE + 1]).is_none());
        let long = format!("{HEADER}\n{}", "rule 2 1 1 1\n".repeat(MAX_LINES + 1));
        assert!(Ledger::parse(long.as_bytes()).is_none());
    }

    #[test]
    fn any_bytes_are_safe() {
        let mut x = 0xabcd_ef01_2345_6789u64;
        let good = sample().encode();
        for _ in 0..5_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let mut b = good.clone();
            let at = (x % b.len() as u64) as usize;
            b[at] = (x >> 40) as u8;
            let _ = Ledger::parse(&b);
        }
    }
}
