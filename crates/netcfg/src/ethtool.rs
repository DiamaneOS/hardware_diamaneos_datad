// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The device features through `SIOCETHTOOL`, the way stock nicmd sets them (`Nicm::Ethtool::setFeature`): the
//! names of the features come from the kernel (`ETHTOOL_GSSET_INFO` and `ETHTOOL_GSTRINGS` for `ETH_SS_FEATURES`),
//! the bit of each name is its place in that list, `ETHTOOL_SFEATURES` asks for the bits, and `ETHTOOL_GFEATURES`
//! says what is active afterwards. Byte layouts are those of `linux/ethtool.h` (UAPI, facts only).
//!
//! The kernel changes the set after the request: a feature the device does not offer stays off, and `rx-gro-hw` is
//! dropped when `rx-checksum` is off. So the request is never taken for done. The active set is read back.
//!
//! The requests are made with a closure that does the `ioctl`, so the order of the requests and the reading of the
//! answers run in host tests against a model of the kernel.

use crate::ops::NetError;

/// `SIOCETHTOOL`.
pub const SIOCETHTOOL: u32 = 0x0000_8946;
const ETHTOOL_GSSET_INFO: u32 = 0x37;
const ETHTOOL_GSTRINGS: u32 = 0x1b;
const ETHTOOL_GFEATURES: u32 = 0x3a;
const ETHTOOL_SFEATURES: u32 = 0x3b;
/// `ETH_SS_FEATURES`, the string set of the feature names.
const ETH_SS_FEATURES: u32 = 4;
/// `ETH_GSTRING_LEN`.
const GSTRING_LEN: usize = 32;
/// The most feature names asked for. The kernel has a few dozen, so more than this is not an answer.
pub const MAX_FEATURES: usize = 256;
/// Features in one block of `ethtool_get_features_block`.
const PER_BLOCK: usize = 32;

fn put(b: &mut [u8], at: usize, v: u32) {
    if let Some(d) = b.get_mut(at..at + 4) {
        d.copy_from_slice(&v.to_ne_bytes());
    }
}

fn get(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .and_then(|d| <[u8; 4]>::try_from(d).ok())
        .map_or(0, u32::from_ne_bytes)
}

/// `struct ethtool_sset_info` for one set: command, reserved, the mask of the sets asked about, and room for
/// the one length it answers with.
fn sset_info_request() -> [u8; 20] {
    let mut b = [0u8; 20];
    put(&mut b, 0, ETHTOOL_GSSET_INFO);
    b[8..16].copy_from_slice(&(1u64 << ETH_SS_FEATURES).to_ne_bytes());
    b
}

/// The number of feature names, from the answer to `sset_info_request`. None: the device does not have the set.
fn feature_count(reply: &[u8; 20]) -> Option<usize> {
    let mask = u64::from_ne_bytes(<[u8; 8]>::try_from(reply.get(8..16)?).ok()?);
    if mask & (1u64 << ETH_SS_FEATURES) == 0 {
        return None;
    }
    let n = usize::try_from(get(reply, 16)).ok()?;
    (n > 0 && n <= MAX_FEATURES).then_some(n)
}

/// `struct ethtool_gstrings` for the feature names, with room for `count` strings.
fn strings_request(count: usize) -> Vec<u8> {
    let mut b = vec![0u8; 12 + count * GSTRING_LEN];
    put(&mut b, 0, ETHTOOL_GSTRINGS);
    put(&mut b, 4, ETH_SS_FEATURES);
    put(&mut b, 8, u32::try_from(count).unwrap_or(0));
    b
}

/// The place of a name in the list of feature names, which is its bit.
fn index_of(strings: &[u8], count: usize, name: &str) -> Option<usize> {
    (0..count).find(|i| {
        let at = 12 + i * GSTRING_LEN;
        let Some(s) = strings.get(at..at + GSTRING_LEN) else {
            return false;
        };
        let end = s.iter().position(|c| *c == 0).unwrap_or(GSTRING_LEN);
        s.get(..end) == Some(name.as_bytes())
    })
}

fn blocks_for(count: usize) -> usize {
    count.div_ceil(PER_BLOCK)
}

/// `struct ethtool_gfeatures` with room for `blocks` blocks of four words.
fn get_features_request(blocks: usize) -> Vec<u8> {
    let mut b = vec![0u8; 8 + blocks * 16];
    put(&mut b, 0, ETHTOOL_GFEATURES);
    put(&mut b, 4, u32::try_from(blocks).unwrap_or(0));
    b
}

/// Is the feature at this place active, in the answer to `get_features_request`?
fn is_active(reply: &[u8], index: usize) -> bool {
    let block = index / PER_BLOCK;
    get(reply, 8 + block * 16 + 8) & (1u32 << (index % PER_BLOCK)) != 0
}

/// `struct ethtool_sfeatures`: for each block the bits that are asked about (`valid`) and the value asked for.
/// Every place in `wanted` is both valid and on, no other bit is asked about.
fn set_features_request(blocks: usize, wanted: &[usize]) -> Vec<u8> {
    let mut b = vec![0u8; 8 + blocks * 8];
    put(&mut b, 0, ETHTOOL_SFEATURES);
    put(&mut b, 4, u32::try_from(blocks).unwrap_or(0));
    for i in wanted {
        let at = 8 + (i / PER_BLOCK) * 8;
        let bit = 1u32 << (i % PER_BLOCK);
        let (valid, requested) = (get(&b, at) | bit, get(&b, at + 4) | bit);
        put(&mut b, at, valid);
        put(&mut b, at + 4, requested);
    }
    b
}

/// Ask for the features in `wanted` and say which of them are not active afterwards. `ioctl` makes one
/// `SIOCETHTOOL` request with the buffer it is given and leaves the answer in the same buffer.
pub fn enable(
    wanted: &[&str],
    ioctl: &mut dyn FnMut(&mut [u8]) -> Result<(), NetError>,
) -> Result<Vec<String>, NetError> {
    let mut info = sset_info_request();
    ioctl(&mut info)?;
    let count = feature_count(&info).ok_or(NetError::Invalid)?;
    let mut strings = strings_request(count);
    ioctl(&mut strings)?;
    let places: Vec<(&str, Option<usize>)> = wanted
        .iter()
        .map(|n| (*n, index_of(&strings, count, n)))
        .collect();
    let blocks = blocks_for(count);
    let known: Vec<usize> = places.iter().filter_map(|p| p.1).collect();
    let mut set = set_features_request(blocks, &known);
    ioctl(&mut set)?;
    let mut got = get_features_request(blocks);
    ioctl(&mut got)?;
    Ok(places
        .into_iter()
        .filter(|(_, at)| !at.is_some_and(|i| is_active(&got, i)))
        .map(|(n, _)| n.to_string())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `netdev_features_strings` of the 6.18 tree (`net/ethtool/common.c`, by the bit numbers of
    /// `include/linux/netdev_features.h`): 64 places in two blocks of 32, the unused bits empty. The second block
    /// holds `tx-udp-segmentation` (33), `rx-checksum` (40) and `rx-gro-hw` (55), three of the twelve features the
    /// daemon asks for. Copied from the tree of the build, 6.18.
    const NAMES: [&str; 64] = [
        "tx-scatter-gather",
        "tx-checksum-ipv4",
        "",
        "tx-checksum-ip-generic",
        "tx-checksum-ipv6",
        "highdma",
        "tx-scatter-gather-fraglist",
        "tx-vlan-hw-insert",
        "rx-vlan-hw-parse",
        "rx-vlan-filter",
        "vlan-challenged",
        "tx-generic-segmentation",
        "",
        "",
        "rx-gro",
        "rx-lro",
        "tx-tcp-segmentation",
        "tx-gso-robust",
        "tx-tcp-ecn-segmentation",
        "tx-tcp-mangleid-segmentation",
        "tx-tcp6-segmentation",
        "tx-fcoe-segmentation",
        "tx-gre-segmentation",
        "tx-gre-csum-segmentation",
        "tx-ipxip4-segmentation",
        "tx-ipxip6-segmentation",
        "tx-udp_tnl-segmentation",
        "tx-udp_tnl-csum-segmentation",
        "tx-gso-partial",
        "tx-tunnel-remcsum-segmentation",
        "tx-sctp-segmentation",
        "tx-esp-segmentation",
        "",
        "tx-udp-segmentation",
        "tx-gso-list",
        "tx-tcp-accecn-segmentation",
        "tx-checksum-fcoe-crc",
        "tx-checksum-sctp",
        "rx-ntuple-filter",
        "rx-hashing",
        "rx-checksum",
        "tx-nocache-copy",
        "loopback",
        "rx-fcs",
        "rx-all",
        "tx-vlan-stag-hw-insert",
        "rx-vlan-stag-hw-parse",
        "rx-vlan-stag-filter",
        "l2-fwd-offload",
        "hw-tc-offload",
        "esp-hw-offload",
        "esp-tx-csum-hw-offload",
        "rx-udp_tunnel-port-offload",
        "tls-hw-tx-offload",
        "tls-hw-rx-offload",
        "rx-gro-hw",
        "tls-hw-record",
        "rx-gro-list",
        "macsec-hw-offload",
        "rx-udp-gro-forwarding",
        "hsr-tag-ins-offload",
        "hsr-tag-rm-offload",
        "hsr-fwd-offload",
        "hsr-dup-offload",
    ];

    fn bit(name: &str) -> u64 {
        1u64 << NAMES.iter().position(|n| *n == name).unwrap()
    }

    /// The kernel as far as these requests go: the table of names above, the features the device offers (the soft
    /// ones are always there), the ones asked for, and the rule that `rx-gro-hw` is not active without
    /// `rx-checksum`. The answer to `ETHTOOL_GFEATURES` has the four words of each block, `available`, `requested`,
    /// `active` and `never_changed`, as the kernel writes them, so a request that reads the wrong word is wrong.
    struct Kernel {
        avail: u64,
        wanted: u64,
        requests: Vec<u32>,
    }

    impl Kernel {
        fn new(offered: &[&str]) -> Self {
            let soft = bit("tx-generic-segmentation") | bit("rx-gro");
            Kernel {
                avail: soft | offered.iter().fold(0, |m, f| m | bit(f)),
                wanted: soft,
                requests: Vec::new(),
            }
        }

        fn active(&self) -> u64 {
            let on = self.wanted & self.avail;
            if on & bit("rx-checksum") == 0 {
                on & !bit("rx-gro-hw")
            } else {
                on
            }
        }

        fn is_on(&self, name: &str) -> bool {
            self.active() & bit(name) != 0
        }

        fn answer(&mut self, b: &mut [u8]) -> Result<(), NetError> {
            let cmd = get(b, 0);
            self.requests.push(cmd);
            match cmd {
                ETHTOOL_GSSET_INFO => {
                    b[8..16].copy_from_slice(&(1u64 << ETH_SS_FEATURES).to_ne_bytes());
                    put(b, 16, NAMES.len() as u32);
                }
                ETHTOOL_GSTRINGS => {
                    assert_eq!(get(b, 4), ETH_SS_FEATURES);
                    assert_eq!(get(b, 8) as usize, NAMES.len());
                    for (i, n) in NAMES.iter().enumerate() {
                        b[12 + i * GSTRING_LEN..][..n.len()].copy_from_slice(n.as_bytes());
                    }
                }
                ETHTOOL_SFEATURES => {
                    // the kernel takes the request only with the size of its own list, two blocks
                    assert_eq!(get(b, 4), 2);
                    let (mut valid, mut requested) = (0u64, 0u64);
                    for blk in 0..2 {
                        valid |= u64::from(get(b, 8 + blk * 8)) << (32 * blk);
                        requested |= u64::from(get(b, 8 + blk * 8 + 4)) << (32 * blk);
                    }
                    let valid = valid & self.avail;
                    self.wanted = (self.wanted & !valid) | (requested & valid);
                }
                ETHTOOL_GFEATURES => {
                    assert_eq!(get(b, 4), 2);
                    let (avail, wanted, active) = (self.avail, self.wanted, self.active());
                    for blk in 0..2 {
                        let at = 8 + blk * 16;
                        put(b, at, (avail >> (32 * blk)) as u32);
                        put(b, at + 4, (wanted >> (32 * blk)) as u32);
                        put(b, at + 8, (active >> (32 * blk)) as u32);
                        put(b, at + 12, 0);
                    }
                }
                _ => return Err(NetError::Invalid),
            }
            Ok(())
        }
    }

    fn run(k: &mut Kernel, wanted: &[&str]) -> Result<Vec<String>, NetError> {
        enable(wanted, &mut |b| k.answer(b))
    }

    #[test]
    fn the_names_the_kernel_lists_are_asked_for_and_the_active_set_is_read_back() {
        let all = [
            "tx-checksum-ipv4",
            "tx-checksum-ipv6",
            "rx-checksum",
            "rx-gro-hw",
            "tx-scatter-gather",
        ];
        let mut k = Kernel::new(&all);
        let missing = run(&mut k, &all).unwrap();
        assert!(missing.is_empty(), "{missing:?}");
        for f in all {
            assert!(k.is_on(f), "{f}");
        }
        assert_eq!(
            k.requests,
            [
                ETHTOOL_GSSET_INFO,
                ETHTOOL_GSTRINGS,
                ETHTOOL_SFEATURES,
                ETHTOOL_GFEATURES
            ]
        );
    }

    /// The twelve features of stock are spread over both blocks of the 6.18 list, and the read-back has to
    /// find each in its own block.
    #[test]
    fn the_stock_set_is_read_back_from_both_blocks_of_the_list() {
        use crate::ops::STOCK_FEATURES;
        let place = |n: &str| NAMES.iter().position(|x| *x == n).unwrap();
        assert_eq!(
            (
                place("tx-udp-segmentation"),
                place("rx-checksum"),
                place("rx-gro-hw")
            ),
            (33, 40, 55)
        );
        assert!(STOCK_FEATURES.iter().any(|f| place(f) < 32));
        assert!(STOCK_FEATURES.iter().filter(|f| place(f) >= 32).count() >= 3);
        let mut k = Kernel::new(&STOCK_FEATURES);
        let missing = run(&mut k, &STOCK_FEATURES).unwrap();
        assert!(missing.is_empty(), "{missing:?}");
        // one feature of the second block that the device does not offer is the only one reported
        for gone in ["rx-gro-hw", "rx-checksum", "tx-udp-segmentation"] {
            let offered: Vec<&str> = STOCK_FEATURES
                .iter()
                .copied()
                .filter(|f| *f != gone)
                .collect();
            let mut k = Kernel::new(&offered);
            let missing = run(&mut k, &STOCK_FEATURES).unwrap();
            // rx-gro-hw is not active without rx-checksum either
            let want: Vec<&str> = if gone == "rx-checksum" {
                vec!["rx-checksum", "rx-gro-hw"]
            } else {
                vec![gone]
            };
            let mut missing = missing;
            missing.sort_unstable();
            assert_eq!(missing, want, "{gone}");
        }
    }

    #[test]
    fn a_feature_the_device_does_not_offer_or_the_kernel_does_not_know_is_reported() {
        let mut k = Kernel::new(&["tx-checksum-ipv4", "rx-checksum"]);
        let missing = run(
            &mut k,
            &[
                "tx-checksum-ipv4",
                "tx-checksum-ipv6",
                "no-such-feature",
                // the start of a name is not a name
                "tx-checksum",
                "rx-checksum",
            ],
        )
        .unwrap();
        assert_eq!(
            missing,
            ["tx-checksum-ipv6", "no-such-feature", "tx-checksum"]
        );
    }

    #[test]
    fn rx_gro_hw_is_dropped_by_the_kernel_without_rx_checksum_and_the_read_back_shows_it() {
        let mut k = Kernel::new(&["rx-gro-hw", "rx-checksum"]);
        // asked alone, it is taken at the request and gone when the kernel fixes the set. The offer and the
        // request say it is there, only the active word says it is not
        let missing = run(&mut k, &["rx-gro-hw"]).unwrap();
        assert_eq!(missing, ["rx-gro-hw"]);
        let missing = run(&mut k, &["rx-gro-hw", "rx-checksum"]).unwrap();
        assert!(missing.is_empty());
    }

    #[test]
    fn only_the_wanted_bits_are_asked_about() {
        let mut k = Kernel::new(&["tx-checksum-ipv4", "tx-nocache-copy"]);
        k.wanted |= bit("tx-nocache-copy");
        run(&mut k, &["tx-checksum-ipv4"]).unwrap();
        assert!(k.is_on("tx-nocache-copy"), "left as it was");
        assert!(k.is_on("rx-gro"), "so were the others");
        let req = set_features_request(2, &[0, 33]);
        assert_eq!(get(&req, 8), 1);
        assert_eq!(get(&req, 12), 1);
        assert_eq!(get(&req, 16), 2);
        assert_eq!(get(&req, 20), 2);
    }

    #[test]
    fn a_request_that_fails_ends_the_sequence_and_a_device_without_the_set_is_an_error() {
        let mut calls = 0;
        let r = enable(&["rx-gro-hw"], &mut |_| {
            calls += 1;
            Err(NetError::Os(95))
        });
        assert_eq!((r, calls), (Err(NetError::Os(95)), 1));
        // an answer that has no feature set, or an absurd number of names
        let r = enable(&["rx-gro-hw"], &mut |_| Ok(()));
        assert_eq!(r, Err(NetError::Invalid));
        let r = enable(&["rx-gro-hw"], &mut |b| {
            if get(b, 0) == ETHTOOL_GSSET_INFO {
                b[8..16].copy_from_slice(&(1u64 << ETH_SS_FEATURES).to_ne_bytes());
                put(b, 16, 100_000);
            }
            Ok(())
        });
        assert_eq!(r, Err(NetError::Invalid));
    }

    #[test]
    fn the_requests_have_the_layouts_of_the_header() {
        let info = sset_info_request();
        assert_eq!((get(&info, 0), info.len()), (0x37, 20));
        assert_eq!(u64::from_ne_bytes(info[8..16].try_into().unwrap()), 1 << 4);
        let s = strings_request(3);
        assert_eq!(
            (get(&s, 0), get(&s, 4), get(&s, 8), s.len()),
            (0x1b, 4, 3, 108)
        );
        let g = get_features_request(2);
        assert_eq!((get(&g, 0), get(&g, 4), g.len()), (0x3a, 2, 40));
        let f = set_features_request(2, &[]);
        assert_eq!((get(&f, 0), get(&f, 4), f.len()), (0x3b, 2, 24));
        assert_eq!(SIOCETHTOOL, 0x8946);
        assert_eq!(blocks_for(33), 2);
        assert_eq!(blocks_for(32), 1);
    }
}
