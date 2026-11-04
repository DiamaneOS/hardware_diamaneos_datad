// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Any datagram from the modem: the framing of QMI over QRTR, then every parser of a message.
#![no_main]
use dataos_fuzz::encode;
use dataos_qmi::dfs;
use dataos_qmi::frame::{Frame, MAX_DATAGRAM};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let plain = Frame::parse(data);
    let wide = Frame::parse_bounded(data, dfs::MAX_MESSAGE);
    if plain.is_ok() {
        assert!(
            wide.is_ok(),
            "a frame within the smaller bound fails the larger one"
        );
        assert!(data.len() <= MAX_DATAGRAM);
    }
    let Ok(f) = wide else {
        return;
    };
    // the TLV walk covers the body exactly, each tag once, and the frame encodes back to the same bytes
    let tlvs: Vec<(u8, Vec<u8>)> = f.tlvs().map(|(t, v)| (t, v.to_vec())).collect();
    for (i, (t, v)) in tlvs.iter().enumerate() {
        assert!(tlvs.iter().skip(i + 1).all(|(o, _)| o != t), "tag twice");
        assert_eq!(f.tlv(*t), Some(&v[..]));
    }
    let kind = data.first().copied().unwrap_or(0);
    assert_eq!(encode(kind, f.txn, f.id, &tlvs), data);
    dataos_fuzz::parsers::run_all(&f);
});
