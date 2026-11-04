// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Messages of the modem that pass the framing: a message ID a parser reads, its tags with values of the right and
//! the wrong shape, then every parser.
#![no_main]
use dataos_fuzz::{encode, messages, tlvs, Input};
use dataos_qmi::dfs;
use dataos_qmi::frame::Frame;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut inp = Input(data);
    let Some(m) = messages::ALL.get(inp.below(messages::ALL.len())) else {
        return;
    };
    let kind = if inp.one_in(16) { inp.u8() % 6 } else { m.kind };
    let txn = inp.u16();
    let list = tlvs(&mut inp, m.tlvs, dfs::MAX_MESSAGE);
    let bytes = encode(kind, txn, m.id, &list);
    let f = Frame::parse_bounded(&bytes, dfs::MAX_MESSAGE);
    if matches!(kind, 0 | 2 | 4) {
        assert!(f.is_ok(), "a well framed message was refused: {f:?}");
    }
    if let Ok(f) = f {
        dataos_fuzz::parsers::run_all(&f);
    }
});
