// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The `0x11c` indications of the modem, in any order and number, with the response that names their ID: each is
//! parsed, put together in `sa::Assembly`, and a whole answer is checked and turned into the two ESP states.
#![no_main]
use dataos_fuzz::{encode, messages, tlvs, value, Input, Shape, INDICATION};
use dataos_qmi::frame::{Frame, MAX_DATAGRAM};
use dataos_qmi::reverse::{self, id};
use dataos_wlan_tunnel::sa::{Added, Assembly};
use libfuzzer_sys::fuzz_target;

/// The head of a segment: mostly IDs and sizes that fit together.
fn head(inp: &mut Input<'_>, ids: &[u16]) -> Vec<u8> {
    if inp.one_in(8) {
        return value(inp, Shape::W(4));
    }
    let id = inp.pick(ids).unwrap_or(0);
    let size = match inp.u8() % 8 {
        0 => inp.u8(),
        n => n % 4,
    };
    let segment = match inp.u8() % 8 {
        0 => inp.u8(),
        n => n % 4,
    };
    let mut v = id.to_le_bytes().to_vec();
    v.extend([size, segment]);
    v
}

fuzz_target!(|data: &[u8]| {
    let mut inp = Input(data);
    let ids = [inp.u16(), inp.u16()];
    let mut a = Assembly::default();
    let mut expected: Option<u32> = None;
    for _ in 0..64 {
        if inp.is_empty() {
            break;
        }
        match inp.u8() % 8 {
            // the response, with the ID of the request
            0 => {
                let e = match inp.pick(&ids) {
                    Some(i) if !inp.one_in(8) => u32::from(i),
                    _ => inp.u32(),
                };
                a.expect(e);
                expected = Some(e);
            }
            // a segment
            _ => {
                let mut list = vec![(0x01, head(&mut inp, &ids))];
                for t in tlvs(&mut inp, messages::SA_SEGMENT, MAX_DATAGRAM - 10) {
                    if t.0 != 0x01 {
                        list.push(t);
                    }
                }
                let bytes = encode(INDICATION, 0, id::IPSEC_SA, &list);
                let Ok(f) = Frame::parse(&bytes) else {
                    continue;
                };
                let Ok(seg) = reverse::parse_sa_segment(&f) else {
                    continue;
                };
                let h = seg.head;
                let added = a.add(seg);
                match added {
                    Added::Complete => {
                        assert!(a.is_complete());
                        assert_eq!(expected, Some(u32::from(h.id)));
                        dataos_fuzz::esp::check(a.take_fields());
                        // the engine asks again for the next tunnel, with a new assembly
                        a = Assembly::default();
                        expected = None;
                    }
                    Added::Waiting => {
                        assert!(!a.is_complete());
                        assert_ne!(h.size, 0);
                        assert!(expected.is_none_or(|e| e == u32::from(h.id)));
                    }
                    Added::Dropped => {
                        assert!(!a.is_complete());
                        let left = a.take_fields();
                        assert!(
                            left.rx_spi.is_none()
                                && left.rx_crypt.is_none()
                                && left.remote.is_none()
                        );
                    }
                }
            }
        }
        if a.is_complete() {
            dataos_fuzz::esp::check(a.take_fields());
            a = Assembly::default();
            expected = None;
        }
    }
});
