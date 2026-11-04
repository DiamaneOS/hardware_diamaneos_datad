// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! What a driver writes back into an ioctl buffer: the ethtool feature sets, and the IPA endpoint numbers and pipe
//! statuses of `rmnet_ipa0`.
#![no_main]
use dataos_fuzz::Input;
use dataos_netcfg::ipa::{self, EGRESS_PARAM_LEN, EXT_LEN, INGRESS_PARAM_LEN};
use dataos_netcfg::{ethtool, NetError, STOCK_FEATURES};
use libfuzzer_sys::fuzz_target;

fn rc(inp: &mut Input<'_>) -> Result<(), NetError> {
    match inp.u8() % 8 {
        0 => Err(NetError::Os(1)),
        1 => Err(NetError::Os(i32::from(inp.u8()))),
        _ => Ok(()),
    }
}

fuzz_target!(|data: &[u8]| {
    let mut inp = Input(data);
    match inp.u8() % 3 {
        0 => {
            let wanted: Vec<&str> = STOCK_FEATURES
                .iter()
                .copied()
                .filter(|_| !inp.one_in(4))
                .collect();
            let mut calls = 0;
            let got = ethtool::enable(&wanted, &mut |buf: &mut [u8]| {
                calls += 1;
                assert!(calls <= 4, "more than four requests");
                if inp.one_in(16) {
                    return Err(NetError::Os(i32::from(inp.u8())));
                }
                // the driver writes anywhere in the buffer it was given, never past it
                match inp.u8() % 4 {
                    0 => {
                        for b in buf.iter_mut() {
                            *b = inp.u8();
                        }
                    }
                    _ => {
                        for _ in 0..inp.below(64) {
                            let at = inp.below(buf.len().max(1));
                            let v = inp.u8();
                            if let Some(b) = buf.get_mut(at) {
                                *b = v;
                            }
                        }
                        // the count of the feature set, where the first answer has it
                        if buf.len() == 20 && inp.bool() {
                            buf[8..16].copy_from_slice(&(1u64 << 4).to_ne_bytes());
                            let n = u32::from(inp.u16() % 300);
                            buf[16..20].copy_from_slice(&n.to_ne_bytes());
                        }
                    }
                }
                Ok(())
            });
            if let Ok(left) = got {
                assert!(left.iter().all(|n| wanted.contains(&n.as_str())));
            }
        }
        1 => {
            let epid: [u8; EXT_LEN] = inp.exact(EXT_LEN).try_into().unwrap_or([0; EXT_LEN]);
            let pair: [u8; EXT_LEN] = inp.exact(EXT_LEN).try_into().unwrap_or([0; EXT_LEN]);
            let _ = ipa::endpoint_of(&epid, &pair);
        }
        _ => {
            let n = inp.below(12);
            let len = match inp.u8() % 4 {
                0 => EGRESS_PARAM_LEN,
                1 => INGRESS_PARAM_LEN,
                2 => inp.below(64),
                _ => 0,
            };
            let extra = inp.below(8);
            let params = inp.exact(n.saturating_mul(len.max(1)) + extra);
            let optional = inp.u32();
            let _ = ipa::outcome(&params, len, optional);
            let r = rc(&mut inp);
            let _ = ipa::egress_result(r, &params);
            let r = rc(&mut inp);
            let _ = ipa::ingress_result(r, &params);
            let _ = ipa::status_of(&params);
        }
    }
});
