// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The values of the ESP states the modem names, as `sa.rs` checks them before they reach the kernel: protocol,
//! mode, the two addresses, the algorithms and their keys, the SPIs and the UDP port.
#![no_main]
use dataos_fuzz::Input;
use dataos_qmi::reverse::SaFields;
use dataos_qmi::secret::Secret;
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn word(inp: &mut Input<'_>, usual: &[u32]) -> Option<u32> {
    match inp.u8() % 8 {
        0 => None,
        1 => Some(inp.u32()),
        _ => inp.pick(usual),
    }
}

fn addr(inp: &mut Input<'_>) -> Option<IpAddr> {
    match inp.u8() % 8 {
        0 => None,
        1 => Some(IpAddr::V4(Ipv4Addr::from(inp.u32()))),
        2 => {
            let b: [u8; 16] = inp.exact(16).try_into().unwrap_or([0; 16]);
            Some(IpAddr::V6(Ipv6Addr::from(b)))
        }
        _ => inp.pick(&[
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201)),
        ]),
    }
}

fn key(inp: &mut Input<'_>, usual: &[usize], max: usize) -> Option<Secret> {
    let n = match inp.u8() % 8 {
        0 => return None,
        1 => inp.below(max + 1),
        _ => inp.pick(usual).unwrap_or(0),
    };
    Some(Secret::copy_of(&inp.exact(n)))
}

fuzz_target!(|data: &[u8]| {
    let mut inp = Input(data);
    let crypt = [16, 20, 24, 28, 32, 36];
    let auth = [16, 20, 32, 48, 64];
    let fields = SaFields {
        rx_spi: word(&mut inp, &[0, 1, 0xc1c2_c3c4]),
        tx_spi: word(&mut inp, &[0, 2, 0xd1d2_d3d4]),
        proto: word(&mut inp, &[2, 3]),
        mode: word(&mut inp, &[1, 2]),
        remote: addr(&mut inp),
        local: addr(&mut inp),
        auth_alg: word(&mut inp, &[5, 6, 7, 12, 20, 21]),
        crypt_alg: word(&mut inp, &[9, 10, 12, 19]),
        rx_crypt: key(&mut inp, &crypt, 128),
        tx_crypt: key(&mut inp, &crypt, 128),
        udp_encap: match inp.u8() % 4 {
            0 => None,
            1 => Some(inp.u8()),
            _ => Some(1),
        },
        aes_mode: word(&mut inp, &[1, 2]),
        encap_port: match inp.u8() % 4 {
            0 => None,
            1 => Some([0, 0]),
            _ => Some([inp.u8(), inp.u8()]),
        },
        rx_auth: key(&mut inp, &auth, 1024),
        tx_auth: key(&mut inp, &auth, 1024),
    };
    dataos_fuzz::esp::check(fields);
});
