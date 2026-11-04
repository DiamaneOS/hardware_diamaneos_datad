// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! What a set of ESP states that `IpsecSa::from_fields` accepted must hold, and that both states build.
use dataos_netcfg::xfrm;
use dataos_qmi::reverse::SaFields;
use dataos_wlan_tunnel::sa::{usable_address, IpsecSa, IKE_NATT_PORT};

pub fn check(fields: SaFields) {
    let proto = fields.proto;
    let Ok(sa) = IpsecSa::from_fields(fields) else {
        return;
    };
    assert!(matches!(proto, Some(2 | 3)));
    assert!(sa.rx_spi != 0 && sa.tx_spi != 0);
    assert_eq!(sa.remote.is_ipv4(), sa.local.is_ipv4());
    assert!(usable_address(sa.remote) && usable_address(sa.local));
    let crypt = sa.rx_crypt.bytes().len();
    assert_eq!(crypt, sa.tx_crypt.bytes().len());
    let sizes: &[usize] = match sa.crypt_name {
        "cbc(des3_ede)" => &[24],
        "cbc(aes)" => &[16, 24, 32],
        "rfc3686(ctr(aes))" => &[20, 28, 36],
        other => panic!("crypto algorithm {other}"),
    };
    assert!(sizes.contains(&crypt));
    let auth = sa.rx_auth.bytes().len();
    assert_eq!(auth, sa.tx_auth.bytes().len());
    assert!(auth > 0 && u32::try_from(auth * 8).is_ok_and(|bits| bits >= sa.auth_trunc_bits));
    assert_ne!(sa.encap_port, Some([0, 0]));
    for (state, mark) in [
        (sa.tx_state(Some(0x20000)), true),
        (sa.rx_state(None), false),
    ] {
        if let Some(e) = state.encap {
            assert!(e.sport == IKE_NATT_PORT || e.dport == IKE_NATT_PORT);
        }
        let Ok(m) = xfrm::new_state(7, &state) else {
            panic!("an accepted state does not build");
        };
        let len = u32::from_ne_bytes([m[0], m[1], m[2], m[3]]);
        assert_eq!(len as usize, m.len());
        assert_eq!(u16::from_ne_bytes([m[4], m[5]]), xfrm::XFRM_MSG_NEWSA);
        assert_eq!(state.mark.is_some(), mark);
    }
}
