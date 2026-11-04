// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Every parser of a QMI message from the modem, run on one frame, with what each result must hold.
use dataos_qmi::frame::Frame;
use dataos_qmi::reverse::{self, MAX_AUTH_KEY, MAX_CRYPT_KEY};
use dataos_qmi::wds::{self, limits, IpFamily};
use dataos_qmi::{dfs, wda};

pub fn run_all(f: &Frame<'_>) {
    let _ = wds::parse_start_network_response(f);
    let _ = wds::parse_route_lookup(f);
    let _ = wds::parse_packet_service_status(f);
    let _ = wds::parse_extended_ip_config(f);
    for family in [IpFamily::V4, IpFamily::V6, IpFamily::Unspecified] {
        if let Ok(s) = wds::parse_runtime_settings(f, family) {
            assert!(s.ipv4_dns.len() <= 2 && s.ipv6_dns.len() <= 2);
            assert!(s.pcscf_v4.len() <= limits::MAX_ADDRS);
            for list in [&s.domains, &s.pcscf_domains] {
                assert!(list.len() <= limits::MAX_NAMES);
                for n in list {
                    assert!(n.len() <= limits::MAX_NAME_LEN && !n.contains('\0'));
                }
            }
            for (_, p) in s.ipv6.iter().chain(s.ipv6_gateway.iter()) {
                assert!(*p <= 128);
            }
        }
    }
    let _ = wda::parse_set_data_format_response(f);
    let _ = reverse::parse_reverse_ind(f);
    let _ = reverse::reverse_tid(f);
    let _ = reverse::parse_ipsec_sa_response(f);
    if let Ok(s) = reverse::parse_sa_segment(f) {
        let fl = &s.fields;
        for k in [&fl.rx_crypt, &fl.tx_crypt].into_iter().flatten() {
            assert!(k.bytes().len() <= MAX_CRYPT_KEY);
        }
        for k in [&fl.rx_auth, &fl.tx_auth].into_iter().flatten() {
            assert!(k.bytes().len() <= MAX_AUTH_KEY);
        }
    }
    for list in [
        dfs::parse_get_filters(f).ok(),
        dfs::parse_filters_changed(f).ok().map(|(_, l)| l),
    ]
    .into_iter()
    .flatten()
    {
        assert!(list.len() <= 255);
        assert!(list.iter().all(|e| e.version == 4 || e.version == 6));
    }
    if let Ok(w) = dfs::parse_ports_wanted(f) {
        assert!(w.wishes.len() <= 255);
    }
    if let Ok(r) = dfs::parse_ports_released(f) {
        assert!(r.len() <= 255);
    }
    let _ = dfs::parse_encap_port(f);
}
