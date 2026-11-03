// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The messages this crate builds and reads against the IDL tables of the stock `libqmiservices.so`
//! (`idl/idl-expected.txt`, held to the library by a dump of its IDL tables). The tables give the TLV
//! tags, the widths, the array and count rules and which TLV is mandatory. They do not give enum members or
//! byte orders, which stay with libqmi's public definitions.
mod idl;

use dataos_qmi::dfs::{self, PortAnswer, PortKind};
use dataos_qmi::frame::{HEADER_LEN, MAX_DATAGRAM};
use dataos_qmi::reverse;
use dataos_qmi::wds::{self, id, IpFamily};
use dataos_qmi::{dpm, wda, Builder, Frame};
use idl::{Kind, Spec};

fn frame(bytes: &[u8]) -> Frame<'_> {
    Frame::parse(bytes).unwrap()
}

fn fits(spec: &Spec, service: &str, bytes: &[u8]) {
    let f = frame(bytes);
    if let Err(e) = spec.check_frame(service, &f) {
        panic!("{service} {:?} {:#06x}: {e}", f.kind, f.id);
    }
}

#[test]
fn the_service_ids_are_the_ones_of_the_service_objects() {
    let spec = Spec::load();
    assert_eq!(spec.services["wds"], wds::SERVICE);
    assert_eq!(spec.services["wda"], wda::SERVICE);
    assert_eq!(spec.services["dpm"], dpm::SERVICE);
    assert_eq!(spec.services["dfs"], dfs::SERVICE);
}

#[test]
fn the_message_ids_are_the_ones_of_the_tables() {
    let spec = Spec::load();
    let pairs = [
        ("wds", id::INDICATION_REGISTER),
        ("wds", id::START_NETWORK),
        ("wds", id::STOP_NETWORK),
        ("wds", id::GET_RUNTIME_SETTINGS),
        ("wds", id::SET_IP_FAMILY),
        ("wds", id::BIND_MUX_DATA_PORT),
        ("wds", id::BIND_SUBSCRIPTION),
        ("wda", wda::SET_DATA_FORMAT),
        ("dpm", dpm::OPEN_PORT),
    ];
    for (service, mid) in pairs {
        spec.message(service, Kind::Request, mid);
        spec.message(service, Kind::Response, mid);
    }
    spec.message("wds", Kind::Indication, id::PACKET_SERVICE_STATUS);
    spec.message("wds", Kind::Indication, id::EXTENDED_IP_CONFIG);
}

#[test]
fn the_route_lookup_is_in_no_table() {
    let spec = Spec::load();
    assert_eq!(
        spec.absent,
        vec![("wds".to_owned(), Kind::Request, id::ROUTE_LOOKUP)]
    );
    assert!(!spec.messages.keys().any(|(_, _, m)| *m == id::ROUTE_LOOKUP));
}

#[test]
fn the_requests_of_the_builders_fit_the_tables() {
    let spec = Spec::load();
    let full = wds::StartNetwork {
        apn: Some("a".repeat(wds::limits::MAX_APN)),
        username: Some("u".repeat(wds::limits::MAX_CRED)),
        password: Some("p".repeat(wds::limits::MAX_CRED)),
        auth: Some(wds::Auth::PapOrChap),
        ip_family: Some(IpFamily::V6),
        profile_3gpp: Some(1),
        technology_preference: Some(1),
        extra: Vec::new(),
    };
    fits(&spec, "wds", &full.encode(1).unwrap());
    fits(
        &spec,
        "wds",
        &wds::StartNetwork::default().encode(1).unwrap(),
    );
    fits(&spec, "wds", &wds::stop_network(1, 7).unwrap());
    for family in [IpFamily::V4, IpFamily::V6] {
        fits(&spec, "wds", &wds::set_ip_family(1, family).unwrap());
    }
    for subscription in [0, 1, 2, 3, wds::DONT_CARE_SUBS] {
        fits(
            &spec,
            "wds",
            &wds::bind_subscription(1, subscription).unwrap(),
        );
    }
    fits(
        &spec,
        "wds",
        &wds::bind_mux_data_port(1, wds::EP_EMBEDDED, 1, 5, 0xff).unwrap(),
    );
    for on in [false, true] {
        fits(&spec, "wds", &wds::indication_register(1, on).unwrap());
    }
    fits(
        &spec,
        "wds",
        &wds::get_runtime_settings(1, wds::settings::IMS).unwrap(),
    );
    fits(
        &spec,
        "wda",
        &wda::SetDataFormat::stock((wds::EP_EMBEDDED, 1), 64844, 63)
            .encode(1)
            .unwrap(),
    );
    let port = dpm::HardwarePort {
        ep_type: 4,
        iface: 1,
        consumer: 2,
        producer: 18,
    };
    fits(&spec, "dpm", &dpm::open_hardware_ports(1, &[port]).unwrap());
    fits(
        &spec,
        "dpm",
        &dpm::open_hardware_ports(1, &[port; 16]).unwrap(),
    );
}

#[test]
fn a_route_lookup_uses_the_numbering_and_widths_of_start_network() {
    // The stock code builds the message raw, with the TLVs of Start Network. Its first TLV, 0x01, is the
    // lookup type and belongs to no table.
    let spec = Spec::load();
    let start = spec.message("wds", Kind::Request, id::START_NETWORK);
    let req = wds::RouteLookup {
        family: IpFamily::V6,
        apn: Some("a".repeat(wds::limits::MAX_APN)),
        apn_type: Some(512),
        apn_type_mask: Some(1 << 9),
        profile_3gpp: Some(3),
        profile_3gpp2: Some(4),
        xt_pref: Some(5),
        backup_name: Some(6),
        backup_type: Some(7),
    };
    let bytes = wds::route_lookup(1, &req).unwrap();
    let f = frame(&bytes);
    assert_eq!(f.id, id::ROUTE_LOOKUP);
    assert_eq!(f.tlv(0x01), Some(&[1u8][..]));
    for (tag, value) in f.tlvs().filter(|(t, _)| *t != 0x01) {
        let t = start
            .iter()
            .find(|t| t.tag == tag)
            .unwrap_or_else(|| panic!("tlv {tag:#04x} is no Start Network TLV"));
        t.ty.check(value, true).unwrap();
    }
    assert_eq!(f.tlvs().count(), 11);
}

fn with_all_tlvs_and_with_the_required_ones(
    spec: &Spec,
    kind: Kind,
    mid: u16,
    each: impl Fn(&[u8]),
) {
    for all in [true, false] {
        let bytes = spec.build("wds", kind, mid, all, 1);
        fits(spec, "wds", &bytes);
        each(&bytes);
    }
}

#[test]
fn the_parsers_take_a_stock_answer_with_everything_in_it() {
    let spec = Spec::load();
    with_all_tlvs_and_with_the_required_ones(&spec, Kind::Response, id::START_NETWORK, |b| {
        assert!(matches!(
            wds::parse_start_network_response(&frame(b)),
            Ok(wds::StartOutcome::Started { .. })
        ));
    });
    with_all_tlvs_and_with_the_required_ones(
        &spec,
        Kind::Indication,
        id::PACKET_SERVICE_STATUS,
        |b| {
            wds::parse_packet_service_status(&frame(b)).unwrap();
        },
    );
    with_all_tlvs_and_with_the_required_ones(
        &spec,
        Kind::Indication,
        id::EXTENDED_IP_CONFIG,
        |b| {
            wds::parse_extended_ip_config(&frame(b)).unwrap();
        },
    );
    for family in [IpFamily::V4, IpFamily::V6] {
        let bytes = spec.build("wds", Kind::Response, id::GET_RUNTIME_SETTINGS, true, 1);
        let s = wds::parse_runtime_settings(&frame(&bytes), family).unwrap();
        assert!(s.ipv4.is_some() || s.ipv6.is_some());
    }
    let bytes = spec.build("wda", Kind::Response, wda::SET_DATA_FORMAT, true, 1);
    let r = wda::parse_set_data_format_response(&frame(&bytes)).unwrap();
    assert_eq!(r.link_layer, Some(1));
    assert_eq!(r.dl_max_size, Some(1));
}

#[test]
fn an_extended_ip_config_indication_needs_none_of_its_tlvs() {
    // The table marks 0x10 and 0x11 as optional. The indication itself says the configuration changed.
    let spec = Spec::load();
    let none = spec.build("wds", Kind::Indication, id::EXTENDED_IP_CONFIG, false, 1);
    assert_eq!(frame(&none).tlvs().count(), 0);
    assert_eq!(wds::parse_extended_ip_config(&frame(&none)), Ok(0));
    let only_second = dataos_qmi::Builder::indication(id::EXTENDED_IP_CONFIG)
        .u32(0x11, 5)
        .unwrap()
        .build()
        .unwrap();
    fits(&spec, "wds", &only_second);
    assert_eq!(wds::parse_extended_ip_config(&frame(&only_second)), Ok(0));
    let first = dataos_qmi::Builder::indication(id::EXTENDED_IP_CONFIG)
        .u32(0x10, 0x30)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(wds::parse_extended_ip_config(&frame(&first)), Ok(0x30));
}

#[test]
fn a_tlv_of_the_wrong_width_in_an_extended_ip_config_indication_is_refused() {
    for tag in [0x10, 0x11] {
        let b = dataos_qmi::Builder::indication(id::EXTENDED_IP_CONFIG)
            .tlv(tag, &[1, 0, 0])
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            wds::parse_extended_ip_config(&frame(&b)),
            Err(dataos_qmi::Error::Length),
            "tag {tag:#04x}"
        );
    }
}

#[test]
fn the_largest_runtime_settings_answer_fits_the_datagram_bound() {
    // Everything the code reads from one Get Runtime Settings answer, each TLV at its stock maximum.
    let spec = Spec::load();
    let bytes = spec.build("wds", Kind::Response, id::GET_RUNTIME_SETTINGS, true, 1);
    assert!(bytes.len() <= MAX_DATAGRAM, "{} bytes", bytes.len());
    let sum: usize = spec
        .message("wds", Kind::Response, id::GET_RUNTIME_SETTINGS)
        .iter()
        .map(|t| 3 + t.ty.size(true).1)
        .sum();
    assert_eq!(bytes.len(), HEADER_LEN + sum);
    // The request names IMS settings, and the modem sends nothing else.
    assert!(sum < MAX_DATAGRAM - HEADER_LEN);
}

#[test]
fn the_limits_are_the_stock_maximums() {
    let spec = Spec::load();
    let start = spec.message("wds", Kind::Request, id::START_NETWORK);
    let max_of = |tag: u8| start.iter().find(|t| t.tag == tag).unwrap().ty.size(true).1;
    assert_eq!(wds::limits::MAX_APN, max_of(0x14));
    assert_eq!(wds::limits::MAX_CRED, max_of(0x17));
    assert_eq!(wds::limits::MAX_CRED, max_of(0x18));
    // An extra TLV may be any Start Network TLV the engine does not set itself, and the largest must pass.
    for t in start
        .iter()
        .filter(|t| !wds::START_TYPED_TAGS.contains(&t.tag))
    {
        let value = t.ty.sample(true, true);
        assert!(
            wds::check_extra_tlv(t.tag, &value).is_ok(),
            "tlv {:#04x} of {} bytes",
            t.tag,
            value.len()
        );
    }
    // Lists and names are cut where the code says, below what the tables allow.
    let settings = spec.message("wds", Kind::Response, id::GET_RUNTIME_SETTINGS);
    let list = |tag: u8| match &settings.iter().find(|t| t.tag == tag).unwrap().ty {
        idl::Ty::Struct(m) => match &m[0] {
            idl::Ty::Array { max, .. } => *max,
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    };
    assert!(wds::limits::MAX_ADDRS <= list(0x23));
    assert!(wds::limits::MAX_NAMES <= list(0x24));
    assert!(wds::limits::MAX_NAMES <= list(0x2a));
}

fn big_frame(bytes: &[u8]) -> Frame<'_> {
    Frame::parse_bounded(bytes, dfs::MAX_MESSAGE).unwrap()
}

#[test]
fn the_reverse_transport_requests_fit_the_tables() {
    let spec = Spec::load();
    for family in [IpFamily::V4, IpFamily::V6] {
        fits(
            &spec,
            "wds",
            &reverse::bind_client(1, family, (wds::EP_EMBEDDED, 1), 18).unwrap(),
        );
    }
    fits(
        &spec,
        "wds",
        &reverse::bind_mux_reverse(1, (wds::EP_EMBEDDED, 1), 18).unwrap(),
    );
    fits(&spec, "wds", &reverse::register(1).unwrap());
    fits(&spec, "wds", &reverse::reverse_answer(1, true, 9).unwrap());
    fits(&spec, "wds", &reverse::ipsec_sa_request(1).unwrap());
}

#[test]
fn a_reverse_indication_with_everything_in_it_reads() {
    let spec = Spec::load();
    for all in [true, false] {
        let b = spec.build("wds", Kind::Indication, reverse::id::REVERSE_IND, all, 1);
        fits(&spec, "wds", &b);
        let r = reverse::parse_reverse_ind(&frame(&b)).unwrap();
        assert_eq!((r.status, r.tid), (1, 1));
        assert_eq!(r.tech.is_some(), all);
    }
}

#[test]
fn an_sa_indication_at_its_largest_fits_the_table_and_the_bound_and_reads() {
    let spec = Spec::load();
    let tunnel = |a: [u8; 16]| {
        let mut v = 6u32.to_le_bytes().to_vec();
        v.push(16);
        v.extend(a);
        v
    };
    let mut crypt = vec![128u8];
    crypt.extend([5u8; 128]);
    let mut auth = 1024u16.to_le_bytes().to_vec();
    auth.extend([6u8; 1024]);
    let b = Builder::indication(reverse::id::IPSEC_SA)
        .tlv(0x01, &[1, 0, 1, 0])
        .unwrap()
        .u32(0x10, 2)
        .unwrap()
        .u32(0x11, 3)
        .unwrap()
        .u32(0x12, 3)
        .unwrap()
        .u32(0x13, 1)
        .unwrap()
        .tlv(0x14, &tunnel([1; 16]))
        .unwrap()
        .tlv(0x15, &tunnel([2; 16]))
        .unwrap()
        .u32(0x16, 6)
        .unwrap()
        .u32(0x17, 12)
        .unwrap()
        .tlv(0x18, &crypt)
        .unwrap()
        .tlv(0x19, &crypt)
        .unwrap()
        .u8(0x1b, 1)
        .unwrap()
        .u32(0x35, 1)
        .unwrap()
        .tlv(0x36, &[0x11, 0x94])
        .unwrap()
        .tlv(0x37, &auth)
        .unwrap()
        .tlv(0x38, &auth)
        .unwrap()
        .build()
        .unwrap();
    fits(&spec, "wds", &b);
    let s = reverse::parse_sa_segment(&frame(&b)).unwrap();
    assert_eq!(s.fields.rx_auth.unwrap().len(), 1024);
    assert_eq!(s.fields.tx_crypt.unwrap().len(), 128);
    // the table's largest indication, every TLV at its maximum, also fits one datagram
    const { assert!(3697 + HEADER_LEN <= MAX_DATAGRAM) };
}

#[test]
fn the_dfs_requests_fit_the_tables() {
    let spec = Spec::load();
    fits(&spec, "dfs", &dfs::bind_client(1, 4, (4, 1), 1).unwrap());
    fits(&spec, "dfs", &dfs::register_link(1).unwrap());
    fits(&spec, "dfs", &dfs::register_ports(1).unwrap());
    fits(&spec, "dfs", &dfs::get_filters(1).unwrap());
    let one = PortAnswer {
        status: 0,
        kind: PortKind::V6Udp,
        port: 5060,
        chosen: false,
    };
    let b = dfs::ports_answer(1, &[one; dfs::MAX_PORT_ANSWERS], Some(3)).unwrap();
    fits(&spec, "dfs", &b);
    assert!(b.len() <= MAX_DATAGRAM);
}

/// A message past the bound of the builder, whose largest datagram is what the daemon sends: header and TLVs by hand.
fn raw_frame(kind: u8, mid: u16, tlvs: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (tag, v) in tlvs {
        body.push(*tag);
        body.extend((v.len() as u16).to_le_bytes());
        body.extend(v);
    }
    let mut out = vec![kind, 1, 0];
    out.extend(mid.to_le_bytes());
    out.extend((body.len() as u16).to_le_bytes());
    out.extend(body);
    out
}

#[test]
fn the_dfs_indications_read_and_a_full_filter_list_is_the_largest_message() {
    let spec = Spec::load();
    let tlv = |id: u16, kind: Kind, tag: u8| {
        spec.message("dfs", kind, id)
            .iter()
            .find(|t| t.tag == tag)
            .unwrap()
            .ty
            .sample(true, true)
    };
    let list = tlv(dfs::id::GET_FILTERS, Kind::Response, 0x10);
    let b = raw_frame(
        2,
        dfs::id::GET_FILTERS,
        &[(0x02, vec![0, 0, 0, 0]), (0x10, list.clone())],
    );
    assert_eq!(b.len(), dfs::MAX_MESSAGE);
    assert!(spec.check_frame("dfs", &big_frame(&b)).is_ok());
    assert_eq!(dfs::parse_get_filters(&big_frame(&b)), Ok(Vec::new()));
    let b = raw_frame(
        4,
        dfs::id::FILTERS_CHANGED,
        &[(0x01, vec![1, 0, 0, 0]), (0x10, list)],
    );
    assert_eq!(b.len(), dfs::MAX_MESSAGE);
    assert!(spec.check_frame("dfs", &big_frame(&b)).is_ok());
    assert_eq!(
        dfs::parse_filters_changed(&big_frame(&b)),
        Ok((1, Vec::new()))
    );
    let b = spec.build("dfs", Kind::Indication, dfs::id::PORTS_WANTED, true, 1);
    fits(&spec, "dfs", &b);
    let p = dfs::parse_ports_wanted(&frame(&b)).unwrap();
    assert_eq!(p.wishes.len(), 255);
    assert_eq!(p.range, Some((1, 1, 1)));
    let b = spec.build("dfs", Kind::Indication, dfs::id::PORTS_RELEASED, true, 1);
    fits(&spec, "dfs", &b);
    assert_eq!(dfs::parse_ports_released(&frame(&b)).unwrap().len(), 255);
    let b = spec.build("dfs", Kind::Indication, dfs::id::ENCAP_PORT, true, 1);
    fits(&spec, "dfs", &b);
    assert_eq!(dfs::parse_encap_port(&frame(&b)), Ok((1, 1)));
}
