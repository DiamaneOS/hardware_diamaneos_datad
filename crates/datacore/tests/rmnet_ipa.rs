// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The bring-up of `rmnet_ipa0` against a fake that answers the way the driver of the 6.18 tree does
//! (`rmnet_ipa.c`): the offloads are not on after the driver registered the device, the coalescing
//! pipe is skipped without them while the ioctl returns 0, and a repeated ingress request answers `EPERM`
//! after it wrote `EXISTS` into every status.
use dataos_datacore::engine::ServiceEvent;
use dataos_datacore::sim::{pump, SimModem};
use dataos_datacore::*;
use dataos_netcfg::fake::Call as NetCall;
use dataos_netcfg::{NetError, PipeState, SharedNet, STOCK_FEATURES};

type Shared = Engine<SimModem, SharedNet>;

fn daemon_on(net: &SharedNet) -> Shared {
    Engine::new(Config::default(), SimModem::new(), net.clone())
}

fn pipe_requests(net: &SharedNet) -> (usize, usize) {
    let n = net.0.borrow();
    let count = |f: fn(&NetCall) -> bool| n.calls.iter().filter(|c| f(c)).count();
    (
        count(|c| matches!(c, NetCall::IpaEgress { .. })),
        count(|c| matches!(c, NetCall::IpaIngress { .. })),
    )
}

/// A device that does not take one of the twelve features (here because it does not offer it)
/// ends the attempt before the first pipe request. `rx-gro-hw` is the first case: the ingress request
/// wrote a failure for the coalescing pipe, made the default pipe and the WAN routing tables in the same call and
/// returned 0, and every retry answered `EPERM`. The scatter-gather and TSO features are the second: the
/// uplink pipe is a ULSO pipe only with them on the device, and the links always offer segmentation.
#[test]
fn a_device_that_does_not_take_all_the_features_gets_no_pipe_request() {
    let soft = ["tx-generic-segmentation", "rx-gro"];
    for missing in STOCK_FEATURES.iter().filter(|f| !soft.contains(f)) {
        let net = SharedNet::new();
        net.0
            .borrow_mut()
            .offered_features
            .retain(|f| f != *missing);
        let mut e = daemon_on(&net);
        e.on_service_event(0, ServiceEvent::ModemUp);
        pump(&mut e, 0);
        let mut now = 0;
        for _ in 0..6 {
            now += 61_000;
            e.tick(now);
            pump(&mut e, now);
        }
        assert!(!e.is_ready(), "{missing}");
        assert_eq!(pipe_requests(&net), (0, 0), "{missing}");
        let m = net.0.borrow().marker.clone();
        assert!(m.is_none(), "nothing was written down: {missing}");
        // the device is repaired (a new one, or the driver offering it) and the next attempt goes through
        net.0.borrow_mut().offered_features =
            STOCK_FEATURES.iter().map(|f| f.to_string()).collect();
        now += 61_000;
        e.tick(now);
        pump(&mut e, now);
        assert!(e.is_ready(), "{missing}");
        assert_eq!(pipe_requests(&net), (1, 1), "{missing}");
    }
}

/// A request for the features that fails ends the attempt the same way, and the attempt is made again.
#[test]
fn a_failing_request_for_the_features_ends_the_attempt_before_any_pipe_and_is_made_again() {
    let net = SharedNet::new();
    net.0.borrow_mut().fail_next = Some(("features", NetError::Os(95)));
    let mut e = daemon_on(&net);
    e.on_service_event(0, ServiceEvent::ModemUp);
    pump(&mut e, 0);
    assert!(!e.is_ready());
    assert_eq!(pipe_requests(&net), (0, 0));
    e.tick(61_000);
    pump(&mut e, 61_000);
    assert!(e.is_ready());
    assert_eq!(pipe_requests(&net), (1, 1));
}

/// The links are not the device: datarmnet offers its own set on them, and a link without a feature works, only
/// slower. The gap is counted and the bring-up goes on.
#[test]
fn links_without_the_segmentation_offloads_work_and_count_the_gap() {
    let net = SharedNet::new();
    net.0.borrow_mut().links_lack_features = STOCK_FEATURES
        .iter()
        .filter(|f| f.ends_with("segmentation") && **f != "tx-generic-segmentation")
        .map(|f| f.to_string())
        .collect();
    let mut e = daemon_on(&net);
    e.on_service_event(0, ServiceEvent::ModemUp);
    pump(&mut e, 0);
    assert!(e.is_ready());
    assert!(e.net().0.borrow().data_path_ok("rmnet_data0"));
    // every link asked for the segmentation offloads and did not get them
    assert_eq!(
        e.stats().feature_gaps,
        u32::from(Config::default().link_count)
    );
}

/// The features are on the device when the pipes are asked for, in the order the driver needs: the
/// coalescing pipe is up, the uplink pipe has the checksum header, and the data path is whole.
#[test]
fn the_pipes_are_set_up_with_the_offloads_on_and_the_data_path_is_whole() {
    let net = SharedNet::new();
    let mut e = daemon_on(&net);
    e.on_service_event(0, ServiceEvent::ModemUp);
    pump(&mut e, 0);
    assert!(e.is_ready());
    let n = net.0.borrow();
    let order: Vec<&str> = n
        .calls
        .iter()
        .filter_map(|c| match c {
            NetCall::SetFeatures { name, .. } if name == "rmnet_ipa0" => Some("features"),
            NetCall::IpaEgress { .. } => Some("egress"),
            NetCall::IpaIngress { .. } => Some("ingress"),
            _ => None,
        })
        .collect();
    assert_eq!(order, ["features", "egress", "ingress"]);
    assert!(n.egress_has_csum_header("rmnet_ipa0"));
    assert!(n.data_path_ok("rmnet_data0") && n.data_path_ok("rmnet_data14"));
}

/// The done record of the ingress pipe is not written (a crash in the
/// window, or a failed write, which never stops the setup). A later instance on the same `rmnet_ipa0` finds
/// the record pending and sends the ingress request again. The driver writes `EXISTS` into every status and
/// then returns `EPERM`, which is the pipes being up already.
#[test]
fn a_repeated_ingress_request_after_a_lost_done_record_is_taken_for_existing() {
    let net = SharedNet::new();
    // egress pending, egress done, ingress pending, then the store fails
    net.0.borrow_mut().marker_stores_left = Some(3);
    let mut a = daemon_on(&net);
    a.on_service_event(0, ServiceEvent::ModemUp);
    pump(&mut a, 0);
    assert!(a.is_ready());
    let m = net.0.borrow().marker.clone().unwrap();
    assert_eq!((m.egress, m.ingress), (PipeState::Done, PipeState::Pending));
    drop(a);
    net.0.borrow_mut().marker_stores_left = None;
    let mut b = daemon_on(&net);
    b.on_service_event(10, ServiceEvent::ModemUp);
    pump(&mut b, 10);
    assert!(b.is_ready(), "EPERM with every status up is not an error");
    assert_eq!(b.stats().pipes_found, 1);
    assert_eq!(net.0.borrow().pipe_refusals, 1);
    let m = net.0.borrow().marker.clone().unwrap();
    assert_eq!((m.egress, m.ingress), (PipeState::Done, PipeState::Done));
}

/// A driver that fails the low latency control pipes and goes on does not end the attempt: the data path does
/// not use them.
#[test]
fn a_low_latency_control_pipe_the_driver_could_not_make_does_not_end_the_bringup() {
    let net = SharedNet::new();
    net.0.borrow_mut().refuse_low_latency_ctrl = true;
    let mut e = daemon_on(&net);
    e.on_service_event(0, ServiceEvent::ModemUp);
    pump(&mut e, 0);
    assert!(e.is_ready());
    assert!(net.0.borrow().data_path_ok("rmnet_data0"));
}

/// A new `rmnet_ipa0` after a modem restart has no features again, so they are asked for again, before the
/// pipes.
#[test]
fn the_features_are_asked_for_again_on_the_device_a_modem_restart_makes() {
    let net = SharedNet::new();
    let mut e = daemon_on(&net);
    e.on_service_event(0, ServiceEvent::ModemUp);
    pump(&mut e, 0);
    assert!(e.is_ready());
    e.on_service_event(100, ServiceEvent::ModemDown);
    net.0.borrow_mut().modem_restart();
    assert!(net.0.borrow().features_of("rmnet_ipa0").len() < STOCK_FEATURES.len());
    e.on_service_event(200, ServiceEvent::ModemUp);
    pump(&mut e, 200);
    assert!(e.is_ready());
    let n = net.0.borrow();
    let asked = n
        .calls
        .iter()
        .filter(|c| matches!(c, NetCall::SetFeatures { name, .. } if name == "rmnet_ipa0"))
        .count();
    assert_eq!(asked, 2);
    assert!(n.data_path_ok("rmnet_data0"));
    // the fake keeps no record of the old links, so the daemon made them again
    assert!(STOCK_FEATURES
        .iter()
        .all(|f| n.features_of("rmnet_ipa0").iter().any(|x| x == f)));
}

/// The flags of a stock phone: the v5 headers both ways, coalescing and deaggregation, and no v4
/// bit, with the mask of every bit.
#[test]
fn the_links_carry_the_flags_stock_sets() {
    use dataos_netcfg::RmnetFlags;
    let f = RmnetFlags::qmap_default();
    assert_eq!((f.flags, f.mask), (0xb400_0071, 0xffff_ffff));
    let net = SharedNet::new();
    let mut e = daemon_on(&net);
    e.on_service_event(0, ServiceEvent::ModemUp);
    pump(&mut e, 0);
    assert!(net.0.borrow().data_path_ok("rmnet_data0"));
}
