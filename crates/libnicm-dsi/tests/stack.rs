// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The exports of libnicm_dsi.so through libnicm.so to a daemon server in
//! another thread, with buffers in the layouts of the closed data module
//! built here by hand. The module itself is not run: what
//! the tests show is that the exports, `StockAbi`, the glue, the gate and the
//! whole path to the daemon agree with those layouts. Simulation only.
#![allow(clippy::disallowed_methods, unsafe_code)]
use dataos_datacore::engine::{Config, Engine, ServiceEvent};
use dataos_datacore::sim::SimModem;
use dataos_datad::server::{Server, ServerConfig};
use dataos_libnicm::abi::{register_with, release_handle, reset_for_tests, UserData};
use dataos_libnicm::sys;
use dataos_libnicm_dsi::abi::{self, install, StockAbi};
use dataos_libnicm_dsi::glue::{self, Failure, Family, Lookup};
use dataos_libnicm_dsi::layout::{self as l, event, request, route_out};
use dataos_netcfg::FakeNet;
use dataos_nicm_abi::{allow_provisional_abi_for_tests, EventBuf, NicmEvent};
use dataos_wire::limits::MAX_MESSAGE;
use std::ffi::c_void;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;

static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn exclusive() -> MutexGuard<'static, ()> {
    let g = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    reset_for_tests();
    install(None);
    abi::use_stock_for_tests(false);
    allow_provisional_abi_for_tests(false);
    EVENTS.lock().unwrap().clear();
    g
}

/// What a test tells the daemon's thread to do.
enum Cmd {
    /// The modem is there.
    Up,
    /// A call of the module connects on this mux ID.
    Connect(u8),
    /// The modem names this instance for a route lookup of this IP family (4 or 6).
    Names(u8, u8),
    /// The modem names this technology for a route lookup of this IP family.
    Technology(u8, u16),
}

struct Daemon {
    commands: Arc<Mutex<Vec<Cmd>>>,
    /// The subscriptions the daemon bound so far, in order.
    bound: Arc<Mutex<Vec<u32>>>,
    /// The route lookup questions the daemon sent to the modem so far.
    asked: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Daemon {
    /// Hand over a command and wait until the thread has taken it. It applies what it took before
    /// it reads the next request, so a request sent after this returns sees the effect.
    fn tell(&self, cmd: Cmd) {
        self.commands.lock().unwrap().push(cmd);
        wait_until("the daemon took the command", || {
            self.commands.lock().unwrap().is_empty()
        });
    }

    fn up(&self) {
        self.tell(Cmd::Up);
    }

    fn connect(&self, mux: u8) {
        self.tell(Cmd::Connect(mux));
    }

    fn names(&self, family: u8, instance: u8) {
        self.tell(Cmd::Names(family, instance));
    }

    fn technology(&self, family: u8, tech: u16) {
        self.tell(Cmd::Technology(family, tech));
    }

    fn kill(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
    }
}

fn wait_until(what: &str, done: impl Fn() -> bool) {
    let t = std::time::Instant::now();
    while !done() {
        assert!(t.elapsed().as_secs() < 5, "waited for: {what}");
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

fn spawn_daemon(fd: OwnedFd) -> Daemon {
    let commands = Arc::new(Mutex::new(Vec::new()));
    let bound = Arc::new(Mutex::new(Vec::new()));
    let asked = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let (c2, b2, s2, a2) = (commands.clone(), bound.clone(), stop.clone(), asked.clone());
    let thread = std::thread::spawn(move || {
        let mut server = Server::new(
            ServerConfig::default(),
            Engine::new(Config::default(), SimModem::new(), FakeNet::new()),
        );
        server.engine().qmi_mut().require_call = true;
        let conn = server.accept(4242, 1001, "u:r:rild:s0").unwrap();
        let (_, wake) = sys::pair().unwrap();
        let mut now = 0u64;
        while !s2.load(Ordering::SeqCst) {
            for cmd in std::mem::take(&mut *c2.lock().unwrap()) {
                now += 1;
                match cmd {
                    Cmd::Up => server.on_service_event(now, ServiceEvent::ModemUp),
                    Cmd::Connect(mux) => server.engine().qmi_mut().external_connect(mux),
                    Cmd::Names(family, instance) => {
                        let tlvs = vec![(0x10, vec![instance])];
                        server.engine().qmi_mut().route_answers.insert(family, tlvs);
                    }
                    Cmd::Technology(family, tech) => {
                        let mut block = vec![0u8; 8];
                        block.extend(tech.to_le_bytes());
                        let q = server.engine().qmi_mut();
                        q.route_no_block = true;
                        q.route_answers.insert(family, vec![(0x01, block)]);
                    }
                }
            }
            while let Some((c, b)) = server.engine().qmi_mut().inbox.pop_front() {
                server.on_qmi(now, c, &b);
            }
            b2.lock()
                .unwrap()
                .clone_from(&server.engine().qmi_mut().bound_subscriptions);
            *a2.lock().unwrap() = server
                .engine()
                .qmi_mut()
                .route_frames
                .iter()
                .map(|(_, b)| b.clone())
                .collect();
            let _ = sys::wait(Some(fd.as_fd()), wake.as_fd(), 5);
            let mut buf = [0u8; MAX_MESSAGE + 1];
            while let Ok(Some(n)) = sys::recv(fd.as_fd(), &mut buf) {
                if n == 0 {
                    return;
                }
                now += 1;
                let _ = server.on_datagram(now, conn, &buf[..n]);
            }
            for d in server.drain_encoded(conn) {
                let _ = sys::send(fd.as_fd(), &d);
            }
        }
    });
    Daemon {
        commands,
        bound,
        asked,
        stop,
        thread: Some(thread),
    }
}

/// The events the module's callback was given.
static EVENTS: Mutex<Vec<NicmEvent>> = Mutex::new(Vec::new());

extern "C" fn no_events(e: *mut c_void, _u: *mut c_void) {
    // SAFETY: the library passes a pointer to an EventBuf that lives through the call.
    let ev = unsafe { (*e.cast::<EventBuf>()).ev };
    EVENTS.lock().unwrap().push(ev);
}

fn connect(ready: bool) -> (Daemon, usize) {
    let (lib, d) = sys::pair().unwrap();
    let daemon = spawn_daemon(d);
    let ends = Mutex::new(Some(lib));
    let h = register_with(
        no_events,
        UserData::new(std::ptr::null_mut()),
        Box::new(move || {
            ends.lock()
                .unwrap()
                .take()
                .ok_or_else(|| std::io::ErrorKind::ConnectionRefused.into())
        }),
    );
    assert!(!h.is_null());
    if ready {
        daemon.up();
        let t = std::time::Instant::now();
        while glue::ready(&abi::LibNicm, h as usize).is_err() {
            assert!(t.elapsed().as_secs() < 5, "waited for ready");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    (daemon, h as usize)
}

extern "C" {
    fn free(p: *mut c_void);
}

fn stock() {
    allow_provisional_abi_for_tests(true);
    install(Some(Arc::new(StockAbi::new())));
}

/// The route lookup request the module builds, in its layout.
fn route_request(family: u32, apn: &str) -> Vec<u8> {
    let mut r = vec![0u8; l::REQUEST_LEN];
    let mut mask = request::MASK_IP_FAMILY | request::MASK_TECH_PREF;
    assert!(l::wr_u32(&mut r, request::VALID, 1));
    assert!(l::wr_u32(&mut r, request::IP_FAMILY, family));
    assert!(l::wr_u8(&mut r, request::TECH_PREF, 9));
    if !apn.is_empty() {
        mask |= request::MASK_APN;
        assert!(l::wr_bytes(&mut r, request::APN, apn.as_bytes()));
    }
    assert!(l::wr_u32(&mut r, request::APN_TYPE, 0x8000_0001));
    assert!(l::wr_u64(&mut r, request::MASK, mask));
    r
}

fn lookup_through_the_export(h: usize, req: &[u8], out: &mut [u8], mode: i32) -> i32 {
    abi::dsiNicmRouteLookup(h, 0, out.as_mut_ptr() as usize, req.as_ptr() as usize, mode)
}

fn wait_ready(h: usize) {
    let t = std::time::Instant::now();
    while abi::dsiInitQueryNicmWrapper(h) != 0 {
        assert!(t.elapsed().as_secs() < 5);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[test]
fn every_export_refuses_in_the_form_of_its_prototype_until_the_layouts_are_verified() {
    // the run with the flag on has nothing to refuse
    if dataos_nicm_abi::STOCK_ABI_VERIFIED {
        return;
    }
    let _g = exclusive();
    // arguments that would crash if they were read as pointers
    let junk = 0xdead_beef_usize;
    let all_refuse = || {
        assert_eq!(abi::dsiInitQueryNicmWrapper(junk), -1);
        assert_eq!(abi::dsiTranslateNicmEvent(junk, junk, junk), -1);
        assert_eq!(abi::dsiTranslateRouteLookupRequest(1, junk, junk), -1);
        assert_eq!(abi::dsiNicmRouteLookup(junk, 1, junk, junk, 5), -1);
        assert_eq!(abi::dsiNicmQueryLLNetworkHndl(junk, junk), -1);
        assert_eq!(abi::dsiNicmGetLinkMtu(junk, 1, 0, junk), -1);
        assert_eq!(abi::dsiNicmLinkRelease(junk, 1), -1);
        assert_eq!(abi::dsiNicmProcessPFRequest(junk, 2, 2, junk), -1);
        assert_eq!(abi::dsiNicmOEMProxy(junk, junk, junk), -1);
        assert_eq!(abi::dsiNicmProcessScreenState(junk, 1), -1);
        // the one that returns a pointer returns a null pointer, not -1
        assert!(abi::setNicmInfo(junk).is_null());
    };
    all_refuse();
    // an implementation alone is not enough, the layouts must be marked verified
    install(Some(Arc::new(StockAbi::new())));
    all_refuse();
    // and the switch alone is not enough either
    install(None);
    allow_provisional_abi_for_tests(true);
    all_refuse();
}

#[test]
fn a_lookup_a_mtu_a_release_and_the_refusals_through_the_exports() {
    let _g = exclusive();
    stock();
    let (daemon, h) = connect(false);
    // the readiness query fails until the daemon is ready
    assert_eq!(abi::dsiInitQueryNicmWrapper(h), -1);
    daemon.up();
    wait_ready(h);
    let req = route_request(4, "internet.example");
    let mut out = vec![0xaau8; l::INFO_LEN];
    assert_eq!(lookup_through_the_export(h, &req, &mut out, 5), 0);
    assert_eq!(l::rd_u32(&out, route_out::VALID), Some(0), "a new call");
    assert_eq!(l::rd_u32(&out, route_out::LINK), Some(0));
    assert_eq!(l::rd_u32(&out, route_out::COMPANION), Some(0));
    assert_eq!(l::rd_u32(&out, route_out::TECH), Some(l::TECH_DEFAULT));
    assert_eq!(
        l::rd_u8(&out, 0),
        Some(0),
        "the rest of the answer is cleared"
    );
    // the other family of the same APN gets the same link
    let req6 = route_request(6, "internet.example");
    assert_eq!(lookup_through_the_export(h, &req6, &mut out, 5), 0);
    assert_eq!(l::rd_u32(&out, route_out::LINK), Some(0));
    // no call is up on the link, so there is no MTU yet, and the answer stays as it was
    let mut mtu = [0u8; l::MTU_OUT_LEN];
    assert_eq!(
        abi::dsiNicmGetLinkMtu(h, 0, 0, mtu.as_mut_ptr() as usize),
        -1
    );
    assert_eq!(mtu, [0u8; l::MTU_OUT_LEN]);
    assert_eq!(abi::dsiNicmProcessScreenState(h, 0), 0);
    assert_eq!(abi::dsiNicmProcessScreenState(h, 1), 0);
    // the daemon does not do these, the exports answer with the failure of their prototype
    let oem_in = [0u8; l::OEM_IN_LEN];
    let mut buf = vec![0u8; l::INFO_LEN];
    assert_eq!(
        abi::dsiNicmOEMProxy(h, oem_in.as_ptr() as usize, buf.as_mut_ptr() as usize),
        -1
    );
    assert_eq!(
        abi::dsiNicmProcessPFRequest(h, 2, 2, buf.as_mut_ptr() as usize),
        -1
    );
    let mut handle = [0xffu8; l::HANDLE_OUT_LEN];
    assert_eq!(
        abi::dsiNicmQueryLLNetworkHndl(h, handle.as_mut_ptr() as usize),
        -1
    );
    assert_eq!(
        handle,
        [0u8; l::HANDLE_OUT_LEN],
        "stored 0 as the stock function does"
    );
    assert_eq!(
        abi::dsiTranslateRouteLookupRequest(0, req.as_ptr() as usize, buf.as_mut_ptr() as usize),
        -1
    );
    assert_eq!(abi::dsiNicmLinkRelease(h, 0), 0);
    assert_eq!(abi::dsiNicmLinkRelease(h, 0), -1, "twice");
    // a handle that is not one, and a null one
    assert_eq!(abi::dsiNicmLinkRelease(0x10, 0), -1);
    assert_eq!(abi::dsiNicmLinkRelease(0, 0), -1);
    release_handle(h as *mut c_void);
    daemon.kill();
}

#[test]
fn values_from_the_module_are_checked_before_anything_is_sent() {
    let _g = exclusive();
    stock();
    let (daemon, h) = connect(true);
    let mut out = vec![0u8; l::INFO_LEN];
    let good = route_request(4, "internet.example");
    // any kind but the route lookup (5) and the matching call query (11) is not one
    for mode in [0, 1, 6, 12, -1] {
        let mut out = vec![0xaau8; l::INFO_LEN];
        assert_eq!(lookup_through_the_export(h, &good, &mut out, mode), -1);
        assert_eq!(
            l::rd_u32(&out, route_out::VALID),
            Some(0),
            "cleared on a refusal"
        );
    }
    // a family that is not 4 or 6, a request that is not marked valid, an APN without an end
    for family in [0, 5, 8, 10] {
        assert_eq!(
            lookup_through_the_export(h, &route_request(family, "x"), &mut out, 5),
            -1
        );
    }
    let mut r = route_request(4, "x");
    assert!(l::wr_u32(&mut r, request::VALID, 0));
    assert_eq!(lookup_through_the_export(h, &r, &mut out, 5), -1);
    let unended = "a".repeat(request::APN_LEN);
    assert_eq!(
        lookup_through_the_export(h, &route_request(4, &unended), &mut out, 5),
        -1
    );
    // a subscription outside a byte, null buffers, overlapping buffers
    assert_eq!(
        abi::dsiNicmRouteLookup(h, 300, out.as_mut_ptr() as usize, good.as_ptr() as usize, 5),
        -1
    );
    assert_eq!(
        abi::dsiNicmRouteLookup(h, 0, 0, good.as_ptr() as usize, 5),
        -1
    );
    assert_eq!(
        abi::dsiNicmRouteLookup(h, 0, out.as_mut_ptr() as usize, 0, 5),
        -1
    );
    assert_eq!(
        abi::dsiNicmRouteLookup(0, 0, out.as_mut_ptr() as usize, good.as_ptr() as usize, 5),
        -1
    );
    let mut one = vec![0u8; l::INFO_LEN];
    let p = one.as_mut_ptr() as usize;
    assert_eq!(
        abi::dsiNicmRouteLookup(h, 0, p, p, 5),
        -1,
        "request inside the answer"
    );
    // the answer starts inside the request, after the fields that make it valid
    let mut both = vec![0u8; l::INFO_LEN + 0x100];
    let req = route_request(4, "internet.example");
    assert!(l::wr_bytes(&mut both, 0, &req));
    let base = both.as_mut_ptr() as usize;
    assert_eq!(
        abi::dsiNicmRouteLookup(h, 0, base + 0x20, base, 5),
        -1,
        "answer inside the request"
    );
    // links beyond what the module names, requests that are not 2 to 4, families that are not 2 or 10
    assert_eq!(abi::dsiNicmLinkRelease(h, 33), -1);
    assert_eq!(abi::dsiNicmLinkRelease(h, -1), -1);
    let mut mtu = [0u8; l::MTU_OUT_LEN];
    assert_eq!(
        abi::dsiNicmGetLinkMtu(h, 33, 0, mtu.as_mut_ptr() as usize),
        -1
    );
    assert_eq!(abi::dsiNicmGetLinkMtu(h, 0, 0, 0), -1);
    let mut buf = vec![0u8; l::INFO_LEN];
    for (req, af) in [(1, 2), (5, 2), (2, 0), (2, 4), (3, 11)] {
        assert_eq!(
            abi::dsiNicmProcessPFRequest(h, req, af, buf.as_mut_ptr() as usize),
            -1
        );
    }
    assert_eq!(abi::dsiNicmProcessPFRequest(h, 2, 2, 0), -1);
    assert_eq!(abi::dsiNicmOEMProxy(h, 0, buf.as_mut_ptr() as usize), -1);
    assert_eq!(abi::dsiNicmQueryLLNetworkHndl(h, 0), -1);
    release_handle(h as *mut c_void);
    daemon.kill();
}

/// An event buffer as the library hands it to the callback of the module.
fn event_buf(ev: NicmEvent) -> Box<EventBuf> {
    Box::new(EventBuf::new(ev))
}

fn translate(buf: &EventBuf) -> (i32, Vec<u8>, u32) {
    let info = std::ptr::from_ref(buf) as usize;
    let copy = abi::setNicmInfo(info);
    assert!(!copy.is_null(), "a copy of an event of ours");
    let mut out = vec![0u8; l::INFO_LEN];
    let mut kind = [0xffu8; 4];
    let rc = abi::dsiTranslateNicmEvent(
        copy as usize,
        out.as_mut_ptr() as usize,
        kind.as_mut_ptr() as usize,
    );
    // SAFETY: the copy is a calloc result of setNicmInfo, which the module frees with free.
    unsafe { free(copy) };
    (rc, out, u32::from_le_bytes(kind))
}

#[test]
fn an_event_goes_through_the_copy_and_the_translation_into_the_layout_of_the_module() {
    let _g = exclusive();
    stock();
    // a new IPv4 address
    let mut ev = NicmEvent::new(dataos_nicm_abi::event::NEW_ADDR);
    ev.link = 3;
    ev.slot = 1;
    ev.family = 4;
    ev.value = 29;
    ev.addr[..4].copy_from_slice(&[10, 20, 30, 40]);
    let (rc, out, kind) = translate(&event_buf(ev));
    // the address of a family is the event nicmd sends for it: an up that arrives when the interface
    // was announced already, which is a reconfiguration with the address in it
    assert_eq!((rc, kind), (0, event::KIND_RECONFIGURED));
    assert_eq!(l::rd_u32(&out, event::ID), Some(event::ID_RECONFIGURED));
    assert_eq!(l::rd_u32(&out, event::LINK), Some(3));
    assert_eq!(l::rd_u32(&out, event::SUB), Some(1));
    assert_eq!(l::rd_u16(&out, event::ADDR_FAMILY), Some(l::AF_INET));
    assert_eq!(
        out.get(event::ADDR..event::ADDR + 4),
        Some(&[10, 20, 30, 40][..])
    );
    assert_eq!(l::rd_u32(&out, event::PREFIX), Some(29));
    // an MTU update for IPv4 and then for IPv6 keeps the first when it names the second
    let mut mtu = NicmEvent::new(dataos_nicm_abi::event::MTU_UPDATE);
    mtu.link = 3;
    mtu.family = 4;
    mtu.value = 1500;
    let (rc, out, kind) = translate(&event_buf(mtu));
    assert_eq!((rc, kind), (0, event::KIND_MTU_UPDATE));
    assert_eq!(l::rd_u32(&out, event::MTU_V4), Some(1500));
    assert_eq!(l::rd_u32(&out, event::MTU_V6), Some(0));
    mtu.family = 6;
    mtu.value = 1400;
    let (_, out, _) = translate(&event_buf(mtu));
    assert_eq!(l::rd_u32(&out, event::MTU_V4), Some(1500));
    assert_eq!(l::rd_u32(&out, event::MTU_V6), Some(1400));
    assert_eq!(l::rd_u32(&out, event::MTU_IFACE), Some(1400));
    // the restart notices
    for (k, state) in [
        (dataos_nicm_abi::event::RESTART_START, 0),
        (dataos_nicm_abi::event::RESTART_DONE, 2),
    ] {
        let (rc, out, kind) = translate(&event_buf(NicmEvent::new(k)));
        assert_eq!((rc, kind), (0, 0));
        assert_eq!(l::rd_u32(&out, event::ID), Some(event::ID_USER_CMD));
        assert_eq!(l::rd_u32(&out, event::RESTART_STATE), Some(state));
    }
}

#[test]
fn what_is_not_an_event_of_ours_is_refused_by_the_copy_and_the_translation() {
    let _g = exclusive();
    stock();
    let good = event_buf(NicmEvent::new(dataos_nicm_abi::event::DOWN));
    // the header: the stock library's event info would start with other numbers
    for (magic, size) in [
        (0, 56),
        (dataos_nicm_abi::MAGIC, 57),
        (dataos_nicm_abi::MAGIC, 0),
    ] {
        let mut ev = NicmEvent::new(dataos_nicm_abi::event::DOWN);
        ev.magic = magic;
        ev.size = size;
        let buf = event_buf(ev);
        assert!(abi::setNicmInfo(std::ptr::from_ref(&*buf) as usize).is_null());
    }
    assert!(abi::setNicmInfo(0).is_null());
    // values outside what the module takes: an event kind of nobody, a family, a prefix, a link
    let bad = |f: &dyn Fn(&mut NicmEvent)| {
        let mut ev = NicmEvent::new(dataos_nicm_abi::event::NEW_ADDR);
        ev.family = 4;
        ev.value = 24;
        f(&mut ev);
        translate(&event_buf(ev)).0
    };
    assert_eq!(bad(&|_| {}), 0);
    assert_eq!(bad(&|e| e.kind = 99), -1);
    assert_eq!(bad(&|e| e.family = 5), -1);
    assert_eq!(bad(&|e| e.value = 33), -1);
    assert_eq!(bad(&|e| e.link = 33), -1);
    // null pointers and overlapping buffers
    let copy = abi::setNicmInfo(std::ptr::from_ref(&*good) as usize);
    assert!(!copy.is_null());
    let mut out = vec![0u8; l::INFO_LEN];
    let mut kind = [0u8; 4];
    let (o, k) = (out.as_mut_ptr() as usize, kind.as_mut_ptr() as usize);
    assert_eq!(abi::dsiTranslateNicmEvent(0, o, k), -1);
    assert_eq!(abi::dsiTranslateNicmEvent(copy as usize, 0, k), -1);
    assert_eq!(abi::dsiTranslateNicmEvent(copy as usize, o, 0), -1);
    assert_eq!(
        abi::dsiTranslateNicmEvent(copy as usize, copy as usize, k),
        -1
    );
    // SAFETY: the copy is a calloc result of setNicmInfo, which the module frees with free.
    unsafe { free(copy) };
}

#[test]
fn an_apn_of_the_longest_stock_size_passes_the_whole_path() {
    // The stock Start Network and the stock route lookup take an APN of 150 bytes, and so does the
    // module's request field (151 bytes with the end). A lookup for one must not be refused.
    let _g = exclusive();
    let (daemon, h) = connect(false);
    daemon.up();
    let t = std::time::Instant::now();
    while glue::ready(&abi::LibNicm, h).is_err() {
        assert!(t.elapsed().as_secs() < 5);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_eq!(dataos_nicm_abi::MAX_APN, 150);
    let longest: &'static str = Box::leak("a".repeat(150).into_boxed_str());
    let lookup = |apn| Lookup {
        slot: 0,
        family: Family::V4,
        apn: Some(apn),
        apn_type: 1,
        apn_type_mask: 1,
        profile_3gpp: None,
        profile_3gpp2: None,
        xt_tech_pref: None,
        bu_apn_name: None,
        bu_apn_type: None,
    };
    let ok = glue::route_lookup(&abi::LibNicm, h, &lookup(longest)).unwrap();
    assert_eq!(ok.ifname.as_str(), "rmnet_data0");
    let too_long: &'static str = Box::leak("a".repeat(151).into_boxed_str());
    assert_eq!(
        glue::route_lookup(&abi::LibNicm, h, &lookup(too_long)),
        Err(Failure::BadArgument)
    );
    release_handle(h as *mut c_void);
    daemon.kill();
}

#[test]
fn the_glue_checks_values_and_names_the_failure() {
    let _g = exclusive();
    let (daemon, h) = connect(false);
    let lk = |apn: Option<&'static str>, family| Lookup {
        slot: 0,
        family,
        apn,
        apn_type: 1,
        apn_type_mask: 1,
        profile_3gpp: None,
        profile_3gpp2: None,
        xt_tech_pref: None,
        bu_apn_name: None,
        bu_apn_type: None,
    };
    // the daemon is not ready yet
    assert_eq!(
        glue::route_lookup(&abi::LibNicm, h, &lk(None, Family::V4)),
        Err(Failure::NotReady)
    );
    daemon.up();
    let t = std::time::Instant::now();
    while glue::ready(&abi::LibNicm, h).is_err() {
        assert!(t.elapsed().as_secs() < 5);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    // values outside the bounds never leave
    let long = "a".repeat(dataos_nicm_abi::MAX_APN + 1);
    assert_eq!(
        glue::route_lookup(
            &abi::LibNicm,
            h,
            &lk(Some(Box::leak(long.into_boxed_str())), Family::V4)
        ),
        Err(Failure::BadArgument)
    );
    assert_eq!(
        glue::route_lookup(&abi::LibNicm, h, &lk(Some("a\0b"), Family::V4)),
        Err(Failure::BadArgument)
    );
    // a handle nobody gave out, and a link that does not exist
    assert_eq!(
        glue::link_release(&abi::LibNicm, 0x10, 0),
        Err(Failure::NoAnswer)
    );
    assert_eq!(
        glue::link_release(&abi::LibNicm, h, 7),
        Err(Failure::Refused(3))
    );
    let ok =
        glue::route_lookup(&abi::LibNicm, h, &lk(Some("internet.example"), Family::V6)).unwrap();
    assert_eq!((ok.number, ok.ifname.as_str()), (0, "rmnet_data0"));
    release_handle(h as *mut c_void);
    daemon.kill();
}

#[test]
fn a_daemon_that_does_not_answer_is_named_no_answer_through_the_real_sender() {
    let _g = exclusive();
    dataos_libnicm::state::set_request_timeout_for_tests(150);
    // an end of the socket pair that nobody reads
    let (lib, _silent) = sys::pair().unwrap();
    let ends = Mutex::new(Some(lib));
    let h = register_with(
        no_events,
        UserData::new(std::ptr::null_mut()),
        Box::new(move || {
            ends.lock()
                .unwrap()
                .take()
                .ok_or_else(|| std::io::ErrorKind::ConnectionRefused.into())
        }),
    );
    assert!(!h.is_null());
    assert_eq!(
        glue::link_release(&abi::LibNicm, h as usize, 0),
        Err(Failure::NoAnswer)
    );
    assert_eq!(
        glue::ready(&abi::LibNicm, h as usize),
        Err(Failure::NoAnswer)
    );
    release_handle(h);
    dataos_libnicm::state::set_request_timeout_for_tests(5_000);
}

#[test]
fn the_device_path_keeps_the_mtu_of_the_other_family_between_calls() {
    let _g = exclusive();
    // no implementation installed: the library uses StockAbi by itself, as a device build will
    abi::use_stock_for_tests(true);
    allow_provisional_abi_for_tests(true);
    let mut mtu = NicmEvent::new(dataos_nicm_abi::event::MTU_UPDATE);
    mtu.link = 5;
    mtu.family = 4;
    mtu.value = 1500;
    let (rc, out, _) = translate(&event_buf(mtu));
    assert_eq!(rc, 0);
    assert_eq!(l::rd_u32(&out, event::MTU_V4), Some(1500));
    mtu.family = 6;
    mtu.value = 1400;
    let (_, out, _) = translate(&event_buf(mtu));
    assert_eq!(
        l::rd_u32(&out, event::MTU_V4),
        Some(1500),
        "the other family is kept"
    );
    assert_eq!(l::rd_u32(&out, event::MTU_V6), Some(1400));
    // a call that ended does not leave its MTUs to a new call on the same number
    let down = NicmEvent::new(dataos_nicm_abi::event::DOWN);
    let mut down = down;
    down.link = 5;
    let (rc, _, _) = translate(&event_buf(down));
    assert_eq!(rc, 0);
    mtu.family = 4;
    mtu.value = 1280;
    let (_, out, _) = translate(&event_buf(mtu));
    assert_eq!(
        l::rd_u32(&out, event::MTU_V6),
        Some(0),
        "nothing from the old call"
    );
}

#[test]
fn the_requests_the_daemon_cannot_serve_are_refused_without_waiting_for_it() {
    let _g = exclusive();
    stock();
    dataos_libnicm::state::set_request_timeout_for_tests(2_000);
    // a daemon that never reads: anything sent would wait for the whole timeout
    let (lib, _silent) = sys::pair().unwrap();
    let ends = Mutex::new(Some(lib));
    let h = register_with(
        no_events,
        UserData::new(std::ptr::null_mut()),
        Box::new(move || {
            ends.lock()
                .unwrap()
                .take()
                .ok_or_else(|| std::io::ErrorKind::ConnectionRefused.into())
        }),
    );
    assert!(!h.is_null());
    let mut buf = vec![0u8; l::INFO_LEN];
    let oem_in = [0u8; l::OEM_IN_LEN];
    let mut handle = [0xffu8; l::HANDLE_OUT_LEN];
    let t = std::time::Instant::now();
    assert_eq!(
        abi::dsiNicmOEMProxy(
            h as usize,
            oem_in.as_ptr() as usize,
            buf.as_mut_ptr() as usize
        ),
        -1
    );
    assert_eq!(
        abi::dsiNicmProcessPFRequest(h as usize, 2, 2, buf.as_mut_ptr() as usize),
        -1
    );
    assert_eq!(
        abi::dsiNicmQueryLLNetworkHndl(h as usize, handle.as_mut_ptr() as usize),
        -1
    );
    assert_eq!(handle, [0u8; l::HANDLE_OUT_LEN]);
    assert!(
        t.elapsed() < std::time::Duration::from_millis(500),
        "waited for a daemon that is never asked: {:?}",
        t.elapsed()
    );
    release_handle(h);
    dataos_libnicm::state::set_request_timeout_for_tests(5_000);
}

#[test]
fn the_kind_pointer_may_not_lie_inside_the_event_or_its_copy() {
    let _g = exclusive();
    stock();
    let buf = event_buf(NicmEvent::new(dataos_nicm_abi::event::DOWN));
    let copy = abi::setNicmInfo(std::ptr::from_ref(&*buf) as usize);
    assert!(!copy.is_null());
    let mut out = vec![0u8; l::INFO_LEN];
    let o = out.as_mut_ptr() as usize;
    let c = copy as usize;
    let mut kind = [0u8; 4];
    let k = kind.as_mut_ptr() as usize;
    assert_eq!(
        abi::dsiTranslateNicmEvent(c, o, k),
        0,
        "separate buffers work"
    );
    assert_eq!(
        abi::dsiTranslateNicmEvent(c, o, o + 0x10),
        -1,
        "kind inside the answer"
    );
    assert_eq!(
        abi::dsiTranslateNicmEvent(c, o, c + 0x10),
        -1,
        "kind inside the copy"
    );
    // SAFETY: the copy is a calloc result of setNicmInfo, which the module frees with free.
    unsafe { free(copy) };
}

fn out_buf() -> Vec<u8> {
    vec![0xaau8; l::INFO_LEN]
}

fn wait_for_mtu(h: usize, link: i32) {
    wait_until("the call is up", || {
        let mut mtu = [0u8; l::MTU_OUT_LEN];
        abi::dsiNicmGetLinkMtu(h, link, 0, mtu.as_mut_ptr() as usize) == 0
    });
}

/// A lookup through the export for a family and a subscription, in a buffer that is not clean.
fn lookup_for(h: usize, subs: i32, family: u32, apn: &str, mode: i32) -> (i32, Vec<u8>) {
    let req = route_request(family, apn);
    let mut out = out_buf();
    let rc = abi::dsiNicmRouteLookup(
        h,
        subs,
        out.as_mut_ptr() as usize,
        req.as_ptr() as usize,
        mode,
    );
    (rc, out)
}

#[test]
fn the_subscription_of_a_lookup_is_bound_as_given_and_comes_back_in_the_events() {
    let _g = exclusive();
    stock();
    let (daemon, h) = connect(true);
    for (subs, apn, link) in [(1, "first.example", 0u8), (2, "second.example", 1)] {
        let (rc, out) = lookup_for(h, subs, 4, apn, 5);
        assert_eq!(rc, 0);
        assert_eq!(l::rd_u32(&out, route_out::LINK), Some(u32::from(link)));
        daemon.connect(link + 1);
        wait_for_mtu(h, i32::from(link));
    }
    // the daemon follows both families of a link, each with a client bound to the module's value
    assert_eq!(
        *daemon.bound.lock().unwrap(),
        [1, 1, 2, 2],
        "the values the module gave"
    );
    // the events come on the listener thread of the library, so they may lag behind the MTU
    let t = std::time::Instant::now();
    while EVENTS.lock().unwrap().len() < 4 {
        assert!(t.elapsed().as_secs() < 5, "up and address for each");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let events = EVENTS.lock().unwrap().clone();
    for ev in events {
        let (rc, out, _) = translate(&event_buf(ev));
        assert_eq!(rc, 0);
        let want = ev.link + 1;
        assert_eq!(l::rd_u32(&out, event::SUB), Some(want), "link {}", ev.link);
    }
    release_handle(h as *mut c_void);
    daemon.kill();
}

#[test]
fn the_flags_of_a_call_that_is_up_reach_the_module_with_the_second_family() {
    let _g = exclusive();
    stock();
    let (daemon, h) = connect(true);
    // nothing is up: a new call, no flags
    let (rc, out) = lookup_for(h, 0, 4, "internet.example", 5);
    assert_eq!(rc, 0);
    assert_eq!(l::rd_u32(&out, route_out::VALID), Some(0));
    daemon.connect(1);
    wait_for_mtu(h, 0);
    // the other family of the call that is up: the instance exists and is the companion's
    let (rc, out) = lookup_for(h, 0, 6, "internet.example", 5);
    assert_eq!(rc, 0);
    assert_eq!(l::rd_u32(&out, route_out::VALID), Some(1));
    assert_eq!(l::rd_u32(&out, route_out::COMPANION), Some(1));
    assert_eq!(l::rd_u32(&out, route_out::LINK), Some(0));
    release_handle(h as *mut c_void);
    daemon.kill();
}

#[test]
fn a_link_that_went_down_does_not_leave_its_mtu_to_the_next_call_on_the_number() {
    let _g = exclusive();
    stock();
    let (daemon, h) = connect(true);
    let (rc, _) = lookup_for(h, 0, 4, "internet.example", 5);
    assert_eq!(rc, 0);
    let mtu_event = |family: u32, value: u32| {
        let mut ev = NicmEvent::new(dataos_nicm_abi::event::MTU_UPDATE);
        ev.link = 0;
        ev.family = family;
        ev.value = value;
        let (_, out, _) = translate(&event_buf(ev));
        (
            l::rd_u32(&out, event::MTU_V4),
            l::rd_u32(&out, event::MTU_V6),
        )
    };
    assert_eq!(mtu_event(4, 1500), (Some(1500), Some(0)));
    assert_eq!(mtu_event(6, 1400), (Some(1500), Some(1400)), "remembered");
    // a release that the daemon keeps (the call is up) and a failed operation forget nothing
    assert_eq!(abi::dsiNicmLinkRelease(h, 0), 0);
    let mut failed = NicmEvent::new(dataos_nicm_abi::event::OP_FAILED);
    failed.link = 0;
    translate(&event_buf(failed));
    assert_eq!(
        mtu_event(6, 1350),
        (Some(1500), Some(1350)),
        "still remembered"
    );
    // the module hears the link down: from then on it is forgotten
    let mut down = NicmEvent::new(dataos_nicm_abi::event::DOWN);
    down.link = 0;
    translate(&event_buf(down));
    assert_eq!(
        mtu_event(6, 1300),
        (Some(0), Some(1300)),
        "forgotten with the call"
    );
    release_handle(h as *mut c_void);
    daemon.kill();
}

#[test]
fn a_second_request_for_the_apn_of_a_call_that_is_up_gets_its_interface() {
    let _g = exclusive();
    stock();
    let (daemon, h) = connect(true);
    let (rc, _) = lookup_for(h, 0, 4, "internet.example", 5);
    assert_eq!(rc, 0);
    daemon.connect(1);
    wait_for_mtu(h, 0);
    daemon.names(4, 0);
    let (rc, out) = lookup_for(h, 0, 4, "internet.example", 11);
    assert_eq!(rc, 0);
    assert_eq!(out.get(0x3a0..0x3a0 + 12), Some(&b"rmnet_data0\0"[..]));
    assert_eq!(l::rd_u32(&out, 0x3b4), Some(1));
    assert_eq!(
        out.iter().filter(|b| **b != 0).count(),
        11 + 1,
        "the rest is clear"
    );
    // no new link was taken: the next new call still gets the next number
    let (rc, out) = lookup_for(h, 0, 4, "other.example", 5);
    assert_eq!((rc, l::rd_u32(&out, route_out::LINK)), (0, Some(1)));
    // another APN, another subscription, an instance that is not ours: no matching call, the mark stays 0
    for (subs, apn, instance) in [
        (0, "ims.example", 0),
        (2, "internet.example", 0),
        (0, "internet.example", 9),
    ] {
        daemon.names(4, instance);
        daemon.names(6, instance);
        let (rc, out) = lookup_for(h, subs, 4, apn, 11);
        assert_eq!(rc, -1, "{apn} {subs} {instance}");
        assert!(out.iter().all(|b| *b == 0), "cleared, nothing marked");
    }
    release_handle(h as *mut c_void);
    daemon.kill();
}

#[test]
fn the_other_values_of_the_modules_request_reach_the_modem_in_a_matching_call() {
    let _g = exclusive();
    stock();
    let (daemon, h) = connect(true);
    let (rc, _) = lookup_for(h, 0, 4, "internet.example", 5);
    assert_eq!(rc, 0);
    daemon.connect(1);
    wait_for_mtu(h, 0);
    daemon.names(4, 0);
    let mut req = route_request(4, "internet.example");
    let mask = l::rd_u64(&req, request::MASK).unwrap()
        | request::MASK_PROFILE_3GPP
        | request::MASK_PROFILE_3GPP2
        | request::MASK_XT_TECH_PREF
        | request::MASK_BU_APN_NAME
        | request::MASK_BU_APN_TYPE;
    assert!(l::wr_u64(&mut req, request::MASK, mask));
    assert!(l::wr_u8(&mut req, request::PROFILE_3GPP, 3));
    assert!(l::wr_u8(&mut req, request::PROFILE_3GPP2, 4));
    assert!(l::wr_u32(&mut req, request::XT_TECH_PREF, 0x0102));
    assert!(l::wr_u32(&mut req, request::BU_APN_NAME, 1));
    assert!(l::wr_u32(&mut req, request::BU_APN_TYPE, 2));
    let mut out = out_buf();
    let rc = abi::dsiNicmRouteLookup(h, 0, out.as_mut_ptr() as usize, req.as_ptr() as usize, 11);
    assert_eq!(rc, 0);
    wait_until("the question reached the modem", || {
        !daemon.asked.lock().unwrap().is_empty()
    });
    let frames = daemon.asked.lock().unwrap().clone();
    let frame = frames.first().unwrap();
    // a QMI message: 7 bytes of header, then tag, 16 bit length and value
    let tlv = |tag: u8| -> Option<Vec<u8>> {
        let mut rest = frame.get(7..)?;
        while rest.len() >= 3 {
            let len = usize::from(u16::from_le_bytes([rest[1], rest[2]]));
            let value = rest.get(3..3 + len)?;
            if rest[0] == tag {
                return Some(value.to_vec());
            }
            rest = rest.get(3 + len..)?;
        }
        None
    };
    assert_eq!(tlv(0x31), Some(vec![3]));
    assert_eq!(tlv(0x32), Some(vec![4]));
    assert_eq!(tlv(0x34), Some(vec![2, 1]));
    assert_eq!(tlv(0x3c), Some(vec![1]));
    assert_eq!(tlv(0x3d), Some(vec![2]));
    release_handle(h as *mut c_void);
    daemon.kill();
}

#[test]
fn a_route_lookup_with_a_preference_asks_the_modem_and_writes_the_wifi_technology() {
    let _g = exclusive();
    stock();
    let (daemon, h) = connect(true);
    daemon.technology(4, 0x8021);
    let mut req = route_request(4, "ims.example");
    let mask = l::rd_u64(&req, request::MASK).unwrap() | request::MASK_XT_TECH_PREF;
    assert!(l::wr_u64(&mut req, request::MASK, mask));
    assert!(l::wr_u32(&mut req, request::XT_TECH_PREF, 0x0102));
    let mut out = out_buf();
    let rc = abi::dsiNicmRouteLookup(h, 0, out.as_mut_ptr() as usize, req.as_ptr() as usize, 5);
    assert_eq!(rc, 0);
    assert_eq!(l::rd_u32(&out, route_out::TECH), Some(0x8021));
    let frames = daemon.asked.lock().unwrap().clone();
    let frame = frames.first().unwrap();
    assert!(frame.windows(5).any(|w| w == [0x34, 2, 0, 2, 1]));
    // without a preference the modem is not asked and the fixed value stands
    let (rc, out) = lookup_for(h, 0, 4, "other.example", 5);
    assert_eq!(rc, 0);
    assert_eq!(l::rd_u32(&out, route_out::TECH), Some(l::TECH_DEFAULT));
    assert_eq!(daemon.asked.lock().unwrap().len(), frames.len());
    release_handle(h as *mut c_void);
    daemon.kill();
}
