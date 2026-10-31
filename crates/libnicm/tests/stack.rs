// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The library against a real daemon server in another thread, over a socket
//! pair. The data module's callback is a function of this test. Simulation only.
//! The process has one connection, so the tests run one after the other.
#![allow(clippy::disallowed_methods, unsafe_code)]
use dataos_datacore::engine::{Config, Engine, ServiceEvent};
use dataos_datacore::sim::SimModem;
use dataos_datad::server::{Server, ServerConfig};
use dataos_libnicm::abi::Callback;
use dataos_libnicm::abi::{
    register_with, release_handle, reset_for_tests, send_cmd, withheld_events, UserData,
};
use dataos_libnicm::state::{
    fail_descriptor_copies_for_tests, request_wait, resync_hook_for_tests,
    set_request_timeout_for_tests, set_retry_first_for_tests, MATCHING_CALL_TIMEOUT_MS,
    REQUEST_TIMEOUT_MS,
};
use dataos_libnicm::sys;
use dataos_netcfg::FakeNet;
use dataos_nicm_abi::{
    allow_provisional_abi_for_tests, event, hint, kind, status, EventBuf, NicmCmd, NicmEvent,
    NicmReply,
};
use dataos_wire::limits::MAX_MESSAGE;
use dataos_wire::ResultCode;
use std::ffi::c_void;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());
static EVENTS: Mutex<Vec<NicmEvent>> = Mutex::new(Vec::new());
static CALLBACK_ASKED: Mutex<Vec<i32>> = Mutex::new(Vec::new());

/// Callbacks that got user data other than the registered value, with the test that was running.
/// A callback is an `extern "C"` function, a panic in it would end the process without saying which
/// test it was, so the callback writes the value down and the test checks when it ends.
static BAD_USER: Mutex<Vec<usize>> = Mutex::new(Vec::new());

struct Exclusive {
    _g: MutexGuard<'static, ()>,
}

impl Drop for Exclusive {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let bad = BAD_USER.lock().unwrap().clone();
            assert!(bad.is_empty(), "callbacks got other user data: {bad:x?}");
        }
    }
}

fn exclusive() -> Exclusive {
    let g = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    reset_for_tests();
    EVENTS.lock().unwrap().clear();
    CALLBACK_ASKED.lock().unwrap().clear();
    BAD_USER.lock().unwrap().clear();
    set_request_timeout_for_tests(5_000);
    set_retry_first_for_tests(1_000);
    allow_provisional_abi_for_tests(false);
    Exclusive { _g: g }
}

#[derive(Default)]
struct Control {
    commands: Vec<Command>,
}

enum Command {
    ModemUp,
    ModemDown,
    Connect(u8),
    Disconnect(u8),
}

struct Daemon {
    control: Arc<Mutex<Control>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Daemon {
    fn send(&self, c: Command) {
        self.control.lock().unwrap().commands.push(c);
    }

    fn up(&self) {
        self.send(Command::ModemUp);
    }

    /// Stop serving: the connection closes.
    fn kill(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            t.join().unwrap();
        }
    }
}

fn spawn_daemon(fd: OwnedFd, mute: bool) -> Daemon {
    let control = Arc::new(Mutex::new(Control::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let (c2, s2) = (control.clone(), stop.clone());
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
            for c in std::mem::take(&mut c2.lock().unwrap().commands) {
                now += 1;
                match c {
                    Command::ModemUp => server.on_service_event(now, ServiceEvent::ModemUp),
                    Command::ModemDown => server.on_service_event(now, ServiceEvent::ModemDown),
                    Command::Connect(m) => server.engine().qmi_mut().external_connect(m),
                    Command::Disconnect(m) => {
                        server.engine().qmi_mut().external_disconnect(m, 3, 26)
                    }
                }
            }
            loop {
                let next = server.engine().qmi_mut().inbox.pop_front();
                match next {
                    Some((c, b)) => server.on_qmi(now, c, &b),
                    None => break,
                }
            }
            let _ = sys::wait(Some(fd.as_fd()), wake.as_fd(), 5);
            let mut buf = [0u8; MAX_MESSAGE + 1];
            while let Ok(Some(n)) = sys::recv(fd.as_fd(), &mut buf) {
                if n == 0 {
                    return;
                }
                if !mute {
                    now += 1;
                    let _ = server.on_datagram(now, conn, &buf[..n]);
                }
            }
            for d in server.drain_encoded(conn) {
                let _ = sys::send(fd.as_fd(), &d);
            }
        }
        // dropping fd closes the connection
    });
    Daemon {
        control,
        stop,
        thread: Some(thread),
    }
}

/// A connector that hands out the daemon's ends one after the other.
fn connector(ends: Vec<OwnedFd>) -> dataos_libnicm::state::Connector {
    let ends = Mutex::new(ends.into_iter());
    Box::new(move || {
        ends.lock()
            .unwrap()
            .next()
            .ok_or_else(|| std::io::ErrorKind::ConnectionRefused.into())
    })
}

extern "C" fn on_event(ev: *mut c_void, user: *mut c_void) {
    if user as usize != 0x1234 {
        BAD_USER.lock().unwrap().push(user as usize);
    }
    // SAFETY: the library passes a pointer to an EventBuf that lives through the call.
    let e = unsafe { (*ev.cast::<EventBuf>()).ev };
    EVENTS.lock().unwrap().push(e);
}

extern "C" fn on_event_asking(ev: *mut c_void, user: *mut c_void) {
    on_event(ev, user);
    // the module calls back from its callback: this must not wait for ever
    let mut cmd = NicmCmd::new(kind::QUERY_MTU);
    cmd.link = 0;
    let mut reply = NicmReply::failed(0);
    let h = HANDLE.load(std::sync::atomic::Ordering::SeqCst) as *mut c_void;
    // SAFETY: cmd and reply are valid for the call.
    let rc = unsafe { send_cmd(h, &cmd, &mut reply) };
    CALLBACK_ASKED.lock().unwrap().push(rc);
}

static HANDLE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn ask(h: *mut c_void, cmd: NicmCmd) -> (i32, NicmReply) {
    let mut reply = NicmReply::failed(999);
    // SAFETY: cmd and reply are valid for the call.
    let rc = unsafe { send_cmd(h, &cmd, &mut reply) };
    (rc, reply)
}

fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < Duration::from_secs(5), "waited for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn lookup(family: u32) -> NicmCmd {
    let mut c = NicmCmd::new(kind::ROUTE_LOOKUP);
    c.slot = 0;
    c.family = family;
    c.apn_type = 1;
    c.apn_type_mask = 1;
    let apn = b"internet.example";
    c.apn[..apn.len()].copy_from_slice(apn);
    c.apn_len = apn.len() as u32;
    c
}

fn events_of(k: u32) -> usize {
    EVENTS
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.kind == k)
        .count()
}

fn start(cb: Callback, ends: Vec<OwnedFd>) -> *mut c_void {
    let h = register_with(cb, UserData::new(0x1234 as *mut c_void), connector(ends));
    assert!(!h.is_null());
    HANDLE.store(h as usize, Ordering::SeqCst);
    h
}

#[test]
fn a_lookup_a_call_the_events_and_the_release_through_the_library() {
    let _g = exclusive();
    allow_provisional_abi_for_tests(true);
    let (lib, d) = sys::pair().unwrap();
    let daemon = spawn_daemon(d, false);
    let h = start(on_event_asking, vec![lib]);
    // the readiness query says not ready until the modem is up
    let (rc, r) = ask(h, NicmCmd::new(kind::READY));
    assert_eq!((rc, r.status), (0, 6));
    daemon.up();
    wait_for("ready", || {
        ask(h, NicmCmd::new(kind::READY)).1.status == status::OK
    });
    let (rc, r) = ask(h, lookup(4));
    assert_eq!((rc, r.status, r.link), (0, status::OK, 0));
    assert_eq!(&r.ifname[..r.name_len as usize], b"rmnet_data0");
    daemon.send(Command::Connect(1));
    wait_for("the events", || events_of(event::NEW_ADDR) == 1);
    let evs = EVENTS.lock().unwrap().clone();
    assert_eq!(
        evs.iter().map(|e| e.kind).collect::<Vec<_>>(),
        vec![event::UP, event::NEW_ADDR]
    );
    assert_eq!((evs[1].family, evs[1].value), (4, 30));
    assert_eq!(&evs[1].addr[..4], &[192, 0, 2, 10]);
    // the callback asked for the MTU from its own thread and got an answer
    wait_for("the callback's question", || {
        CALLBACK_ASKED.lock().unwrap().len() == 2
    });
    assert!(CALLBACK_ASKED.lock().unwrap().iter().all(|rc| *rc == 0));
    let (rc, r) = ask(h, NicmCmd::new(kind::QUERY_MTU));
    assert_eq!((rc, r.status, r.v4_mtu), (0, status::OK, 1400));
    daemon.send(Command::Disconnect(1));
    wait_for("the end of the call", || events_of(event::DOWN) == 1);
    assert_eq!(events_of(event::DEL_ADDR), 1);
    let mut rel = NicmCmd::new(kind::LINK_RELEASE);
    rel.link = 0;
    assert_eq!(
        ask(h, rel).1.status,
        3,
        "the link went with the end of the call"
    );
    release_handle(h);
    daemon.kill();
}

#[test]
fn events_are_withheld_while_the_layouts_are_not_verified() {
    // the run with the flag on has nothing to withhold
    if dataos_nicm_abi::STOCK_ABI_VERIFIED {
        return;
    }
    let _g = exclusive();
    let (lib, d) = sys::pair().unwrap();
    let daemon = spawn_daemon(d, false);
    let h = start(on_event, vec![lib]);
    daemon.up();
    wait_for("ready", || {
        ask(h, NicmCmd::new(kind::READY)).1.status == status::OK
    });
    assert_eq!(ask(h, lookup(4)).1.status, status::OK);
    daemon.send(Command::Connect(1));
    wait_for("the events", || withheld_events() == 2);
    assert!(
        EVENTS.lock().unwrap().is_empty(),
        "the module's callback was not called"
    );
    release_handle(h);
    daemon.kill();
}

#[test]
fn a_lost_daemon_fails_what_waits_announces_the_restart_and_connects_again() {
    let _g = exclusive();
    allow_provisional_abi_for_tests(true);
    let (lib1, d1) = sys::pair().unwrap();
    let (lib2, d2) = sys::pair().unwrap();
    let first = spawn_daemon(d1, false);
    let h = start(on_event, vec![lib1, lib2]);
    first.up();
    wait_for("ready", || {
        ask(h, NicmCmd::new(kind::READY)).1.status == status::OK
    });
    // the daemon goes away
    first.kill();
    // a request notices it first or the listener does, either way it fails
    let (rc, r) = ask(h, NicmCmd::new(kind::QUERY_MTU));
    assert_eq!((rc, r.status), (0, status::TRANSPORT));
    wait_for("the restart notice", || {
        events_of(event::RESTART_START) == 1
    });
    // the second connection is made after the first pause, the new daemon is ready
    let second = spawn_daemon(d2, false);
    second.up();
    wait_for("the end of the restart", || {
        events_of(event::RESTART_DONE) == 1
    });
    assert_eq!(ask(h, NicmCmd::new(kind::READY)).1.status, status::OK);
    assert_eq!(events_of(event::RESTART_START), 1);
    release_handle(h);
    second.kill();
}

/// The daemon's end of the first connection, for the hook that writes to it.
static DAEMON_END: Mutex<Option<OwnedFd>> = Mutex::new(None);

fn write_a_down_into_the_socket() {
    let down = dataos_wire::Notify::Event {
        link: 6,
        slot: 0,
        event: dataos_wire::IfaceEvent::Down(dataos_wire::EndReason::Qmi(1)),
    };
    if let Some(fd) = DAEMON_END.lock().unwrap().as_ref() {
        sys::send(fd.as_fd(), &down.encode().unwrap()).unwrap();
    }
}

/// What the daemon has written and the reader has not taken is read before the connection is given up, and
/// the module hears it ahead of INIT_START. The hook writes the Down while the reader is kept from the socket.
#[test]
fn a_down_still_in_the_socket_is_read_before_the_connection_is_given_up() {
    let _g = exclusive();
    allow_provisional_abi_for_tests(true);
    set_retry_first_for_tests(50);
    GATE.store(true, Ordering::SeqCst);
    let (lib, d) = sys::pair().unwrap();
    let (lib2, d2) = sys::pair().unwrap();
    let h = start(on_event_gated, vec![lib, lib2]);
    let sender = flood(d, 20_000);
    let again = replaying(d2);
    *DAEMON_END.lock().unwrap() = Some(sender.join().unwrap());
    resync_hook_for_tests(Some(write_a_down_into_the_socket));
    GATE.store(false, Ordering::SeqCst);
    wait_for("the replay", || events_of(event::UP) >= 1);
    let _second = again.join().unwrap();
    resync_hook_for_tests(None);
    *DAEMON_END.lock().unwrap() = None;
    let events = EVENTS.lock().unwrap().clone();
    let last_event = events
        .iter()
        .rposition(|e| e.kind == event::RECONFIGURED)
        .unwrap();
    let kinds: Vec<(u32, u32)> = events
        .iter()
        .skip(last_event + 1)
        .map(|e| (e.kind, e.link))
        .collect();
    assert_eq!(
        kinds,
        vec![
            (event::DOWN, 6),
            (event::RESTART_START, 0),
            (event::RESTART_DONE, 0),
            (event::UP, 0)
        ]
    );
    release_handle(h);
}

/// A connection that cannot be waited on, because its descriptor cannot be copied, is a connection
/// that is lost: the module hears INIT_START, and INIT_DONE when the connection is made again.
#[test]
fn a_connection_that_cannot_be_waited_on_is_lost_and_the_module_is_told() {
    let _g = exclusive();
    allow_provisional_abi_for_tests(true);
    set_retry_first_for_tests(50);
    let (lib1, d1) = sys::pair().unwrap();
    let (lib2, d2) = sys::pair().unwrap();
    let first = spawn_daemon(d1, false);
    let second = spawn_daemon(d2, false);
    let h = start(on_event, vec![lib1, lib2]);
    first.up();
    second.up();
    wait_for("ready", || {
        ask(h, NicmCmd::new(kind::READY)).1.status == status::OK
    });
    fail_descriptor_copies_for_tests(true);
    // the reader wakes for the answer and meets the failure
    let _ = ask(h, NicmCmd::new(kind::QUERY_MTU));
    wait_for("the restart notice", || {
        events_of(event::RESTART_START) >= 1
    });
    fail_descriptor_copies_for_tests(false);
    wait_for("the end of the restart", || {
        events_of(event::RESTART_DONE) >= 1
    });
    release_handle(h);
    first.kill();
    second.kill();
}

/// The descriptors this process holds open.
fn open_descriptors() -> usize {
    // SAFETY: fcntl with F_GETFD only reads the flags of a descriptor, whether it is open or not.
    (0..4096)
        .filter(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } != -1)
        .count()
}

/// The count once the reader has settled: it holds a copy of the connection only while it waits on it.
fn settled_descriptors() -> usize {
    let mut last = open_descriptors();
    for _ in 0..100 {
        std::thread::sleep(Duration::from_millis(50));
        let now = open_descriptors();
        if now == last {
            return now;
        }
        last = now;
    }
    last
}

/// A connection that is given up is closed at once: its descriptor is released, and not held until the next
/// connection replaces it, which a daemon on Linux would meet as a connection that never ends. Of the two
/// descriptors fewer afterwards, one is the copy the reader waited on and one is the connection.
#[test]
fn a_connection_that_is_given_up_is_closed_and_not_held_until_the_next_one() {
    let _g = exclusive();
    allow_provisional_abi_for_tests(true);
    set_retry_first_for_tests(30_000);
    let (lib1, d1) = sys::pair().unwrap();
    let (lib2, _d2) = sys::pair().unwrap();
    let first = spawn_daemon(d1, false);
    let h = start(on_event, vec![lib1, lib2]);
    first.up();
    wait_for("ready", || {
        ask(h, NicmCmd::new(kind::READY)).1.status == status::OK
    });
    let before = settled_descriptors();
    fail_descriptor_copies_for_tests(true);
    let _ = ask(h, NicmCmd::new(kind::QUERY_MTU));
    wait_for("the restart notice", || {
        events_of(event::RESTART_START) >= 1
    });
    assert_eq!(settled_descriptors() + 2, before);
    fail_descriptor_copies_for_tests(false);
    release_handle(h);
    first.kill();
}

#[test]
fn a_modem_restart_is_announced_to_the_module_and_its_end_too() {
    let _g = exclusive();
    allow_provisional_abi_for_tests(true);
    let (lib, d) = sys::pair().unwrap();
    let daemon = spawn_daemon(d, false);
    let h = start(on_event, vec![lib]);
    daemon.up();
    wait_for("ready", || {
        ask(h, NicmCmd::new(kind::READY)).1.status == status::OK
    });
    assert_eq!(ask(h, lookup(4)).1.status, status::OK);
    daemon.send(Command::ModemDown);
    wait_for("the restart", || events_of(event::RESTART_START) == 1);
    assert_eq!(
        ask(h, NicmCmd::new(kind::READY)).1.status,
        6,
        "not ready now"
    );
    daemon.up();
    wait_for("the end", || events_of(event::RESTART_DONE) == 1);
    // the link of the old call went back with the restart, and its number is not handed
    // out at once: the module may still release the old call
    assert_eq!(ask(h, lookup(4)).1.link, 1);
    release_handle(h);
    daemon.kill();
}

#[test]
fn a_daemon_that_never_answers_is_waited_for_a_while_and_no_longer() {
    let _g = exclusive();
    set_request_timeout_for_tests(150);
    let (lib, d) = sys::pair().unwrap();
    let daemon = spawn_daemon(d, true);
    let h = start(on_event, vec![lib]);
    let t = Instant::now();
    let (rc, r) = ask(h, NicmCmd::new(kind::QUERY_MTU));
    assert_eq!((rc, r.status), (0, status::TIMEOUT));
    assert!(t.elapsed() >= Duration::from_millis(150) && t.elapsed() < Duration::from_secs(3));
    release_handle(h);
    daemon.kill();
}

#[test]
fn handles_commands_and_pointers_are_checked() {
    let _g = exclusive();
    let (lib, d) = sys::pair().unwrap();
    let daemon = spawn_daemon(d, false);
    let h = start(on_event, vec![lib]);
    daemon.up();
    wait_for("ready", || {
        ask(h, NicmCmd::new(kind::READY)).1.status == status::OK
    });
    // a handle that was never given out, null pointers, a second release
    let mut reply = NicmReply::failed(0);
    let cmd = NicmCmd::new(kind::READY);
    // SAFETY: the pointers are valid or null, which send_cmd accepts.
    unsafe {
        assert_eq!(send_cmd(0x10 as *mut c_void, &cmd, &mut reply), -1);
        assert_eq!(send_cmd(h, std::ptr::null(), &mut reply), -1);
        assert_eq!(send_cmd(h, &cmd, std::ptr::null_mut()), -1);
    }
    // a command that is not one of ours (the stock library's would start with other numbers)
    // is refused and the reply is left as it was
    for (magic, size) in [
        (0, 512),
        (dataos_nicm_abi::MAGIC, 296),
        (dataos_nicm_abi::MAGIC, 0),
    ] {
        let mut other = NicmCmd::new(kind::READY);
        other.magic = magic;
        other.size = size;
        let mut untouched = NicmReply::failed(999);
        // SAFETY: the pointers are valid.
        assert_eq!(unsafe { send_cmd(h, &other, &mut untouched) }, -1);
        assert_eq!(untouched.status, 999);
    }
    release_handle(0x10 as *mut c_void);
    release_handle(std::ptr::null_mut());
    // values outside their bounds never reach the daemon
    let mut c = lookup(5);
    assert_eq!(ask(h, c).1.status, status::BAD_ARGUMENT);
    c = lookup(4);
    c.slot = 300;
    assert_eq!(ask(h, c).1.status, status::BAD_ARGUMENT);
    c = lookup(4);
    c.apn_len = dataos_nicm_abi::MAX_APN as u32 + 1;
    assert_eq!(ask(h, c).1.status, status::BAD_ARGUMENT);
    c = lookup(4);
    c.apn[0] = 0;
    assert_eq!(ask(h, c).1.status, status::BAD_ARGUMENT);
    assert_eq!(ask(h, NicmCmd::new(99)).1.status, status::BAD_ARGUMENT);
    let mut l = NicmCmd::new(kind::LINK_RELEASE);
    l.link = 256;
    assert_eq!(ask(h, l).1.status, status::BAD_ARGUMENT);
    // and the daemon's own refusals come back with their code
    let (rc, r) = ask(h, NicmCmd::new(kind::QUERY_MTU));
    assert_eq!(rc, 0);
    assert_ne!(r.status, status::OK);
    release_handle(h);
    release_handle(h);
    assert_eq!(
        ask(h, NicmCmd::new(kind::READY)).0,
        -1,
        "a released handle is dead"
    );
    daemon.kill();
}

#[test]
fn only_a_few_registrations_and_the_connection_ends_with_the_last() {
    let _g = exclusive();
    let (lib, d) = sys::pair().unwrap();
    let daemon = spawn_daemon(d, false);
    let first = start(on_event, vec![lib]);
    let mut more = Vec::new();
    for _ in 0..3 {
        let h = register_with(
            on_event,
            UserData::new(0x1234 as *mut c_void),
            connector(vec![]),
        );
        assert!(!h.is_null());
        more.push(h);
    }
    let fifth = register_with(
        on_event,
        UserData::new(0x1234 as *mut c_void),
        connector(vec![]),
    );
    assert!(fifth.is_null(), "four registrations at most");
    for h in more {
        release_handle(h);
    }
    daemon.up();
    wait_for("ready", || {
        ask(first, NicmCmd::new(kind::READY)).1.status == status::OK
    });
    release_handle(first);
    daemon.kill();
    // and a new start works
    let (lib, d) = sys::pair().unwrap();
    let daemon = spawn_daemon(d, false);
    let again = start(on_event, vec![lib]);
    daemon.up();
    wait_for("ready again", || {
        ask(again, NicmCmd::new(kind::READY)).1.status == status::OK
    });
    release_handle(again);
    daemon.kill();
}

static RELEASED_IN_CALLBACK: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

extern "C" fn on_event_releasing(ev: *mut c_void, user: *mut c_void) {
    on_event(ev, user);
    // the module releases its registration from its own callback
    release_handle(HANDLE.load(Ordering::SeqCst) as *mut c_void);
    RELEASED_IN_CALLBACK.fetch_add(1, Ordering::SeqCst);
}

#[test]
fn a_callback_may_release_the_last_registration() {
    let _g = exclusive();
    allow_provisional_abi_for_tests(true);
    RELEASED_IN_CALLBACK.store(0, Ordering::SeqCst);
    let (lib, d) = sys::pair().unwrap();
    let daemon = spawn_daemon(d, false);
    let h = start(on_event_releasing, vec![lib]);
    daemon.up();
    wait_for("ready", || {
        ask(h, NicmCmd::new(kind::READY)).1.status == status::OK
    });
    assert_eq!(ask(h, lookup(4)).1.status, status::OK);
    daemon.send(Command::Connect(1));
    wait_for("the release from the callback", || {
        RELEASED_IN_CALLBACK.load(Ordering::SeqCst) >= 1
    });
    // the handle is dead, and nothing is delivered after the release
    assert_eq!(ask(h, NicmCmd::new(kind::READY)).0, -1);
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(RELEASED_IN_CALLBACK.load(Ordering::SeqCst), 1);
    assert_eq!(
        EVENTS.lock().unwrap().len(),
        1,
        "only the event of the callback"
    );
    daemon.kill();
}

static IN_SLOW: AtomicBool = AtomicBool::new(false);
static LET_GO: AtomicBool = AtomicBool::new(false);
static SLOW_DONE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

extern "C" fn on_event_slow(ev: *mut c_void, user: *mut c_void) {
    on_event(ev, user);
    IN_SLOW.store(true, Ordering::SeqCst);
    while !LET_GO.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(1));
    }
    SLOW_DONE.fetch_add(1, Ordering::SeqCst);
}

#[test]
fn a_release_waits_for_the_callback_that_is_running_and_none_follows() {
    let _g = exclusive();
    allow_provisional_abi_for_tests(true);
    IN_SLOW.store(false, Ordering::SeqCst);
    LET_GO.store(false, Ordering::SeqCst);
    SLOW_DONE.store(0, Ordering::SeqCst);
    // whatever happens, the callback is let go when the test ends, or the next test would wait for it
    struct LetGo;
    impl Drop for LetGo {
        fn drop(&mut self) {
            LET_GO.store(true, Ordering::SeqCst);
        }
    }
    let _let_go = LetGo;
    let (lib, d) = sys::pair().unwrap();
    let daemon = spawn_daemon(d, false);
    let slow = start(on_event_slow, vec![lib]);
    // a second registration, so that releasing the first is not the last release
    let other = register_with(
        on_event,
        UserData::new(0x1234 as *mut c_void),
        connector(vec![]),
    );
    assert!(!other.is_null());
    daemon.up();
    wait_for("ready", || {
        ask(slow, NicmCmd::new(kind::READY)).1.status == status::OK
    });
    assert_eq!(ask(slow, lookup(4)).1.status, status::OK);
    daemon.send(Command::Connect(1));
    wait_for("the callback", || IN_SLOW.load(Ordering::SeqCst));
    let slow_addr = slow as usize;
    let released = Arc::new(AtomicBool::new(false));
    let r2 = released.clone();
    let t = std::thread::spawn(move || {
        release_handle(slow_addr as *mut c_void);
        r2.store(true, Ordering::SeqCst);
    });
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !released.load(Ordering::SeqCst),
        "the release returned while the callback was still running"
    );
    LET_GO.store(true, Ordering::SeqCst);
    t.join().unwrap();
    assert_eq!(
        SLOW_DONE.load(Ordering::SeqCst),
        1,
        "the callback had returned when the release did"
    );
    // the first registration gets nothing more, the second still does
    let seen = SLOW_DONE.load(Ordering::SeqCst);
    wait_for("the events of the other registration", || {
        events_of(event::NEW_ADDR) >= 1
    });
    assert_eq!(SLOW_DONE.load(Ordering::SeqCst), seen);
    release_handle(other);
    daemon.kill();
}

/// A daemon that does nothing but send events, as fast as the socket takes them.
fn flood(fd: OwnedFd, count: u32) -> JoinHandle<OwnedFd> {
    std::thread::spawn(move || {
        let (_, wake) = sys::pair().unwrap();
        let ev = dataos_wire::Notify::Event {
            link: 0,
            slot: 0,
            event: dataos_wire::IfaceEvent::Reconfigured,
        };
        let bytes = ev.encode().unwrap();
        let ready = dataos_wire::Notify::Ready { ready: true }.encode().unwrap();
        let _ = sys::send(fd.as_fd(), &ready);
        let mut sent = 0;
        while sent < count {
            match sys::send(fd.as_fd(), &bytes) {
                Ok(()) => sent += 1,
                Err(_) => {
                    let _ = sys::wait(None, wake.as_fd(), 1);
                }
            }
        }
        // the connection stays open, so that no end of it is told to the module
        fd
    })
}

/// The daemon that the library finds when it connects again after the flood: it answers the Hello with
/// readiness and then replays one interface that is up.
fn replaying(fd: OwnedFd) -> JoinHandle<OwnedFd> {
    std::thread::spawn(move || {
        let (_, wake) = sys::pair().unwrap();
        let mut buf = [0u8; MAX_MESSAGE + 1];
        loop {
            let _ = sys::wait(Some(fd.as_fd()), wake.as_fd(), 20);
            if let Ok(Some(n)) = sys::recv(fd.as_fd(), &mut buf) {
                if n > 0 {
                    break;
                }
            }
        }
        let ack = dataos_wire::Notify::HelloAck { ready: true };
        let up = dataos_wire::Notify::Event {
            link: 0,
            slot: 0,
            event: dataos_wire::IfaceEvent::Up,
        };
        for m in [ack, up] {
            let _ = sys::send(fd.as_fd(), &m.encode().unwrap());
        }
        fd
    })
}

extern "C" fn on_event_slowly(ev: *mut c_void, user: *mut c_void) {
    on_event(ev, user);
    std::thread::sleep(Duration::from_micros(100));
}

#[test]
fn a_flood_of_events_is_bounded_and_the_connection_is_made_again_for_the_replay() {
    let _g = exclusive();
    allow_provisional_abi_for_tests(true);
    set_retry_first_for_tests(50);
    const SENT: u32 = 20_000;
    let (lib, d) = sys::pair().unwrap();
    let (lib2, d2) = sys::pair().unwrap();
    let h = start(on_event_slowly, vec![lib, lib2]);
    let sender = flood(d, SENT);
    let again = replaying(d2);
    // the reader does not hold the lock while events pour in: a request that nobody
    // answers fails by its own deadline
    set_request_timeout_for_tests(300);
    let t = Instant::now();
    let _ = ask(h, NicmCmd::new(kind::QUERY_MTU));
    assert!(
        t.elapsed() < Duration::from_secs(2),
        "the lock is held during the flood"
    );
    let _daemon_end = sender.join().unwrap();
    // events that did not fit in the queue were dropped and counted
    wait_for("the flood to be dealt with", || events_of(event::UP) >= 1);
    let _second = again.join().unwrap();
    let dropped = dataos_libnicm::abi::dropped_events();
    assert!(dropped > 0, "nothing was dropped");
    let delivered = u32::try_from(events_of(event::RECONFIGURED)).unwrap();
    assert_eq!(
        delivered + dropped,
        SENT,
        "every event is delivered or counted"
    );
    // The module hears INIT_START after the events that were kept, and the connection is made again: the
    // answer to the Hello is INIT_DONE, and the daemon's replay comes after it and nothing else does.
    // (DSI keeps its interfaces across INIT_START, so the restart events alone would give it nothing back.)
    let kinds: Vec<u32> = EVENTS.lock().unwrap().iter().map(|e| e.kind).collect();
    let start_at = kinds
        .iter()
        .position(|k| *k == event::RESTART_START)
        .unwrap();
    assert_eq!(kinds.get(start_at + 1), Some(&event::RESTART_DONE));
    assert_eq!(kinds.get(start_at + 2), Some(&event::UP));
    assert_eq!(kinds.len(), start_at + 3);
    assert!(kinds
        .iter()
        .take(start_at)
        .all(|k| *k == event::RECONFIGURED));
    release_handle(h);
}

/// The module is stuck in its first callback until the test lets go.
static GATE: AtomicBool = AtomicBool::new(true);

extern "C" fn on_event_gated(ev: *mut c_void, user: *mut c_void) {
    let t = Instant::now();
    while GATE.load(Ordering::SeqCst) && t.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(1));
    }
    on_event(ev, user);
}

/// A daemon that sends events as fast as the socket takes them and ends with the Down of one link.
fn flood_then_down(fd: OwnedFd, count: u32, link: u8) -> JoinHandle<OwnedFd> {
    std::thread::spawn(move || {
        let (_, wake) = sys::pair().unwrap();
        let reconf = dataos_wire::Notify::Event {
            link: 0,
            slot: 0,
            event: dataos_wire::IfaceEvent::Reconfigured,
        };
        let down = dataos_wire::Notify::Event {
            link,
            slot: 0,
            event: dataos_wire::IfaceEvent::Down(dataos_wire::EndReason::Qmi(1)),
        };
        let ready = dataos_wire::Notify::Ready { ready: true };
        let mut all = vec![ready];
        all.extend(std::iter::repeat_n(reconf, count as usize));
        all.push(down);
        for m in all {
            let bytes = m.encode().unwrap();
            while sys::send(fd.as_fd(), &bytes).is_err() {
                let _ = sys::wait(None, wake.as_fd(), 1);
            }
        }
        fd
    })
}

/// A Down that was dropped because the module was slow is not in the replay, which shows only the links
/// that are held. It is given right after INIT_DONE and ahead of the replay.
#[test]
fn a_down_dropped_for_a_slow_module_is_given_after_init_done_and_ahead_of_the_replay() {
    let _g = exclusive();
    allow_provisional_abi_for_tests(true);
    set_retry_first_for_tests(50);
    GATE.store(true, Ordering::SeqCst);
    let (lib, d) = sys::pair().unwrap();
    let (lib2, d2) = sys::pair().unwrap();
    let h = start(on_event_gated, vec![lib, lib2]);
    let sender = flood_then_down(d, 20_000, 7);
    let again = replaying(d2);
    let _daemon_end = sender.join().unwrap();
    // the reader has taken everything and dropped what did not fit, the module has seen nothing
    assert!(EVENTS.lock().unwrap().is_empty());
    // F-C. The library holds a Down the module has not been given: a number must not be asked for again, so
    // the lookups fail as they do for a lost connection, and the other requests are not held back
    set_request_timeout_for_tests(300);
    for cmd in [lookup(4), matching(4)] {
        let (rc, r) = ask(h, cmd);
        assert_eq!((rc, r.status), (0, status::TRANSPORT));
    }
    assert_eq!(
        ask(h, NicmCmd::new(kind::QUERY_MTU)).1.status,
        status::TIMEOUT
    );
    GATE.store(false, Ordering::SeqCst);
    wait_for("the replay", || events_of(event::UP) >= 1);
    let _second = again.join().unwrap();
    assert!(
        dataos_libnicm::abi::dropped_events() > 0,
        "nothing was dropped"
    );
    let events = EVENTS.lock().unwrap().clone();
    let start_at = events
        .iter()
        .position(|e| e.kind == event::RESTART_START)
        .unwrap();
    let kinds: Vec<(u32, u32)> = events
        .iter()
        .skip(start_at)
        .map(|e| (e.kind, e.link))
        .collect();
    assert_eq!(
        kinds,
        vec![
            (event::RESTART_START, 0),
            (event::RESTART_DONE, 0),
            (event::DOWN, 7),
            (event::UP, 0)
        ]
    );
    // and once the Down has been given the lookups go to the daemon again
    assert_eq!(ask(h, lookup(4)).1.status, status::TIMEOUT);
    release_handle(h);
}

/// F-C, the other half. Notices were dropped and none of them is a Down: nothing is held, and the lookups still
/// fail until the module has caught up, because it has missed something all the same.
#[test]
fn lookups_fail_while_notices_are_dropped_and_no_down_is_among_them() {
    let _g = exclusive();
    allow_provisional_abi_for_tests(true);
    GATE.store(true, Ordering::SeqCst);
    let (lib, d) = sys::pair().unwrap();
    let h = start(on_event_gated, vec![lib]);
    let _daemon_end = flood(d, 20_000).join().unwrap();
    set_request_timeout_for_tests(300);
    for cmd in [lookup(4), matching(4)] {
        let (rc, r) = ask(h, cmd);
        assert_eq!((rc, r.status), (0, status::TRANSPORT));
    }
    GATE.store(false, Ordering::SeqCst);
    release_handle(h);
}

/// Set once the module is held in the callback of a Reconfigured event.
static HELD_AT_RECONFIGURED: AtomicBool = AtomicBool::new(false);

/// The module sees every event at once, except a Reconfigured one, which holds it until the gate opens.
extern "C" fn on_event_held_at_reconfigured(ev: *mut c_void, user: *mut c_void) {
    // SAFETY: the library passes a pointer to an EventBuf that lives through the call.
    let e = unsafe { (*ev.cast::<EventBuf>()).ev };
    if e.kind == event::RECONFIGURED {
        HELD_AT_RECONFIGURED.store(true, Ordering::SeqCst);
        let t = Instant::now();
        while GATE.load(Ordering::SeqCst) && t.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    on_event(ev, user);
}

/// F-C. A Down that came inside a restart waits for the module, and nothing was dropped: the lookups fail while
/// it waits, which is not the case of the dropped notices.
#[test]
fn lookups_fail_while_a_down_waits_and_no_notice_was_dropped() {
    let _g = exclusive();
    allow_provisional_abi_for_tests(true);
    GATE.store(true, Ordering::SeqCst);
    HELD_AT_RECONFIGURED.store(false, Ordering::SeqCst);
    let (lib, d) = sys::pair().unwrap();
    let h = start(on_event_held_at_reconfigured, vec![lib]);
    let say = |m: dataos_wire::Notify| sys::send(d.as_fd(), &m.encode().unwrap()).unwrap();
    say(dataos_wire::Notify::Ready { ready: true });
    say(dataos_wire::Notify::Ready { ready: false });
    say(dataos_wire::Notify::Event {
        link: 7,
        slot: 0,
        event: dataos_wire::IfaceEvent::Down(dataos_wire::EndReason::Qmi(1)),
    });
    say(dataos_wire::Notify::Event {
        link: 0,
        slot: 0,
        event: dataos_wire::IfaceEvent::Reconfigured,
    });
    wait_for("the module in its callback", || {
        HELD_AT_RECONFIGURED.load(Ordering::SeqCst)
    });
    assert_eq!(events_of(event::RESTART_START), 1);
    assert_eq!(events_of(event::DOWN), 0, "the Down waits for INIT_DONE");
    set_request_timeout_for_tests(300);
    for cmd in [lookup(4), matching(4)] {
        let (rc, r) = ask(h, cmd);
        assert_eq!((rc, r.status), (0, status::TRANSPORT));
    }
    GATE.store(false, Ordering::SeqCst);
    say(dataos_wire::Notify::Ready { ready: true });
    wait_for("the Down", || events_of(event::DOWN) == 1);
    release_handle(h);
}

#[test]
fn a_full_socket_fails_the_request_and_does_not_end_the_connection() {
    use dataos_nicm_compat::Transport;
    let _g = exclusive();
    let (a, b) = sys::pair().unwrap();
    let mut t = dataos_libnicm::conn::FdTransport::default();
    t.set(a);
    let mut failed = false;
    for _ in 0..200_000 {
        if t.send(&dataos_wire::Request::Hello).is_err() {
            failed = true;
            break;
        }
    }
    assert!(failed, "the socket buffer fills");
    assert!(t.connected(), "a full buffer is not a lost connection");
    // the daemon takes what is there and the next request goes out
    let mut buf = [0u8; MAX_MESSAGE + 1];
    while let Ok(Some(n)) = sys::recv(b.as_fd(), &mut buf) {
        assert!(n > 0);
    }
    assert!(t.send(&dataos_wire::Request::Hello).is_ok());
}

#[test]
fn a_daemon_that_closes_at_once_is_not_reconnected_in_a_tight_loop() {
    let _g = exclusive();
    set_retry_first_for_tests(10);
    let connects = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let c2 = connects.clone();
    let connector: dataos_libnicm::state::Connector = Box::new(move || {
        c2.fetch_add(1, Ordering::SeqCst);
        let (lib, peer) = sys::pair()?;
        drop(peer);
        Ok(lib)
    });
    let h = register_with(on_event, UserData::new(0x1234 as *mut c_void), connector);
    assert!(!h.is_null());
    std::thread::sleep(Duration::from_millis(1000));
    let n = connects.load(Ordering::SeqCst);
    release_handle(h);
    // 10, 20, 40 ... milliseconds apart: a handful of connections in a second, not ninety
    assert!(n <= 10, "{n} connections in a second");
    assert!(n >= 3, "{n} connections in a second");
}

#[test]
fn a_ninth_waiting_request_is_busy_and_a_silent_daemon_times_out_with_its_own_status() {
    let _g = exclusive();
    set_request_timeout_for_tests(600);
    let (lib, d) = sys::pair().unwrap();
    let daemon = spawn_daemon(d, true);
    let h = start(on_event, vec![lib]);
    let addr = h as usize;
    let waiters: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(move || {
                let mut reply = NicmReply::failed(999);
                let cmd = NicmCmd::new(kind::QUERY_MTU);
                // SAFETY: cmd and reply are valid for the call.
                let rc = unsafe { send_cmd(addr as *mut c_void, &cmd, &mut reply) };
                (rc, reply.status)
            })
        })
        .collect();
    std::thread::sleep(Duration::from_millis(250));
    let (rc, r) = ask(h, NicmCmd::new(kind::QUERY_MTU));
    assert_eq!(
        (rc, r.status),
        (0, status::BUSY),
        "too many requests wait: the reply says so"
    );
    for w in waiters {
        assert_eq!(w.join().unwrap(), (0, status::TIMEOUT));
    }
    release_handle(h);
    daemon.kill();
}

#[test]
fn the_open_replacement_marks_itself_for_the_other_library() {
    assert_eq!(
        dataos_libnicm::abi::nicm_open_replacement(),
        dataos_nicm_abi::MAGIC
    );
}

fn matching(family: u32) -> NicmCmd {
    NicmCmd {
        kind: kind::MATCHING_CALL,
        ..lookup(family)
    }
}

#[test]
fn the_matching_call_question_goes_to_the_daemon_and_a_refusal_comes_back() {
    let _g = exclusive();
    allow_provisional_abi_for_tests(true);
    let (lib, d) = sys::pair().unwrap();
    let daemon = spawn_daemon(d, false);
    let h = start(on_event, vec![lib]);
    // not ready: the refusal says so
    let (rc, r) = ask(h, matching(4));
    assert_eq!((rc, r.status), (0, u32::from(ResultCode::NotReady.code())));
    daemon.up();
    wait_for("ready", || {
        ask(h, NicmCmd::new(kind::READY)).1.status == status::OK
    });
    // nothing is up: no matching call, and the link number and the name stay empty
    let (rc, r) = ask(h, matching(4));
    assert_eq!((rc, r.status), (0, u32::from(ResultCode::NoMatch.code())));
    assert_eq!((r.link, r.name_len), (0, 0));
    // the values are checked here as for a route lookup
    for family in [0, 5, 10] {
        let (rc, r) = ask(h, matching(family));
        assert_eq!((rc, r.status), (0, status::BAD_ARGUMENT), "family {family}");
    }
    release_handle(h);
    daemon.kill();
}

#[test]
fn the_matching_call_question_does_not_hold_the_thread_for_the_long_wait_of_the_others() {
    let _g = exclusive();
    allow_provisional_abi_for_tests(true);
    // the production wait of the others
    set_request_timeout_for_tests(REQUEST_TIMEOUT_MS);
    let (lib, d) = sys::pair().unwrap();
    let daemon = spawn_daemon(d, true);
    let h = start(on_event, vec![lib]);
    let t = Instant::now();
    let (rc, r) = ask(h, matching(4));
    assert_eq!((rc, r.status), (0, status::TIMEOUT));
    let waited = t.elapsed();
    assert!(
        waited >= Duration::from_millis(MATCHING_CALL_TIMEOUT_MS)
            && waited < Duration::from_secs(6),
        "{waited:?}"
    );
    // and a test's shorter wait applies to it too
    set_request_timeout_for_tests(150);
    let t = Instant::now();
    let (_, r) = ask(h, matching(4));
    assert_eq!(r.status, status::TIMEOUT);
    assert!(t.elapsed() < Duration::from_secs(2));
    release_handle(h);
    daemon.kill();
}

#[test]
fn the_waits_of_the_requests_are_the_stock_one_and_the_short_one_of_the_matching_call() {
    let _g = exclusive();
    set_request_timeout_for_tests(REQUEST_TIMEOUT_MS);
    let ms = |k: u32| request_wait(k).as_millis();
    for k in [
        kind::ROUTE_LOOKUP,
        kind::LINK_RELEASE,
        kind::QUERY_MTU,
        kind::SCREEN_STATE,
        kind::READY,
    ] {
        assert_eq!(ms(k), u128::from(REQUEST_TIMEOUT_MS), "kind {k}");
    }
    assert_eq!(
        ms(kind::MATCHING_CALL),
        u128::from(MATCHING_CALL_TIMEOUT_MS)
    );
    // a shorter wait of a test applies to all of them, a longer one only to the others
    set_request_timeout_for_tests(150);
    assert_eq!((ms(kind::QUERY_MTU), ms(kind::MATCHING_CALL)), (150, 150));
    set_request_timeout_for_tests(20_000);
    assert_eq!(
        (ms(kind::QUERY_MTU), ms(kind::MATCHING_CALL)),
        (20_000, u128::from(MATCHING_CALL_TIMEOUT_MS))
    );
}

#[test]
fn the_requests_the_daemon_never_did_are_answered_by_the_library_at_once() {
    let _g = exclusive();
    allow_provisional_abi_for_tests(true);
    // a daemon that never answers: the library must not ask it
    let (lib, d) = sys::pair().unwrap();
    let daemon = spawn_daemon(d, true);
    let h = start(on_event, vec![lib]);
    let t = Instant::now();
    for k in [
        kind::QUERY_NETWORK_HANDLE,
        kind::PORT_FORWARD,
        kind::OEM_PROXY,
    ] {
        let mut c = NicmCmd::new(k);
        c.link = 9999;
        let (rc, r) = ask(h, c);
        assert_eq!(
            (rc, r.status),
            (0, u32::from(ResultCode::Unsupported.code())),
            "kind {k}"
        );
    }
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    release_handle(h);
    daemon.kill();
}

#[test]
fn a_value_of_the_matching_call_request_outside_a_byte_is_refused_before_it_is_sent() {
    let _g = exclusive();
    allow_provisional_abi_for_tests(true);
    let (lib, d) = sys::pair().unwrap();
    let daemon = spawn_daemon(d, true);
    let h = start(on_event, vec![lib]);
    for bit in [hint::PROFILE_3GPP, hint::PROFILE_3GPP2] {
        let mut c = matching(4);
        c.hint_mask = bit;
        c.profile_3gpp = 256;
        c.profile_3gpp2 = 256;
        let (rc, r) = ask(h, c);
        assert_eq!((rc, r.status), (0, status::BAD_ARGUMENT), "{bit:#x}");
    }
    release_handle(h);
    daemon.kill();
}
