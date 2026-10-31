// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The C exports of `libnicm_dsi.so` and `StockAbi`, the one place that reads and
//! writes what the closed data module owns. The prototypes are those of the stock
//! library. Each export does nothing until the stock layouts
//! are marked verified (`STOCK_ABI_VERIFIED`), and then refuses in the way its
//! prototype says: an `int` export returns -1, `setNicmInfo` returns a null
//! pointer. Pointers are taken as plain integers and turned into byte slices of
//! their known sizes here, in the `view` helpers, and nowhere else. The layout code
//! (`layout.rs`) and the glue to `libnicm.so` (`glue.rs`) are safe code.
#![allow(unsafe_code)]
use crate::glue::{self, Family, Lookup, Sender};
use crate::layout::{self, Ev};
use dataos_nicm_abi::{abi_enabled, NicmCmd, NicmReply, STOCK_ABI_VERIFIED};
use std::ffi::{c_int, c_void};
use std::sync::{Arc, Mutex, PoisonError};

/// The ten exports and the one DSI uses itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    InitQuery,
    TranslateEvent,
    TranslateRouteLookupRequest,
    RouteLookup,
    SetNicmInfo,
    QueryLlNetworkHandle,
    GetLinkMtu,
    LinkRelease,
    ProcessPfRequest,
    OemProxy,
    ProcessScreenState,
}

/// The implementation behind the exports. `args` are the first five argument
/// registers of the call. An `int` argument is zero extended from its 32 bits,
/// a pointer is its address. The result is an `int` (-1 as `usize::MAX`) or, for
/// `setNicmInfo`, a pointer.
pub trait DsiAbi: Send + Sync {
    fn call(&self, op: Op, args: [usize; 5], libnicm: &dyn Sender) -> usize;
}

const FAIL: usize = usize::MAX;
const OK: usize = 0;

fn status(ok: bool) -> usize {
    if ok {
        OK
    } else {
        FAIL
    }
}

/// A buffer of the closed side, read.
///
/// # Safety
/// `p` must be zero or the address of `len` readable bytes that nobody writes while the
/// slice lives.
unsafe fn view<'a>(p: usize, len: usize) -> Option<&'a [u8]> {
    if p == 0 {
        return None;
    }
    // SAFETY: the caller's contract. A byte slice has no alignment requirement.
    Some(unsafe { std::slice::from_raw_parts(p as *const u8, len) })
}

/// A buffer of the closed side, written.
///
/// # Safety
/// `p` must be zero or the address of `len` writable bytes that nobody else uses while
/// the slice lives.
unsafe fn view_mut<'a>(p: usize, len: usize) -> Option<&'a mut [u8]> {
    if p == 0 {
        return None;
    }
    // SAFETY: the caller's contract. A byte slice has no alignment requirement.
    Some(unsafe { std::slice::from_raw_parts_mut(p as *mut u8, len) })
}

/// Do two buffers share a byte?
fn overlap(a: usize, alen: usize, b: usize, blen: usize) -> bool {
    match (a.checked_add(alen), b.checked_add(blen)) {
        (Some(aend), Some(bend)) => a < bend && b < aend,
        _ => true,
    }
}

extern "C" {
    fn calloc(n: usize, size: usize) -> *mut c_void;
}

/// The implementation for the stock layouts.
pub struct StockAbi {
    /// The last IPv4 and IPv6 MTU told for each link, because an MTU update names both.
    mtu: Mutex<[[u32; 2]; 33]>,
}

impl Default for StockAbi {
    fn default() -> Self {
        Self::new()
    }
}

/// The one instance a device build uses, so that what it remembers between two calls lasts.
static STOCK: StockAbi = StockAbi::new();

impl StockAbi {
    pub const fn new() -> Self {
        StockAbi {
            mtu: Mutex::new([[0; 2]; 33]),
        }
    }

    /// A link that went down does not leave its MTUs to the next call on that number.
    fn forget_mtu(&self, link: u32) {
        let mut g = self.mtu.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(slot) = usize::try_from(link).ok().and_then(|l| g.get_mut(l)) {
            *slot = [0; 2];
        }
    }

    fn handle_ok(h: usize) -> bool {
        h != 0
    }

    /// `setNicmInfo`: a copy of the event the callback was given, on the heap, for
    /// the module to keep and to free with `free`. Null for anything but an event of ours.
    fn set_info(&self, info: usize) -> usize {
        // SAFETY: the callback hands over a pointer to an event buffer of this library,
        // which is 4096 bytes and lives through the callback. The stock function copies
        // the same 960 bytes.
        let Some(src) = (unsafe { view(info, layout::INFO_LEN) }) else {
            return 0;
        };
        let head_ok = match (layout::rd_u32(src, 0), layout::rd_u32(src, 4)) {
            (Some(magic), Some(size)) => dataos_nicm_abi::header_ok(magic, size, EVENT_LEN),
            _ => false,
        };
        if !head_ok {
            return 0;
        }
        // SAFETY: calloc has no preconditions. The module frees the result with free.
        let copy = unsafe { calloc(1, layout::INFO_LEN) };
        // SAFETY: a non-null result of calloc is 960 writable bytes that nobody else has.
        let Some(dst) = (unsafe { view_mut(copy as usize, layout::INFO_LEN) }) else {
            return 0;
        };
        if !layout::wr_bytes(dst, 0, src) {
            return 0;
        }
        copy as usize
    }

    /// `dsiTranslateNicmEvent`: the copy of an event of ours to the event of the module.
    fn translate_event(&self, info: usize, out: usize, kind: usize) -> usize {
        if overlap(info, layout::INFO_LEN, out, layout::INFO_LEN)
            || overlap(kind, 4, info, layout::INFO_LEN)
            || overlap(kind, 4, out, layout::INFO_LEN)
        {
            return FAIL;
        }
        // SAFETY: the module passes the copy `setNicmInfo` made, 960 bytes, a buffer
        // of 960 bytes it allocated for the result, and the address of an int. No pair
        // of them shares a byte (checked above).
        let (Some(src), Some(dst), Some(kind_out)) = (
            unsafe { view(info, layout::INFO_LEN) },
            unsafe { view_mut(out, layout::INFO_LEN) },
            unsafe { view_mut(kind, 4) },
        ) else {
            return FAIL;
        };
        let Some(ev) = read_event(src) else {
            return FAIL;
        };
        // The MTUs of a link are forgotten when the module hears it down. Not at a release, which the
        // daemon may keep (a call is up on the link), and not at a failed operation of a start.
        if let Ev::Down { link, .. } = ev {
            self.forget_mtu(link);
        }
        let ev = match ev {
            Ev::Mtu { link, sub, v4, v6 } => {
                // an update names one family, the module wants both
                let (v4, v6) = self.remember_mtu(link, v4, v6);
                Ev::Mtu { link, sub, v4, v6 }
            }
            other => other,
        };
        let Some(t) = layout::write_event(dst, &ev) else {
            return FAIL;
        };
        status(layout::wr_u32(kind_out, 0, t.kind))
    }

    /// The MTUs of a link with the one just told: a value of 0 means "no news".
    fn remember_mtu(&self, link: u32, v4: u32, v6: u32) -> (u32, u32) {
        let mut g = self.mtu.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(slot) = usize::try_from(link).ok().and_then(|l| g.get_mut(l)) else {
            return (v4, v6);
        };
        let [old4, old6] = *slot;
        let now = [
            if v4 == 0 { old4 } else { v4 },
            if v6 == 0 { old6 } else { v6 },
        ];
        *slot = now;
        (now[0], now[1])
    }

    fn route_lookup(&self, s: &dyn Sender, a: [usize; 5]) -> usize {
        let (hndl, subs, out, req, mode) = (a[0], a[1] as u32, a[2], a[3], a[4] as u32);
        if !Self::handle_ok(hndl) || overlap(out, layout::INFO_LEN, req, layout::REQUEST_LEN) {
            return FAIL;
        }
        // SAFETY: the module passes a 960 byte buffer for the answer and the 208 byte
        // request it built, two different allocations (checked above).
        let (Some(out), Some(req)) = (unsafe { view_mut(out, layout::INFO_LEN) }, unsafe {
            view(req, layout::REQUEST_LEN)
        }) else {
            return FAIL;
        };
        // the stock function clears the answer first, whatever happens next
        for b in out.iter_mut() {
            *b = 0;
        }
        // 5 is the route lookup and 11 the query for a matching call. Nothing else is asked.
        if mode != layout::LOOKUP_ROUTE && mode != layout::LOOKUP_MATCHING_CALL {
            return FAIL;
        }
        let Ok(request) = layout::read_request(req) else {
            return FAIL;
        };
        let Ok(slot) = u8::try_from(subs) else {
            return FAIL;
        };
        let lookup = Lookup {
            slot: u32::from(slot),
            family: if request.ip_family == 6 {
                Family::V6
            } else {
                Family::V4
            },
            apn: request.apn.as_deref(),
            apn_type: request.apn_type,
            apn_type_mask: request.apn_type_mask,
            profile_3gpp: request.profile_3gpp,
            profile_3gpp2: request.profile_3gpp2,
            xt_tech_pref: request.xt_tech_pref,
            bu_apn_name: request.bu_apn_name,
            bu_apn_type: request.bu_apn_type,
        };
        if mode == layout::LOOKUP_MATCHING_CALL {
            // The stock function fails when there is no match, with the mark left at 0. The name
            // is the daemon's, for a call of this connection that is up.
            return match glue::matching_call(s, hndl, &lookup) {
                Ok(link) if layout::write_matching(out, &link.ifname) => OK,
                _ => FAIL,
            };
        }
        let Ok(link) = glue::route_lookup(s, hndl, &lookup) else {
            return FAIL;
        };
        if layout::write_route(out, link.number, link.existing, link.companion) {
            OK
        } else {
            // a link the module cannot name: give it back
            let _ = glue::link_release(s, hndl, link.number);
            FAIL
        }
    }

    fn link_arg(v: usize) -> Option<u32> {
        let v = v as u32;
        (v <= layout::MAX_LINK).then_some(v)
    }

    fn mtu_query(&self, s: &dyn Sender, a: [usize; 5]) -> usize {
        let (hndl, link, out) = (a[0], Self::link_arg(a[1]), a[3]);
        // SAFETY: the module passes the address of 12 bytes for the answer.
        let (Some(out), Some(link)) = (unsafe { view_mut(out, layout::MTU_OUT_LEN) }, link) else {
            return FAIL;
        };
        if !Self::handle_ok(hndl) {
            return FAIL;
        }
        match glue::link_mtu(s, hndl, link) {
            Ok((v4, v6)) => status(layout::write_mtu(out, v4, v6)),
            Err(_) => FAIL,
        }
    }

    /// Nothing is sent for the network handle either: the daemon has none (no netd and no Binder in
    /// it) and the module takes the failure the same way.
    fn handle_query(&self, a: [usize; 5]) -> usize {
        // SAFETY: the module passes the address of 8 bytes for the handle.
        if let Some(out) = unsafe { view_mut(a[1], layout::HANDLE_OUT_LEN) } {
            // the stock function stores 0 when the query fails
            let _ = layout::wr_u64(out, 0, 0);
        }
        FAIL
    }
}

/// The size of an event of ours.
const EVENT_LEN: usize = dataos_nicm_abi::EVENT_LEN;

fn family_code(code: u32) -> Option<u16> {
    match code {
        4 => Some(layout::AF_INET),
        6 => Some(layout::AF_INET6),
        _ => None,
    }
}

/// Read an event of ours from the bytes of the module's copy. None: not an event of
/// ours, or a value outside what the module takes.
fn read_event(b: &[u8]) -> Option<Ev> {
    let word = |off: usize| layout::rd_u32(b, off);
    if !dataos_nicm_abi::header_ok(word(0)?, word(4)?, EVENT_LEN) {
        return None;
    }
    use dataos_nicm_abi::at;
    let (kind, link, slot, family, value) = (
        word(at::KIND)?,
        word(at::LINK)?,
        word(at::SLOT)?,
        word(at::FAMILY)?,
        word(at::VALUE)?,
    );
    let addr_bytes = b.get(at::ADDR..at::ADDR.checked_add(16)?)?;
    let mut addr = [0u8; 16];
    for (d, s) in addr.iter_mut().zip(addr_bytes) {
        *d = *s;
    }
    let address = || family_code(family).map(|f| (f, addr, value));
    use dataos_nicm_abi::event as e;
    Some(match kind {
        e::UP => Ev::Up {
            link,
            sub: slot,
            addr: address(),
        },
        e::DOWN => Ev::Down { link, sub: slot },
        e::RECONFIGURED => Ev::Reconfigured {
            link,
            sub: slot,
            addr: address(),
        },
        e::NEW_ADDR | e::DEL_ADDR => {
            let (family, addr, prefix) = address()?;
            let max = if family == layout::AF_INET { 32 } else { 128 };
            if prefix > max {
                return None;
            }
            if kind == e::NEW_ADDR {
                Ev::NewAddr {
                    link,
                    sub: slot,
                    family,
                    addr,
                    prefix,
                }
            } else {
                Ev::DelAddr {
                    link,
                    sub: slot,
                    family,
                    addr,
                    prefix,
                }
            }
        }
        e::MTU_UPDATE => {
            let (v4, v6) = match family {
                4 => (value, 0),
                6 => (0, value),
                _ => return None,
            };
            Ev::Mtu {
                link,
                sub: slot,
                v4,
                v6,
            }
        }
        e::OP_FAILED => Ev::OpFailed { link, sub: slot },
        e::RESTART_START => Ev::Restart { done: false },
        e::RESTART_DONE => Ev::Restart { done: true },
        _ => return None,
    })
}

impl DsiAbi for StockAbi {
    fn call(&self, op: Op, a: [usize; 5], s: &dyn Sender) -> usize {
        match op {
            Op::InitQuery => status(Self::handle_ok(a[0]) && glue::ready(s, a[0]).is_ok()),
            Op::SetNicmInfo => self.set_info(a[0]),
            Op::TranslateEvent => self.translate_event(a[0], a[1], a[2]),
            // Nothing imports it: the stock library only calls it from the route lookup.
            Op::TranslateRouteLookupRequest => FAIL,
            Op::RouteLookup => self.route_lookup(s, a),
            Op::QueryLlNetworkHandle => self.handle_query(a),
            Op::GetLinkMtu => self.mtu_query(s, a),
            Op::LinkRelease => match Self::link_arg(a[1]) {
                Some(link) if Self::handle_ok(a[0]) => {
                    status(glue::link_release(s, a[0], link).is_ok())
                }
                _ => FAIL,
            },
            // The daemon has no port forwarding and no OEM proxy, and the module takes the failure
            // the same whatever the daemon would say, so nothing is sent: a stuck daemon holds no
            // thread of the radio daemon for a refusal that is known.
            Op::ProcessPfRequest | Op::OemProxy => FAIL,
            Op::ProcessScreenState => status(
                Self::handle_ok(a[0]) && glue::screen_state(s, a[0], a[1] as u32 != 0).is_ok(),
            ),
        }
    }
}

static INSTALLED: Mutex<Option<Arc<dyn DsiAbi>>> = Mutex::new(None);

/// Install an implementation (the tests do, the library uses `StockAbi` once the
/// layouts are verified).
pub fn install(abi: Option<Arc<dyn DsiAbi>>) {
    *INSTALLED.lock().unwrap_or_else(PoisonError::into_inner) = abi;
}

#[cfg(target_os = "android")]
extern "C" {
    /// liblog (`shared_libs` of the Android.bp).
    fn __android_log_write(
        prio: c_int,
        tag: *const std::ffi::c_char,
        text: *const std::ffi::c_char,
    ) -> c_int;
}

/// One line to logd at the information level, tag `nicm_dsi`. Nothing happens off Android (the host tests). A
/// line is cut at 1000 bytes, and a zero byte in it is left out.
pub fn log_info(text: &str) {
    #[cfg(target_os = "android")]
    {
        let mut line: Vec<u8> = text.bytes().filter(|b| *b != 0).take(1000).collect();
        line.push(0);
        // SAFETY: the tag and the line are NUL-terminated, live through the call, and liblog only reads them.
        let _ = unsafe { __android_log_write(4, c"nicm_dsi".as_ptr(), line.as_ptr().cast()) };
    }
    #[cfg(not(target_os = "android"))]
    let _ = text;
}

extern "C" {
    /// From `libnicm.so`. Soong links this library against it (`shared_libs`).
    fn nicm_send_client_cmd(hndl: *mut c_void, cmd: *const NicmCmd, reply: *mut NicmReply)
        -> c_int;
    /// From `libnicm.so`, the open replacement only. The stock library has no such
    /// function, so this library does not load next to it.
    fn nicm_open_replacement() -> u32;
}

/// The real sender: `nicm_send_client_cmd` of `libnicm.so`.
pub struct LibNicm;

impl Sender for LibNicm {
    fn send(&self, hndl: usize, cmd: &NicmCmd) -> Option<NicmReply> {
        // SAFETY: the function takes nothing and returns a number.
        if unsafe { nicm_open_replacement() } != dataos_nicm_abi::MAGIC {
            return None;
        }
        let mut reply = NicmReply::failed(0);
        // SAFETY: cmd and reply are valid for the call and of the types libnicm.so expects.
        // The handle is only a number to it, it checks it against its own table.
        let rc = unsafe {
            nicm_send_client_cmd(hndl as *mut c_void, std::ptr::from_ref(cmd), &mut reply)
        };
        (rc == 0 && reply.header_ok()).then_some(reply)
    }
}

static STOCK_FOR_TESTS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Tests run the path of a device build, where `StockAbi` is the implementation and nobody
/// installed one. Nothing in the library calls this.
pub fn use_stock_for_tests(on: bool) {
    STOCK_FOR_TESTS.store(on, std::sync::atomic::Ordering::SeqCst);
}

/// Run an operation on the implementation in use: `StockAbi` on a device build, an installed one in tests.
fn call_current(op: Op, args: [usize; 5]) -> Option<usize> {
    if STOCK_ABI_VERIFIED || STOCK_FOR_TESTS.load(std::sync::atomic::Ordering::SeqCst) {
        return Some(STOCK.call(op, args, &LibNicm));
    }
    let installed = INSTALLED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()?;
    Some(installed.call(op, args, &LibNicm))
}

fn dispatch(op: Op, args: [usize; 5]) -> usize {
    crate::log::first_call();
    if !abi_enabled() {
        crate::log::refused(op, "the layouts of the data module are not verified");
        return FAIL;
    }
    let result = call_current(op, args).unwrap_or(FAIL);
    crate::log::answered(op, result);
    result
}

/// The refusal in the form of the prototype: -1 for an `int`.
fn int(op: Op, args: [usize; 5]) -> c_int {
    c_int::try_from(dispatch(op, args) as isize).unwrap_or(-1)
}

#[no_mangle]
pub extern "C" fn dsiInitQueryNicmWrapper(hndl: usize) -> c_int {
    int(Op::InitQuery, [hndl, 0, 0, 0, 0])
}

#[no_mangle]
pub extern "C" fn dsiTranslateNicmEvent(info: usize, out: usize, kind: usize) -> c_int {
    int(Op::TranslateEvent, [info, out, kind, 0, 0])
}

#[no_mangle]
pub extern "C" fn dsiTranslateRouteLookupRequest(subs: c_int, req: usize, cmd: usize) -> c_int {
    int(
        Op::TranslateRouteLookupRequest,
        [subs as u32 as usize, req, cmd, 0, 0],
    )
}

#[no_mangle]
pub extern "C" fn dsiNicmRouteLookup(
    hndl: usize,
    subs: c_int,
    out: usize,
    req: usize,
    mode: c_int,
) -> c_int {
    int(
        Op::RouteLookup,
        [hndl, subs as u32 as usize, out, req, mode as u32 as usize],
    )
}

/// A pointer to a copy on the heap, null when there is none.
#[no_mangle]
pub extern "C" fn setNicmInfo(info: usize) -> *mut c_void {
    if !abi_enabled() {
        return std::ptr::null_mut();
    }
    match call_current(Op::SetNicmInfo, [info, 0, 0, 0, 0]) {
        Some(p) => p as *mut c_void,
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn dsiNicmQueryLLNetworkHndl(hndl: usize, out: usize) -> c_int {
    int(Op::QueryLlNetworkHandle, [hndl, out, 0, 0, 0])
}

#[no_mangle]
pub extern "C" fn dsiNicmGetLinkMtu(hndl: usize, link: c_int, family: c_int, out: usize) -> c_int {
    int(
        Op::GetLinkMtu,
        [hndl, link as u32 as usize, family as u32 as usize, out, 0],
    )
}

#[no_mangle]
pub extern "C" fn dsiNicmLinkRelease(hndl: usize, link: c_int) -> c_int {
    int(Op::LinkRelease, [hndl, link as u32 as usize, 0, 0, 0])
}

#[no_mangle]
pub extern "C" fn dsiNicmProcessPFRequest(
    hndl: usize,
    req: c_int,
    family: c_int,
    out: usize,
) -> c_int {
    int(
        Op::ProcessPfRequest,
        [hndl, req as u32 as usize, family as u32 as usize, out, 0],
    )
}

#[no_mangle]
pub extern "C" fn dsiNicmOEMProxy(hndl: usize, input: usize, out: usize) -> c_int {
    int(Op::OemProxy, [hndl, input, out, 0, 0])
}

#[no_mangle]
pub extern "C" fn dsiNicmProcessScreenState(hndl: usize, on: c_int) -> c_int {
    int(Op::ProcessScreenState, [hndl, on as u32 as usize, 0, 0, 0])
}
