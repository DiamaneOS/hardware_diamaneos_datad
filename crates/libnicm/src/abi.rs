// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The C exports. Prototypes are inferred from the closed libraries, not verified:
//! `nicm_client_register` mirrors the constructor `NicmClient(void (*)(void*,
//! void*), void*)` the stock library calls, `nicm_send_client_cmd` is a tail call
//! of `NicmClient::sendMessage(ClientCmdInfo*, NicmEventInfo*)`, so it takes the
//! handle and the two structs. Here the two structs are those of `dataos-nicm-abi`,
//! because only our own `libnicm_dsi.so` calls it.
//!
//! The handle given out is the address of a small allocation of ours. It is not
//! read through. The functions look it up in a table and refuse any other value.
#![allow(unsafe_code)]
use crate::state::{Connector, Shared};
use crate::sys;
use dataos_nicm_abi::{header_ok, EventBuf, NicmCmd, NicmReply, CMD_LEN};
use std::ffi::{c_int, c_void};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// The callback of the data module: the event info first, the user data second,
/// as `NicmClient::processEvent` calls it. Until the stock
/// layouts are verified, events are not delivered (see `abi_enabled`).
// SAFETY: only a function pointer type. The call is the unsafe act, see `call_module`.
pub type Callback = unsafe extern "C" fn(*mut std::ffi::c_void, *mut std::ffi::c_void);

/// The user data of the data module, kept to give it back with each event.
#[derive(Clone, Copy)]
pub struct UserData(usize);

impl UserData {
    pub fn new(p: *mut c_void) -> Self {
        UserData(p as usize)
    }

    pub fn addr(&self) -> usize {
        self.0
    }
}

/// A plain address, never dereferenced, so the registration can move to a thread.
// SAFETY: the value is an integer. This library never reads through it, it only hands
// it back to the callback of the module that gave it.
unsafe impl Send for UserData {}

struct Global {
    shared: Option<Arc<Shared>>,
    /// (address of the handle, registration id)
    handles: Vec<(usize, u64)>,
}

static GLOBAL: Mutex<Global> = Mutex::new(Global {
    shared: None,
    handles: Vec::new(),
});

fn global() -> MutexGuard<'static, Global> {
    GLOBAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Register a callback. `connector` opens the connection if this is the first.
pub fn register_with(cb: Callback, user: UserData, connector: Connector) -> *mut c_void {
    let mut g = global();
    let shared = match &g.shared {
        Some(s) => Arc::clone(s),
        None => {
            let Some(s) = Shared::start(connector) else {
                return std::ptr::null_mut();
            };
            g.shared = Some(Arc::clone(&s));
            s
        }
    };
    let Some(id) = shared.register(cb, user) else {
        return std::ptr::null_mut();
    };
    let handle = Box::into_raw(Box::new([0u64; 8]));
    g.handles.push((handle as usize, id));
    handle.cast()
}

/// Events the data module was not given because the layouts are not verified.
pub fn withheld_events() -> u32 {
    global().shared.as_ref().map_or(0, |s| s.withheld_events())
}

/// The other library asks for this at load time: it is the marker of the open replacement.
#[no_mangle]
pub extern "C" fn nicm_open_replacement() -> u32 {
    dataos_nicm_abi::MAGIC
}

/// Events dropped because the queue to the module was full.
pub fn dropped_events() -> u32 {
    global().shared.as_ref().map_or(0, |s| s.dropped_events())
}

/// Call the callback of the data module with an event buffer of this library.
/// `cb` and `user` come from a registration (`nicm_client_register`), which is
/// the module's promise that the function may be called with the buffer and the
/// user data until the registration is released.
pub fn call_module(cb: Callback, event: &mut EventBuf, user: usize) {
    // SAFETY: cb is the function the module registered, event is a buffer of this
    // library that lives through the call, and user is what the module registered it
    // with. The module's callback copies what it keeps during the call and does not
    // keep the pointer.
    unsafe { cb(std::ptr::from_mut(event).cast(), user as *mut c_void) }
}

/// Drop every registration and the connection, so a failed test leaves nothing behind.
pub fn reset_for_tests() {
    let handles: Vec<usize> = global().handles.iter().map(|(a, _)| *a).collect();
    for h in handles {
        release_handle(h as *mut c_void);
    }
}

/// Give a handle back. Anything that is not a live handle is ignored.
pub fn release_handle(hndl: *mut c_void) {
    let (shared, id) = {
        let mut g = global();
        let Some((addr, id)) = g.handles.iter().find(|(a, _)| *a == hndl as usize).copied() else {
            return;
        };
        g.handles.retain(|(a, _)| *a != addr);
        // SAFETY: addr is the address of a Box<[u64; 8]> that register_with leaked and
        // that was still in the table, so it is live and nobody else frees it.
        drop(unsafe { Box::from_raw(addr as *mut [u64; 8]) });
        let Some(shared) = g.shared.clone() else {
            return;
        };
        (shared, id)
    };
    // The global lock is not held here: this waits for a callback that is running, and
    // that callback may call into this library.
    if !shared.unregister(id) {
        return;
    }
    let last = {
        let mut g = global();
        // somebody may have registered while this waited
        let same = g.shared.as_ref().is_some_and(|s| Arc::ptr_eq(s, &shared));
        if same && g.handles.is_empty() {
            g.shared = None;
            true
        } else {
            false
        }
    };
    if last {
        shared.shutdown();
    }
}

fn shared_of(hndl: *mut c_void) -> Option<Arc<Shared>> {
    let g = global();
    g.handles.iter().find(|(a, _)| *a == hndl as usize)?;
    g.shared.clone()
}

/// Send a command and wait for the answer. 0: `reply` is written and its status says
/// what happened (the daemon's result code, or no connection, no answer in time, bad
/// arguments, too many requests waiting). Negative: not a live handle, a null
/// pointer, or not a command of ours, and nothing is written.
///
/// # Safety
/// `cmd` must be null or point to a readable `NicmCmd`, `reply` null or point to room for a `NicmReply`.
pub unsafe fn send_cmd(hndl: *mut c_void, cmd: *const NicmCmd, reply: *mut NicmReply) -> c_int {
    if cmd.is_null() || reply.is_null() {
        return -1;
    }
    let Some(shared) = shared_of(hndl) else {
        return -1;
    };
    // SAFETY: the caller passes a readable command, and every command starts with an
    // 8 byte header (the stock ClientCmdInfo is 296 bytes). Alignment is not assumed.
    let head = unsafe { cmd.cast::<[u32; 2]>().read_unaligned() };
    if !header_ok(head[0], head[1], CMD_LEN) {
        // not a command of ours (the stock library next to this one): read and write nothing more
        return -1;
    }
    // SAFETY: the header says the caller passes a whole NicmCmd of ours. The struct is
    // plain integers, so any bytes are a valid value. Alignment is not assumed.
    let c = unsafe { cmd.read_unaligned() };
    let r = shared.execute(&c);
    // SAFETY: the caller passes room for a NicmReply. Alignment is not assumed.
    unsafe { reply.write_unaligned(r) };
    // the reply says what happened, whether the daemon answered or not
    0
}

#[no_mangle]
pub extern "C" fn nicm_client_register(cb: Option<Callback>, userdata: *mut c_void) -> *mut c_void {
    let Some(cb) = cb else {
        return std::ptr::null_mut();
    };
    register_with(
        cb,
        UserData::new(userdata),
        Box::new(|| sys::connect(crate::SOCKET_PATH)),
    )
}

#[no_mangle]
pub extern "C" fn nicm_client_release(hndl: *mut c_void) {
    release_handle(hndl);
}

/// # Safety
/// `cmd` must be null or point to a readable `NicmCmd`, `reply` null or point to room for a `NicmReply`.
#[no_mangle]
pub unsafe extern "C" fn nicm_send_client_cmd(
    hndl: *mut c_void,
    cmd: *const NicmCmd,
    reply: *mut NicmReply,
) -> c_int {
    // SAFETY: the caller's contract is the one of send_cmd.
    unsafe { send_cmd(hndl, cmd, reply) }
}

// The three functions of the vendor-hal event client. Nothing in the vendor image
// imports them (checked with grep over the libraries and binaries), so they only
// have to exist and to refuse.
#[no_mangle]
pub extern "C" fn vh_event_client_register(_a: usize, _b: usize, _c: usize) -> usize {
    0
}

#[no_mangle]
pub extern "C" fn vh_event_client_release(_a: usize) {}

#[no_mangle]
pub extern "C" fn vh_event_send_client_cmd(_a: usize, _b: usize, _c: usize) -> c_int {
    -1
}
