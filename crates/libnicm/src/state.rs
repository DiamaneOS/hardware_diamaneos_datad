// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The one connection of the process to the data daemon, its listener thread,
//! the registrations of the data module and the blocking request. The data
//! module calls from several threads and gets its events on the listener
//! thread. No lock is held while it is called back, because it calls back into
//! this library from its callback.
use crate::abi::Callback;
use crate::command::{self, Pending};
use crate::conn::FdTransport;
use crate::log;
use crate::restart::Restart;
use crate::sys;
use dataos_nicm_abi::{abi_enabled, kind, status, EventBuf, NicmCmd, NicmReply};
use dataos_nicm_compat::{Client, Notice};
use std::os::fd::{AsFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{JoinHandle, ThreadId};
use std::time::Duration;

/// How long a request waits for the daemon, in milliseconds. The stock timeout is
/// not known **[U]**.
pub const REQUEST_TIMEOUT_MS: u64 = 10_000;
static TIMEOUT_MS: AtomicU64 = AtomicU64::new(REQUEST_TIMEOUT_MS);

/// The wait for the question whether a call can be used again. The module asks it on a thread
/// of the radio daemon, and a stuck daemon must not hold that thread for the 10 seconds of the
/// others. It is longer than the 2 seconds the daemon gives the modem, so the daemon's answer is
/// the one that comes.
pub const MATCHING_CALL_TIMEOUT_MS: u64 = 3_000;

/// How long the request of this kind waits for the daemon.
pub fn request_wait(kind: u32) -> Duration {
    let ms = TIMEOUT_MS.load(Ordering::SeqCst);
    Duration::from_millis(if kind == dataos_nicm_abi::kind::MATCHING_CALL {
        ms.min(MATCHING_CALL_TIMEOUT_MS)
    } else {
        ms
    })
}

/// Tests shorten the wait. Nothing in the library calls this.
pub fn set_request_timeout_for_tests(ms: u64) {
    TIMEOUT_MS.store(ms, Ordering::SeqCst);
}
static RETRY_FIRST: std::sync::atomic::AtomicI32 =
    std::sync::atomic::AtomicI32::new(RETRY_FIRST_MS);

/// Tests shorten the first pause of a reconnect. Nothing in the library calls this.
pub fn set_retry_first_for_tests(ms: i32) {
    RETRY_FIRST.store(ms, Ordering::SeqCst);
}

static RESYNC_HOOK: Mutex<Option<fn()>> = Mutex::new(None);

/// Tests run this where the connection is read to its end before it is given up. Nothing in the library calls this.
pub fn resync_hook_for_tests(hook: Option<fn()>) {
    *lock(&RESYNC_HOOK) = hook;
}

static FAIL_DUP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Tests make the copy of the connection descriptor that the reader waits on fail. Nothing in the library calls this.
pub fn fail_descriptor_copies_for_tests(on: bool) {
    FAIL_DUP.store(on, Ordering::SeqCst);
}

/// A silent connection is looked at again after this long.
const IDLE_MS: i32 = 60_000;
const RETRY_FIRST_MS: i32 = 1_000;
const RETRY_MAX_MS: i32 = 30_000;
/// Registrations the data module may hold at once.
pub const MAX_REGISTRATIONS: usize = 4;
/// Batches of notices that wait for the module's callback. When the module is
/// slower than the daemon, the rest is dropped and the connection is made again (see `resync`).
pub const MAX_QUEUED_BATCHES: usize = 64;

/// Opens the connection. The daemon's socket in the library, a socket pair in the tests.
pub type Connector = Box<dyn FnMut() -> std::io::Result<OwnedFd> + Send>;

pub struct Registration {
    pub id: u64,
    pub cb: Callback,
    pub user: crate::abi::UserData,
}

struct Inner {
    client: Client<FdTransport>,
    regs: Vec<Registration>,
    connector: Connector,
    wake_r: OwnedFd,
    wake_w: OwnedFd,
    stop: bool,
    thread: Option<JoinHandle<()>>,
    dispatcher: Option<JoinHandle<()>>,
    /// Notices for the dispatcher thread, which calls the data module back.
    notices: Option<SyncSender<Vec<Notice>>>,
    next_id: u64,
    /// Events the data module was not given because the layouts are not verified.
    withheld: u32,
    /// The registration whose callback is running now.
    calling: Option<u64>,
    dispatcher_id: Option<ThreadId>,
    /// Notices that did not fit in the queue, and whether the module has to be told.
    dropped: u32,
    overflow: bool,
    /// Where the module is in a restart, and the Downs it has missed.
    restart: Restart,
}

pub struct Shared {
    inner: Mutex<Inner>,
    cond: Condvar,
    /// Signalled when a callback has returned.
    idle: Condvar,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Give the connection up: the daemon cannot write to it any more, what it wrote is read to the end and the
/// connection is lost, in one hold of the lock. Whatever else the library does with the notices comes after,
/// so no callback runs between the reading and the closing, and a Down the daemon wrote is never dropped with
/// the socket. Used wherever the connection ends, whatever the reason.
fn give_up(g: &mut Inner) -> Vec<Notice> {
    log::info("nicm: the connection to datad ended");
    let notices = g.client.finish();
    g.client.transport_mut().close();
    notices
}

impl Shared {
    /// Start the connection and its thread. None: nothing could be set up.
    pub fn start(mut connector: Connector) -> Option<Arc<Shared>> {
        let (wake_r, wake_w) = sys::wake_pipe().ok()?;
        let mut client = Client::new(FdTransport::default());
        match connector() {
            Ok(fd) => {
                client.transport_mut().set(fd);
                let _ = client.hello();
                log::info("nicm: connected to datad, readiness question sent");
            }
            Err(e) => log::info(&format!("nicm: cannot connect to datad: {e}")),
        }
        let (tx, rx) = sync_channel(MAX_QUEUED_BATCHES);
        let shared = Arc::new(Shared {
            inner: Mutex::new(Inner {
                client,
                regs: Vec::new(),
                connector,
                wake_r,
                wake_w,
                stop: false,
                thread: None,
                dispatcher: None,
                notices: Some(tx),
                next_id: 1,
                withheld: 0,
                calling: None,
                dispatcher_id: None,
                dropped: 0,
                overflow: false,
                restart: Restart::default(),
            }),
            cond: Condvar::new(),
            idle: Condvar::new(),
        });
        // The thread that calls the module back first, so that a failure to start the
        // reader leaves nothing running. Events only come from the reader.
        let for_dispatch = Arc::clone(&shared);
        let dispatcher = std::thread::Builder::new()
            .name("nicm-events".into())
            .spawn(move || for_dispatch.dispatch(rx))
            .ok()?;
        lock(&shared.inner).dispatcher_id = Some(dispatcher.thread().id());
        let for_thread = Arc::clone(&shared);
        let listener = std::thread::Builder::new()
            .name("nicm-listener".into())
            .spawn(move || for_thread.listen());
        let Ok(listener) = listener else {
            // closing the queue ends the dispatcher
            lock(&shared.inner).notices = None;
            let _ = dispatcher.join();
            return None;
        };
        let mut g = lock(&shared.inner);
        g.thread = Some(listener);
        g.dispatcher = Some(dispatcher);
        drop(g);
        Some(shared)
    }

    /// Add a registration. None: too many.
    pub fn register(&self, cb: Callback, user: crate::abi::UserData) -> Option<u64> {
        let mut g = lock(&self.inner);
        if g.regs.len() >= MAX_REGISTRATIONS {
            return None;
        }
        let id = g.next_id;
        g.next_id = g.next_id.wrapping_add(1).max(1);
        g.regs.push(Registration { id, cb, user });
        Some(id)
    }

    /// Remove a registration. True when none is left. When its callback is running
    /// on another thread, this waits for it to return, so that nothing of the module
    /// is called after the release returned. A release from the callback itself (on
    /// the dispatcher thread) cannot wait for itself: the callback returns after it.
    pub fn unregister(&self, id: u64) -> bool {
        let mut g = lock(&self.inner);
        g.regs.retain(|r| r.id != id);
        if g.dispatcher_id != Some(std::thread::current().id()) {
            while g.calling == Some(id) {
                g = self.idle.wait(g).unwrap_or_else(PoisonError::into_inner);
            }
        }
        g.regs.is_empty()
    }

    pub fn withheld_events(&self) -> u32 {
        lock(&self.inner).withheld
    }

    /// Notices dropped because the queue to the module was full.
    pub fn dropped_events(&self) -> u32 {
        lock(&self.inner).dropped
    }

    pub fn connected(&self) -> bool {
        lock(&self.inner).client.transport_mut().connected()
    }

    /// Stop the threads and wait for them.
    pub fn shutdown(&self) {
        let (t, d) = {
            let mut g = lock(&self.inner);
            g.stop = true;
            sys::wake(g.wake_w.as_fd());
            // the dispatcher ends when its channel is closed
            g.notices = None;
            (g.thread.take(), g.dispatcher.take())
        };
        // A release from the module's callback runs on the dispatcher thread, which
        // cannot wait for itself: it ends on its own once the callback returns.
        let me = std::thread::current().id();
        for t in [t, d].into_iter().flatten() {
            if t.thread().id() != me {
                let _ = t.join();
            }
        }
    }

    /// Send a command and wait for its answer. Never panics, never waits for ever. A failure is written to
    /// the log (`log::reply`).
    pub fn execute(&self, cmd: &NicmCmd) -> NicmReply {
        let reply = self.execute_inner(cmd);
        log::reply(cmd.kind, reply.status);
        reply
    }

    fn execute_inner(&self, cmd: &NicmCmd) -> NicmReply {
        let mut g = lock(&self.inner);
        // While the library holds a Down it has not given the module yet, or has dropped notices and is about
        // to make the connection again, the module has not heard all that the daemon said. A number could be
        // asked for again that the module still has a call on. DSI refuses a new call the same way while it is
        // not inited, so the lookups fail as they do for a lost connection.
        let behind = g.overflow || g.restart.waiting() > 0;
        if behind && matches!(cmd.kind, kind::ROUTE_LOOKUP | kind::MATCHING_CALL) {
            return NicmReply::failed(status::TRANSPORT);
        }
        let pending = match command::begin(&mut g.client, cmd) {
            Ok(p) => p,
            Err(s) => {
                // A send that fails ends the connection. The listener may not have noticed
                // yet, so it looks again.
                if g.client.transport_mut().is_dead() {
                    sys::wake(g.wake_w.as_fd());
                }
                return NicmReply::failed(s);
            }
        };
        let started = std::time::Instant::now();
        loop {
            // the listener thread feeds the client and wakes us
            match &pending {
                Pending::Txn(t) => {
                    if let Some(r) = g.client.take_reply(*t) {
                        return command::reply_of(r);
                    }
                }
                Pending::Ready(seen) => {
                    if g.client.ready_count() != *seen {
                        return command::ready_reply(g.client.ready());
                    }
                }
            }
            if !g.client.transport_mut().connected() {
                if let Pending::Txn(t) = &pending {
                    g.client.forget(*t);
                }
                return NicmReply::failed(status::TRANSPORT);
            }
            let limit = request_wait(cmd.kind);
            let left = limit.saturating_sub(started.elapsed());
            if left.is_zero() {
                if let Pending::Txn(t) = &pending {
                    g.client.forget(*t);
                }
                return NicmReply::failed(status::TIMEOUT);
            }
            g = self
                .cond
                .wait_timeout(g, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// Hand notices to the dispatcher thread. When the queue is full they are
    /// dropped and counted, and the connection is made again once the module has
    /// caught up (see `dispatch`). The reader never waits for the module.
    fn queue(&self, notices: Vec<Notice>) {
        if notices.is_empty() {
            return;
        }
        let tx = lock(&self.inner).notices.clone();
        let Some(tx) = tx else { return };
        let n = u32::try_from(notices.len()).unwrap_or(u32::MAX);
        match tx.try_send(notices) {
            Ok(()) | Err(TrySendError::Disconnected(_)) => {}
            Err(TrySendError::Full(lost)) => {
                let mut g = lock(&self.inner);
                g.dropped = g.dropped.saturating_add(n);
                g.overflow = true;
                // the Downs among them are given after the next INIT_DONE, the replay does not tell of them
                g.restart.keep(&lost);
            }
        }
    }

    /// Did notices get dropped since the last time? Clears the mark.
    fn take_overflow(&self) -> bool {
        std::mem::take(&mut lock(&self.inner).overflow)
    }

    /// The thread that calls the data module back. It is not the thread that
    /// reads the socket: a callback may call into this library and wait for the
    /// answer, which only the reader can bring. Whenever the queue has run empty
    /// after notices were dropped, the connection is made again (`resync`).
    fn dispatch(&self, rx: Receiver<Vec<Notice>>) {
        loop {
            let batch = match rx.try_recv() {
                Ok(b) => b,
                Err(TryRecvError::Disconnected) => return,
                Err(TryRecvError::Empty) => {
                    if self.take_overflow() {
                        self.resync();
                        continue;
                    }
                    match rx.recv() {
                        Ok(b) => b,
                        Err(_) => return,
                    }
                }
            };
            self.deliver(batch);
        }
    }

    /// Notices were dropped, so the module has missed something. DSI keeps its interfaces and calls across
    /// INIT_START and INIT_DONE, the restart events alone give it nothing back. The daemon replays the
    /// state of the links a process holds to a connection that says Hello after INIT_DONE, so the connection is
    /// closed as if the daemon had been lost: the module hears INIT_START, the reader connects again, and the
    /// answer to the Hello is INIT_DONE and the replay. The replay shows the links that are held, not the ones
    /// that ended. So what the socket still holds is read and given first, and the Downs that were dropped or
    /// come between INIT_START and INIT_DONE are given right after INIT_DONE (`Restart`).
    fn resync(&self) {
        let notices = {
            let mut g = lock(&self.inner);
            if g.stop {
                return;
            }
            if let Some(hook) = *lock(&RESYNC_HOOK) {
                hook();
            }
            let n = give_up(&mut g);
            sys::wake(g.wake_w.as_fd());
            n
        };
        self.cond.notify_all();
        self.deliver(notices);
    }

    /// Mark the callback of a registration as running. False: it was released.
    fn begin_call(&self, id: u64) -> bool {
        let mut g = lock(&self.inner);
        if !g.regs.iter().any(|r| r.id == id) {
            return false;
        }
        g.calling = Some(id);
        true
    }

    fn end_call(&self) {
        lock(&self.inner).calling = None;
        self.idle.notify_all();
    }

    fn deliver(&self, notices: Vec<Notice>) {
        for n in notices {
            let given = lock(&self.inner).restart.pass(n);
            for n in given {
                self.call_registrations(n);
            }
        }
    }

    fn call_registrations(&self, n: Notice) {
        // the registrations as they are now: one released a moment ago gets nothing
        let regs: Vec<(u64, Callback, usize)> = {
            let mut g = lock(&self.inner);
            if !abi_enabled() {
                g.withheld = g.withheld.saturating_add(1);
                return;
            }
            g.regs.iter().map(|r| (r.id, r.cb, r.user.addr())).collect()
        };
        let ev = command::event_of(n);
        for (id, cb, user) in regs {
            if !self.begin_call(id) {
                continue;
            }
            let mut buf = Box::new(EventBuf::new(ev));
            crate::abi::call_module(cb, &mut buf, user);
            self.end_call();
        }
    }

    fn listen(&self) {
        let first = RETRY_FIRST.load(Ordering::SeqCst);
        let mut backoff = first;
        // the pause starts over only when a daemon answered: one that closes at once does not
        let mut answers = 0;
        // the last readiness the daemon told, for the log
        let mut told: Option<bool> = None;
        loop {
            let (stop, wake_r_fd) = {
                let g = lock(&self.inner);
                (g.stop, g.wake_r.try_clone())
            };
            let Ok(wake_r) = wake_r_fd else { return };
            if stop {
                return;
            }
            let connected = lock(&self.inner).client.transport_mut().connected();
            if !connected {
                // try again after a pause that grows, and stay ready to stop
                let _ = sys::wait(None, wake_r.as_fd(), backoff);
                sys::drain(wake_r.as_fd());
                let mut g = lock(&self.inner);
                if g.stop {
                    return;
                }
                let fd = (g.connector)();
                match fd {
                    Ok(fd) => {
                        g.client.transport_mut().set(fd);
                        let _ = g.client.reconnected();
                        log::info("nicm: connected to datad again, readiness question sent");
                        backoff = backoff.saturating_mul(2).min(RETRY_MAX_MS);
                    }
                    Err(e) => {
                        log::repeated(
                            log::RECONNECT,
                            u32::try_from(e.raw_os_error().unwrap_or(0)).unwrap_or(0),
                            &format!("nicm: cannot connect to datad: {e}"),
                        );
                        backoff = backoff.saturating_mul(2).min(RETRY_MAX_MS);
                    }
                }
                continue;
            }
            // wait on the connection and the wake pipe without the lock
            let conn = {
                let g = lock(&self.inner);
                g.client
                    .transport()
                    .fd()
                    .filter(|_| !FAIL_DUP.load(Ordering::SeqCst))
                    .and_then(|f| f.try_clone_to_owned().ok())
            };
            let Some(conn) = conn else {
                // the connection cannot be waited on: it is lost, and the module is told
                let mut g = lock(&self.inner);
                let lost = give_up(&mut g);
                answers = g.client.ready_count();
                drop(g);
                self.cond.notify_all();
                self.queue(lost);
                continue;
            };
            let woke = sys::wait(Some(conn.as_fd()), wake_r.as_fd(), IDLE_MS);
            sys::drain(wake_r.as_fd());
            let mut notices = Vec::new();
            {
                let mut g = lock(&self.inner);
                if g.stop {
                    return;
                }
                if woke.is_err() {
                    notices.extend(give_up(&mut g));
                    // our own note that the daemon is gone is not an answer of a daemon
                    answers = g.client.ready_count();
                } else {
                    // one poll per wake: the lock is let go between two, and the wait
                    // below returns at once while the socket has more
                    notices.extend(g.client.poll());
                    if g.client.ready_count() != answers {
                        answers = g.client.ready_count();
                        backoff = first;
                        let ready = g.client.ready();
                        if ready != told {
                            told = ready;
                            log::info(match ready {
                                Some(true) => "nicm: datad says it is ready",
                                _ => "nicm: datad says it is not ready",
                            });
                        }
                    }
                    if g.client.transport_mut().is_dead() {
                        notices.extend(give_up(&mut g));
                        // our own note that the daemon is gone is not an answer of a daemon
                        answers = g.client.ready_count();
                    }
                }
            }
            self.cond.notify_all();
            self.queue(notices);
        }
    }
}
