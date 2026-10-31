// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The signals the daemon takes: a request to stop, and a closed socket that must not kill it.
#![allow(unsafe_code)]
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_stop(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

pub fn stop_requested() -> bool {
    STOP.load(Ordering::Relaxed)
}

/// SIGTERM, SIGINT and SIGHUP ask the loop to stop, and SIGPIPE is ignored.
pub fn install() -> io::Result<()> {
    let handler = on_stop as extern "C" fn(libc::c_int) as libc::sighandler_t;
    for (signal, action) in [
        (libc::SIGTERM, handler),
        (libc::SIGINT, handler),
        (libc::SIGHUP, handler),
        (libc::SIGPIPE, libc::SIG_IGN),
    ] {
        // SAFETY: the handler only stores an atomic flag, which is allowed in a signal handler,
        // and SIG_IGN is a valid action.
        if unsafe { libc::signal(signal, action) } == libc::SIG_ERR {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handler_of(signal: libc::c_int) -> libc::sighandler_t {
        // SAFETY: sigaction with no new action only reads the current one into the struct.
        unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            assert_eq!(libc::sigaction(signal, std::ptr::null(), &mut old), 0);
            old.sa_sigaction
        }
    }

    #[test]
    fn the_stop_signals_get_the_handler_and_a_closed_socket_is_ignored() {
        // start from the default action, so what install does shows
        for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGPIPE] {
            // SAFETY: setting the default action of a signal this test owns.
            unsafe { libc::signal(signal, libc::SIG_DFL) };
        }
        install().unwrap();
        let handler = on_stop as extern "C" fn(libc::c_int) as libc::sighandler_t;
        for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            assert_eq!(handler_of(signal), handler, "{signal}");
        }
        assert_eq!(handler_of(libc::SIGPIPE), libc::SIG_IGN);
        // and one of them does set the flag
        assert!(!stop_requested());
        // SAFETY: raise sends a signal to this thread, and the handler was installed above.
        assert_eq!(unsafe { libc::raise(libc::SIGHUP) }, 0);
        assert!(stop_requested());
        STOP.store(false, Ordering::Relaxed);
    }
}
