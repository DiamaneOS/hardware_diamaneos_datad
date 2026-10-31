// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Which errno is which kind of fault, by what the daemon does about it. The kinds are those the
//! kernel paths know (`af_qrtr.c` and `ns.c` of the qcom module, read for this file **[V source]**):
//! `EAGAIN` while the flow control of a remote node holds a send back, `ENOBUFS` and `ENOMEM` when
//! memory is short, `ECONNRESET` for a node that is not known, `ENODEV` and `EPIPE` for an endpoint
//! that is gone, and `ENETRESET` on every socket when a new name service takes the control port
//! (`qrtr_reset_ports`, called from `__qrtr_bind` for that port, so with the name service of the kernel,
//! which binds it once at start, it should not happen). The handling stays. Anything
//! else is not guessed at.
use dataos_datad::ipc::IpcFault;
use dataos_datad::transport::Fault;
use std::io;

pub fn classify(error: &io::Error) -> Fault {
    match error.raw_os_error() {
        Some(libc::EAGAIN | libc::EINTR) => Fault::Retry,
        Some(libc::ENOBUFS | libc::ENOMEM) => Fault::Exhausted,
        Some(libc::EPIPE | libc::ENODEV | libc::ECONNRESET | libc::EHOSTUNREACH) => Fault::PeerGone,
        Some(libc::ENETRESET) => Fault::Reset,
        _ => Fault::Other,
    }
}

/// A Unix socket of the protocol: no room is a wait, anything else ends the connection.
pub fn ipc_fault(error: &io::Error) -> IpcFault {
    match error.raw_os_error() {
        Some(libc::EAGAIN | libc::EINTR | libc::ENOBUFS | libc::ENOMEM) => IpcFault::Busy,
        _ => IpcFault::Gone,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(code: i32) -> io::Error {
        io::Error::from_raw_os_error(code)
    }

    #[test]
    fn the_kernel_paths_errors_are_told_apart() {
        for code in [libc::EAGAIN, libc::EINTR] {
            assert_eq!(classify(&os(code)), Fault::Retry);
        }
        for code in [libc::ENOBUFS, libc::ENOMEM] {
            assert_eq!(classify(&os(code)), Fault::Exhausted);
        }
        for code in [
            libc::EPIPE,
            libc::ENODEV,
            libc::ECONNRESET,
            libc::EHOSTUNREACH,
        ] {
            assert_eq!(classify(&os(code)), Fault::PeerGone);
        }
        assert_eq!(classify(&os(libc::ENETRESET)), Fault::Reset);
    }

    #[test]
    fn nothing_else_is_guessed_at() {
        for code in [libc::EBADF, libc::EINVAL, libc::EPERM, libc::EMSGSIZE] {
            assert_eq!(classify(&os(code)), Fault::Other);
        }
        assert_eq!(classify(&io::Error::other("short write")), Fault::Other);
    }

    #[test]
    fn a_unix_socket_that_is_full_waits_and_any_other_error_ends_it() {
        for code in [libc::EAGAIN, libc::EINTR, libc::ENOBUFS, libc::ENOMEM] {
            assert_eq!(ipc_fault(&os(code)), IpcFault::Busy);
        }
        for code in [libc::EPIPE, libc::ECONNRESET, libc::EBADF, libc::EMSGSIZE] {
            assert_eq!(ipc_fault(&os(code)), IpcFault::Gone);
        }
        assert_eq!(ipc_fault(&io::Error::other("x")), IpcFault::Gone);
    }
}
