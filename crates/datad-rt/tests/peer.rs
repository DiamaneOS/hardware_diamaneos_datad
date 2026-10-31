// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The accept path with `SO_PEERCRED` and `SO_PEERSEC`, which only a Linux kernel answers. These tests
//! compile for aarch64 Linux (`cargo clippy --target aarch64-unknown-linux-gnu --all-targets`) and run on a Linux host. They can run on a
//! phone as well (build the binary with `cargo test -p dataos-datad-rt --test peer --target
//! aarch64-unknown-linux-gnu --no-run` and push it to a directory the shell can run it from): there
//! SELinux answers, and the label the daemon reads for its peer must be its own context. Where
//! SELinux does not answer, an accept of a peer must refuse it.
#![cfg(any(target_os = "linux", target_os = "android"))]
use dataos_datad::ipc::{Ipc, IpcFault};
use dataos_datad_rt::unix::{peer_info, UnixIpc};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

fn seqpacket() -> OwnedFd {
    // SAFETY: socket() takes integers and returns a new descriptor or -1.
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    assert!(raw >= 0);
    // SAFETY: just returned, nothing else owns it.
    unsafe { OwnedFd::from_raw_fd(raw) }
}

fn abstract_addr(name: &str) -> (libc::sockaddr_un, libc::socklen_t) {
    // SAFETY: sockaddr_un is plain integers and bytes, all zero is a valid value.
    let mut a: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    a.sun_family = libc::AF_UNIX as libc::sa_family_t;
    // a leading NUL byte is an abstract name: no file on the disk
    for (d, s) in a.sun_path.iter_mut().skip(1).zip(name.bytes()) {
        *d = s as libc::c_char;
    }
    let len = std::mem::size_of::<libc::sa_family_t>() + 1 + name.len();
    (a, len as libc::socklen_t)
}

fn listener(name: &str) -> OwnedFd {
    let fd = seqpacket();
    let (a, len) = abstract_addr(name);
    // SAFETY: a is a sockaddr_un of the length given.
    unsafe {
        assert_eq!(
            libc::bind(fd.as_raw_fd(), (&a as *const libc::sockaddr_un).cast(), len),
            0
        );
        assert_eq!(libc::listen(fd.as_raw_fd(), 4), 0);
    }
    fd
}

fn connect(name: &str) -> OwnedFd {
    let fd = seqpacket();
    let (a, len) = abstract_addr(name);
    // SAFETY: a is a sockaddr_un of the length given.
    let rc = unsafe { libc::connect(fd.as_raw_fd(), (&a as *const libc::sockaddr_un).cast(), len) };
    assert_eq!(rc, 0);
    fd
}

/// This process's own SELinux context, if the kernel has SELinux.
fn own_context() -> Option<String> {
    let raw = std::fs::read("/proc/self/attr/current").ok()?;
    let text = String::from_utf8(raw).ok()?;
    let text = text.trim_end_matches('\0').trim().to_string();
    (!text.is_empty() && text != "kernel").then_some(text)
}

fn selinux_answers(fd: i32) -> bool {
    let mut buf = [0u8; 256];
    let mut len = buf.len() as libc::socklen_t;
    // SAFETY: the buffer is 256 bytes and len says so.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    };
    rc == 0
}

#[test]
fn the_process_and_the_user_of_a_peer_are_those_of_its_socket() {
    let name = format!("datad-peer-test-{}-a", std::process::id());
    let l = listener(&name);
    let _c = connect(&name);
    // SAFETY: accept with no address asked for.
    let raw = unsafe { libc::accept(l.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut()) };
    assert!(raw >= 0);
    // SAFETY: just returned, nothing else owns it.
    let served = unsafe { OwnedFd::from_raw_fd(raw) };
    match peer_info(served.as_raw_fd()) {
        Ok(info) => {
            // SELinux answered: the peer is this very process
            assert_eq!(info.pid, std::process::id());
            // SAFETY: getuid cannot fail.
            assert_eq!(info.uid, unsafe { libc::getuid() });
            assert_eq!(Some(info.label), own_context());
        }
        Err(_) => assert!(
            !selinux_answers(served.as_raw_fd()),
            "SELinux answered but the peer was refused"
        ),
    }
}

#[test]
fn an_accepted_peer_has_a_label_or_is_refused_and_closed() {
    let name = format!("datad-peer-test-{}-b", std::process::id());
    let mut ipc = UnixIpc::from_listener(listener(&name)).unwrap();
    assert_eq!(ipc.accept(), Ok(None));
    let client = connect(&name);
    let got = ipc.accept();
    // SELinux answers: the peer is handed over with the context of this process. It does not: the
    // peer is closed and the accept says so, and no connection is kept
    match (own_context(), got) {
        (Some(ctx), Ok(Some((_, info)))) => {
            assert_eq!(info.label, ctx);
            assert_eq!(info.pid, std::process::id());
            assert_eq!(ipc.fds().len(), 2);
        }
        (_, Err(IpcFault::Gone)) => {
            assert_eq!(ipc.fds().len(), 1, "the refused peer is not kept");
            // the client sees the end
            let mut b = [0u8; 4];
            // SAFETY: the buffer is 4 bytes.
            let n = unsafe { libc::recv(client.as_raw_fd(), b.as_mut_ptr().cast(), 4, 0) };
            assert_eq!(n, 0);
        }
        (ctx, got) => panic!("unexpected: context {ctx:?}, accept {got:?}"),
    }
}
