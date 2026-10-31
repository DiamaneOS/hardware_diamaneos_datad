// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The libc calls, and nothing else. Every unsafe block says why it is sound.
#![allow(unsafe_code)]
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

/// The daemon's socket keeps message boundaries. The host tests (macOS has no
/// SOCK_SEQPACKET for Unix sockets) use datagrams, which do the same.
#[cfg(any(target_os = "linux", target_os = "android"))]
const KIND: libc::c_int = libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const KIND: libc::c_int = libc::SOCK_DGRAM;

#[cfg(any(target_os = "linux", target_os = "android"))]
const NO_SIGNAL: libc::c_int = libc::MSG_NOSIGNAL;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const NO_SIGNAL: libc::c_int = 0;

fn check(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn own(fd: libc::c_int) -> OwnedFd {
    // SAFETY: the descriptor was just returned by the kernel and nothing else owns it.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

fn set_flags(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on a descriptor this process owns, with integer arguments only.
    unsafe {
        let fl = check(libc::fcntl(fd, libc::F_GETFL))?;
        check(libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK))?;
        check(libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC))?;
    }
    Ok(())
}

/// Connect to a Unix socket by path.
pub fn connect(path: &str) -> io::Result<OwnedFd> {
    // SAFETY: socket() takes integers only.
    let fd = own(check(unsafe { libc::socket(libc::AF_UNIX, KIND, 0) })?);
    // SAFETY: sockaddr_un is plain integers and bytes, all zeroes is a valid value.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_bytes();
    if bytes.len() >= addr.sun_path.len() || bytes.contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    for (d, s) in addr.sun_path.iter_mut().zip(bytes) {
        *d = *s as libc::c_char;
    }
    let len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    // SAFETY: addr is a valid sockaddr_un that lives through the call and len is its size.
    check(unsafe {
        libc::connect(
            fd.as_raw_fd(),
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            len,
        )
    })?;
    set_flags(fd.as_raw_fd())?;
    Ok(fd)
}

/// Two connected ends, for the tests and as the daemon's side in them.
pub fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: fds is an array of two integers, as socketpair requires.
    check(unsafe { libc::socketpair(libc::AF_UNIX, KIND, 0, fds.as_mut_ptr()) })?;
    let [a, b] = fds;
    let (a, b) = (own(a), own(b));
    set_flags(a.as_raw_fd())?;
    set_flags(b.as_raw_fd())?;
    Ok((a, b))
}

/// A pipe that wakes the listener thread: (read end, write end).
pub fn wake_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: fds is an array of two integers, as pipe requires.
    check(unsafe { libc::pipe(fds.as_mut_ptr()) })?;
    let [r, w] = fds;
    let (r, w) = (own(r), own(w));
    set_flags(r.as_raw_fd())?;
    set_flags(w.as_raw_fd())?;
    Ok((r, w))
}

/// Send one message. Anything but the whole message is an error.
pub fn send(fd: BorrowedFd<'_>, buf: &[u8]) -> io::Result<()> {
    // SAFETY: the pointer and the length are those of buf, which lives through the call.
    let n = unsafe { libc::send(fd.as_raw_fd(), buf.as_ptr().cast(), buf.len(), NO_SIGNAL) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(n).ok() != Some(buf.len()) {
        return Err(io::ErrorKind::WriteZero.into());
    }
    Ok(())
}

/// Stop the other side from writing: its next send fails with a broken pipe. What it wrote before stays to be read.
pub fn shutdown_read(fd: BorrowedFd<'_>) {
    // SAFETY: shutdown takes the descriptor and a constant, and a failure changes nothing that matters here.
    let _ = unsafe { libc::shutdown(fd.as_raw_fd(), libc::SHUT_RD) };
}

/// One message without waiting. None: nothing there. Some(0): the other side closed.
pub fn recv(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<Option<usize>> {
    // SAFETY: the pointer and the length are those of buf, which lives through the call.
    let n = unsafe {
        libc::recv(
            fd.as_raw_fd(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            libc::MSG_DONTWAIT,
        )
    };
    if n < 0 {
        let e = io::Error::last_os_error();
        return if e.kind() == io::ErrorKind::WouldBlock {
            Ok(None)
        } else {
            Err(e)
        };
    }
    Ok(Some(usize::try_from(n).unwrap_or(0)))
}

/// Wait until the connection or the wake pipe is readable, or the time is over.
/// Returns (connection readable or closed, woken).
pub fn wait(
    conn: Option<BorrowedFd<'_>>,
    wake: BorrowedFd<'_>,
    ms: i32,
) -> io::Result<(bool, bool)> {
    let mut fds = [
        libc::pollfd {
            fd: conn.map_or(-1, |c| c.as_raw_fd()),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: wake.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    // SAFETY: fds is an array of two pollfd structs, the count is two.
    let r = unsafe { libc::poll(fds.as_mut_ptr(), 2, ms) };
    if r < 0 {
        let e = io::Error::last_os_error();
        return if e.kind() == io::ErrorKind::Interrupted {
            Ok((false, false))
        } else {
            Err(e)
        };
    }
    let [c, w] = fds;
    let any = libc::POLLIN | libc::POLLHUP | libc::POLLERR;
    Ok((c.revents & any != 0, w.revents & any != 0))
}

/// Make the listener thread look again. A full pipe already wakes it.
pub fn wake(w: BorrowedFd<'_>) {
    let b = [1u8];
    // SAFETY: the pointer and the length are those of b.
    let _ = unsafe { libc::write(w.as_raw_fd(), b.as_ptr().cast(), 1) };
}

/// Empty the wake pipe.
pub fn drain(r: BorrowedFd<'_>) {
    let mut b = [0u8; 16];
    // SAFETY: the pointer and the length are those of b.
    while unsafe { libc::read(r.as_raw_fd(), b.as_mut_ptr().cast(), b.len()) } > 0 {}
}

#[cfg(target_os = "android")]
extern "C" {
    /// liblog (`libnicm.so` links it: `shared_libs` of its Android.bp).
    fn __android_log_write(
        prio: libc::c_int,
        tag: *const libc::c_char,
        text: *const libc::c_char,
    ) -> libc::c_int;
}

/// One line to logd at the information level, tag `nicm`. Nothing happens off Android (the host tests). A line
/// is cut at 1000 bytes, and a zero byte in it is left out.
pub fn log_info(text: &str) {
    #[cfg(target_os = "android")]
    {
        let mut line: Vec<u8> = text.bytes().filter(|b| *b != 0).take(1000).collect();
        line.push(0);
        // SAFETY: the tag and the line are NUL-terminated, live through the call, and liblog only reads them.
        let _ = unsafe { __android_log_write(4, c"nicm".as_ptr(), line.as_ptr().cast()) };
    }
    #[cfg(not(target_os = "android"))]
    let _ = text;
}
