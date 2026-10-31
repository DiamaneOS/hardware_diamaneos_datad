// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Messages on a connected Unix socket, whole and without waiting. The socket of the protocol keeps
//! message boundaries (`SOCK_SEQPACKET`), so one read is one message. The host tests use a stream
//! pair, which does the same for one small message at a time.
#![allow(unsafe_code)]
use std::io;
use std::os::fd::RawFd;

#[cfg(any(target_os = "linux", target_os = "android"))]
const NO_SIGNAL: libc::c_int = libc::MSG_NOSIGNAL;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const NO_SIGNAL: libc::c_int = 0;

#[derive(Debug, PartialEq, Eq)]
pub enum Recv {
    Message(Vec<u8>),
    /// Nothing to read now.
    Empty,
    /// The other side closed.
    Closed,
    /// A message above the limit. It was read and thrown away.
    TooLong,
}

/// The next message of at most `max` bytes. The protocol has no empty message, so a read of
/// nothing is the other side closing.
pub fn recv_message(fd: RawFd, max: usize) -> io::Result<Recv> {
    let mut buf = vec![0u8; max.saturating_add(1)];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // SAFETY: msghdr is plain integers and pointers, all zero means "no name, no control data".
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    // SAFETY: the message names one writable buffer that lives through the call.
    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        let e = io::Error::last_os_error();
        return match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(Recv::Empty),
            _ => Err(e),
        };
    }
    let n = usize::try_from(n).unwrap_or(0);
    if n == 0 {
        return Ok(Recv::Closed);
    }
    // the buffer holds one byte more than the limit, so a longer message shows as too long here
    if n > max {
        return Ok(Recv::TooLong);
    }
    buf.truncate(n);
    Ok(Recv::Message(buf))
}

/// One whole message without waiting and without a signal if the other side is gone. Less than
/// the whole message is an error.
pub fn send_message(fd: RawFd, bytes: &[u8]) -> io::Result<()> {
    // SAFETY: the pointer and the length are those of `bytes`, which lives through the call.
    let n = unsafe {
        libc::send(
            fd,
            bytes.as_ptr().cast(),
            bytes.len(),
            libc::MSG_DONTWAIT | NO_SIGNAL,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(n).ok() != Some(bytes.len()) {
        return Err(io::ErrorKind::WriteZero.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    fn pair() -> (UnixStream, UnixStream) {
        let (a, b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        b.set_nonblocking(true).unwrap();
        (a, b)
    }

    #[test]
    fn a_message_comes_whole() {
        let (a, mut b) = pair();
        assert_eq!(recv_message(a.as_raw_fd(), 16).unwrap(), Recv::Empty);
        b.write_all(&[1, 2, 3]).unwrap();
        assert_eq!(
            recv_message(a.as_raw_fd(), 16).unwrap(),
            Recv::Message(vec![1, 2, 3])
        );
        assert_eq!(recv_message(a.as_raw_fd(), 16).unwrap(), Recv::Empty);
    }

    #[test]
    fn a_message_of_exactly_the_limit_is_kept_and_one_more_byte_is_too_long() {
        let (a, mut b) = pair();
        b.write_all(&[7; 16]).unwrap();
        assert_eq!(
            recv_message(a.as_raw_fd(), 16).unwrap(),
            Recv::Message(vec![7; 16])
        );
        b.write_all(&[7; 17]).unwrap();
        assert_eq!(recv_message(a.as_raw_fd(), 16).unwrap(), Recv::TooLong);
    }

    #[test]
    fn the_other_side_closing_is_told_apart_from_nothing_to_read() {
        let (a, b) = pair();
        drop(b);
        assert_eq!(recv_message(a.as_raw_fd(), 16).unwrap(), Recv::Closed);
    }

    #[test]
    fn a_descriptor_that_is_none_is_an_error() {
        assert!(recv_message(-1, 16).is_err());
        assert!(send_message(-1, &[1]).is_err());
    }

    #[test]
    fn a_message_goes_out_whole_and_a_full_socket_is_an_error_that_says_so() {
        let (a, mut b) = pair();
        send_message(a.as_raw_fd(), &[5, 6]).unwrap();
        let mut buf = [0u8; 8];
        let n = std::io::Read::read(&mut b, &mut buf).unwrap();
        assert_eq!(&buf[..n], &[5, 6]);
        // fill the socket until it has no room
        let chunk = [0u8; 4096];
        let mut full = None;
        for _ in 0..100_000 {
            if let Err(e) = send_message(a.as_raw_fd(), &chunk) {
                full = Some(e);
                break;
            }
        }
        let e = full.expect("the socket never filled up");
        assert_eq!(
            crate::fault::ipc_fault(&e),
            dataos_datad::ipc::IpcFault::Busy
        );
    }

    #[test]
    fn a_send_to_a_closed_peer_is_an_error_and_no_signal() {
        let (a, b) = pair();
        drop(b);
        let e = send_message(a.as_raw_fd(), &[1]).unwrap_err();
        assert_eq!(
            crate::fault::ipc_fault(&e),
            dataos_datad::ipc::IpcFault::Gone
        );
    }
}
