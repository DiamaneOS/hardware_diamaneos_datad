// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! QRTR datagram sockets (`AF_QIPCRTR`). Every socket is non-blocking and bound to a port the
//! kernel picks. A datagram that was cut short is read and left out, because the kernel reports the
//! length it copied and not the length it had. The same patterns as the IMS daemon.
#![allow(unsafe_code)]
use std::io;
use std::mem;
use std::os::fd::RawFd;

/// `struct sockaddr_qrtr` of the Linux UAPI.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Address {
    pub family: u16,
    pub reserved: u16,
    pub node: u32,
    pub port: u32,
}

pub const AF_QIPCRTR: u16 = 42;
pub const ADDRESS_LEN: usize = mem::size_of::<Address>();

impl Address {
    pub fn empty() -> Self {
        Address {
            family: 0,
            reserved: 0,
            node: 0,
            port: 0,
        }
    }

    pub fn to(node: u32, port: u32) -> Self {
        Address {
            family: AF_QIPCRTR,
            reserved: 0,
            node,
            port,
        }
    }
}

/// One datagram into `bytes`, without waiting: the number of bytes and the length of the address
/// that came with it. None: nothing there, or the datagram was cut short (and is gone).
pub fn recv_packet(
    fd: RawFd,
    bytes: &mut [u8],
    address: &mut Address,
) -> io::Result<Option<(usize, libc::socklen_t)>> {
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: msghdr is plain integers and pointers. Null control data with a zero length is valid.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_name = (address as *mut Address).cast();
    message.msg_namelen = ADDRESS_LEN as libc::socklen_t;
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    // SAFETY: the message names one writable slice and a buffer of the size of the address, all of
    // which live through the call, and nothing escapes it.
    let n = unsafe { libc::recvmsg(fd, &mut message, libc::MSG_DONTWAIT) };
    if n < 0 {
        let e = io::Error::last_os_error();
        return match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(None),
            _ => Err(e),
        };
    }
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Ok(None);
    }
    Ok(Some((usize::try_from(n).unwrap_or(0), message.msg_namelen)))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::QrtrSockets;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux {
    use super::*;
    use crate::fault::classify;
    use dataos_datad::qrtr::Peer;
    use dataos_datad::transport::{Fault, Qrtr, SockId};
    use dataos_qmi::frame::MAX_DATAGRAM;
    use std::collections::BTreeMap;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    pub struct QrtrSockets {
        socks: BTreeMap<SockId, (OwnedFd, Peer)>,
        next: SockId,
    }

    impl QrtrSockets {
        pub fn new() -> Self {
            QrtrSockets {
                socks: BTreeMap::new(),
                next: 1,
            }
        }
    }

    impl Default for QrtrSockets {
        fn default() -> Self {
            Self::new()
        }
    }

    fn name_of(fd: RawFd) -> io::Result<Address> {
        let mut a = Address::empty();
        let mut len = ADDRESS_LEN as libc::socklen_t;
        // SAFETY: the buffer is the size of the address and `len` says so.
        let rc = unsafe { libc::getsockname(fd, (&mut a as *mut Address).cast(), &mut len) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        if len as usize != ADDRESS_LEN || a.family != AF_QIPCRTR {
            return Err(io::Error::other("invalid QRTR address"));
        }
        Ok(a)
    }

    fn open_bound() -> io::Result<(OwnedFd, Peer)> {
        // SAFETY: socket() takes integers only and returns a new descriptor or -1.
        let raw = unsafe {
            libc::socket(
                libc::c_int::from(AF_QIPCRTR),
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a descriptor that was just returned and nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // A new socket knows the node of this machine already, and bind refuses any other node,
        // so ask the kernel for it and bind that with port 0 (any free port).
        let mut a = name_of(fd.as_raw_fd())?;
        a.port = 0;
        // SAFETY: the address is a sockaddr_qrtr of the size given.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&a as *const Address).cast(),
                ADDRESS_LEN as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        let bound = name_of(fd.as_raw_fd())?;
        if bound.port == 0 {
            return Err(io::Error::other("invalid QRTR bind"));
        }
        Ok((
            fd,
            Peer {
                node: bound.node,
                port: bound.port,
            },
        ))
    }

    impl Qrtr for QrtrSockets {
        fn open(&mut self) -> Result<SockId, Fault> {
            let (fd, local) = open_bound().map_err(|e| classify(&e))?;
            let id = self.next;
            self.next = self.next.wrapping_add(1);
            self.socks.insert(id, (fd, local));
            Ok(id)
        }

        fn close(&mut self, sock: SockId) {
            self.socks.remove(&sock);
        }

        fn local(&self, sock: SockId) -> Option<Peer> {
            self.socks.get(&sock).map(|(_, p)| *p)
        }

        fn send(&mut self, sock: SockId, to: Peer, bytes: &[u8]) -> Result<(), Fault> {
            let Some((fd, _)) = self.socks.get(&sock) else {
                return Err(Fault::Other);
            };
            let addr = Address::to(to.node, to.port);
            // SAFETY: the buffer and the address live through the call and their sizes are given.
            let rc = unsafe {
                libc::sendto(
                    fd.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    libc::MSG_DONTWAIT,
                    (&addr as *const Address).cast(),
                    ADDRESS_LEN as libc::socklen_t,
                )
            };
            if rc < 0 {
                return Err(classify(&io::Error::last_os_error()));
            }
            if usize::try_from(rc).ok() != Some(bytes.len()) {
                return Err(Fault::Other);
            }
            Ok(())
        }

        fn recv(&mut self, sock: SockId) -> Result<Option<(Peer, Vec<u8>)>, Fault> {
            let Some((fd, _)) = self.socks.get(&sock) else {
                return Err(Fault::Other);
            };
            let mut bytes = vec![0u8; MAX_DATAGRAM];
            let mut from = Address::empty();
            let got =
                recv_packet(fd.as_raw_fd(), &mut bytes, &mut from).map_err(|e| classify(&e))?;
            let Some((n, len)) = got else {
                return Ok(None);
            };
            if len as usize != ADDRESS_LEN || from.family != AF_QIPCRTR {
                return Ok(None);
            }
            bytes.truncate(n);
            Ok(Some((
                Peer {
                    node: from.node,
                    port: from.port,
                },
                bytes,
            )))
        }

        fn fds(&self) -> Vec<RawFd> {
            self.socks.values().map(|(fd, _)| fd.as_raw_fd()).collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixDatagram;

    #[test]
    fn the_address_is_the_size_the_kernel_expects() {
        assert_eq!(ADDRESS_LEN, 12);
        let a = Address::to(3, 4);
        assert_eq!((a.family, a.reserved, a.node, a.port), (42, 0, 3, 4));
        let e = Address::empty();
        assert_eq!((e.family, e.node, e.port), (0, 0, 0));
    }

    #[test]
    fn a_datagram_larger_than_the_buffer_is_dropped_even_when_the_kernel_reports_what_it_copied() {
        let (sender, receiver) = UnixDatagram::pair().unwrap();
        receiver.set_nonblocking(true).unwrap();
        let mut buffer = [0; 8];
        let mut address = Address::empty();
        sender.send(&[1; 9]).unwrap();
        assert!(recv_packet(receiver.as_raw_fd(), &mut buffer, &mut address)
            .unwrap()
            .is_none());
        // it is gone, and a datagram of exactly the size is whole
        sender.send(&[2; 8]).unwrap();
        let got = recv_packet(receiver.as_raw_fd(), &mut buffer, &mut address)
            .unwrap()
            .unwrap();
        assert_eq!(got.0, 8);
        assert_eq!(buffer, [2; 8]);
        // and nothing there is nothing
        assert!(recv_packet(receiver.as_raw_fd(), &mut buffer, &mut address)
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_descriptor_that_is_none_is_an_error() {
        let mut buffer = [0; 8];
        let mut address = Address::empty();
        assert!(recv_packet(-1, &mut buffer, &mut address).is_err());
    }
}
