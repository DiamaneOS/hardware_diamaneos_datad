// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The socket of the protocol: a Unix socket that keeps message boundaries, created by init for the
//! service (`socket datad seqpacket 0660 ...` in the rc file) and handed over as a descriptor whose
//! number is in `ANDROID_SOCKET_datad`. A peer is handed to the server only with the process, the
//! user, the SELinux label and the identity of the process the kernel gives for it (`SO_PEERCRED`,
//! `SO_PEERSEC`, `SO_PEERPIDFD`). One whose credentials cannot be read is closed.
//!
//! Linux only. The accept and the credentials cannot be tried on the host: macOS has neither
//! `SOCK_SEQPACKET` for Unix sockets nor `SO_PEERSEC`. The reading and writing of messages is
//! `sock`, which the host tests do run.
#![allow(unsafe_code)]
use crate::fault::ipc_fault;
use crate::sock::{self, Recv};
use dataos_datad::ipc::{peer_label, Ipc, IpcFault, IpcId, PeerInfo, Read};
use dataos_wire::limits::MAX_MESSAGE;
use std::collections::BTreeMap;
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// The longest label read. A longer one is refused with the connection.
const LABEL_BUF: usize = 256;
/// `SO_PEERPIDFD` (Linux 6.5): a pidfd of the process that connected, also when it has exited since. The
/// libc crate of the platform build may not name it. The inode is the process's own from 6.9 (pidfs), and the
/// daemon does not start on an older kernel (`kernel::refuse_before`).
const SO_PEERPIDFD: libc::c_int = 77;
/// The queue of connections that wait: the server takes four, the rest wait here.
const BACKLOG: libc::c_int = 8;
/// Connections held at once, whatever the server decides: it takes four.
const MAX_OPEN: usize = 16;

pub struct UnixIpc {
    listener: OwnedFd,
    conns: BTreeMap<IpcId, OwnedFd>,
    next: IpcId,
}

fn check(rc: libc::c_int) -> io::Result<libc::c_int> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

fn int_option(fd: RawFd, level: libc::c_int, name: libc::c_int) -> io::Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: the buffer is one int and `len` says so.
    check(unsafe {
        libc::getsockopt(
            fd,
            level,
            name,
            (&mut value as *mut libc::c_int).cast(),
            &mut len,
        )
    })?;
    Ok(value)
}

fn make_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on a descriptor with integer arguments only.
    unsafe {
        let flags = check(libc::fcntl(fd, libc::F_GETFL))?;
        check(libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK))?;
        check(libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC))?;
    }
    Ok(())
}

impl UnixIpc {
    /// The socket init made for the service of this name.
    pub fn inherited(name: &str) -> io::Result<Self> {
        let value = std::env::var(format!("ANDROID_SOCKET_{name}"))
            .map_err(|_| io::Error::other("init gave no socket"))?;
        let raw: RawFd = value
            .parse()
            .map_err(|_| io::Error::other("the socket number is not a number"))?;
        // the standard descriptors are never init's socket, and a number that is no descriptor
        // is not wrapped (closing it would close something else)
        if raw < 3 {
            return Err(io::Error::other(
                "the socket number is a standard descriptor",
            ));
        }
        // SAFETY: fcntl on an integer.
        check(unsafe { libc::fcntl(raw, libc::F_GETFD) })?;
        // SAFETY: init hands this descriptor to the service, nothing else in the process uses it,
        // and it was just seen to be open.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        Self::from_listener(fd)
    }

    /// A socket that keeps message boundaries, made to listen when it does not yet. init calls listen()
    /// only for a socket of the `+listen` type, so the socket of the rc file is bound and not listening
    /// (`system/core/init/util.cpp`, `service_parser.cpp`). The daemon does what lmkd does, before the
    /// syscall filter goes on.
    pub fn from_listener(fd: OwnedFd) -> io::Result<Self> {
        let raw = fd.as_raw_fd();
        if int_option(raw, libc::SOL_SOCKET, libc::SO_TYPE)? != libc::SOCK_SEQPACKET {
            return Err(io::Error::other(
                "the socket does not keep message boundaries",
            ));
        }
        if int_option(raw, libc::SOL_SOCKET, libc::SO_ACCEPTCONN)? == 0 {
            // SAFETY: listen takes a descriptor and a number.
            check(unsafe { libc::listen(raw, BACKLOG) })?;
        }
        make_nonblocking(raw)?;
        Ok(UnixIpc {
            listener: fd,
            conns: BTreeMap::new(),
            next: 1,
        })
    }

    /// A connected socket taken as a connection, for the tests.
    #[cfg(test)]
    fn adopt(&mut self, fd: OwnedFd) -> IpcId {
        let id = self.next;
        self.next = self.next.wrapping_add(1);
        self.conns.insert(id, fd);
        id
    }
}

/// The identity of the peer's process: the inode of its pidfd. On Linux 6.9 and later, where the daemon starts,
/// the pidfd is on pidfs, which numbers its inodes with a 64-bit counter that does not repeat in a boot, so a
/// new process with an old PID has another one. The pidfd is made at connect time, so a peer that has exited
/// since still has it.
fn peer_inode(fd: RawFd) -> io::Result<u64> {
    let raw = int_option(fd, libc::SOL_SOCKET, SO_PEERPIDFD)?;
    // SAFETY: the kernel gave a new descriptor with the option and nothing else owns it.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: stat is plain data and fstat fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is open and st is a stat.
    check(unsafe { libc::fstat(pidfd.as_raw_fd(), &mut st) })?;
    // the descriptor closes here
    #[allow(clippy::useless_conversion)] // st_ino is 32 bits on a 32-bit target
    let ino = u64::from(st.st_ino);
    if ino == 0 {
        return Err(io::Error::other("the process has no identity"));
    }
    Ok(ino)
}

/// The process, user and label the kernel gives for the peer of a connected socket, and the identity of its
/// process. A peer that has none of them is refused.
pub fn peer_info(fd: RawFd) -> io::Result<PeerInfo> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the buffer is one ucred and `len` says so.
    check(unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    })?;
    if len as usize != size_of::<libc::ucred>() {
        return Err(io::Error::other("credentials of the wrong size"));
    }
    let mut label = [0u8; LABEL_BUF];
    let mut label_len = LABEL_BUF as libc::socklen_t;
    // SAFETY: the buffer is LABEL_BUF bytes and `label_len` says so.
    check(unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            label.as_mut_ptr().cast(),
            &mut label_len,
        )
    })?;
    let text = label
        .get(..label_len as usize)
        .and_then(peer_label)
        .ok_or_else(|| io::Error::other("no usable label"))?;
    let pid = u32::try_from(cred.pid).map_err(|_| io::Error::other("bad process number"))?;
    Ok(PeerInfo {
        pid,
        ino: peer_inode(fd)?,
        uid: cred.uid,
        label: text,
    })
}

impl Ipc for UnixIpc {
    fn accept(&mut self) -> Result<Option<(IpcId, PeerInfo)>, IpcFault> {
        // SAFETY: accept4 with no address asked for returns a new descriptor or -1.
        let raw = unsafe {
            libc::accept4(
                self.listener.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            )
        };
        if raw < 0 {
            let e = io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(libc::EAGAIN | libc::EINTR | libc::ECONNABORTED) => Ok(None),
                _ => Err(ipc_fault(&e)),
            };
        }
        // SAFETY: raw was just returned by accept4 and nothing else owns it.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        if self.conns.len() >= MAX_OPEN {
            return Err(IpcFault::Busy);
        }
        // a peer that cannot be identified is closed with the descriptor
        let info = peer_info(fd.as_raw_fd()).map_err(|_| IpcFault::Gone)?;
        let id = self.next;
        self.next = self.next.wrapping_add(1);
        self.conns.insert(id, fd);
        Ok(Some((id, info)))
    }

    fn recv(&mut self, id: IpcId) -> Result<Read, IpcFault> {
        let Some(fd) = self.conns.get(&id) else {
            return Err(IpcFault::Gone);
        };
        match sock::recv_message(fd.as_raw_fd(), MAX_MESSAGE) {
            Ok(Recv::Message(bytes)) => Ok(Read::Message(bytes)),
            Ok(Recv::Empty) => Ok(Read::Empty),
            Ok(Recv::Closed) => Ok(Read::Closed),
            Ok(Recv::TooLong) => Err(IpcFault::Gone),
            Err(e) => Err(ipc_fault(&e)),
        }
    }

    fn send(&mut self, id: IpcId, bytes: &[u8]) -> Result<(), IpcFault> {
        let Some(fd) = self.conns.get(&id) else {
            return Err(IpcFault::Gone);
        };
        sock::send_message(fd.as_raw_fd(), bytes).map_err(|e| ipc_fault(&e))
    }

    fn close(&mut self, id: IpcId) {
        self.conns.remove(&id);
    }

    fn fds(&self) -> Vec<RawFd> {
        std::iter::once(self.listener.as_raw_fd())
            .chain(self.conns.values().map(|fd| fd.as_raw_fd()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seqpacket_pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: fds is an array of two ints, as socketpair needs.
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
                fds.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0);
        // SAFETY: both descriptors were just made and nothing else owns them.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    fn listener(kind: libc::c_int, listen: bool) -> OwnedFd {
        // SAFETY: socket() takes integers. The address is a zeroed sockaddr_un, which is an
        // unnamed local address, so bind picks an abstract name.
        unsafe {
            let raw = libc::socket(libc::AF_UNIX, kind, 0);
            assert!(raw >= 0);
            let fd = OwnedFd::from_raw_fd(raw);
            let mut addr: libc::sockaddr_un = std::mem::zeroed();
            addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
            // an autobind: the address is only the family
            let len = size_of::<libc::sa_family_t>() as libc::socklen_t;
            assert_eq!(
                libc::bind(
                    fd.as_raw_fd(),
                    (&addr as *const libc::sockaddr_un).cast(),
                    len
                ),
                0
            );
            if listen {
                assert_eq!(libc::listen(fd.as_raw_fd(), 4), 0);
            }
            fd
        }
    }

    #[test]
    fn only_a_listening_socket_that_keeps_message_boundaries_is_taken() {
        assert!(UnixIpc::from_listener(listener(libc::SOCK_STREAM, true)).is_err());
        assert!(UnixIpc::from_listener(listener(libc::SOCK_STREAM, false)).is_err());
        assert!(UnixIpc::from_listener(listener(libc::SOCK_SEQPACKET, true)).is_ok());
    }

    #[test]
    fn a_socket_that_is_bound_and_does_not_listen_is_made_to_listen() {
        // what init hands over for `socket datad seqpacket ...` without +listen
        let fd = listener(libc::SOCK_SEQPACKET, false);
        let raw = fd.as_raw_fd();
        assert_eq!(
            int_option(raw, libc::SOL_SOCKET, libc::SO_ACCEPTCONN).unwrap(),
            0
        );
        let mut ipc = UnixIpc::from_listener(fd).unwrap();
        assert_eq!(
            int_option(raw, libc::SOL_SOCKET, libc::SO_ACCEPTCONN).unwrap(),
            1
        );
        assert_eq!(ipc.accept(), Ok(None));
    }

    /// The inode of the pidfd of this process, as the kernel gives it to `pidfd_open`.
    #[cfg(target_os = "linux")]
    fn own_pidfd_inode() -> u64 {
        // SAFETY: pidfd_open takes the PID of this process and flags 0.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
        assert!(raw >= 0, "pidfd_open: {}", io::Error::last_os_error());
        // SAFETY: the kernel gave a new descriptor and nothing else owns it.
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw as libc::c_int) };
        // SAFETY: stat is plain data and fstat fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: the descriptor is open and st is a stat.
        assert_eq!(unsafe { libc::fstat(pidfd.as_raw_fd(), &mut st) }, 0);
        st.st_ino
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_identity_of_a_peer_is_the_inode_of_its_pidfd_and_the_same_for_every_socket_of_a_process()
    {
        let (a, _keep_a) = seqpacket_pair();
        let (b, _keep_b) = seqpacket_pair();
        let ino = peer_inode(a.as_raw_fd()).unwrap();
        assert_ne!(ino, 0);
        assert_eq!(peer_inode(b.as_raw_fd()).unwrap(), ino);
        assert_eq!(ino, own_pidfd_inode());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_descriptor_that_has_no_peer_process_has_no_identity() {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: fds is an array of two ints, as pipe needs.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: both descriptors were just made and nothing else owns them.
        let (r, _w) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        assert!(peer_inode(r.as_raw_fd()).is_err());
    }

    #[test]
    fn a_listener_has_no_connection_waiting_and_is_in_the_poll_set() {
        let mut ipc = UnixIpc::from_listener(listener(libc::SOCK_SEQPACKET, true)).unwrap();
        assert_eq!(ipc.accept(), Ok(None));
        assert_eq!(ipc.fds().len(), 1);
    }

    #[test]
    fn messages_go_both_ways_whole_and_a_hangup_is_seen() {
        let mut ipc = UnixIpc::from_listener(listener(libc::SOCK_SEQPACKET, true)).unwrap();
        let (ours, theirs) = seqpacket_pair();
        let id = ipc.adopt(ours);
        assert_eq!(ipc.fds().len(), 2);
        assert_eq!(ipc.recv(id), Ok(Read::Empty));
        sock::send_message(theirs.as_raw_fd(), &[1, 2, 3]).unwrap();
        sock::send_message(theirs.as_raw_fd(), &[4]).unwrap();
        assert_eq!(ipc.recv(id), Ok(Read::Message(vec![1, 2, 3])));
        assert_eq!(ipc.recv(id), Ok(Read::Message(vec![4])));
        ipc.send(id, &[9, 9]).unwrap();
        assert_eq!(
            sock::recv_message(theirs.as_raw_fd(), 16).unwrap(),
            Recv::Message(vec![9, 9])
        );
        drop(theirs);
        assert_eq!(ipc.recv(id), Ok(Read::Closed));
        assert_eq!(ipc.send(id, &[1]), Err(IpcFault::Gone));
        ipc.close(id);
        assert_eq!(ipc.fds().len(), 1);
        assert_eq!(ipc.recv(id), Err(IpcFault::Gone));
        assert_eq!(ipc.send(id, &[1]), Err(IpcFault::Gone));
    }

    #[test]
    fn a_message_above_the_protocol_limit_ends_the_connection() {
        let mut ipc = UnixIpc::from_listener(listener(libc::SOCK_SEQPACKET, true)).unwrap();
        let (ours, theirs) = seqpacket_pair();
        let id = ipc.adopt(ours);
        sock::send_message(theirs.as_raw_fd(), &[0; MAX_MESSAGE]).unwrap();
        assert!(matches!(ipc.recv(id), Ok(Read::Message(m)) if m.len() == MAX_MESSAGE));
        sock::send_message(theirs.as_raw_fd(), &[0; MAX_MESSAGE + 1]).unwrap();
        assert_eq!(ipc.recv(id), Err(IpcFault::Gone));
    }

    #[test]
    fn a_full_socket_is_busy() {
        let mut ipc = UnixIpc::from_listener(listener(libc::SOCK_SEQPACKET, true)).unwrap();
        let (ours, _theirs) = seqpacket_pair();
        let id = ipc.adopt(ours);
        let mut busy = false;
        for _ in 0..100_000 {
            match ipc.send(id, &[0; 200]) {
                Ok(()) => (),
                Err(IpcFault::Busy) => {
                    busy = true;
                    break;
                }
                Err(IpcFault::Gone) => break,
            }
        }
        assert!(busy);
    }
}
