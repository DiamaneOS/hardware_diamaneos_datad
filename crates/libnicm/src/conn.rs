// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The daemon connection as a transport of the client.
use crate::sys;
use dataos_nicm_compat::{NicmError, Transport};
use dataos_wire::limits::MAX_MESSAGE;
use dataos_wire::{Notify, Request};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

#[derive(Default)]
pub struct FdTransport {
    fd: Option<OwnedFd>,
    dead: bool,
}

impl FdTransport {
    pub fn connected(&self) -> bool {
        self.fd.is_some() && !self.dead
    }

    pub fn fd(&self) -> Option<BorrowedFd<'_>> {
        self.fd.as_ref().map(|f| f.as_fd())
    }

    /// The connection ended, or the daemon sent what the protocol does not allow.
    pub fn is_dead(&self) -> bool {
        self.dead
    }

    pub fn set(&mut self, fd: OwnedFd) {
        self.fd = Some(fd);
        self.dead = false;
    }

    pub fn close(&mut self) {
        self.fd = None;
        self.dead = false;
    }
}

/// The socket has no room right now.
fn is_busy(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::WouldBlock || e.raw_os_error() == Some(libc::ENOBUFS)
}

impl Transport for FdTransport {
    fn send(&mut self, req: &Request) -> Result<(), NicmError> {
        let bytes = req.encode().map_err(|_| NicmError::Invalid)?;
        let fd = match &self.fd {
            Some(f) if !self.dead => f.as_fd(),
            _ => return Err(NicmError::Transport),
        };
        if let Err(e) = sys::send(fd, &bytes) {
            // A full socket (the daemon is slow) fails this request and nothing else: the
            // connection carries calls of the module that must go on.
            if !is_busy(&e) {
                self.dead = true;
            }
            return Err(NicmError::Transport);
        }
        Ok(())
    }

    fn close_read(&mut self) {
        if let Some(fd) = &self.fd {
            sys::shutdown_read(fd.as_fd());
        }
    }

    fn recv(&mut self) -> Option<Notify> {
        if self.dead {
            return None;
        }
        let fd = self.fd.as_ref()?.as_fd();
        let mut buf = [0u8; MAX_MESSAGE.saturating_add(1)];
        match sys::recv(fd, &mut buf) {
            Ok(None) => None,
            Ok(Some(n)) if n > 0 && n <= MAX_MESSAGE => match Notify::decode(buf.get(..n)?) {
                Ok(n) => Some(n),
                Err(_) => {
                    self.dead = true;
                    None
                }
            },
            // closed, too long, or an error
            Ok(Some(_)) | Err(_) => {
                self.dead = true;
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `close_read` is what stops the daemon from writing: what it wrote before stays to be read, and the
    /// descriptor then reads as closed, on Linux and on the BSDs alike.
    #[test]
    fn a_connection_closed_for_reading_reads_as_closed_when_nothing_is_left() {
        let (lib, daemon) = sys::pair().unwrap();
        let mut t = FdTransport::default();
        t.set(lib);
        sys::send(
            daemon.as_fd(),
            &Notify::Ready { ready: true }.encode().unwrap(),
        )
        .unwrap();
        assert!(t.recv().is_some());
        assert!(
            t.recv().is_none() && !t.is_dead(),
            "nothing there is not the end"
        );
        t.close_read();
        assert!(t.recv().is_none());
        assert!(t.is_dead());
    }
}
