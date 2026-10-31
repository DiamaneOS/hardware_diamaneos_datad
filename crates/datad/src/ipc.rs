// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The socket of the protocol as the main loop sees it: connections that come in, messages that
//! arrive whole, messages that go out whole. The real socket (a Unix socket that keeps message
//! boundaries, handed over by init) is in the runtime crate.
use std::os::fd::RawFd;

pub type IpcId = u32;

/// Who connected, as the kernel says it (`SO_PEERCRED`, `SO_PEERSEC`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    pub pid: u32,
    /// The identity of the process: the inode of the pidfd the kernel gives for the peer (`SO_PEERPIDFD`).
    /// A radio daemon that comes back with an old PID has another one and takes over nothing of the old one.
    pub ino: u64,
    pub uid: u32,
    pub label: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpcFault {
    /// No room, or nothing to take, right now.
    Busy,
    /// The connection is gone or broken.
    Gone,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Read {
    Message(Vec<u8>),
    /// Nothing there now.
    Empty,
    /// The other side closed.
    Closed,
}

pub trait Ipc {
    /// The next connection that waits, if there is one. A peer whose credentials or label cannot
    /// be read is not handed out: the implementation closes it.
    fn accept(&mut self) -> Result<Option<(IpcId, PeerInfo)>, IpcFault>;
    /// The next message of a connection. One larger than the protocol allows is a fault (`Gone`).
    fn recv(&mut self, id: IpcId) -> Result<Read, IpcFault>;
    /// One whole message, or `Busy` when the socket has no room, or `Gone`.
    fn send(&mut self, id: IpcId, bytes: &[u8]) -> Result<(), IpcFault>;
    fn close(&mut self, id: IpcId);
    fn fds(&self) -> Vec<RawFd>;
}

/// The longest label accepted. SELinux contexts are far shorter.
const MAX_LABEL: usize = 255;

/// The label as `SO_PEERSEC` gives it: text with the one NUL the kernel adds at the end. The
/// text must be UTF-8 and have no other NUL, or there is no label to compare.
pub fn peer_label(raw: &[u8]) -> Option<String> {
    let text = raw.strip_suffix(&[0]).unwrap_or(raw);
    if text.is_empty() || text.len() > MAX_LABEL || text.contains(&0) {
        return None;
    }
    String::from_utf8(text.to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_nul_the_kernel_adds_is_taken_off() {
        assert_eq!(peer_label(b"u:r:rild:s0\0").as_deref(), Some("u:r:rild:s0"));
        assert_eq!(peer_label(b"u:r:rild:s0").as_deref(), Some("u:r:rild:s0"));
    }

    #[test]
    fn a_label_with_another_nul_or_none_or_a_bad_text_is_no_label() {
        assert_eq!(peer_label(b""), None);
        assert_eq!(peer_label(b"\0"), None);
        // two NULs at the end: the kernel adds one, a second belongs to the text
        assert_eq!(peer_label(b"u:r:rild:s0\0\0"), None);
        assert_eq!(peer_label(b"u:r:\0rild:s0\0"), None);
        assert_eq!(peer_label(&[0xff, 0xfe, 0]), None);
    }

    #[test]
    fn a_label_has_a_length_limit() {
        let ok = vec![b'a'; 255];
        assert!(peer_label(&ok).is_some());
        let mut with_nul = ok.clone();
        with_nul.push(0);
        assert!(peer_label(&with_nul).is_some());
        let long = vec![b'a'; 256];
        assert_eq!(peer_label(&long), None);
    }
}
