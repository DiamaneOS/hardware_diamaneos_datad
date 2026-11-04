// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The ports held for the modem. A port is held by an open bound socket for as long as it is needed, so no
//! AP application can take it, and it goes to `rmnet_wlan` as a tuple. The two ports of IMS signalling are always
//! in the store, whether their socket could be bound or not.
use crate::kernel::SockHandle;
use dataos_netcfg::genl::{Tuple, TupleKey};
use dataos_qmi::dfs::PortKind;

pub const WELL_KNOWN: [u16; 2] = [5060, 7275];
/// The most ports the store holds. Each is one file descriptor.
pub const MAX_PORTS: usize = 192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub port: u16,
    pub kind: PortKind,
    pub sock: Option<SockHandle>,
}

#[derive(Default)]
pub struct Store {
    entries: Vec<Entry>,
}

pub fn tuple_of(port: u16, kind: PortKind) -> Tuple {
    Tuple {
        key: TupleKey::Port(port),
        version: kind.ip(),
        proto: kind.proto(),
    }
}

impl Store {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn has_room(&self) -> bool {
        self.entries.len() < MAX_PORTS
    }

    pub fn find(&self, port: u16, kind: PortKind) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|e| e.port == port && e.kind == kind)
    }

    /// Add a port, or give a known one its socket.
    pub fn put(&mut self, port: u16, kind: PortKind, sock: Option<SockHandle>) {
        if let Some(e) = self
            .entries
            .iter_mut()
            .find(|e| e.port == port && e.kind == kind)
        {
            e.sock = sock;
        } else if self.entries.len() < MAX_PORTS {
            self.entries.push(Entry { port, kind, sock });
        }
    }

    pub fn remove(&mut self, port: u16, kind: PortKind) -> Option<Entry> {
        let at = self
            .entries
            .iter()
            .position(|e| e.port == port && e.kind == kind)?;
        Some(self.entries.remove(at))
    }

    /// Take out everything but the two well known ports.
    pub fn take_asked(&mut self) -> Vec<Entry> {
        let (keep, gone) = self
            .entries
            .iter()
            .copied()
            .partition(|e| WELL_KNOWN.contains(&e.port));
        self.entries = keep;
        gone
    }

    pub fn tuples(&self) -> Vec<Tuple> {
        self.entries
            .iter()
            .map(|e| tuple_of(e.port, e.kind))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_store_is_bounded_and_keeps_one_entry_per_port_and_kind() {
        let mut s = Store::default();
        assert!(s.is_empty());
        s.put(5060, PortKind::V4Udp, None);
        s.put(5060, PortKind::V4Udp, Some(3));
        assert_eq!(s.len(), 1);
        assert_eq!(s.find(5060, PortKind::V4Udp).unwrap().sock, Some(3));
        assert!(s.find(5060, PortKind::V6Udp).is_none());
        for p in 0..(MAX_PORTS as u16 + 5) {
            s.put(p + 20000, PortKind::V6Tcp, None);
        }
        assert_eq!(s.len(), MAX_PORTS);
        assert!(!s.has_room());
    }

    #[test]
    fn only_the_asked_ports_are_taken_out() {
        let mut s = Store::default();
        s.put(5060, PortKind::V4Udp, Some(1));
        s.put(7275, PortKind::V6Tcp, None);
        s.put(40000, PortKind::V4Tcp, Some(2));
        let gone = s.take_asked();
        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0].port, 40000);
        assert_eq!(s.len(), 2);
        assert_eq!(s.remove(5060, PortKind::V4Udp).unwrap().sock, Some(1));
        assert!(s.remove(5060, PortKind::V4Udp).is_none());
        assert_eq!(s.tuples().len(), 1);
        assert_eq!(s.tuples()[0].bytes(), [0x1c, 0x6b, 0, 0, 6, 6, 0, 0]);
    }
}
