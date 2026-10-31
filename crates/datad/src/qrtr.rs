// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! QRTR control packets, and the table of modem services that the name service announces.
//!
//! What the name service of the kernel does with a lookup (`ns.c` of the qcom module, read for
//! this file **[V source]**): `NEW_LOOKUP` registers the sender, answers with a `NEW_SERVER` for
//! every matching server of every node and ends with an empty one (all words zero), and from then
//! on sends `NEW_SERVER` and `DEL_SERVER` for the servers that come and go. A server is
//! kept per node and port, so a new one on a known port replaces the old one without a
//! `DEL_SERVER`. When a node goes away (`BYE`, which goes to the local servers only and never to a lookup), every server of it gets its `DEL_SERVER`.
//! The packets come from the control port of the local node. A server that registers on the
//! local node is announced with the local node, whatever it names in the packet.
use dataos_datacore::ServiceEvent;
use dataos_qmi::{dpm, wda, wds};
use std::collections::{BTreeMap, BTreeSet};

pub const CTRL_PORT: u32 = 0xffff_fffe;
pub const NEW_SERVER: u32 = 4;
pub const DEL_SERVER: u32 = 5;
pub const NEW_LOOKUP: u32 = 10;
pub const DEL_LOOKUP: u32 = 11;

/// The services the data path needs from the modem, in the order of the bring-up.
pub const WANTED: [u8; 3] = [wda::SERVICE, dpm::SERVICE, wds::SERVICE];

/// The most servers kept. The lookups ask for three services, so a few per service is plenty and
/// a flood of announcements cannot grow the table.
const MAX_ENTRIES: usize = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Peer {
    pub node: u32,
    pub port: u32,
}

/// A control packet: the command and four words (service, instance, node, port for a server,
/// node and port for a client).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Control {
    pub command: u32,
    pub words: [u32; 4],
}

impl Control {
    pub const LEN: usize = 20;

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != Self::LEN {
            return None;
        }
        let mut w = [0u32; 5];
        for (slot, chunk) in w.iter_mut().zip(b.chunks_exact(4)) {
            *slot = u32::from_le_bytes(chunk.try_into().ok()?);
        }
        let [command, a, b, c, d] = w;
        Some(Control {
            command,
            words: [a, b, c, d],
        })
    }

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        let words = std::iter::once(self.command).chain(self.words);
        for (chunk, w) in out.chunks_exact_mut(4).zip(words) {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    /// The registration for every instance of one service.
    pub fn lookup(service: u8) -> Self {
        Control {
            command: NEW_LOOKUP,
            words: [u32::from(service), 0, 0, 0],
        }
    }

    pub fn withdraw(service: u8) -> Self {
        Control {
            command: DEL_LOOKUP,
            words: [u32::from(service), 0, 0, 0],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    service: u8,
    instance: u32,
}

/// What `Services::apply` did not use, for the counters of the host.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServiceStats {
    /// A server on the local node: any process of the phone can register one, so none is used.
    pub local_refused: u32,
    /// A server the table had no room for.
    pub table_full: u32,
    /// A removal that named a server that is not the one in the table.
    pub stale_removals: u32,
}

/// The three servers one modem session uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Chosen {
    servers: [(Entry, Peer); 3],
}

/// The modem's data services as the name service announces them. The modem is up when one remote
/// node has all of WDA, DPM and WDS. The three servers stay chosen as long as they are there, so
/// another instance showing up does not restart anything, and when one of them goes or is replaced
/// the modem is down and a new choice follows from what is left.
pub struct Services {
    local_node: u32,
    entries: BTreeMap<Peer, Entry>,
    chosen: Option<Chosen>,
    stats: ServiceStats,
}

impl Services {
    pub fn new(local_node: u32) -> Self {
        Services {
            local_node,
            entries: BTreeMap::new(),
            chosen: None,
            stats: ServiceStats::default(),
        }
    }

    pub fn stats(&self) -> ServiceStats {
        self.stats
    }

    pub fn is_up(&self) -> bool {
        self.chosen.is_some()
    }

    /// Where the chosen server of this service is. None while the modem is down.
    pub fn target(&self, service: u8) -> Option<Peer> {
        self.chosen?
            .servers
            .iter()
            .find(|(e, _)| e.service == service)
            .map(|(_, p)| *p)
    }

    /// One packet from the name service. The events say what the data engine must be told, in order.
    pub fn apply(&mut self, c: Control) -> Vec<ServiceEvent> {
        let [service, instance, node, port] = c.words;
        match c.command {
            NEW_SERVER => self.add(service, instance, node, port),
            DEL_SERVER => self.remove(service, instance, node, port),
            _ => return Vec::new(),
        }
        self.settle()
    }

    /// Forget everything, because the name service cannot be heard any more.
    pub fn clear(&mut self) -> Vec<ServiceEvent> {
        self.entries.clear();
        self.settle()
    }

    fn add(&mut self, service: u32, instance: u32, node: u32, port: u32) {
        // service 0 is the end of a lookup's list, port 0 is no server
        let Some(service) = u8::try_from(service).ok().filter(|s| WANTED.contains(s)) else {
            return;
        };
        if port == 0 {
            return;
        }
        if node == self.local_node {
            self.stats.local_refused = self.stats.local_refused.saturating_add(1);
            return;
        }
        let at = Peer { node, port };
        if !self.entries.contains_key(&at) && self.entries.len() >= MAX_ENTRIES {
            self.stats.table_full = self.stats.table_full.saturating_add(1);
            return;
        }
        self.entries.insert(at, Entry { service, instance });
    }

    fn remove(&mut self, service: u32, instance: u32, node: u32, port: u32) {
        let at = Peer { node, port };
        let Some(entry) = self.entries.get(&at) else {
            return;
        };
        if u32::from(entry.service) == service && entry.instance == instance {
            self.entries.remove(&at);
        } else {
            self.stats.stale_removals = self.stats.stale_removals.saturating_add(1);
        }
    }

    fn settle(&mut self) -> Vec<ServiceEvent> {
        let mut events = Vec::new();
        if let Some(chosen) = &self.chosen {
            let present = chosen
                .servers
                .iter()
                .all(|(e, p)| self.entries.get(p) == Some(e));
            if !present {
                self.chosen = None;
                events.push(ServiceEvent::ModemDown);
            }
        }
        if self.chosen.is_none() {
            if let Some(c) = self.pick() {
                self.chosen = Some(c);
                events.push(ServiceEvent::ModemUp);
            }
        }
        events
    }

    /// The lowest remote node that has all three services, and on it the lowest instance (then the
    /// lowest port) of each. Which instance the stock stack uses when there are several is not
    /// known **[U]**.
    fn pick(&self) -> Option<Chosen> {
        let nodes: BTreeSet<u32> = self.entries.keys().map(|p| p.node).collect();
        for node in nodes {
            let mut servers = Vec::new();
            for service in WANTED {
                let best = self
                    .entries
                    .iter()
                    .filter(|(p, e)| p.node == node && e.service == service)
                    .min_by_key(|(p, e)| (e.instance, p.port));
                if let Some((p, e)) = best {
                    servers.push((*e, *p));
                }
            }
            if let [a, b, c] = servers.as_slice() {
                return Some(Chosen {
                    servers: [*a, *b, *c],
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: u32 = 1;
    const MODEM: u32 = 0;

    fn new_server(service: u8, instance: u32, node: u32, port: u32) -> Control {
        Control {
            command: NEW_SERVER,
            words: [u32::from(service), instance, node, port],
        }
    }

    fn del_server(service: u8, instance: u32, node: u32, port: u32) -> Control {
        Control {
            command: DEL_SERVER,
            words: [u32::from(service), instance, node, port],
        }
    }

    fn all_three(s: &mut Services) -> Vec<ServiceEvent> {
        let mut ev = Vec::new();
        ev.extend(s.apply(new_server(wds::SERVICE, 1, MODEM, 100)));
        ev.extend(s.apply(new_server(wda::SERVICE, 1, MODEM, 101)));
        ev.extend(s.apply(new_server(dpm::SERVICE, 1, MODEM, 102)));
        ev
    }

    #[test]
    fn a_packet_is_twenty_bytes_little_endian() {
        let c = Control {
            command: NEW_SERVER,
            words: [1, 2, 3, 4],
        };
        let b = c.encode();
        assert_eq!(b.len(), 20);
        assert_eq!(&b[..4], &[4, 0, 0, 0]);
        assert_eq!(&b[4..8], &[1, 0, 0, 0]);
        assert_eq!(&b[16..], &[4, 0, 0, 0]);
        assert_eq!(Control::decode(&b), Some(c));
        assert_eq!(Control::decode(&b[..19]), None);
        let mut long = b.to_vec();
        long.push(0);
        assert_eq!(Control::decode(&long), None);
        assert_eq!(Control::decode(&[]), None);
    }

    #[test]
    fn a_lookup_names_the_service_and_every_instance() {
        let c = Control::lookup(0x1a);
        assert_eq!(c.command, NEW_LOOKUP);
        assert_eq!(c.words, [0x1a, 0, 0, 0]);
        let w = Control::withdraw(0x2f);
        assert_eq!(w.command, DEL_LOOKUP);
        assert_eq!(w.words, [0x2f, 0, 0, 0]);
    }

    #[test]
    fn the_modem_is_up_when_the_last_of_the_three_services_is_announced() {
        let mut s = Services::new(LOCAL);
        assert!(s.apply(new_server(wds::SERVICE, 1, MODEM, 100)).is_empty());
        assert!(s.apply(new_server(wda::SERVICE, 1, MODEM, 101)).is_empty());
        assert!(!s.is_up());
        assert_eq!(
            s.apply(new_server(dpm::SERVICE, 1, MODEM, 102)),
            vec![ServiceEvent::ModemUp]
        );
        assert!(s.is_up());
        assert_eq!(
            s.target(wds::SERVICE),
            Some(Peer {
                node: MODEM,
                port: 100
            })
        );
        assert_eq!(
            s.target(wda::SERVICE),
            Some(Peer {
                node: MODEM,
                port: 101
            })
        );
        assert_eq!(
            s.target(dpm::SERVICE),
            Some(Peer {
                node: MODEM,
                port: 102
            })
        );
        assert_eq!(s.target(0x55), None);
    }

    #[test]
    fn nothing_is_a_target_while_the_modem_is_down() {
        let mut s = Services::new(LOCAL);
        s.apply(new_server(wds::SERVICE, 1, MODEM, 100));
        assert_eq!(s.target(wds::SERVICE), None);
    }

    #[test]
    fn a_service_that_goes_takes_the_modem_down_and_its_return_brings_it_up() {
        let mut s = Services::new(LOCAL);
        all_three(&mut s);
        assert_eq!(
            s.apply(del_server(wda::SERVICE, 1, MODEM, 101)),
            vec![ServiceEvent::ModemDown]
        );
        assert!(!s.is_up());
        assert_eq!(s.target(wds::SERVICE), None);
        assert_eq!(
            s.apply(new_server(wda::SERVICE, 1, MODEM, 101)),
            vec![ServiceEvent::ModemUp]
        );
    }

    #[test]
    fn a_server_announced_again_as_it_is_changes_nothing() {
        // a new lookup lists the servers again
        let mut s = Services::new(LOCAL);
        all_three(&mut s);
        assert!(all_three(&mut s).is_empty());
        assert!(s.is_up());
    }

    #[test]
    fn a_server_replaced_on_its_port_is_a_restart_in_one_packet() {
        // the name service replaces a server on a known port without a removal
        let mut s = Services::new(LOCAL);
        all_three(&mut s);
        assert_eq!(
            s.apply(new_server(wda::SERVICE, 2, MODEM, 101)),
            vec![ServiceEvent::ModemDown, ServiceEvent::ModemUp]
        );
        assert!(s.is_up());
    }

    #[test]
    fn the_same_port_with_another_service_replaces_the_entry() {
        let mut s = Services::new(LOCAL);
        all_three(&mut s);
        let ev = s.apply(new_server(0x30, 1, MODEM, 101));
        // 0x30 is not wanted and is ignored, so nothing changes
        assert!(ev.is_empty());
        assert!(s.is_up());
        // a wanted service on the port of another one replaces it and takes the session down
        let ev = s.apply(new_server(dpm::SERVICE, 1, MODEM, 101));
        assert_eq!(ev, vec![ServiceEvent::ModemDown]);
    }

    #[test]
    fn a_server_on_the_local_node_is_never_used() {
        let mut s = Services::new(LOCAL);
        s.apply(new_server(wds::SERVICE, 1, LOCAL, 100));
        s.apply(new_server(wda::SERVICE, 1, LOCAL, 101));
        assert!(s.apply(new_server(dpm::SERVICE, 1, LOCAL, 102)).is_empty());
        assert!(!s.is_up());
        assert_eq!(s.stats().local_refused, 3);
        // and a local one does not complete a modem that lacks a service
        let mut s = Services::new(LOCAL);
        s.apply(new_server(wds::SERVICE, 1, MODEM, 100));
        s.apply(new_server(wda::SERVICE, 1, MODEM, 101));
        assert!(s.apply(new_server(dpm::SERVICE, 1, LOCAL, 102)).is_empty());
        assert!(!s.is_up());
    }

    #[test]
    fn the_end_of_a_listing_and_a_server_without_a_port_are_not_servers() {
        let mut s = Services::new(LOCAL);
        let end = Control {
            command: NEW_SERVER,
            words: [0; 4],
        };
        assert!(s.apply(end).is_empty());
        assert!(s.apply(new_server(wds::SERVICE, 1, MODEM, 0)).is_empty());
        all_three(&mut s);
        assert!(s.is_up());
        // the server without a port was not kept: it would have the lowest port
        assert_eq!(
            s.target(wds::SERVICE),
            Some(Peer {
                node: MODEM,
                port: 100
            })
        );
        // a removal of port 0 or of an unknown server changes nothing
        assert!(s.apply(del_server(wds::SERVICE, 1, MODEM, 0)).is_empty());
        assert!(s.apply(del_server(wds::SERVICE, 1, MODEM, 999)).is_empty());
        assert!(s.is_up());
    }

    #[test]
    fn a_service_number_that_does_not_fit_a_byte_is_not_wanted() {
        let mut s = Services::new(LOCAL);
        // 0x101 would be 1 (WDS) if it were cut to a byte
        let c = Control {
            command: NEW_SERVER,
            words: [0x101, 1, MODEM, 100],
        };
        s.apply(c);
        s.apply(new_server(wda::SERVICE, 1, MODEM, 101));
        assert!(s.apply(new_server(dpm::SERVICE, 1, MODEM, 102)).is_empty());
    }

    #[test]
    fn a_removal_of_something_else_on_that_port_is_stale() {
        let mut s = Services::new(LOCAL);
        all_three(&mut s);
        // the right port, the wrong service
        assert!(s.apply(del_server(wds::SERVICE, 1, MODEM, 101)).is_empty());
        // the right port and service, the wrong instance
        assert!(s.apply(del_server(wda::SERVICE, 2, MODEM, 101)).is_empty());
        assert_eq!(s.stats().stale_removals, 2);
        assert!(s.is_up());
    }

    #[test]
    fn another_instance_does_not_restart_a_session_that_runs() {
        let mut s = Services::new(LOCAL);
        all_three(&mut s);
        // lower instance and lower port than the chosen server
        assert!(s.apply(new_server(wds::SERVICE, 0, MODEM, 50)).is_empty());
        assert_eq!(
            s.target(wds::SERVICE),
            Some(Peer {
                node: MODEM,
                port: 100
            })
        );
        // the chosen one goes: down, and the other instance takes its place
        let ev = s.apply(del_server(wds::SERVICE, 1, MODEM, 100));
        assert_eq!(ev, vec![ServiceEvent::ModemDown, ServiceEvent::ModemUp]);
        assert_eq!(
            s.target(wds::SERVICE),
            Some(Peer {
                node: MODEM,
                port: 50
            })
        );
    }

    #[test]
    fn the_lowest_instance_then_the_lowest_port_is_chosen() {
        let mut s = Services::new(LOCAL);
        s.apply(new_server(wds::SERVICE, 2, MODEM, 10));
        s.apply(new_server(wds::SERVICE, 1, MODEM, 30));
        s.apply(new_server(wds::SERVICE, 1, MODEM, 20));
        s.apply(new_server(wda::SERVICE, 1, MODEM, 101));
        s.apply(new_server(dpm::SERVICE, 1, MODEM, 102));
        assert_eq!(
            s.target(wds::SERVICE),
            Some(Peer {
                node: MODEM,
                port: 20
            })
        );
    }

    #[test]
    fn the_services_come_from_one_node() {
        let mut s = Services::new(LOCAL);
        s.apply(new_server(wds::SERVICE, 1, 5, 100));
        s.apply(new_server(wda::SERVICE, 1, 6, 101));
        assert!(s.apply(new_server(dpm::SERVICE, 1, 5, 102)).is_empty());
        assert!(!s.is_up());
        // the lowest node that has all three
        let ev = s.apply(new_server(wda::SERVICE, 1, 5, 103));
        assert_eq!(ev, vec![ServiceEvent::ModemUp]);
        assert_eq!(s.target(wda::SERVICE), Some(Peer { node: 5, port: 103 }));
        // with several complete nodes to choose from, the lowest one is chosen
        let mut s = Services::new(LOCAL);
        for node in [9, 7, 3] {
            s.apply(new_server(wds::SERVICE, 1, node, 100));
            s.apply(new_server(wda::SERVICE, 1, node, 101));
            s.apply(new_server(dpm::SERVICE, 1, node, 102));
        }
        assert_eq!(s.target(wds::SERVICE).map(|p| p.node), Some(9));
        let ev = s.apply(del_server(wds::SERVICE, 1, 9, 100));
        assert_eq!(ev, vec![ServiceEvent::ModemDown, ServiceEvent::ModemUp]);
        assert_eq!(s.target(wds::SERVICE).map(|p| p.node), Some(3));
    }

    #[test]
    fn the_table_does_not_grow_without_bound() {
        let mut s = Services::new(LOCAL);
        for port in 1..=(MAX_ENTRIES as u32 + 5) {
            s.apply(new_server(wds::SERVICE, 1, MODEM, port));
        }
        assert_eq!(s.stats().table_full, 5);
        // a server on a known port still replaces its entry when the table is full
        let before = s.stats().table_full;
        s.apply(new_server(wda::SERVICE, 1, MODEM, 1));
        assert_eq!(s.stats().table_full, before);
    }

    #[test]
    fn clearing_the_table_takes_a_running_session_down_once() {
        let mut s = Services::new(LOCAL);
        assert!(s.clear().is_empty());
        all_three(&mut s);
        assert_eq!(s.clear(), vec![ServiceEvent::ModemDown]);
        assert!(!s.is_up());
        assert!(s.clear().is_empty());
    }

    #[test]
    fn other_commands_change_nothing() {
        let mut s = Services::new(LOCAL);
        all_three(&mut s);
        for command in [0, 1, 2, 3, 6, NEW_LOOKUP, DEL_LOOKUP, 99] {
            let c = Control {
                command,
                words: [u32::from(wds::SERVICE), 1, MODEM, 100],
            };
            assert!(s.apply(c).is_empty());
        }
        assert!(s.is_up());
    }
}
