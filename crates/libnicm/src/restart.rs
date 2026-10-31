// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The Downs of the module across a restart. DSI drops every event between INIT_START and INIT_DONE, and the
//! daemon's replay shows the links it still holds, not the ones that ended. So a Down that cannot be given
//! while the module is inited is kept, one per link, and given right after INIT_DONE and ahead of the replay.
use dataos_nicm_compat::Notice;
use dataos_wire::IfaceEvent;

/// Where the module is in a restart, and the Downs it has missed.
#[derive(Default)]
pub struct Restart {
    /// Between INIT_START and INIT_DONE.
    restarting: bool,
    /// The last Down of each link, in the order they came. A link is a byte, so these are at most 256.
    held: Vec<Notice>,
}

/// The link of a Down.
fn down_of(n: &Notice) -> Option<u8> {
    match n {
        Notice::Iface {
            link,
            event: IfaceEvent::Down(_),
            ..
        } => Some(*link),
        _ => None,
    }
}

impl Restart {
    /// What the module is given for this notice, in order. A Down in the middle of a restart waits, and
    /// INIT_DONE brings the ones that waited.
    pub fn pass(&mut self, n: Notice) -> Vec<Notice> {
        match (n, down_of(&n)) {
            (Notice::RestartStart, _) => {
                self.restarting = true;
                vec![n]
            }
            (Notice::RestartDone, _) => {
                self.restarting = false;
                let mut out = vec![n];
                out.append(&mut self.held);
                out
            }
            (_, Some(link)) if self.restarting => {
                self.hold(link, n);
                Vec::new()
            }
            _ => vec![n],
        }
    }

    /// Notices that were dropped because the module was slow: the Downs among them are kept.
    pub fn keep(&mut self, dropped: &[Notice]) {
        for n in dropped {
            if let Some(link) = down_of(n) {
                self.hold(link, *n);
            }
        }
    }

    fn hold(&mut self, link: u8, n: Notice) {
        match self.held.iter_mut().find(|h| down_of(h) == Some(link)) {
            Some(old) => *old = n,
            None => self.held.push(n),
        }
    }

    /// How many Downs wait.
    pub fn waiting(&self) -> usize {
        self.held.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dataos_wire::{EndReason, Family};

    fn down(link: u8) -> Notice {
        Notice::Iface {
            link,
            slot: 0,
            event: IfaceEvent::Down(EndReason::Qmi(1)),
        }
    }

    fn up(link: u8) -> Notice {
        Notice::Iface {
            link,
            slot: 0,
            event: IfaceEvent::Up,
        }
    }

    #[test]
    fn a_down_while_the_module_is_inited_goes_through() {
        let mut r = Restart::default();
        assert_eq!(r.pass(down(1)), vec![down(1)]);
        assert_eq!(r.pass(up(1)), vec![up(1)]);
        assert_eq!(r.waiting(), 0);
    }

    #[test]
    fn a_down_between_init_start_and_init_done_comes_after_init_done_and_ahead_of_the_replay() {
        let mut r = Restart::default();
        assert_eq!(r.pass(Notice::RestartStart), vec![Notice::RestartStart]);
        assert!(r.pass(down(3)).is_empty());
        assert!(r.pass(up(4)).len() == 1, "the rest goes through as it did");
        assert_eq!(r.waiting(), 1);
        assert_eq!(
            r.pass(Notice::RestartDone),
            vec![Notice::RestartDone, down(3)]
        );
        assert_eq!(r.waiting(), 0);
        assert_eq!(r.pass(down(3)), vec![down(3)], "and it is given once");
    }

    #[test]
    fn dropped_downs_are_kept_one_per_link_and_come_after_the_next_init_done() {
        let mut r = Restart::default();
        r.keep(&[up(1), down(2), down(2), down(5)]);
        assert_eq!(r.waiting(), 2, "the last Down of a link, and no Up");
        r.pass(Notice::RestartStart);
        assert_eq!(
            r.pass(Notice::RestartDone),
            vec![Notice::RestartDone, down(2), down(5)]
        );
    }

    #[test]
    fn what_waits_is_bounded_by_the_number_of_links() {
        let mut r = Restart::default();
        let all: Vec<Notice> = (0..=255).flat_map(|l| [down(l), down(l)]).collect();
        r.keep(&all);
        assert_eq!(r.waiting(), 256);
        r.pass(Notice::RestartStart);
        for l in 0..=255 {
            assert!(r.pass(down(l)).is_empty());
        }
        assert_eq!(r.waiting(), 256);
    }

    #[test]
    fn an_address_event_is_not_a_down() {
        let mut r = Restart::default();
        r.keep(&[Notice::Iface {
            link: 1,
            slot: 0,
            event: IfaceEvent::MtuUpdate {
                family: Family::V4,
                mtu: 1400,
            },
        }]);
        assert_eq!(r.waiting(), 0);
    }
}
