// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Datagrams that could not be sent yet, kept in order per destination. A destination (a QMI
//! client toward the modem, a connection of the module) whose socket has no room right now keeps
//! its datagrams here and the main loop tries again. The queue is bounded in count and bytes, a
//! datagram waits for a limited time, and a destination that stays blocked past it loses its
//! queue and is reported, so a stuck peer cannot make memory grow or hold the others up.
use std::collections::{BTreeMap, VecDeque};

/// What the sender made of one datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sent {
    Done,
    /// No room right now. Try again later.
    Busy,
    /// The destination cannot be reached any more.
    Failed,
}

/// A destination whose queue was thrown away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dropped<K> {
    /// The first datagram waited longer than the limit.
    Expired(K),
    Failed(K),
}

/// The queue of the destination is full.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

struct Item {
    bytes: Vec<u8>,
    deadline: u64,
}

#[derive(Default)]
struct Queue {
    items: VecDeque<Item>,
    bytes: usize,
}

pub struct Outbox<K: Ord + Copy> {
    queues: BTreeMap<K, Queue>,
    max_items: usize,
    max_bytes: usize,
    wait_ms: u64,
}

impl<K: Ord + Copy> Outbox<K> {
    pub fn new(max_items: usize, max_bytes: usize, wait_ms: u64) -> Self {
        Outbox {
            queues: BTreeMap::new(),
            max_items,
            max_bytes,
            wait_ms,
        }
    }

    /// Is something waiting for this destination? Then a new datagram must queue behind it.
    pub fn waiting(&self, key: K) -> bool {
        self.queues.contains_key(&key)
    }

    pub fn is_empty(&self) -> bool {
        self.queues.is_empty()
    }

    pub fn push(&mut self, key: K, bytes: Vec<u8>, now: u64) -> Result<(), Full> {
        let (items, used) = self
            .queues
            .get(&key)
            .map_or((0, 0), |q| (q.items.len(), q.bytes));
        if items >= self.max_items || bytes.len() > self.max_bytes.saturating_sub(used) {
            return Err(Full);
        }
        let queue = self.queues.entry(key).or_default();
        queue.bytes = queue.bytes.saturating_add(bytes.len());
        queue.items.push_back(Item {
            bytes,
            deadline: now.saturating_add(self.wait_ms),
        });
        Ok(())
    }

    /// Try the datagrams of every destination in order. A destination that is busy keeps what is left
    /// of its queue. One that failed, or whose first datagram is past its time, loses the whole queue and is
    /// reported.
    pub fn flush(&mut self, now: u64, mut send: impl FnMut(K, &[u8]) -> Sent) -> Vec<Dropped<K>> {
        let mut dropped = Vec::new();
        let keys: Vec<K> = self.queues.keys().copied().collect();
        for key in keys {
            let Some(queue) = self.queues.get_mut(&key) else {
                continue;
            };
            let mut gone = None;
            while let Some(item) = queue.items.front() {
                match send(key, &item.bytes) {
                    Sent::Done => {
                        queue.bytes = queue.bytes.saturating_sub(item.bytes.len());
                        queue.items.pop_front();
                    }
                    Sent::Busy if now >= item.deadline => {
                        gone = Some(Dropped::Expired(key));
                        break;
                    }
                    Sent::Busy => break,
                    Sent::Failed => {
                        gone = Some(Dropped::Failed(key));
                        break;
                    }
                }
            }
            if let Some(d) = gone {
                dropped.push(d);
                self.queues.remove(&key);
            } else if queue.items.is_empty() {
                self.queues.remove(&key);
            }
        }
        dropped
    }

    /// The destination is gone. What waits for it is dropped without a word.
    pub fn forget(&mut self, key: K) {
        self.queues.remove(&key);
    }

    /// When the first datagram of some destination runs out of time.
    pub fn next_deadline(&self) -> Option<u64> {
        self.queues
            .values()
            .filter_map(|q| q.items.front().map(|i| i.deadline))
            .min()
    }

    pub fn len(&self) -> usize {
        self.queues.values().map(|q| q.items.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outbox() -> Outbox<u32> {
        Outbox::new(3, 10, 1000)
    }

    fn all_done(_: u32, _: &[u8]) -> Sent {
        Sent::Done
    }

    #[test]
    fn datagrams_go_out_in_the_order_they_came() {
        let mut o = outbox();
        o.push(1, vec![1], 0).unwrap();
        o.push(1, vec![2], 0).unwrap();
        o.push(2, vec![9], 0).unwrap();
        let mut seen = Vec::new();
        let dropped = o.flush(5, |k, b| {
            seen.push((k, b.to_vec()));
            Sent::Done
        });
        assert!(dropped.is_empty());
        assert_eq!(seen, vec![(1, vec![1]), (1, vec![2]), (2, vec![9])]);
        assert!(o.is_empty());
        assert_eq!(o.len(), 0);
    }

    #[test]
    fn a_busy_destination_keeps_its_queue_and_does_not_hold_up_the_others() {
        let mut o = outbox();
        o.push(1, vec![1], 0).unwrap();
        o.push(1, vec![2], 0).unwrap();
        o.push(2, vec![9], 0).unwrap();
        let mut seen = Vec::new();
        let dropped = o.flush(5, |k, b| {
            seen.push((k, b.to_vec()));
            if k == 1 {
                Sent::Busy
            } else {
                Sent::Done
            }
        });
        assert!(dropped.is_empty());
        // only the first datagram of the busy destination was tried
        assert_eq!(seen, vec![(1, vec![1]), (2, vec![9])]);
        assert!(o.waiting(1));
        assert!(!o.waiting(2));
        assert_eq!(o.len(), 2);
        // later it goes through, still in order
        let mut seen = Vec::new();
        o.flush(6, |k, b| {
            seen.push((k, b.to_vec()));
            Sent::Done
        });
        assert_eq!(seen, vec![(1, vec![1]), (1, vec![2])]);
        assert!(o.is_empty());
    }

    #[test]
    fn a_datagram_that_waits_too_long_takes_the_queue_with_it() {
        let mut o = outbox();
        o.push(1, vec![1], 100).unwrap();
        o.push(1, vec![2], 600).unwrap();
        // not yet: 1099 is before 100 + 1000
        assert!(o.flush(1099, |_, _| Sent::Busy).is_empty());
        assert_eq!(o.next_deadline(), Some(1100));
        assert_eq!(o.flush(1100, |_, _| Sent::Busy), vec![Dropped::Expired(1)]);
        assert!(o.is_empty());
        assert_eq!(o.next_deadline(), None);
    }

    #[test]
    fn a_datagram_that_can_go_out_late_is_sent_and_not_dropped() {
        let mut o = outbox();
        o.push(1, vec![1], 0).unwrap();
        assert!(o.flush(5000, all_done).is_empty());
        assert!(o.is_empty());
    }

    #[test]
    fn a_failed_destination_is_reported_once_and_forgotten() {
        let mut o = outbox();
        o.push(1, vec![1], 0).unwrap();
        o.push(1, vec![2], 0).unwrap();
        o.push(2, vec![9], 0).unwrap();
        let dropped = o.flush(1, |k, _| if k == 1 { Sent::Failed } else { Sent::Done });
        assert_eq!(dropped, vec![Dropped::Failed(1)]);
        assert!(o.is_empty());
    }

    #[test]
    fn a_failure_after_a_success_drops_what_is_left() {
        let mut o = outbox();
        o.push(1, vec![1], 0).unwrap();
        o.push(1, vec![2], 0).unwrap();
        let mut n = 0;
        let dropped = o.flush(1, |_, _| {
            n += 1;
            if n == 1 {
                Sent::Done
            } else {
                Sent::Failed
            }
        });
        assert_eq!(dropped, vec![Dropped::Failed(1)]);
        assert!(!o.waiting(1));
    }

    #[test]
    fn the_queue_is_bounded_in_count_and_in_bytes() {
        let mut o = outbox();
        for i in 0..3 {
            o.push(1, vec![i], 0).unwrap();
        }
        assert_eq!(o.push(1, vec![9], 0), Err(Full));
        // another destination has a queue of its own
        o.push(2, vec![0; 10], 0).unwrap();
        assert_eq!(o.push(2, vec![0], 0), Err(Full));
        // exactly the limit fits (above), one byte more does not, and a refusal leaves nothing behind
        let mut o = outbox();
        assert_eq!(o.push(1, vec![0; 11], 0), Err(Full));
        assert!(!o.waiting(1));
        assert!(o.is_empty());
    }

    #[test]
    fn what_was_sent_gives_its_room_back() {
        let mut o = outbox();
        o.push(1, vec![0; 6], 0).unwrap();
        o.push(1, vec![0; 4], 0).unwrap();
        assert_eq!(o.push(1, vec![0], 0), Err(Full));
        // the first goes, the second stays busy
        let mut n = 0;
        o.flush(1, |_, _| {
            n += 1;
            if n == 1 {
                Sent::Done
            } else {
                Sent::Busy
            }
        });
        assert_eq!(o.len(), 1);
        o.push(1, vec![0; 6], 0).unwrap();
        assert_eq!(o.push(1, vec![0], 0), Err(Full));
    }

    #[test]
    fn forgetting_a_destination_drops_its_queue_only() {
        let mut o = outbox();
        o.push(1, vec![1], 0).unwrap();
        o.push(2, vec![2], 0).unwrap();
        o.forget(1);
        assert!(!o.waiting(1));
        assert!(o.waiting(2));
        o.forget(7);
        assert_eq!(o.len(), 1);
    }

    #[test]
    fn the_next_deadline_is_the_earliest_first_datagram() {
        let mut o = outbox();
        assert_eq!(o.next_deadline(), None);
        o.push(1, vec![1], 300).unwrap();
        o.push(2, vec![1], 100).unwrap();
        o.push(2, vec![1], 50).unwrap();
        assert_eq!(o.next_deadline(), Some(1100));
    }
}
