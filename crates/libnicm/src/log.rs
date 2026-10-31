// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! What the library tells the log, at the information level, tag `nicm`: the connection to the daemon, its
//! answer to the readiness question and every request that fails. A line has no identifier in it: no number,
//! name or address of a phone, a SIM, a network or a peer, only the kind of request and a result code.
//!
//! The data module repeats a question every hundred milliseconds while the daemon is not ready, so a line that
//! repeats is written for the first eight times and then each power of two, with its count.
use crate::sys;
use dataos_nicm_abi::{kind, status};
use std::sync::atomic::{AtomicU32, Ordering};

/// The group of the failed reconnects, next to the kinds of request (1 to 9).
pub const RECONNECT: u32 = 10;

pub fn info(text: &str) {
    sys::log_info(text);
}

/// True for the first eight and then for every power of two.
pub fn due(count: u32) -> bool {
    count != 0 && (count <= 8 || count.is_power_of_two())
}

/// Counters of the lines that may repeat: sixteen groups of sixteen result classes.
static COUNTS: [AtomicU32; 256] = [const { AtomicU32::new(0) }; 256];

/// The class of a result: the daemon's codes 0 to 8, the library's own 100 to 104 as 9 to 13, the rest as 15.
fn class(code: u32) -> u32 {
    match code {
        0..=8 => code,
        100 => 9,
        101 => 10,
        102 => 11,
        103 => 12,
        104 => 13,
        _ => 15,
    }
}

/// The count of this kind of event so far, this one included.
fn count(group: u32, code: u32) -> u32 {
    let slot = group.min(15).saturating_mul(16).saturating_add(class(code));
    match usize::try_from(slot).ok().and_then(|s| COUNTS.get(s)) {
        Some(c) => c.fetch_add(1, Ordering::SeqCst).saturating_add(1),
        None => 1,
    }
}

/// A line that may repeat, of this group with the result `code`: written when the count is due.
pub fn repeated(group: u32, code: u32, text: &str) {
    let n = count(group, code);
    if due(n) {
        info(&format!("{text} (number {n} of this kind)"));
    }
}

/// What a request of the data module is called in the log.
pub fn kind_name(k: u32) -> &'static str {
    match k {
        kind::ROUTE_LOOKUP => "route lookup",
        kind::LINK_RELEASE => "link release",
        kind::QUERY_MTU => "mtu query",
        kind::QUERY_NETWORK_HANDLE => "network handle query",
        kind::PORT_FORWARD => "port forwarding",
        kind::SCREEN_STATE => "screen state",
        kind::OEM_PROXY => "oem proxy",
        kind::READY => "readiness question",
        kind::MATCHING_CALL => "matching call",
        _ => "unknown request",
    }
}

/// What a result is called: the codes of the daemon (the order of its `ResultCode`) and the library's own.
pub fn status_name(s: u32) -> &'static str {
    match s {
        status::OK => "ok",
        1 => "invalid",
        2 => "no link",
        3 => "no such link",
        4 => "too many",
        5 => "bad state",
        6 => "not ready",
        7 => "unsupported",
        8 => "no match",
        status::TRANSPORT => "no connection to the daemon",
        status::TIMEOUT => "no answer in time",
        status::BAD_ARGUMENT => "bad argument",
        status::NOT_REGISTERED => "not registered",
        status::BUSY => "too many requests wait",
        _ => "unknown result",
    }
}

/// The answer to a request of the data module: written when it is a failure.
pub fn reply(k: u32, s: u32) {
    if s != status::OK {
        let (what, why) = (kind_name(k), status_name(s));
        repeated(k, s, &format!("nicm: {what} failed: {why}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_repeated_line_is_due_for_the_first_eight_and_then_for_each_power_of_two() {
        let due_at: Vec<u32> = (0..=1100).filter(|n| due(*n)).collect();
        assert_eq!(
            due_at,
            vec![1, 2, 3, 4, 5, 6, 7, 8, 16, 32, 64, 128, 256, 512, 1024]
        );
    }

    #[test]
    fn the_names_cover_every_kind_and_result_the_library_uses() {
        for k in 1..=9 {
            assert_ne!(kind_name(k), "unknown request");
        }
        for s in (0..=8).chain(100..=104) {
            assert_ne!(status_name(s), "unknown result");
        }
        assert_eq!(kind_name(0), "unknown request");
        assert_eq!(status_name(55), "unknown result");
    }

    #[test]
    fn counts_are_kept_for_each_group_and_result() {
        // groups 13 and 14 are not used by the library
        assert_eq!(count(13, 1), 1);
        assert_eq!(count(13, 1), 2);
        assert_eq!(count(13, 2), 1);
        assert_eq!(count(14, 1), 1);
        // results outside the known ones share a class, and a group beyond 15 is the last
        assert_eq!(count(14, 7000), 1);
        assert_eq!(count(14, 7001), 2);
    }
}
