// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! What the library tells the log, at the information level, tag `nicm_dsi`: the first call of the data module,
//! the answers to its readiness question (the module's init waits for a yes, and until then it fails every data
//! call with its cause 0x1004) and every refusal of an operation. A line has no identifier in it.
//!
//! The data module asks the readiness question every hundred milliseconds, so a line that repeats is written
//! for the first eight times and then each power of two, with its count.
use crate::abi::{log_info, Op};
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::Once;

/// True for the first eight and then for every power of two.
pub fn due(count: u32) -> bool {
    count != 0 && (count <= 8 || count.is_power_of_two())
}

fn name(op: Op) -> &'static str {
    match op {
        Op::InitQuery => "readiness question",
        Op::TranslateEvent => "event translation",
        Op::TranslateRouteLookupRequest => "route lookup request translation",
        Op::RouteLookup => "route lookup",
        Op::SetNicmInfo => "event copy",
        Op::QueryLlNetworkHandle => "network handle query",
        Op::GetLinkMtu => "mtu query",
        Op::LinkRelease => "link release",
        Op::ProcessPfRequest => "port forwarding",
        Op::OemProxy => "oem proxy",
        Op::ProcessScreenState => "screen state",
    }
}

/// Counters of the lines that may repeat, one for each operation.
static COUNTS: [AtomicU32; 11] = [const { AtomicU32::new(0) }; 11];

fn index(op: Op) -> usize {
    match op {
        Op::InitQuery => 0,
        Op::TranslateEvent => 1,
        Op::TranslateRouteLookupRequest => 2,
        Op::RouteLookup => 3,
        Op::SetNicmInfo => 4,
        Op::QueryLlNetworkHandle => 5,
        Op::GetLinkMtu => 6,
        Op::LinkRelease => 7,
        Op::ProcessPfRequest => 8,
        Op::OemProxy => 9,
        Op::ProcessScreenState => 10,
    }
}

/// The count of lines of this operation so far, this one included.
fn count(op: Op) -> u32 {
    match COUNTS.get(index(op)) {
        Some(c) => c.fetch_add(1, Ordering::SeqCst).saturating_add(1),
        None => 1,
    }
}

/// The first call of the data module into this library.
pub fn first_call() {
    static FIRST: Once = Once::new();
    FIRST.call_once(|| log_info("nicm_dsi: first call of the data module"));
}

/// An operation refused for a reason that is the library's own.
pub fn refused(op: Op, why: &str) {
    let what = name(op);
    let n = count(op);
    if due(n) {
        log_info(&format!(
            "nicm_dsi: {what} refused: {why} (number {n} of this kind)"
        ));
    }
}

/// 0: not asked yet, 1: the last answer was not ready, 2: ready.
static INIT: AtomicU8 = AtomicU8::new(0);

/// What the library answered to the data module. Only the operations whose refusal tells something are
/// written: the readiness question (each change at once, and a failure again by the rule above), the route
/// lookup, the link release, the mtu query and the screen state.
pub fn answered(op: Op, result: usize) {
    let ok = result == 0;
    match op {
        Op::InitQuery => {
            let now = if ok { 2 } else { 1 };
            if INIT.swap(now, Ordering::SeqCst) != now {
                log_info(if ok {
                    "nicm_dsi: readiness question answered: ready"
                } else {
                    "nicm_dsi: readiness question answered: not ready"
                });
            } else if !ok {
                refused(op, "the daemon is not ready");
            }
        }
        Op::RouteLookup | Op::LinkRelease | Op::GetLinkMtu | Op::ProcessScreenState if !ok => {
            refused(op, "the daemon did not take it")
        }
        _ => {}
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
    fn every_operation_has_a_name_and_a_counter() {
        for op in [
            Op::InitQuery,
            Op::TranslateEvent,
            Op::TranslateRouteLookupRequest,
            Op::RouteLookup,
            Op::SetNicmInfo,
            Op::QueryLlNetworkHandle,
            Op::GetLinkMtu,
            Op::LinkRelease,
            Op::ProcessPfRequest,
            Op::OemProxy,
            Op::ProcessScreenState,
        ] {
            assert!(!name(op).is_empty());
            assert_eq!(count(op), 1);
            assert_eq!(count(op), 2);
        }
    }
}
