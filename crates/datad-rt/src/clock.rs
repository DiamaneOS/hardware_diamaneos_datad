// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The clock of the main loop: `CLOCK_MONOTONIC` itself, in milliseconds. It stops while the phone sleeps,
//! as the deadlines of the engine need (a clock that runs in suspend would fire them all at once after a
//! resume), and it is the same for every process of the boot. The table of the links keeps times of this
//! clock across a restart of the daemon (a Down that is owed, a hold), which a clock that starts at zero in
//! each process, as `Instant` in the standard library does not for a user, would get wrong.
#![allow(unsafe_code)]
use dataos_datad::daemon::Clock;

pub struct MonotonicClock;

impl MonotonicClock {
    pub fn new() -> Self {
        MonotonicClock
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

/// `CLOCK_MONOTONIC` in milliseconds, 0 when the kernel does not answer.
fn monotonic_ms() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a timespec and clock_gettime fills it.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return 0;
    }
    let secs = u64::try_from(ts.tv_sec).unwrap_or(0);
    let millis = u64::try_from(ts.tv_nsec).unwrap_or(0) / 1_000_000;
    secs.saturating_mul(1_000).saturating_add(millis)
}

impl Clock for MonotonicClock {
    fn now_ms(&mut self) -> u64 {
        monotonic_ms()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clock_is_the_one_of_the_system_and_does_not_go_back() {
        let mut c = MonotonicClock::new();
        let before = monotonic_ms();
        let a = c.now_ms();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let b = c.now_ms();
        assert!(a >= before, "{before} {a}");
        assert!(b >= a + 20, "{a} {b}");
        // not the time since this process started: another clock of the same kind agrees with it
        let other = MonotonicClock::new().now_ms();
        assert!(other >= b && other - b < 1_000, "{b} {other}");
    }

    #[test]
    fn the_clock_counts_milliseconds_of_the_system_clock() {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: ts is a timespec and clock_gettime fills it.
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) },
            0
        );
        let secs = u64::try_from(ts.tv_sec).unwrap();
        let now = MonotonicClock::new().now_ms();
        assert!(now >= secs * 1_000, "{secs} {now}");
        assert!(now < secs * 1_000 + 5_000, "{secs} {now}");
    }

    #[test]
    fn a_process_that_starts_later_reads_the_same_clock() {
        let mut first = MonotonicClock::new();
        let a = first.now_ms();
        std::thread::sleep(std::time::Duration::from_millis(30));
        let mut second = MonotonicClock::new();
        // a clock that counts from its own start would read near 0 here, the system's does not
        assert!(second.now_ms() >= a + 30);
    }
}
