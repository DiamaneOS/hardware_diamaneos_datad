// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Waiting for a descriptor with a time limit.
#![allow(unsafe_code)]
use dataos_datad::daemon::Poller;
use std::io;
use std::os::fd::RawFd;
use std::time::Duration;

pub struct SysPoller;

/// What to do when `poll` itself fails: wait this long (at most) so the loop does not spin.
const FAILED_POLL_SLEEP_MS: u64 = 25;

impl Poller for SysPoller {
    fn wait(&mut self, fds: &[RawFd], timeout_ms: u64) -> io::Result<()> {
        let mut set: Vec<libc::pollfd> = fds
            .iter()
            .map(|fd| libc::pollfd {
                fd: *fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        let ms = libc::c_int::try_from(timeout_ms).unwrap_or(libc::c_int::MAX);
        // SAFETY: `set` is an array of pollfd structs and the count is its length.
        let rc = unsafe { libc::poll(set.as_mut_ptr(), set.len() as libc::nfds_t, ms) };
        let error = if rc < 0 {
            io::Error::last_os_error()
        } else {
            return Ok(());
        };
        after_failure(error, timeout_ms)
    }
}

/// A signal that ends the wait early is no failure. Any other error waits a little, so a loop whose
/// poll fails over and over does not spin, and is passed on.
fn after_failure(error: io::Error, timeout_ms: u64) -> io::Result<()> {
    if error.kind() == io::ErrorKind::Interrupted {
        return Ok(());
    }
    std::thread::sleep(Duration::from_millis(timeout_ms.min(FAILED_POLL_SLEEP_MS)));
    Err(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::time::Instant;

    #[test]
    fn it_returns_at_once_when_a_descriptor_can_be_read() {
        let (a, mut b) = UnixStream::pair().unwrap();
        b.write_all(&[1]).unwrap();
        let t = Instant::now();
        SysPoller.wait(&[a.as_raw_fd()], 5_000).unwrap();
        assert!(t.elapsed() < Duration::from_millis(1_000));
    }

    #[test]
    fn it_waits_for_the_time_when_nothing_happens() {
        let (a, _b) = UnixStream::pair().unwrap();
        let t = Instant::now();
        SysPoller.wait(&[a.as_raw_fd()], 40).unwrap();
        assert!(t.elapsed() >= Duration::from_millis(30));
        // and with no descriptors at all it is a sleep
        let t = Instant::now();
        SysPoller.wait(&[], 40).unwrap();
        assert!(t.elapsed() >= Duration::from_millis(30));
    }

    #[test]
    fn a_wait_of_zero_does_not_wait() {
        let (a, _b) = UnixStream::pair().unwrap();
        let t = Instant::now();
        SysPoller.wait(&[a.as_raw_fd()], 0).unwrap();
        assert!(t.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn a_signal_ends_the_wait_without_an_error() {
        let t = Instant::now();
        assert!(after_failure(io::ErrorKind::Interrupted.into(), 5_000).is_ok());
        assert!(t.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn a_failure_waits_a_little_and_is_passed_on() {
        // a short timeout is waited out, a long one is cut to the pause
        let t = Instant::now();
        let e = after_failure(io::Error::other("poll"), 40).unwrap_err();
        assert!(t.elapsed() >= Duration::from_millis(25));
        assert_eq!(e.kind(), io::ErrorKind::Other);
        let t = Instant::now();
        assert!(after_failure(io::Error::other("poll"), 5_000).is_err());
        assert!(t.elapsed() < Duration::from_millis(1_000));
        let t = Instant::now();
        assert!(after_failure(io::Error::other("poll"), 0).is_err());
        assert!(t.elapsed() < Duration::from_millis(20));
    }

    #[test]
    fn a_bad_descriptor_is_not_an_error_of_poll_itself() {
        // poll reports it in the revents of that descriptor, and the loop finds out when it reads
        assert!(SysPoller.wait(&[-1], 10).is_ok());
    }
}
