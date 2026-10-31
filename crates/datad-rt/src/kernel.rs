// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The kernel the daemon runs on. The identity of a peer is the inode of its pidfd, and the inode is the process's
//! own only from Linux 6.9, when pidfds moved to pidfs. Before that, every pidfd is on one anonymous inode, and
//! all processes would look the same. From 6.9 on, `SO_PEERPIDFD` always gives a pidfd on pidfs, so a check of the
//! release at start is enough and the daemon needs no look at the filesystem of each descriptor.
#![allow(unsafe_code)]
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::io;

/// The first kernel on which a pidfd has an inode of its own.
pub const PIDFD_IDENTITY: (u32, u32) = (6, 9);

/// The major and minor number at the start of a release such as `6.18.37-android16-0`. None: the release does
/// not start with two numbers separated by a dot.
fn version_of(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts
        .next()?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()?;
    Some((major, minor))
}

/// Is this release the given version or a later one? A release that cannot be read is not.
pub fn at_least(release: &str, wanted: (u32, u32)) -> bool {
    version_of(release).is_some_and(|v| v >= wanted)
}

/// The release of the running kernel (`uname -r`).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn release() -> io::Result<String> {
    // SAFETY: utsname is plain data and uname fills it.
    let mut name: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: the pointer is to a utsname that lives through the call.
    if unsafe { libc::uname(&mut name) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let bytes: Vec<u8> = name
        .release
        .iter()
        .take_while(|c| **c != 0)
        .flat_map(|c| c.to_ne_bytes())
        .collect();
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Stop the daemon on a kernel older than the given version. The message has no release in it.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn refuse_before(wanted: (u32, u32)) -> io::Result<()> {
    if at_least(&release()?, wanted) {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "the kernel is older than {}.{}, which the identity of a peer needs",
            wanted.0, wanted.1
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_release_is_read_by_its_first_two_numbers() {
        assert_eq!(version_of("6.18.37-android16-9-g1234"), Some((6, 18)));
        assert_eq!(version_of("6.9.0"), Some((6, 9)));
        assert_eq!(version_of("6.9-rc1"), Some((6, 9)));
        assert_eq!(version_of("6.12.107+deb13-amd64"), Some((6, 12)));
        assert_eq!(version_of("5.15"), Some((5, 15)));
    }

    /// The releases that Android kernels have: the GKI suffixes, a 4k page build, a dirty tree.
    #[test]
    fn the_releases_of_android_kernels_are_read() {
        for ok in [
            "6.18.37-4k-g03c6a8d2a9cd",
            "6.18.37-android17-0-g03c6a8d2a9cd-ab12345678",
            "6.18.37-android17-0-g03c6a8d2a9cd-dirty",
            "6.12.23-android16-5-maybe-dirty-4k",
            "6.9.0-rc1+",
            "6.10-rc7",
        ] {
            assert!(at_least(ok, PIDFD_IDENTITY), "{ok}");
        }
        for old in [
            "6.1.145-android14-11-g1234567",
            "6.6.92-android15-8-g0000000-4k",
            "5.15.180-android13-8",
            "6.8.0-rc1",
        ] {
            assert!(!at_least(old, PIDFD_IDENTITY), "{old}");
        }
    }

    #[test]
    fn a_release_that_is_not_two_numbers_has_no_version() {
        for bad in ["", "6", "six.nine", "6.", "6.x", ".9", "-6.9", "6,9"] {
            assert_eq!(version_of(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn pidfs_starts_at_6_9_and_a_release_that_cannot_be_read_is_refused() {
        for old in ["6.8.12", "6.1.99-android14", "5.15.0", "4.19", "6.0.0"] {
            assert!(!at_least(old, PIDFD_IDENTITY), "{old}");
        }
        for new in [
            "6.9",
            "6.9.0",
            "6.10.1",
            "6.18.37-android16",
            "7.0",
            "10.1.2",
        ] {
            assert!(at_least(new, PIDFD_IDENTITY), "{new}");
        }
        for bad in ["", "garbage", "6"] {
            assert!(!at_least(bad, PIDFD_IDENTITY), "{bad:?}");
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn the_running_kernel_is_read_and_a_future_one_is_refused() {
        assert!(version_of(&release().unwrap()).is_some());
        assert!(refuse_before((0, 0)).is_ok());
        assert!(refuse_before((u32::MAX, 0)).is_err());
    }
}
