//! The daemon never runs with the power of root. The real, effective and saved user and group
//! IDs are all looked at, and so are the supplementary groups and the capabilities: a process that
//! started as root and gave up only its effective ID can take the saved one back, a root group gives
//! files that no user ID does, and a capability beyond the one the rc file asks for is power too.
#![allow(unsafe_code)]
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::io;

/// `CAP_NET_ADMIN`, the one capability the daemon has (`capabilities NET_ADMIN` in its rc file).
pub const ALLOWED_CAPS: u64 = 1 << 12;

/// Is root among these IDs, or among the supplementary groups?
pub fn any_root(uids: [u32; 3], gids: [u32; 3], groups: &[u32]) -> bool {
    uids.contains(&0) || gids.contains(&0) || groups.contains(&0)
}

/// The capabilities of `/proc/self/status` (the effective, permitted and ambient sets) that are not in
/// `ALLOWED_CAPS`. None: a line is missing or is not a number, and a status that cannot be read is no proof.
pub fn caps_beyond(status: &str) -> Option<u64> {
    let mut beyond = 0;
    for name in ["CapPrm:", "CapEff:", "CapAmb:"] {
        let value = status.lines().find_map(|l| l.strip_prefix(name))?.trim();
        let set = u64::from_str_radix(value, 16).ok()?;
        beyond |= set & !ALLOWED_CAPS;
    }
    Some(beyond)
}
#[cfg(any(target_os = "linux", target_os = "android"))]
fn check(rc: libc::c_int) -> io::Result<()> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// The real, effective and saved user IDs and group IDs of this process.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn ids() -> io::Result<([u32; 3], [u32; 3])> {
    let (mut ru, mut eu, mut su) = (0, 0, 0);
    let (mut rg, mut eg, mut sg) = (0, 0, 0);
    // SAFETY: three pointers to integers that live through the call, as getresuid needs.
    check(unsafe { libc::getresuid(&mut ru, &mut eu, &mut su) })?;
    // SAFETY: the same for the group IDs.
    check(unsafe { libc::getresgid(&mut rg, &mut eg, &mut sg) })?;
    Ok(([ru, eu, su], [rg, eg, sg]))
}

/// The supplementary groups of this process.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn groups() -> io::Result<Vec<u32>> {
    // SAFETY: with a size of 0 the call only returns the number of groups and writes nothing.
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    check(n)?;
    let mut list = vec![0 as libc::gid_t; usize::try_from(n).unwrap_or(0)];
    // SAFETY: the buffer has room for the `n` groups the call said there were, and the size says so.
    let got = unsafe { libc::getgroups(n, list.as_mut_ptr()) };
    check(got)?;
    list.truncate(usize::try_from(got).unwrap_or(0));
    Ok(list)
}

/// An error when this process is root in any ID or group, or has a capability the rc file did not ask for.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn refuse_root() -> io::Result<()> {
    let (uids, gids) = ids()?;
    if any_root(uids, gids, &groups()?) {
        return Err(io::Error::other("must not run as root"));
    }
    let status = std::fs::read_to_string("/proc/self/status")?;
    match caps_beyond(&status) {
        Some(0) => Ok(()),
        Some(_) => Err(io::Error::other(
            "has capabilities beyond the one it asked for",
        )),
        None => Err(io::Error::other("cannot tell the capabilities")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_in_any_of_the_six_or_in_a_group_is_root() {
        assert!(!any_root([1000; 3], [1000; 3], &[]));
        assert!(!any_root([1000; 3], [1000; 3], &[3009, 2998]));
        for i in 0..3 {
            let mut u = [1000; 3];
            u[i] = 0;
            assert!(any_root(u, [1000; 3], &[]), "user {i}");
            let mut g = [1000; 3];
            g[i] = 0;
            assert!(any_root([1000; 3], g, &[]), "group {i}");
        }
        assert!(
            any_root([1000; 3], [1000; 3], &[3009, 0]),
            "a supplementary group"
        );
    }

    fn status(prm: &str, eff: &str, amb: &str) -> String {
        format!(
            "Name:\tdatad\nCapInh:\t0000000000001000\nCapPrm:\t{prm}\nCapEff:\t{eff}\nCapBnd:\t000001ffffffffff\nCapAmb:\t{amb}\n"
        )
    }

    #[test]
    fn only_net_admin_is_allowed_in_the_three_sets() {
        let net_admin = "0000000000001000";
        assert_eq!(
            caps_beyond(&status(net_admin, net_admin, net_admin)),
            Some(0)
        );
        assert_eq!(
            caps_beyond(&status(
                "0000000000000000",
                "0000000000000000",
                "0000000000000000"
            )),
            Some(0)
        );
        // a second capability in any one of the sets, the bounding set is not looked at
        let more = "0000000000003000";
        assert_eq!(
            caps_beyond(&status(more, net_admin, net_admin)),
            Some(0x2000)
        );
        assert_eq!(
            caps_beyond(&status(net_admin, more, net_admin)),
            Some(0x2000)
        );
        assert_eq!(
            caps_beyond(&status(net_admin, net_admin, more)),
            Some(0x2000)
        );
        assert_eq!(
            caps_beyond(&status("000001ffffffffff", net_admin, net_admin)),
            Some(0x1ffffffefff)
        );
        // a line missing or not a number is no proof
        assert_eq!(caps_beyond("CapPrm:\t0\nCapEff:\t0\n"), None);
        assert_eq!(caps_beyond(&status("zz", net_admin, net_admin)), None);
        assert_eq!(caps_beyond(""), None);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn the_ids_of_this_process_are_the_ones_it_has() {
        let (uids, gids) = ids().unwrap();
        // SAFETY: getuid and getgid take nothing and cannot fail.
        let (u, g) = unsafe { (libc::getuid(), libc::getgid()) };
        assert_eq!((uids[0], gids[0]), (u, g));
        let groups = groups().unwrap();
        // a test run by a user has no capabilities, and root has more than NET_ADMIN
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let expect_refusal = any_root(uids, gids, &groups) || caps_beyond(&status) != Some(0);
        assert_eq!(refuse_root().is_err(), expect_refusal);
    }
}
