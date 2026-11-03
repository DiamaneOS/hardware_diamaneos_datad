// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The syscall table of this daemon, on the program builder of the data daemon. It is the list of that daemon
//! without `accept4` and with `connect` (the UDP socket of a tunnel). `socket` is for QRTR and the two IP
//! families only, because the netlink sockets exist before the filter goes on.
use dataos_datad_rt::seccomp::{self, nr, Action, Insn};

/// `SIOCGIFNAME`, the name of the interface that has a tunnel's local address.
pub const SIOCGIFNAME: u32 = 0x8910;
pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 10;

fn allowed() -> Vec<u32> {
    seccomp::ALLOWED
        .iter()
        .copied()
        .filter(|n| *n != nr::ACCEPT4)
        .chain([nr::CONNECT])
        .collect()
}

const SOCKET_FAMILIES: [u32; 3] = [seccomp::AF_QIPCRTR, AF_INET, AF_INET6];
const IOCTLS: [u32; 2] = [seccomp::SIOCGIFINDEX, SIOCGIFNAME];
const FCNTLS: [u32; 4] = [
    seccomp::F_GETFD,
    seccomp::F_SETFD,
    seccomp::F_GETFL,
    seccomp::F_SETFL,
];

pub fn program(action: Action) -> Vec<Insn> {
    seccomp::filter_of(
        action,
        &allowed(),
        &[
            (nr::SOCKET, 0, &SOCKET_FAMILIES),
            (nr::IOCTL, 1, &IOCTLS),
            (nr::FCNTL, 1, &FCNTLS),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use dataos_datad_rt::seccomp::{run, AUDIT_ARCH_AARCH64, RET_ALLOW, RET_LOG};

    const AF_NETLINK: u64 = 16;
    const EPERM: u32 = 0x0005_0001;
    const ENOSYS: u32 = 0x0005_0026;

    fn ask(action: Action, number: u32, args: [u64; 6]) -> u32 {
        run(&program(action), AUDIT_ARCH_AARCH64, number, args).unwrap()
    }

    #[test]
    fn the_calls_of_the_daemon_are_allowed() {
        let a = Action::Errno;
        for family in [42, 2, 10] {
            assert_eq!(ask(a, nr::SOCKET, [family, 0, 0, 0, 0, 0]), RET_ALLOW);
        }
        for request in [0x8933, 0x8910] {
            assert_eq!(ask(a, nr::IOCTL, [3, request, 0, 0, 0, 0]), RET_ALLOW);
        }
        for call in [
            nr::CONNECT,
            nr::BIND,
            nr::SETSOCKOPT,
            nr::SENDTO,
            nr::RECVMSG,
            nr::WRITEV,
            nr::RENAMEAT,
            nr::GETRANDOM,
        ] {
            assert_eq!(ask(a, call, [0; 6]), RET_ALLOW, "{call}");
        }
    }

    #[test]
    fn what_it_has_no_use_for_is_refused() {
        let a = Action::Errno;
        assert_eq!(ask(a, nr::SOCKET, [AF_NETLINK, 0, 0, 0, 0, 0]), EPERM);
        assert_eq!(ask(a, nr::IOCTL, [3, 0x8946, 0, 0, 0, 0]), EPERM);
        assert_eq!(ask(a, nr::IOCTL, [3, 0x89fd, 0, 0, 0, 0]), EPERM);
        assert_eq!(ask(a, nr::IOCTL, [3, 0x89fe, 0, 0, 0, 0]), EPERM);
        for call in [
            nr::ACCEPT4,
            nr::LISTEN,
            nr::EXECVE,
            nr::CLONE,
            nr::BPF,
            nr::PTRACE,
        ] {
            assert_eq!(ask(a, call, [0; 6]), ENOSYS, "{call}");
        }
    }

    #[test]
    fn log_mode_lets_a_refusal_through_with_a_trace() {
        assert_eq!(ask(Action::Log, nr::EXECVE, [0; 6]), RET_LOG);
        assert_eq!(
            ask(Action::Log, nr::SOCKET, [AF_NETLINK, 0, 0, 0, 0, 0]),
            RET_LOG
        );
    }
}
