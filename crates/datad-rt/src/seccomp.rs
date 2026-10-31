// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The syscall filter of the daemon, arm64 only, in the pattern of the IMS daemon. SELinux decides
//! which paths, sockets and ioctl numbers the daemon may use. The filter takes away the rest of the
//! kernel interface: only the syscalls below, `socket` for QRTR only, `ioctl` for the two requests
//! the daemon makes, and `fcntl` for the four flag commands. It is installed after the netlink
//! socket and the socket of the protocol exist, and before the first byte is read from either.
//!
//! The program is built here as data, with the syscall numbers written out, so the host tests
//! can run it on made-up syscalls (a small interpreter of the three instruction kinds it uses). On
//! aarch64 Linux a compile-time check holds every number against the one `libc` knows.
//!
//! **The list is from the code and the standard library, not from a run.** Until a log-mode run on
//! the phone (bring-up, a call, a modem restart, a marker write) has shown what is missing, the
//! filter only logs what it would refuse. `Action::Errno` enforces it.
#![allow(unsafe_code)]
use std::io;

/// What a syscall that is not on the list gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Allowed, and logged by the kernel's audit (`SECCOMP_RET_LOG`).
    Log,
    /// Refused with `ENOSYS`.
    Errno,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

// BPF_LD | BPF_W | BPF_ABS, BPF_JMP | BPF_JEQ | BPF_K, BPF_RET | BPF_K
const LD: u16 = 0x20;
const JEQ: u16 = 0x15;
const RET: u16 = 0x06;

pub const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
const OFFSET_NR: u32 = 0;
const OFFSET_ARCH: u32 = 4;
const OFFSET_ARGS: u32 = 16;

pub const RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const RET_ALLOW: u32 = 0x7fff_0000;
pub const RET_LOG: u32 = 0x7ffc_0000;
const RET_ERRNO: u32 = 0x0005_0000;

pub const AF_QIPCRTR: u32 = 42;
pub const SIOCGIFINDEX: u32 = 0x8933;
/// `SIOCDEVPRIVATE + 13`, the extended request of the rmnet device.
pub const RMNET_IOCTL_EXTENDED: u32 = 0x89fd;
/// `SIOCDEVPRIVATE + 14`, the V2 request of the rmnet device (the data format of the pipes).
pub const RMNET_IOCTL_EXTENDED_V2: u32 = 0x89fe;
/// `SIOCETHTOOL`, the device features (`ETHTOOL_SFEATURES` and the requests around it).
pub const SIOCETHTOOL: u32 = 0x8946;
pub const F_GETFD: u32 = 1;
pub const F_SETFD: u32 = 2;
pub const F_GETFL: u32 = 3;
pub const F_SETFL: u32 = 4;

/// arm64 syscall numbers (asm-generic).
pub mod nr {
    pub const FCNTL: u32 = 25;
    pub const IOCTL: u32 = 29;
    pub const UNLINKAT: u32 = 35;
    pub const RENAMEAT: u32 = 38;
    pub const FACCESSAT: u32 = 48;
    pub const OPENAT: u32 = 56;
    pub const CLOSE: u32 = 57;
    pub const LSEEK: u32 = 62;
    pub const READ: u32 = 63;
    pub const WRITE: u32 = 64;
    pub const WRITEV: u32 = 66;
    pub const PREAD64: u32 = 67;
    pub const PPOLL: u32 = 73;
    pub const READLINKAT: u32 = 78;
    pub const NEWFSTATAT: u32 = 79;
    pub const FSTAT: u32 = 80;
    pub const FSYNC: u32 = 82;
    pub const FDATASYNC: u32 = 83;
    pub const EXIT: u32 = 93;
    pub const EXIT_GROUP: u32 = 94;
    pub const SET_TID_ADDRESS: u32 = 96;
    pub const FUTEX: u32 = 98;
    pub const SET_ROBUST_LIST: u32 = 99;
    pub const NANOSLEEP: u32 = 101;
    pub const CLOCK_GETTIME: u32 = 113;
    pub const CLOCK_NANOSLEEP: u32 = 115;
    pub const SCHED_YIELD: u32 = 124;
    pub const RESTART_SYSCALL: u32 = 128;
    pub const TGKILL: u32 = 131;
    pub const SIGALTSTACK: u32 = 132;
    pub const RT_SIGACTION: u32 = 134;
    pub const RT_SIGPROCMASK: u32 = 135;
    pub const RT_SIGRETURN: u32 = 139;
    pub const UNAME: u32 = 160;
    pub const PRCTL: u32 = 167;
    pub const RT_TGSIGQUEUEINFO: u32 = 240;
    pub const GETTIMEOFDAY: u32 = 169;
    pub const GETPID: u32 = 172;
    pub const GETUID: u32 = 174;
    pub const GETEUID: u32 = 175;
    pub const GETGID: u32 = 176;
    pub const GETEGID: u32 = 177;
    pub const GETTID: u32 = 178;
    pub const SOCKET: u32 = 198;
    pub const BIND: u32 = 200;
    pub const GETSOCKNAME: u32 = 204;
    pub const SENDTO: u32 = 206;
    pub const RECVFROM: u32 = 207;
    pub const SETSOCKOPT: u32 = 208;
    pub const GETSOCKOPT: u32 = 209;
    pub const SENDMSG: u32 = 211;
    pub const RECVMSG: u32 = 212;
    pub const BRK: u32 = 214;
    pub const MUNMAP: u32 = 215;
    pub const MREMAP: u32 = 216;
    pub const MMAP: u32 = 222;
    pub const MPROTECT: u32 = 226;
    pub const MADVISE: u32 = 233;
    pub const ACCEPT4: u32 = 242;
    pub const PRLIMIT64: u32 = 261;
    pub const RENAMEAT2: u32 = 276;
    pub const GETRANDOM: u32 = 278;
    pub const STATX: u32 = 291;
    // not on the list, named for the tests
    pub const MOUNT: u32 = 40;
    pub const PTRACE: u32 = 117;
    pub const SETUID: u32 = 146;
    pub const INIT_MODULE: u32 = 105;
    pub const CLONE: u32 = 220;
    pub const EXECVE: u32 = 221;
    pub const BPF: u32 = 280;
    pub const CONNECT: u32 = 203;
    pub const LISTEN: u32 = 201;
}

/// The syscalls that need no condition. The last five end the process (a normal exit, the abort of
/// the standard library and of bionic) or restart a call a signal interrupted, and are never refused.
pub const ALLOWED: [u32; 60] = [
    nr::READ,
    nr::WRITE,
    nr::WRITEV,
    nr::CLOSE,
    nr::OPENAT,
    nr::NEWFSTATAT,
    nr::FSTAT,
    nr::STATX,
    nr::READLINKAT,
    nr::FACCESSAT,
    nr::LSEEK,
    nr::PREAD64,
    nr::RENAMEAT,
    nr::RENAMEAT2,
    nr::UNLINKAT,
    nr::FSYNC,
    nr::FDATASYNC,
    nr::MMAP,
    nr::MPROTECT,
    nr::MUNMAP,
    nr::MREMAP,
    nr::MADVISE,
    nr::BRK,
    nr::BIND,
    nr::GETSOCKNAME,
    nr::SENDTO,
    nr::SENDMSG,
    nr::RECVFROM,
    nr::RECVMSG,
    nr::ACCEPT4,
    nr::GETSOCKOPT,
    nr::SETSOCKOPT,
    nr::PPOLL,
    nr::FUTEX,
    nr::SET_ROBUST_LIST,
    nr::SET_TID_ADDRESS,
    nr::RT_SIGACTION,
    nr::RT_SIGPROCMASK,
    nr::RT_SIGRETURN,
    nr::SIGALTSTACK,
    nr::CLOCK_GETTIME,
    nr::CLOCK_NANOSLEEP,
    nr::NANOSLEEP,
    nr::GETTIMEOFDAY,
    nr::SCHED_YIELD,
    nr::GETPID,
    nr::GETTID,
    nr::GETUID,
    nr::GETEUID,
    nr::GETGID,
    nr::GETEGID,
    nr::GETRANDOM,
    nr::UNAME,
    nr::PRLIMIT64,
    nr::PRCTL,
    nr::EXIT,
    nr::EXIT_GROUP,
    nr::TGKILL,
    // bionic's abort() raises its signal with it, and a call that a signal interrupted is restarted with it
    nr::RT_TGSIGQUEUEINFO,
    nr::RESTART_SYSCALL,
];

/// The syscalls that run only with one of these values in the argument (0-based) named.
pub const CONDITIONAL: [(u32, u32, &[u32]); 3] = [
    (nr::SOCKET, 0, &[AF_QIPCRTR]),
    (
        nr::IOCTL,
        1,
        &[
            SIOCGIFINDEX,
            RMNET_IOCTL_EXTENDED,
            RMNET_IOCTL_EXTENDED_V2,
            SIOCETHTOOL,
        ],
    ),
    (nr::FCNTL, 1, &[F_GETFD, F_SETFD, F_GETFL, F_SETFL]),
];

fn insn(code: u16, jt: u8, jf: u8, k: u32) -> Insn {
    Insn { code, jt, jf, k }
}

fn skip(n: usize) -> u8 {
    u8::try_from(n).unwrap_or(u8::MAX)
}

/// The program. A call of another architecture ends the process. A call on the list runs
/// (with a condition on one argument for some). Anything else gets the action.
pub fn filter(action: Action) -> Vec<Insn> {
    let mut f = vec![
        insn(LD, 0, 0, OFFSET_ARCH),
        insn(JEQ, 1, 0, AUDIT_ARCH_AARCH64),
        insn(RET, 0, 0, RET_KILL_PROCESS),
        insn(LD, 0, 0, OFFSET_NR),
    ];
    // a block is a test of the number and, when it matches, the answer. Each block ends in a
    // return, so a match never falls into the next test, and a miss skips the whole body
    for (call, arg, values) in CONDITIONAL {
        let n = values.len();
        // load, one test per value, the refusal, the allow
        let body = 1 + n + 1 + 1;
        f.push(insn(JEQ, 0, skip(body), call));
        f.push(insn(LD, 0, 0, OFFSET_ARGS + 8 * arg));
        for (i, v) in values.iter().enumerate() {
            // a match jumps over the remaining tests and the refusal to the allow
            f.push(insn(JEQ, skip(n - i), 0, *v));
        }
        // in log mode a refusal is only logged too, or a run in that mode would show nothing of them
        f.push(insn(
            RET,
            0,
            0,
            match action {
                Action::Log => RET_LOG,
                Action::Errno => RET_ERRNO | libc_eperm(),
            },
        ));
        f.push(insn(RET, 0, 0, RET_ALLOW));
    }
    for call in ALLOWED {
        f.push(insn(JEQ, 0, 1, call));
        f.push(insn(RET, 0, 0, RET_ALLOW));
    }
    f.push(insn(
        RET,
        0,
        0,
        match action {
            Action::Log => RET_LOG,
            Action::Errno => RET_ERRNO | libc_enosys(),
        },
    ));
    f
}

const fn libc_eperm() -> u32 {
    1
}

const fn libc_enosys() -> u32 {
    38
}

/// Run the program on a made-up call: the architecture, the syscall number and its six
/// arguments (the low words matter). The answer is the return value.
pub fn run(program: &[Insn], arch: u32, number: u32, args: [u64; 6]) -> Option<u32> {
    let mut pc = 0usize;
    let mut acc = 0u32;
    for _ in 0..program.len().saturating_mul(2) {
        let i = *program.get(pc)?;
        pc += 1;
        match i.code {
            LD => {
                acc = match i.k {
                    OFFSET_NR => number,
                    OFFSET_ARCH => arch,
                    k if k >= OFFSET_ARGS && (k - OFFSET_ARGS) & 7 == 0 => {
                        let idx = usize::try_from((k - OFFSET_ARGS) / 8).ok()?;
                        // little endian: the low word is at the offset itself
                        u32::try_from(*args.get(idx)? & 0xffff_ffff).ok()?
                    }
                    _ => return None,
                }
            }
            JEQ => pc += usize::from(if acc == i.k { i.jt } else { i.jf }),
            RET => return Some(i.k),
            _ => return None,
        }
    }
    None
}

/// Install the filter: no new privileges, then the program. Only for aarch64 Linux.
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
pub fn install(action: Action) -> io::Result<()> {
    let program = filter(action);
    let mut raw: Vec<libc::sock_filter> = program
        .iter()
        .map(|i| libc::sock_filter {
            code: i.code,
            jt: i.jt,
            jf: i.jf,
            k: i.k,
        })
        .collect();
    let prog = libc::sock_fprog {
        len: u16::try_from(raw.len()).map_err(|_| io::Error::other("filter too long"))?,
        filter: raw.as_mut_ptr(),
    };
    // SAFETY: both calls take integers and, for the second, a pointer to the program, which the
    // kernel copies during the call and which lives until it returns.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &prog as *const libc::sock_fprog,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
)))]
pub fn install(_action: Action) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the filter is for arm64 Linux",
    ))
}

// The numbers above against the ones libc has for this target. A wrong one does not build.
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
mod numbers_agree_with_libc {
    use super::nr;
    macro_rules! same {
        ($($name:ident => $sys:ident),* $(,)?) => {
            $(const _: () = assert!(nr::$name as libc::c_long == libc::$sys);)*
        };
    }
    same! {
        FCNTL => SYS_fcntl, IOCTL => SYS_ioctl, UNLINKAT => SYS_unlinkat, RENAMEAT => SYS_renameat,
        FACCESSAT => SYS_faccessat, OPENAT => SYS_openat, CLOSE => SYS_close, LSEEK => SYS_lseek,
        READ => SYS_read, WRITE => SYS_write, WRITEV => SYS_writev, PREAD64 => SYS_pread64,
        PPOLL => SYS_ppoll, READLINKAT => SYS_readlinkat, FSYNC => SYS_fsync, FDATASYNC => SYS_fdatasync, EXIT => SYS_exit,
        EXIT_GROUP => SYS_exit_group, SET_TID_ADDRESS => SYS_set_tid_address, FUTEX => SYS_futex,
        SET_ROBUST_LIST => SYS_set_robust_list, NANOSLEEP => SYS_nanosleep,
        CLOCK_GETTIME => SYS_clock_gettime, CLOCK_NANOSLEEP => SYS_clock_nanosleep,
        SCHED_YIELD => SYS_sched_yield, TGKILL => SYS_tgkill, SIGALTSTACK => SYS_sigaltstack,
        RT_SIGACTION => SYS_rt_sigaction, RT_SIGPROCMASK => SYS_rt_sigprocmask,
        RT_SIGRETURN => SYS_rt_sigreturn, UNAME => SYS_uname, PRCTL => SYS_prctl,
        GETTIMEOFDAY => SYS_gettimeofday, GETPID => SYS_getpid, GETUID => SYS_getuid,
        GETEUID => SYS_geteuid, GETGID => SYS_getgid, GETEGID => SYS_getegid,
        GETTID => SYS_gettid, SOCKET => SYS_socket, BIND => SYS_bind,
        GETSOCKNAME => SYS_getsockname, SENDTO => SYS_sendto, RECVFROM => SYS_recvfrom,
        SETSOCKOPT => SYS_setsockopt, GETSOCKOPT => SYS_getsockopt, SENDMSG => SYS_sendmsg,
        RECVMSG => SYS_recvmsg, BRK => SYS_brk, MUNMAP => SYS_munmap, MREMAP => SYS_mremap,
        MMAP => SYS_mmap, MPROTECT => SYS_mprotect, MADVISE => SYS_madvise, ACCEPT4 => SYS_accept4,
        PRLIMIT64 => SYS_prlimit64, RESTART_SYSCALL => SYS_restart_syscall,
        RT_TGSIGQUEUEINFO => SYS_rt_tgsigqueueinfo, RENAMEAT2 => SYS_renameat2, GETRANDOM => SYS_getrandom,
        STATX => SYS_statx, MOUNT => SYS_mount, PTRACE => SYS_ptrace, SETUID => SYS_setuid,
        INIT_MODULE => SYS_init_module, CLONE => SYS_clone, EXECVE => SYS_execve, BPF => SYS_bpf,
        CONNECT => SYS_connect, LISTEN => SYS_listen,
    }
    // The libc crate of the platform build (target Android) has no names for these two.
    #[cfg(not(target_os = "android"))]
    same! { NEWFSTATAT => SYS_newfstatat, FSTAT => SYS_fstat }
    const _: () = assert!(super::libc_eperm() as i32 == libc::EPERM);
    const _: () = assert!(super::libc_enosys() as i32 == libc::ENOSYS);
    const _: () = assert!(super::AF_QIPCRTR as i32 == 42);
    const _: () = assert!(super::F_GETFD as i32 == libc::F_GETFD);
    const _: () = assert!(super::F_SETFD as i32 == libc::F_SETFD);
    const _: () = assert!(super::F_GETFL as i32 == libc::F_GETFL);
    const _: () = assert!(super::F_SETFL as i32 == libc::F_SETFL);
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARCH: u32 = AUDIT_ARCH_AARCH64;

    fn call(p: &[Insn], number: u32, args: [u64; 6]) -> u32 {
        run(p, ARCH, number, args).unwrap()
    }

    fn plain(p: &[Insn], number: u32) -> u32 {
        call(p, number, [0; 6])
    }

    #[test]
    fn a_program_that_never_jumps_out_of_itself_and_always_returns() {
        for action in [Action::Log, Action::Errno] {
            let p = filter(action);
            assert!(p.len() < 4096);
            assert_eq!(p.last().unwrap().code, RET);
            for (n, i) in p.iter().enumerate() {
                if i.code == JEQ {
                    // both ways land inside the program
                    assert!(n + 1 + usize::from(i.jt) < p.len(), "{n} jt");
                    assert!(n + 1 + usize::from(i.jf) < p.len(), "{n} jf");
                }
            }
            // every path ends: run on every number the program knows and on others
            for number in 0..400 {
                assert!(run(&p, ARCH, number, [0; 6]).is_some(), "{number}");
            }
        }
    }

    #[test]
    fn another_architecture_ends_the_process() {
        let p = filter(Action::Errno);
        // x86-64 and 32-bit arm, with a number that would be allowed on arm64
        for arch in [0xc000_003e, 0x4000_0028, 0] {
            assert_eq!(run(&p, arch, nr::READ, [0; 6]), Some(RET_KILL_PROCESS));
        }
    }

    #[test]
    fn every_syscall_on_the_list_runs() {
        let p = filter(Action::Errno);
        for n in ALLOWED {
            assert_eq!(plain(&p, n), RET_ALLOW, "{n}");
        }
        // the list has no number twice, and none of the conditional ones
        let mut all = ALLOWED.to_vec();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), ALLOWED.len());
        for (call, _, _) in CONDITIONAL {
            assert!(!ALLOWED.contains(&call));
        }
    }

    #[test]
    fn the_numbers_are_those_of_arm64() {
        // asm-generic/unistd.h. On aarch64 Linux the build checks them against libc as well
        let table: [(u32, u32); 72] = [
            (nr::FCNTL, 25),
            (nr::IOCTL, 29),
            (nr::UNLINKAT, 35),
            (nr::RENAMEAT, 38),
            (nr::FACCESSAT, 48),
            (nr::OPENAT, 56),
            (nr::CLOSE, 57),
            (nr::LSEEK, 62),
            (nr::READ, 63),
            (nr::WRITE, 64),
            (nr::WRITEV, 66),
            (nr::PREAD64, 67),
            (nr::PPOLL, 73),
            (nr::READLINKAT, 78),
            (nr::NEWFSTATAT, 79),
            (nr::FSTAT, 80),
            (nr::FSYNC, 82),
            (nr::FDATASYNC, 83),
            (nr::EXIT, 93),
            (nr::EXIT_GROUP, 94),
            (nr::SET_TID_ADDRESS, 96),
            (nr::FUTEX, 98),
            (nr::SET_ROBUST_LIST, 99),
            (nr::NANOSLEEP, 101),
            (nr::CLOCK_GETTIME, 113),
            (nr::CLOCK_NANOSLEEP, 115),
            (nr::SCHED_YIELD, 124),
            (nr::TGKILL, 131),
            (nr::SIGALTSTACK, 132),
            (nr::RT_SIGACTION, 134),
            (nr::RT_SIGPROCMASK, 135),
            (nr::RT_SIGRETURN, 139),
            (nr::UNAME, 160),
            (nr::PRCTL, 167),
            (nr::GETTIMEOFDAY, 169),
            (nr::GETPID, 172),
            (nr::GETUID, 174),
            (nr::GETEUID, 175),
            (nr::GETGID, 176),
            (nr::GETEGID, 177),
            (nr::GETTID, 178),
            (nr::SOCKET, 198),
            (nr::BIND, 200),
            (nr::GETSOCKNAME, 204),
            (nr::SENDTO, 206),
            (nr::RECVFROM, 207),
            (nr::SETSOCKOPT, 208),
            (nr::GETSOCKOPT, 209),
            (nr::SENDMSG, 211),
            (nr::RECVMSG, 212),
            (nr::BRK, 214),
            (nr::MUNMAP, 215),
            (nr::MREMAP, 216),
            (nr::MMAP, 222),
            (nr::MPROTECT, 226),
            (nr::MADVISE, 233),
            (nr::ACCEPT4, 242),
            (nr::PRLIMIT64, 261),
            (nr::RENAMEAT2, 276),
            (nr::GETRANDOM, 278),
            (nr::STATX, 291),
            (nr::MOUNT, 40),
            (nr::PTRACE, 117),
            (nr::SETUID, 146),
            (nr::INIT_MODULE, 105),
            (nr::CLONE, 220),
            (nr::EXECVE, 221),
            (nr::BPF, 280),
            (nr::RESTART_SYSCALL, 128),
            (nr::RT_TGSIGQUEUEINFO, 240),
            (nr::CONNECT, 203),
            (nr::LISTEN, 201),
        ];
        for (got, want) in table {
            assert_eq!(got, want);
        }
        assert_eq!(AUDIT_ARCH_AARCH64, 0xc000_00b7);
        assert_eq!(
            (AF_QIPCRTR, SIOCGIFINDEX, RMNET_IOCTL_EXTENDED),
            (42, 0x8933, 0x89fd)
        );
        assert_eq!((RMNET_IOCTL_EXTENDED_V2, SIOCETHTOOL), (0x89fe, 0x8946));
        assert_eq!((F_GETFD, F_SETFD, F_GETFL, F_SETFL), (1, 2, 3, 4));
        assert_eq!(
            (RET_KILL_PROCESS, RET_ALLOW, RET_LOG),
            (0x8000_0000, 0x7fff_0000, 0x7ffc_0000)
        );
    }

    #[test]
    fn what_is_not_on_the_list_gets_the_action() {
        let enforce = filter(Action::Errno);
        let log = filter(Action::Log);
        for n in [
            nr::EXECVE,
            nr::MOUNT,
            nr::PTRACE,
            nr::SETUID,
            nr::INIT_MODULE,
            nr::CLONE,
            nr::BPF,
            nr::CONNECT,
            nr::LISTEN,
            435,
            9999,
        ] {
            assert_eq!(plain(&enforce, n), RET_ERRNO | 38, "{n}");
            assert_eq!(plain(&log, n), RET_LOG, "{n}");
        }
    }

    #[test]
    fn a_socket_is_for_qrtr_and_nothing_else() {
        for (action, refused) in [(Action::Errno, RET_ERRNO | 1), (Action::Log, RET_LOG)] {
            let p = filter(action);
            assert_eq!(call(&p, nr::SOCKET, [42, 2, 0, 0, 0, 0]), RET_ALLOW);
            // inet, inet6, netlink, unix, packet, tipc: refused, or only logged in log mode
            for family in [2u64, 10, 16, 1, 17, 30] {
                assert_eq!(
                    call(&p, nr::SOCKET, [family, 2, 0, 0, 0, 0]),
                    refused,
                    "{family}"
                );
            }
        }
    }

    #[test]
    fn in_log_mode_the_refusals_of_an_argument_are_logged_not_silent() {
        // or a run in log mode would show nothing of them, and the list would look complete
        let p = filter(Action::Log);
        assert_eq!(call(&p, nr::SOCKET, [2, 0, 0, 0, 0, 0]), RET_LOG);
        assert_eq!(call(&p, nr::IOCTL, [3, 0x5412, 0, 0, 0, 0]), RET_LOG);
        assert_eq!(call(&p, nr::FCNTL, [3, 8, 0, 0, 0, 0]), RET_LOG);
        assert_eq!(plain(&p, nr::EXECVE), RET_LOG);
        // and what is allowed stays allowed
        assert_eq!(
            call(&p, nr::IOCTL, [3, SIOCGIFINDEX as u64, 0, 0, 0, 0]),
            RET_ALLOW
        );
    }

    #[test]
    fn the_calls_bionic_needs_to_abort_and_to_restart_a_call_are_allowed() {
        let p = filter(Action::Errno);
        assert_eq!(plain(&p, nr::RT_TGSIGQUEUEINFO), RET_ALLOW);
        assert_eq!(plain(&p, nr::RESTART_SYSCALL), RET_ALLOW);
    }

    #[test]
    fn the_arguments_are_taken_from_their_own_places() {
        let p = filter(Action::Errno);
        // socket looks at the first argument, ioctl and fcntl at the second
        assert_eq!(call(&p, nr::SOCKET, [2, 42, 0, 0, 0, 0]), RET_ERRNO | 1);
        assert_eq!(
            call(&p, nr::IOCTL, [SIOCGIFINDEX as u64, 0, 0, 0, 0, 0]),
            RET_ERRNO | 1
        );
        assert_eq!(
            call(&p, nr::FCNTL, [F_GETFD as u64, 0, 0, 0, 0, 0]),
            RET_ERRNO | 1
        );
        assert_eq!(
            call(&p, nr::IOCTL, [0, SIOCGIFINDEX as u64, 0, 0, 0, 0]),
            RET_ALLOW
        );
        // the value in the right place but in a later argument is no help
        assert_eq!(
            call(&p, nr::IOCTL, [0, 0, SIOCGIFINDEX as u64, 0, 0, 0]),
            RET_ERRNO | 1
        );
    }

    #[test]
    fn an_ioctl_is_one_of_the_four_requests_and_nothing_else() {
        let p = filter(Action::Errno);
        for req in [
            SIOCGIFINDEX,
            RMNET_IOCTL_EXTENDED,
            RMNET_IOCTL_EXTENDED_V2,
            SIOCETHTOOL,
        ] {
            assert_eq!(call(&p, nr::IOCTL, [3, req as u64, 0, 0, 0, 0]), RET_ALLOW);
        }
        // the next request of the rmnet device after the V2 one, a terminal request that pushes
        // input, setting an address, and the one just next to each allowed number
        for req in [
            0x89ffu64, 0x5412, 0x8916, 0x8934, 0x8932, 0x89fc, 0x8945, 0x8947, 0,
        ] {
            assert_eq!(
                call(&p, nr::IOCTL, [3, req, 0, 0, 0, 0]),
                RET_ERRNO | 1,
                "{req:#x}"
            );
        }
    }

    #[test]
    fn an_fcntl_is_one_of_the_four_flag_commands() {
        let p = filter(Action::Errno);
        for cmd in [F_GETFD, F_SETFD, F_GETFL, F_SETFL] {
            assert_eq!(call(&p, nr::FCNTL, [3, cmd as u64, 0, 0, 0, 0]), RET_ALLOW);
        }
        // dup with close-on-exec, owner, lock, and the numbers next to the allowed ones
        for cmd in [0u64, 5, 8, 1030, 6] {
            assert_eq!(
                call(&p, nr::FCNTL, [3, cmd, 0, 0, 0, 0]),
                RET_ERRNO | 1,
                "{cmd}"
            );
        }
    }

    #[test]
    fn only_the_low_word_of_an_argument_counts() {
        // the kernel takes an int and an unsigned int, so the high word is cut off before it looks
        let p = filter(Action::Errno);
        assert_eq!(
            call(&p, nr::SOCKET, [0x1_0000_002a, 0, 0, 0, 0, 0]),
            RET_ALLOW
        );
        assert_eq!(
            call(&p, nr::SOCKET, [0x2a_0000_0002, 0, 0, 0, 0, 0]),
            RET_ERRNO | 1
        );
    }

    #[test]
    fn the_interpreter_refuses_what_it_does_not_know() {
        let bad = [insn(0x99, 0, 0, 0)];
        assert_eq!(run(&bad, ARCH, 1, [0; 6]), None);
        let odd_load = [insn(LD, 0, 0, 3)];
        assert_eq!(run(&odd_load, ARCH, 1, [0; 6]), None);
        let off_the_end = [insn(JEQ, 5, 5, 0)];
        assert_eq!(run(&off_the_end, ARCH, 1, [0; 6]), None);
        // a loop-free program of a single return
        let ret = [insn(RET, 0, 0, 7)];
        assert_eq!(run(&ret, ARCH, 1, [0; 6]), Some(7));
        // the sixth argument is there, the seventh is not
        let sixth = [insn(LD, 0, 0, OFFSET_ARGS + 40), insn(RET, 0, 0, 1)];
        assert_eq!(run(&sixth, ARCH, 1, [0; 6]), Some(1));
        let seventh = [insn(LD, 0, 0, OFFSET_ARGS + 48), insn(RET, 0, 0, 1)];
        assert_eq!(run(&seventh, ARCH, 1, [0; 6]), None);
    }

    #[cfg(not(all(
        any(target_os = "linux", target_os = "android"),
        target_arch = "aarch64"
    )))]
    #[test]
    fn installing_is_for_arm64_linux_only() {
        assert_eq!(
            install(Action::Errno).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }
}
