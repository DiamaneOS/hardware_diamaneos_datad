# Android integration

The Soong modules, the device wiring and the policy of the open data stack. Everything is behind one build switch
of the device, `DIAMANEOS_DATAD`. A build without it is the stock data stack: the Soong modules do not
exist, the policy is not added and the product does not change.

- `Android.bp` has the init rc module and the Soong default that switches the Rust modules off. The modules are next to
  their crates (`crates/*/Android.bp`). They take `diamaneos_datad_defaults`, which is `enabled: false` unless the Soong
  config `diamaneos_datad.datad_enabled` is set (`datad-soong.mk`). Soong writes an install rule for every module that exists
  and `libnicm` and `libnicm_dsi` install to the paths of the stock files, so with the stock vendor tree the two would meet
  in Kati ("overriding commands for target").
- `datad-board.mk`: included by the device `BoardConfig.mk` only with the switch on. Policy directory, the m4 define
  `datad_enabled` (the device `qrtr.te` names `diamaneos_datad` under `ifdef`), the vendor UID file and the Soong config.
- `datad-product.mk`: included by the device `telephony.mk` only with the switch on. It stops the build when a closed peer
  is not the pinned file (`datad-pins.mk`), or when the vendor tree still has a stock nicm file, and adds the packages.
  `test-datad-product.sh` runs it on made-up trees.
- `datad-pins.mk`: SHA-256 of `libdsi_netctrl.so`, `libqdi.so` and `libqcrilDataModule.so` of the stock release the layouts
  were read from (FP6.QREL.16.111.0). A stock update changes at least one of them and the build stops until the layouts
  in `crates/nicm-abi` and `crates/libnicm-dsi/src/layout.rs` are checked against the new files and the pins are changed on purpose.
- `datad.rc`: init service of the data daemon (replaces `nicmd.rc`), with no supplementary group. It keeps the three performance
  module triggers of `nicmd.rc` word for word and says who sets their properties.
- `sepolicy/vendor/`: `datad.te` (domain, netlink rules for kernels 6.13 and later, interface ioctls on the netlink
  socket, peer rules, narrow IPv6 sysctl label, neverallows), `file_contexts`, `genfs_contexts`. Every permission set is exact, with
  the call it is for. It is compiled on a build host the way the build does (m4, checkpolicy, then the
  versioned vendor policy and secilc with the neverallows). Each of the seven violations in `sepolicy/plants` must be refused by
  a neverallow of `datad.te`, and the accesses in `sepolicy/access.txt` (the radio daemon makes its socket and connects to
  ours, the daemon does what its code does) must be allowed by the compiled policy while a shell connecting is not. The
  recovery policy takes the vendor policy as well, so `m sepolicy.recovery` builds with it.
- `config.fs`: the vendor UID, 2998. 2995 is `AID_VENDOR_POWERSTATS`. The value must be in the OEM range (2900 to 2999),
  not shared with another section of any `config.fs` of the product, and outside the stock range 2901 to 2917.
- `vendor-selection.md`: the stock files that leave the vendor image, and how the project tools take them out.

Rust modules: `libdataos_wire`, `libdataos_nicm_compat` and `libdataos_nicm_abi` and the two shared libraries `libnicm` and
`libnicm_dsi` run inside `qcrilNrd` and have a `clippy.toml` next to their `Android.bp`. `libdataos_qmi`, `libdataos_netcfg`,
`libdataos_datacore`, `libdataos_datad`, `libdataos_datad_rt` and the binary `datad` run in the daemon. Every module has
`clippy_lints: "android"`, `lints: "vendor"` and `cargo_env_compat: true`, and tests in `crates/nicm-compat/tests/no_panic.rs`
fail if one is missing, if the Soong dependencies differ from the Cargo ones, or if a module lacks the switch default. The
Rust code treats the Android target as Linux (`target_os = "android"` in the cfg lists).

Two things the first build on the builder showed. The five crates of `qcrilNrd` list `clippy.toml` among their `srcs` and
name `crate_root`, because the clippy action reads the file and Soong stops a build for a file it read that was not an input.
And `libnicm`, `libnicm_dsi` and `datad` take `prefer_rlib: true`: the default links the Rust libraries and std as dylibs,
and `libnicm.so` would then need `libstd.dylib.so` and `libdataos_wire.dylib.so` inside `qcrilNrd`. Built that way the two
libraries need `libc.so` and, for the second, `libnicm.so`, and have the sonames and the exports of the stock ones.

Soong builds the platform `liblibc` (0.2.183 in this tree), Cargo.lock pins 0.2.174. The host tests use the pinned one.
Its aarch64 Android constants lack `SYS_newfstatat` and `SYS_fstat`, so the filter checks those two numbers against libc
on Linux only.

Seccomp of `qcrilNrd` (log mode today, to be listed before it enforces). The two libraries add
these arm64 syscalls: `socket` (AF_UNIX, SOCK_SEQPACKET), `connect`, `sendto` (a send on a connected socket
may use `sendto` or `sendmsg`), `recvfrom` (or `recvmsg`), `ppoll`, `shutdown` (the library stops the daemon from writing before it gives a connection up), `close`, `fcntl` (flags and `dup`), `pipe2`
(the wake pipe), `read` and `write` on it, and for the two threads `clone3` or `clone`, `futex`, `mmap`,
`munmap`, `mprotect`, `madvise`, `prctl` (thread names), `rt_sigprocmask`, `set_robust_list`, `rseq`.
Bionic's `send` and `recv` are wrappers over those names, and `poll` is `ppoll` on arm64. Check with the
log-mode seccomp reports of one data call before relying on the list.
The data daemon has its own filter (pattern of the IMS daemon, `crates/datad-rt/src/seccomp.rs`, built as data and
tested on made-up calls). `socket` only for QRTR (the netlink socket and the listener exist before the filter goes on),
`ioctl` only for `SIOCGIFINDEX`, the extended requests of the rmnet device (`SIOCDEVPRIVATE + 13` and `+ 14`) and `SIOCETHTOOL` (the offload features), `fcntl` for the four
flag commands, `accept4`, `bind`, `getsockname`, `getsockopt`, `setsockopt`, `sendto`, `sendmsg`, `recvfrom`, `recvmsg`,
`ppoll`, `openat`, `read`, `write`, `writev`, `close`, `renameat` and `renameat2`, `unlinkat`, `fsync`, `fdatasync`, `statx`,
`newfstatat`, `fstat`, `readlinkat`, `faccessat`, `lseek`, `pread64`, the memory calls (`mmap`, `mprotect`, `munmap`,
`mremap`, `madvise`, `brk`), the clock and sleep calls, the signal calls, `futex` and the thread bookkeeping of the
standard library, `getrandom`, `prctl`, `prlimit64`, the calls that end the process (`exit`, `exit_group`, `tgkill`, and `rt_tgsigqueueinfo`, which bionic's `abort()` uses) and `restart_syscall`. No `clone`, no `execve`.
That list is from the code and the standard library, not from a run. The filter is on in log mode (it allows and the kernel
logs what it would refuse, the refusals of an argument of `socket`, `ioctl` and `fcntl` included) until a run on the phone (bring-up, a call, a modem restart, a marker write) shows nothing
missing. Then `main.rs` sets `Action::Errno`.

## Looking at a run

The daemon and the two libraries say what they do at the information level, and none of the lines has an
identifier of a phone, a SIM, a network or a peer.

- `logcat -s datad nicm nicm_dsi` has the lines: the start of the daemon, the modem's data services coming and going,
  every step of the bring-up with the modem's answer (QMI error code), the data module connecting, the answers to its
  readiness question and every request that is refused. A question that repeats every hundred milliseconds is written
  for the first eight times and then for each power of two, with its count.
- `/dev/datad/status` (as root, `cat`) has the last 48 lines of the daemon with the time of the kernel log in front, for
  the first minutes of a run when the log buffer has rolled over. The directory is tmpfs, so a reboot clears it.
- The data module fails every data call with its cause `OEM_DCFAILCAUSE_4` (0x1004) until its init has finished, and
  its init waits for the readiness question to be answered with a yes. A daemon that is not ready says so in both places
  above, and the bring-up line before it names the step that did not finish.

## Proving the wall in a platform build

The wall is the forbid lints in each `lib.rs` and the `disallowed-methods` list in each `clippy.toml`. On a host,
`cargo clippy --all-targets -- -D warnings` runs both, and a violation planted in a copy of the tree must be caught by
clippy or by the source scan in `crates/nicm-compat/tests/no_panic.rs`. Soong is a different build, so prove it there before the first import and
again after any change of Soong, the prebuilt clippy or the Android.bp files, by steps 2
to 5 below for `nicm-compat`, `wire`, `libnicm` (in `state.rs`) and `libnicm_dsi` in an overlay of the build tree (done so: the unwrap fails with `unwrap_used`, the
pow with `disallowed_methods`, in all four, and the clean tree builds. A path in the list that does not resolve is
not an error in Soong, a host run with `-D warnings` catches it):

1. Import the crates at a commit that passed `cargo clippy --all-targets -- -D warnings` and `cargo test`, and note that commit.
2. Plant `.unwrap()` on an `Option` in `crates/nicm-compat/src/client.rs`. The build of `libdataos_nicm_compat`
   must fail with a clippy error. If it builds, clippy does not run for the module (`clippy_lints`).
3. Remove the plant and plant `2u32.pow(n)` instead. Only `clippy.toml` knows this call. The build must fail
   with a `disallowed_methods` error. If it builds, clippy runs but does not find `clippy.toml`
   (`cargo_env_compat`, or the build does not run from the crate directory). A path in the list that the
   prebuilt clippy cannot resolve is a warning, which fails the build only if the module turns warnings
   into errors. Check that too, with a made-up path in the list.
4. Do the same in `crates/wire`, and plant an `unsafe` block without a reason in `crates/libnicm/src/sys.rs`
   (the build does not stop that one, the source scan does).
5. Remove every plant and build the library once more.

What Soong cannot prove: the source scan of `no_panic.rs` (inner `cfg_attr`, raw maps and queues) is a test
and does not run in the platform build. So the code in the tree must be a commit that passed the tests,
and nothing else may be imported into the five crates.
