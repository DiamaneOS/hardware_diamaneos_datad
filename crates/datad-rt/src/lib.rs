// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The sockets, the syscall filter and the process setup of the data daemon. The logic is in
//! `dataos-datad`, which has no unsafe code and no libc. Here the libc calls are, each unsafe
//! block with its reason, in the modules that are named `sys`-like: `sock`, `qrtr`, `unix`,
//! `poll`, `signals` and `seccomp`. The parts that only exist on Linux are not built elsewhere,
//! and they are compiled and linted for aarch64 Linux.
#![deny(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]
pub mod clock;
pub mod fault;
pub mod ids;
pub mod kernel;
pub mod log;
pub mod poll;
pub mod qrtr;
pub mod seccomp;
pub mod signals;
pub mod sock;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod unix;
