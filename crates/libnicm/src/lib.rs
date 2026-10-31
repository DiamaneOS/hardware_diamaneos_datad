// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Replacement for the IPC library `libnicm.so`: the connection of the data
//! module to the interface manager, now a Unix socket to the data daemon. It
//! exports the three functions `libdsi_netctrl.so` and `libnicm_dsi.so` use
//! (`nicm_client_register`, `nicm_client_release`, `nicm_send_client_cmd`) and
//! stubs for the three `vh_event_*` functions nobody imports.
//!
//! This code runs inside `qcrilNrd`: a panic ends the process that carries voice
//! and emergency calls. The same lints as in the shim crates apply, `unsafe` is
//! confined to `sys.rs` (libc) and `abi.rs` (the C exports), and every unsafe
//! block says why it is sound. `tests/no_panic.rs` of `dataos-nicm-compat` checks it.
#![deny(unsafe_code)]
#![cfg_attr(
    not(test),
    forbid(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::unwrap_in_result,
        clippy::get_unwrap,
        clippy::panic_in_result_fn,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::dbg_macro,
        clippy::exit
    ),
    deny(clippy::arithmetic_side_effects)
)]
pub mod abi;
pub mod command;
pub mod conn;
pub mod log;
pub mod restart;
pub mod state;
pub mod sys;

/// The control socket of the data daemon (created by init).
pub const SOCKET_PATH: &str = "/dev/socket/datad";
