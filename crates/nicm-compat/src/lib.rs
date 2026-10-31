// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The client side of the replacement for `libnicm.so` and `libnicm_dsi.so`:
//! what the closed data module asks of the interface manager, expressed over the
//! data daemon protocol, without any C ABI. `Client` is single threaded and never
//! blocks: the C veneer decides how to wait for a reply and which thread
//! delivers notices to the data module.
//!
//! This code runs inside `qcrilNrd`, where Soong builds Rust with
//! `panic=abort`: a panic would end the process that carries voice and
//! emergency calls. So nothing here may panic. The lints below forbid the
//! usual causes, the crate depends only on `dataos-wire`, and the tests in
//! `tests/no_panic.rs` check both.
#![forbid(unsafe_code)]
// Forbidden, not just denied: an `allow` or `expect` further down cannot switch these off.
// The arithmetic lint stays at deny because the compile-time limits need an allow.
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
pub mod client;
mod coll;

pub use client::{Client, NicmError, Notice, Reply, Transport};
