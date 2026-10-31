// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Replacement for `libnicm_dsi.so`, the translation layer between the closed
//! DSI library and the interface manager: the ten functions DSI calls
//! (`dsiInitQueryNicmWrapper`, `dsiNicmRouteLookup`, `dsiNicmLinkRelease`,
//! `dsiNicmGetLinkMtu`, `dsiNicmProcessPFRequest`, `dsiNicmProcessScreenState`,
//! `dsiNicmOEMProxy`, `dsiNicmQueryLLNetworkHndl`, `dsiTranslateNicmEvent`,
//! `setNicmInfo`) and the eleventh it uses itself (`dsiTranslateRouteLookupRequest`).
//!
//! The prototypes and the layouts of the structs behind them come from call-site
//! analysis of the closed libraries. `layout` has the
//! layouts as safe code over byte slices, `abi` has the exports and `StockAbi`,
//! the only code that turns the addresses the module passes into slices, and
//! `glue` has the commands for `libnicm.so` with every value checked. Until
//! every field is verified (`STOCK_ABI_VERIFIED`) the exports
//! refuse in the form of their prototype and read and write nothing.
//!
//! This code runs inside `qcrilNrd`: a panic ends the process that carries voice
//! and emergency calls. The same lints as in the shim crates apply, `unsafe` is
//! confined to `abi.rs`, and `tests/no_panic.rs` of `dataos-nicm-compat` checks it.
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
pub mod glue;
pub mod layout;
pub mod log;
