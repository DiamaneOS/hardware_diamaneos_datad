// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The private protocol between the radio daemon's DSI replacement and the
//! data daemon, with its own types. This code is linked into `qcrilNrd`,
//! where Soong builds Rust with `panic=abort`. A panic here would kill the
//! process that carries voice and emergency calls. So the crate has no
//! dependencies, no unsafe code, and the lints below stop `unwrap`, `expect`,
//! `panic!`, indexing, unchecked arithmetic and the like in non-test code.
//! Every decoder returns an error for any input and every encoder refuses a
//! value that does not fit instead of cutting it.
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

mod codec;
pub mod limits;
pub mod msg;
pub mod types;

pub use codec::{DecodeError, EncodeError};
pub use limits::{HEADER_LEN, MAX_MESSAGE, VERSION};
pub use msg::{Notify, Request, ResultCode};
pub use types::{EndReason, Family, IfaceEvent, LocalReason, MatchHint, RouteRequest};
