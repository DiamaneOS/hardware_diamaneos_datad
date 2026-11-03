// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Bounded QMI service framing over QRTR and the data-path messages
//! (WDS with its reverse transport, DFS, WDA, DPM). No sockets and no Android dependencies.
//!
//! Wire facts come from public sources only: the Linux QRTR UAPI, the field
//! layouts that libqmi publishes as data, and the DCM codec in
//! hardware/diamaneos/ims. No vendor code is included.
#![forbid(unsafe_code)]
// A panic in this crate would take the data daemon down. Parsers get bytes from the modem.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing
    )
)]
pub mod dfs;
pub mod dpm;
pub mod frame;
pub mod reverse;
pub mod secret;
pub mod wda;
pub mod wds;

pub use frame::{Builder, Error, Frame, Kind, QmiStatus};
