// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Data call logic of the open nicmd replacement: link pool, WDS call
//! sequence per IP family, interface configuration, modem restart handling.
//!
//! The engine is synchronous and never blocks. Its inputs are datagrams from
//! the modem, timer ticks and call requests. Its outputs are QMI requests,
//! `NetOps` calls and `Event`s, so the whole data path runs in host tests
//! against `sim::SimModem`.
#![forbid(unsafe_code)]
// A panic here would take the data daemon down.
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
pub mod engine;
pub mod model;
#[cfg(any(test, feature = "sim"))]
pub mod sim;

pub use engine::{Config, Engine, Look, Note, Qmi, QmiError, ServiceEvent, Stats};
pub use model::*;
