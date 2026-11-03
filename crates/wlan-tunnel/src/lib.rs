// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The logic of the Wi-Fi tunnel daemon. The modem negotiates IKE and hands the tunnel over: this code makes the
//! reverse links, installs the ESP states and policies the modem names, configures `rmnet_wlan`, keeps the
//! ports the modem asks for and answers the modem. It has no sockets, and runs in host tests against a simulated
//! modem and a fake kernel. It lives apart from the data daemon so that a fault in the path of the ESP keys cannot
//! take down cellular data or the emergency path.
#![forbid(unsafe_code)]
// A panic here would take the tunnel daemon down.
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
pub mod daemon;
pub mod engine;
#[cfg(any(test, feature = "fake"))]
pub mod fake;
pub mod kernel;
pub mod ports;
pub mod sa;
pub mod state;

pub use engine::{Config, Engine};
pub use kernel::{Ip, Kernel, KernelError};
