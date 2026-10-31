// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The privileged data daemon (replacement for nicmd): the server that maps
//! connections and handles of the private protocol (`dataos-wire`) onto the
//! data call engine. Sockets and process setup (UID, capabilities, seccomp,
//! SELinux) live in the Android integration, not here.
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
pub mod convert;
pub mod daemon;
#[cfg(any(test, feature = "fake"))]
pub mod fake;
pub mod ipc;
pub mod outbox;
pub mod qrtr;
pub mod server;
pub mod table;
pub mod transport;
