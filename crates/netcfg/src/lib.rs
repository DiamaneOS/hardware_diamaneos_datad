// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Network interface configuration for modem data calls: rtnetlink message
//! builders, the `NetOps` seam that the rest of the code uses, a recording
//! fake for tests and the Linux netlink backend.
// Only the Linux backend needs unsafe code. A panic here would take the daemon down.
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
pub mod ethtool;
pub mod genl;
pub mod ipa;
pub mod ops;
pub mod rtnl;
pub mod rtnl_tunnel;
pub mod xfrm;

#[cfg(any(test, feature = "fake"))]
pub mod fake;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod linux;

#[cfg(any(test, feature = "fake"))]
pub use fake::{FakeNet, SharedNet};
pub use ipa::IpaFormat;
pub use ops::{
    AddrFlags, EgressPipe, Endpoint, IngressPipe, Ipv6Settings, NetError, NetOps, PipeState,
    PipeStatus, RmnetFlags, SetupMarker, STOCK_FEATURES,
};
