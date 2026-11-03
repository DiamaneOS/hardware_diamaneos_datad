// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Every bound of the protocol in one place. The QMI parser in `dataos-qmi`
//! keeps at most as much as fits here, and a test in `dataos-datad` checks it.
//! The arithmetic below only runs at compile time, where an overflow is an error.
#![allow(clippy::arithmetic_side_effects)]

/// Protocol version byte. Changes whenever a message layout changes.
pub const VERSION: u8 = 5;
pub const HEADER_LEN: usize = 8;
/// Largest datagram either side sends or accepts. Every message is far smaller.
pub const MAX_MESSAGE: usize = 256;
pub const MAX_PAYLOAD: usize = 248;
/// An APN, as the modem takes it (the stock Start Network TLV 0x14).
pub const MAX_APN: usize = 150;
pub const MAX_IFNAME: usize = 15;

const MATCH_HINT: usize = 5 + 1 + 1 + 2 + 1 + 1;
const ROUTE_REQUEST: usize = 1 + 1 + (1 + 1 + MAX_APN) + 4 + 8 + MATCH_HINT;
const ADDR_EVENT: usize = 1 + 1 + 1 + (1 + 16) + 1;
const ROUTE_REPLY: usize = 1 + 1 + (1 + MAX_IFNAME);

pub const MAX_LARGEST_PAYLOAD: usize = {
    let a = if ROUTE_REQUEST > ADDR_EVENT {
        ROUTE_REQUEST
    } else {
        ADDR_EVENT
    };
    if a > ROUTE_REPLY {
        a
    } else {
        ROUTE_REPLY
    }
};

const _: () = assert!(MAX_LARGEST_PAYLOAD <= MAX_PAYLOAD);
const _: () = assert!(MAX_PAYLOAD + HEADER_LEN == MAX_MESSAGE);
const _: () = assert!(MAX_APN <= 255 && MAX_IFNAME <= 255);
