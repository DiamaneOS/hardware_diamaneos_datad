// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The structs `libnicm_dsi.so` hands to `libnicm.so`, and the event `libnicm.so`
//! hands to the callback of the data module. Both libraries are ours, so this
//! layout is ours. The closed data module only copies an event (960 bytes, by
//! `setNicmInfo` of our `libnicm_dsi.so`, inside its callback) and passes the copy
//! back to `dsiTranslateNicmEvent`.
//!
//! Every struct starts with a magic number and its own size, which the receiving
//! library checks before it reads anything else (a stock library of the same name
//! next to ours is refused). The command and the reply are padded to at least the
//! size of the stock `ClientCmdInfo` (296 bytes) and `NicmEventInfo` (960 bytes),
//! so a stock library that writes through our pointer stays inside the buffer.
//!
//! Plain integers and byte arrays only, every bit pattern is a valid value.
#![forbid(unsafe_code)]
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
use std::sync::atomic::{AtomicBool, Ordering};

/// The stock layouts (the prototypes of the ten `libnicm_dsi.so` exports, the
/// structs behind them, the order of the callback arguments) are checked against
/// the closed libraries, every field the libraries read or write in two places.
/// While it is false the libraries do not read or write anything the data
/// module owns. The limits that remain are the CDMA2000 technologies, and what only a
/// modem and the stock logs can show.
pub const STOCK_ABI_VERIFIED: bool = true;

// A device build (the Soong modules set the cfg) cannot ship the two libraries while the flag is
// off: they would refuse every request, DSI would never finish its init, and the phone would have
// no mobile data and no emergency PDN. A plain `cargo` build is not a device build.
const _: () = assert!(
    STOCK_ABI_VERIFIED || !cfg!(device_build),
    "device build with STOCK_ABI_VERIFIED false: the libraries would refuse everything"
);

static PROVISIONAL: AtomicBool = AtomicBool::new(false);

/// Tests switch the unverified layouts on. Nothing in the libraries calls this.
pub fn allow_provisional_abi_for_tests(on: bool) {
    PROVISIONAL.store(on, Ordering::SeqCst);
}

/// May the libraries use the layouts they guess?
pub fn abi_enabled() -> bool {
    STOCK_ABI_VERIFIED || PROVISIONAL.load(Ordering::SeqCst)
}

/// The `apn_type` of a route lookup request when the module sets none (`MASK_APN_TYPE` clear).
pub const APN_TYPE_NOT_SET: u32 = 0x8000_0001;

/// The link MTU of a call from the MTUs of its two families (0: not known), as nicmd computes it in
/// `InterfaceInfo::setMtu` (0x7bf88 to 0x7bfc8): the smaller of the two but at least 1280, the one
/// that is known but at least 1280, and 1500 when neither is known. Then comes the cap
/// (`InterfaceInfo` +0x14c, `setMtu` 0x7bfcc to 0x7c008): a larger result is replaced by it. The cap is
/// 9216 (0x2400) unless the configuration of nicmd sets another one **[I]**, and it is that here.
pub fn link_mtu(v4: u32, v6: u32) -> u32 {
    const FLOOR: u32 = 1280;
    let chosen = match (v4, v6) {
        (0, 0) => 1500,
        (a, 0) | (0, a) => a.max(FLOOR),
        (a, b) => a.min(b).max(FLOOR),
    };
    chosen.min(MAX_LINK_MTU)
}

/// The most a link MTU can be, the default of `InterfaceInfo` (constructor 0x78678 to 0x7868c).
pub const MAX_LINK_MTU: u32 = 0x2400;

/// The longest APN, as the stock Start Network request and the stock route lookup take it.
pub const MAX_APN: usize = 150;
pub const IFNAME_LEN: usize = 16;

/// First field of every struct between the two libraries.
pub const MAGIC: u32 = 0x444e_4d49;
/// The command is at least as large as the stock `ClientCmdInfo`.
pub const CMD_LEN: usize = 512;
/// The reply is at least as large as the stock `NicmEventInfo`.
pub const REPLY_LEN: usize = 1024;

/// Is this the header of a struct of ours, of this size?
pub fn header_ok(magic: u32, size: u32, expected: usize) -> bool {
    magic == MAGIC && usize::try_from(size).ok() == Some(expected)
}

pub mod kind {
    pub const ROUTE_LOOKUP: u32 = 1;
    pub const LINK_RELEASE: u32 = 2;
    pub const QUERY_MTU: u32 = 3;
    pub const QUERY_NETWORK_HANDLE: u32 = 4;
    pub const PORT_FORWARD: u32 = 5;
    pub const SCREEN_STATE: u32 = 6;
    pub const OEM_PROXY: u32 = 7;
    /// The readiness query of the data module.
    pub const READY: u32 = 8;
    /// The question whether a call is up that the module can use again.
    pub const MATCHING_CALL: u32 = 9;
}

/// Replies carry the daemon's result codes (0 to 7, the order of `ResultCode`) and these.
pub mod status {
    pub const OK: u32 = 0;
    pub const TRANSPORT: u32 = 100;
    pub const TIMEOUT: u32 = 101;
    pub const BAD_ARGUMENT: u32 = 102;
    pub const NOT_REGISTERED: u32 = 103;
    /// Too many requests wait for their reply.
    pub const BUSY: u32 = 104;
}

pub mod event {
    pub const UP: u32 = 1;
    pub const DOWN: u32 = 2;
    pub const RECONFIGURED: u32 = 3;
    pub const NEW_ADDR: u32 = 4;
    pub const DEL_ADDR: u32 = 5;
    pub const MTU_UPDATE: u32 = 6;
    pub const OP_FAILED: u32 = 7;
    pub const RESTART_START: u32 = 8;
    pub const RESTART_DONE: u32 = 9;
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NicmCmd {
    pub magic: u32,
    pub size: u32,
    pub kind: u32,
    pub slot: u32,
    /// 4 or 6.
    pub family: u32,
    pub link: u32,
    /// Enable, screen on.
    pub flag: u32,
    pub apn_type: u32,
    pub apn_type_mask: u64,
    /// 0: no APN.
    pub apn_len: u32,
    pub apn: [u8; MAX_APN + 4],
    /// Which of the values below are present (`hint::*`), for the matching call question.
    pub hint_mask: u32,
    pub profile_3gpp: u32,
    pub profile_3gpp2: u32,
    pub xt_pref: u32,
    pub backup_name: u32,
    pub backup_type: u32,
    pub pad: [u8; CMD_PAD],
}

/// The bits of `NicmCmd::hint_mask`.
pub mod hint {
    pub const PROFILE_3GPP: u32 = 0x1;
    pub const PROFILE_3GPP2: u32 = 0x2;
    pub const XT_PREF: u32 = 0x4;
    pub const BACKUP_NAME: u32 = 0x8;
    pub const BACKUP_TYPE: u32 = 0x10;
}

const CMD_USED: usize = 224;
const CMD_PAD: usize = CMD_LEN - CMD_USED;

impl NicmCmd {
    pub fn new(kind: u32) -> Self {
        NicmCmd {
            magic: MAGIC,
            size: CMD_LEN as u32,
            kind,
            slot: 0,
            family: 4,
            link: 0,
            flag: 0,
            apn_type: 0,
            apn_type_mask: 0,
            apn_len: 0,
            apn: [0; MAX_APN + 4],
            hint_mask: 0,
            profile_3gpp: 0,
            profile_3gpp2: 0,
            xt_pref: 0,
            backup_name: 0,
            backup_type: 0,
            pad: [0; CMD_PAD],
        }
    }

    /// Is the header the one of a command of ours?
    pub fn header_ok(&self) -> bool {
        header_ok(self.magic, self.size, CMD_LEN)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NicmReply {
    pub magic: u32,
    pub size: u32,
    pub status: u32,
    pub link: u32,
    pub v4_mtu: u32,
    pub v6_mtu: u32,
    pub name_len: u32,
    pub ifname: [u8; IFNAME_LEN],
    /// A route reply: the modem has the call already, and it is the other family's.
    pub existing: u32,
    pub companion: u32,
    /// A route reply: the technology for a Wi-Fi call that the modem named, 0 for none.
    pub tech: u32,
    pub pad: [u8; REPLY_PAD],
}

const REPLY_USED: usize = 56;
const REPLY_PAD: usize = REPLY_LEN - REPLY_USED;

impl NicmReply {
    /// Is the header the one of a reply of ours?
    pub fn header_ok(&self) -> bool {
        header_ok(self.magic, self.size, REPLY_LEN)
    }

    pub fn failed(status: u32) -> Self {
        NicmReply {
            magic: MAGIC,
            size: REPLY_LEN as u32,
            status,
            link: 0,
            v4_mtu: 0,
            v6_mtu: 0,
            name_len: 0,
            ifname: [0; IFNAME_LEN],
            existing: 0,
            companion: 0,
            tech: 0,
            pad: [0; REPLY_PAD],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NicmEvent {
    pub magic: u32,
    pub size: u32,
    pub kind: u32,
    pub link: u32,
    pub slot: u32,
    /// 4 or 6, 0 when the event has no family.
    pub family: u32,
    /// Prefix length of an address, the MTU of an MTU update.
    pub value: u32,
    /// The `EndReason` kind of a down or failed event: 0 network, 1 basic, 2 qmi, 3 local.
    pub reason_kind: u32,
    pub reason_a: u32,
    pub reason_b: i32,
    pub addr: [u8; 16],
}

impl NicmEvent {
    pub fn new(kind: u32) -> Self {
        NicmEvent {
            magic: MAGIC,
            size: EVENT_LEN as u32,
            kind,
            link: 0,
            slot: 0,
            family: 0,
            value: 0,
            reason_kind: 0,
            reason_a: 0,
            reason_b: 0,
            addr: [0; 16],
        }
    }

    /// Is the header the one of an event of ours?
    pub fn header_ok(&self) -> bool {
        header_ok(self.magic, self.size, EVENT_LEN)
    }
}

/// The size of `NicmEvent`.
pub const EVENT_LEN: usize = 56;

/// Where the fields of `NicmEvent` are, for the code that reads an event from the
/// bytes of the copy the data module keeps (checked against the struct below).
pub mod at {
    pub const KIND: usize = 8;
    pub const LINK: usize = 12;
    pub const SLOT: usize = 16;
    pub const FAMILY: usize = 20;
    pub const VALUE: usize = 24;
    pub const ADDR: usize = 40;
}

/// What the data module is given. The data module copies 960 bytes of it (the
/// stock size of an event info), so the event is followed by zeroes up to far
/// more than that.
pub const EVENT_BUF: usize = 4096;
const EVENT_PAD: usize = EVENT_BUF - EVENT_LEN;

#[repr(C)]
pub struct EventBuf {
    pub ev: NicmEvent,
    pub pad: [u8; EVENT_PAD],
}

impl EventBuf {
    pub fn new(ev: NicmEvent) -> Self {
        EventBuf {
            ev,
            pad: [0; EVENT_PAD],
        }
    }
}

const _: () = assert!(core::mem::size_of::<NicmEvent>() == EVENT_LEN);
const _: () = assert!(core::mem::offset_of!(NicmEvent, kind) == at::KIND);
const _: () = assert!(core::mem::offset_of!(NicmEvent, link) == at::LINK);
const _: () = assert!(core::mem::offset_of!(NicmEvent, slot) == at::SLOT);
const _: () = assert!(core::mem::offset_of!(NicmEvent, family) == at::FAMILY);
const _: () = assert!(core::mem::offset_of!(NicmEvent, value) == at::VALUE);
const _: () = assert!(core::mem::offset_of!(NicmEvent, addr) == at::ADDR);
const _: () = assert!(core::mem::size_of::<EventBuf>() == EVENT_BUF);
const _: () = assert!(core::mem::size_of::<NicmCmd>() == CMD_LEN);
const _: () = assert!(core::mem::size_of::<NicmReply>() == REPLY_LEN);
const _: () = assert!(CMD_LEN >= 0x128 && REPLY_LEN >= 0x3c0 && EVENT_BUF >= 0x3c0);

#[cfg(test)]
mod tests {
    use super::{link_mtu, MAX_LINK_MTU};

    #[test]
    fn the_link_mtu_is_what_nicmd_makes_of_the_two_families() {
        assert_eq!(link_mtu(0, 0), 1500, "nothing known");
        assert_eq!(link_mtu(1400, 0), 1400);
        assert_eq!(link_mtu(0, 1380), 1380);
        assert_eq!(link_mtu(1400, 1380), 1380, "the smaller");
        assert_eq!(link_mtu(1400, 1500), 1400);
        assert_eq!(link_mtu(1000, 0), 1280, "at least what IPv6 needs");
        assert_eq!(link_mtu(1000, 1100), 1280);
        assert_eq!(link_mtu(576, 1500), 1280);
        // the cap, whichever family is large
        assert_eq!(link_mtu(MAX_LINK_MTU, MAX_LINK_MTU), MAX_LINK_MTU);
        assert_eq!(link_mtu(MAX_LINK_MTU + 1, MAX_LINK_MTU + 5), MAX_LINK_MTU);
        assert_eq!(link_mtu(50_000, 0), MAX_LINK_MTU);
        assert_eq!(link_mtu(0, 50_000), MAX_LINK_MTU);
        assert_eq!(MAX_LINK_MTU, 9216);
    }
}
