// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The value types of the protocol. They are the protocol's own: a change in
//! the data daemon's engine does not change them, the conversion in
//! `dataos-datad` breaks at compile time instead.
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

/// Why a call ended without a network reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalReason {
    UserRequested,
    ModemRestart,
    NoQmiClient,
    Timeout,
    BindFailed,
    LinkFailed,
    BadSettings,
    Malformed,
    /// The connection to the data daemon was lost. Only the client library makes this one.
    DaemonLost,
}

impl LocalReason {
    pub(crate) fn code(self) -> u8 {
        match self {
            LocalReason::UserRequested => 0,
            LocalReason::ModemRestart => 1,
            LocalReason::NoQmiClient => 2,
            LocalReason::Timeout => 3,
            LocalReason::BindFailed => 4,
            LocalReason::LinkFailed => 5,
            LocalReason::BadSettings => 6,
            LocalReason::Malformed => 7,
            LocalReason::DaemonLost => 8,
        }
    }

    pub(crate) fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            0 => LocalReason::UserRequested,
            1 => LocalReason::ModemRestart,
            2 => LocalReason::NoQmiClient,
            3 => LocalReason::Timeout,
            4 => LocalReason::BindFailed,
            5 => LocalReason::LinkFailed,
            6 => LocalReason::BadSettings,
            7 => LocalReason::Malformed,
            8 => LocalReason::DaemonLost,
            _ => return None,
        })
    }
}

/// Why a family or a call ended. Network reasons keep the modem's numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndReason {
    /// Verbose call end reason (type, reason) from the modem.
    Network {
        kind: u16,
        reason: i16,
    },
    /// Basic call end reason only.
    NetworkBasic(u16),
    /// The modem refused the request without a call end reason.
    Qmi(u16),
    Local(LocalReason),
}

/// What is known about one connected family.
/// What the closed data module asks when it looks for a link for a call. Only
/// what the daemon uses is carried: the subscription, the family, the APN and
/// its type, which decide the link and whether the call may use the emergency reserve.
#[derive(Clone, PartialEq, Eq)]
pub struct RouteRequest {
    pub slot: u8,
    pub family: Family,
    pub apn: Option<String>,
    pub apn_type: u32,
    pub apn_type_mask: u64,
}

/// The other values of the module's request that the matching call question passes on to the modem.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MatchHint {
    pub profile_3gpp: Option<u8>,
    pub profile_3gpp2: Option<u8>,
    pub xt_pref: Option<u16>,
    pub backup_name: Option<u8>,
    pub backup_type: Option<u8>,
}

// No derived Debug: the APN stays out of logs.
impl std::fmt::Debug for RouteRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteRequest")
            .field("slot", &self.slot)
            .field("family", &self.family)
            .field("apn_type", &self.apn_type)
            .field("apn_type_mask", &self.apn_type_mask)
            .finish_non_exhaustive()
    }
}

/// An interface event for the data module, in the vocabulary of the nicm
/// events it knows (EVENT_IFACE_UP, DOWN, RECONFIGURED, NEWADDR, DELADDR,
/// MTU_UPDATE and Event_OP_FAILED).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IfaceEvent {
    /// The first family of the link is configured.
    Up,
    /// No family of the link is up any more.
    Down(EndReason),
    Reconfigured,
    NewAddr {
        family: Family,
        addr: IpAddr,
        prefix: u8,
    },
    DelAddr {
        family: Family,
        addr: IpAddr,
        prefix: u8,
    },
    MtuUpdate {
        family: Family,
        mtu: u32,
    },
    /// The family could not be followed at all.
    OpFailed(EndReason),
}

// No derived Debug: addresses stay out of logs.
impl std::fmt::Debug for IfaceEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IfaceEvent::Up => f.write_str("Up"),
            IfaceEvent::Down(r) => write!(f, "Down({r:?})"),
            IfaceEvent::Reconfigured => f.write_str("Reconfigured"),
            IfaceEvent::NewAddr { family, .. } => write!(f, "NewAddr({family:?})"),
            IfaceEvent::DelAddr { family, .. } => write!(f, "DelAddr({family:?})"),
            IfaceEvent::MtuUpdate { family, mtu } => write!(f, "MtuUpdate({family:?}, {mtu})"),
            IfaceEvent::OpFailed(r) => write!(f, "OpFailed({r:?})"),
        }
    }
}
