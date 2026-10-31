// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Engine types to wire types. The protocol has its own types, so a change in
//! the engine breaks this file at compile time instead of changing the protocol.
use dataos_datacore as eng;
use dataos_wire as wire;
use std::net::IpAddr;

pub fn family(f: eng::Family) -> wire::Family {
    match f {
        eng::Family::V4 => wire::Family::V4,
        eng::Family::V6 => wire::Family::V6,
    }
}

pub fn engine_family(f: wire::Family) -> eng::Family {
    match f {
        wire::Family::V4 => eng::Family::V4,
        wire::Family::V6 => eng::Family::V6,
    }
}

pub fn lookup_hint(h: wire::MatchHint) -> eng::LookupHint {
    eng::LookupHint {
        profile_3gpp: h.profile_3gpp,
        profile_3gpp2: h.profile_3gpp2,
        xt_pref: h.xt_pref,
        backup_name: h.backup_name,
        backup_type: h.backup_type,
    }
}

pub fn reason(r: eng::EndReason) -> wire::EndReason {
    match r {
        eng::EndReason::Network { kind, reason } => wire::EndReason::Network { kind, reason },
        eng::EndReason::NetworkBasic(v) => wire::EndReason::NetworkBasic(v),
        eng::EndReason::Qmi(v) => wire::EndReason::Qmi(v),
        eng::EndReason::Local(l) => wire::EndReason::Local(match l {
            eng::LocalReason::UserRequested => wire::LocalReason::UserRequested,
            eng::LocalReason::ModemRestart => wire::LocalReason::ModemRestart,
            eng::LocalReason::NoQmiClient => wire::LocalReason::NoQmiClient,
            eng::LocalReason::Timeout => wire::LocalReason::Timeout,
            eng::LocalReason::BindFailed => wire::LocalReason::BindFailed,
            eng::LocalReason::LinkFailed => wire::LocalReason::LinkFailed,
            eng::LocalReason::BadSettings => wire::LocalReason::BadSettings,
            eng::LocalReason::Malformed => wire::LocalReason::Malformed,
        }),
    }
}

/// Address and prefix of one family of a configured call.
pub fn address(info: &eng::CallInfo, fam: eng::Family) -> Option<(IpAddr, u8)> {
    match fam {
        eng::Family::V4 => {
            let s = &info.v4.as_ref()?.settings;
            let prefix = s.ipv4_mask.and_then(eng::prefix_from_mask).unwrap_or(32);
            Some((IpAddr::V4(s.ipv4?), prefix))
        }
        eng::Family::V6 => {
            let (a, p) = info.v6.as_ref()?.settings.ipv6?;
            Some((IpAddr::V6(a), p))
        }
    }
}

/// The MTU the data module is told for a family.
pub fn family_mtu(info: &eng::CallInfo, fam: eng::Family) -> Option<u32> {
    match fam {
        eng::Family::V4 => info.v4.as_ref()?.mtu,
        eng::Family::V6 => info.v6.as_ref()?.mtu,
    }
}
