// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The structs between the two libraries and the requests and notices of the
//! client. Everything read from a struct is checked here.
use dataos_nicm_abi::{event, hint, kind, status, NicmCmd, NicmEvent, NicmReply, MAX_APN};
use dataos_nicm_compat::{Client, NicmError, Notice, Reply, Transport};
use dataos_wire::{
    EndReason, Family, IfaceEvent, LocalReason, MatchHint, ResultCode, RouteRequest,
};

/// A request that is sent and waits for its answer.
pub enum Pending {
    Txn(u32),
    /// The readiness query: done when the next readiness message arrived.
    Ready(u32),
}

fn small(v: u32) -> Option<u8> {
    u8::try_from(v).ok()
}

fn apn_of(cmd: &NicmCmd) -> Result<Option<String>, ()> {
    let len = usize::try_from(cmd.apn_len).map_err(|_| ())?;
    if len == 0 {
        return Ok(None);
    }
    if len > MAX_APN {
        return Err(());
    }
    let bytes = cmd.apn.get(..len).ok_or(())?;
    if bytes.contains(&0) {
        return Err(());
    }
    String::from_utf8(bytes.to_vec()).map(Some).map_err(|_| ())
}

fn match_hint(cmd: &NicmCmd) -> Result<MatchHint, u32> {
    let bad = status::BAD_ARGUMENT;
    let has = |bit: u32| cmd.hint_mask & bit != 0;
    let byte = |bit: u32, v: u32| -> Result<Option<u8>, u32> {
        if has(bit) {
            Ok(Some(small(v).ok_or(bad)?))
        } else {
            Ok(None)
        }
    };
    Ok(MatchHint {
        profile_3gpp: byte(hint::PROFILE_3GPP, cmd.profile_3gpp)?,
        profile_3gpp2: byte(hint::PROFILE_3GPP2, cmd.profile_3gpp2)?,
        // nicmd writes the low two bytes of the field (TLV 0x34), as the others write the low byte
        xt_pref: has(hint::XT_PREF).then_some((cmd.xt_pref & 0xffff) as u16),
        backup_name: byte(hint::BACKUP_NAME, cmd.backup_name & 0xff)?,
        backup_type: byte(hint::BACKUP_TYPE, cmd.backup_type & 0xff)?,
    })
}

fn route_request(cmd: &NicmCmd) -> Result<RouteRequest, u32> {
    let bad = status::BAD_ARGUMENT;
    let family = match cmd.family {
        4 => Family::V4,
        6 => Family::V6,
        _ => return Err(bad),
    };
    Ok(RouteRequest {
        slot: small(cmd.slot).ok_or(bad)?,
        family,
        apn: apn_of(cmd).map_err(|_| bad)?,
        apn_type: cmd.apn_type,
        apn_type_mask: cmd.apn_type_mask,
    })
}

/// Send the request a command stands for. Err: nothing was sent, with the status.
pub fn begin<T: Transport>(c: &mut Client<T>, cmd: &NicmCmd) -> Result<Pending, u32> {
    let bad = status::BAD_ARGUMENT;
    let sent = match cmd.kind {
        kind::ROUTE_LOOKUP => c.route_lookup(route_request(cmd)?),
        kind::MATCHING_CALL => c.matching_call(route_request(cmd)?, match_hint(cmd)?),
        kind::LINK_RELEASE => c.link_release(small(cmd.link).ok_or(bad)?),
        kind::QUERY_MTU => c.query_mtu(small(cmd.link).ok_or(bad)?),
        // The daemon has no network handle (no netd and no Binder in it), no port forwarding and
        // no OEM proxy, and the module takes the failure the same whatever the reason. The answer
        // is given here, so a stuck daemon holds no thread of the radio daemon for it.
        kind::QUERY_NETWORK_HANDLE | kind::PORT_FORWARD | kind::OEM_PROXY => {
            return Err(u32::from(ResultCode::Unsupported.code()));
        }
        kind::SCREEN_STATE => c.screen_state(cmd.flag != 0),
        kind::READY => {
            let seen = c.ready_count();
            return c
                .hello()
                .map(|()| Pending::Ready(seen))
                .map_err(error_status);
        }
        _ => return Err(bad),
    };
    sent.map(Pending::Txn).map_err(error_status)
}

pub fn error_status(e: NicmError) -> u32 {
    match e {
        NicmError::Transport => status::TRANSPORT,
        NicmError::Invalid => status::BAD_ARGUMENT,
        NicmError::TooMany => status::BUSY,
        NicmError::Refused(code) => u32::from(code.code()),
    }
}

pub fn reply_of(r: Result<Reply, NicmError>) -> NicmReply {
    match r {
        Ok(Reply::Route {
            link,
            existing,
            companion,
            ifname,
        }) => {
            let mut out = NicmReply::failed(status::OK);
            out.link = u32::from(link);
            out.existing = u32::from(existing);
            out.companion = u32::from(companion);
            let name = ifname.as_bytes();
            let n = name.len().min(out.ifname.len());
            for (d, s) in out.ifname.iter_mut().zip(name.iter().take(n)) {
                *d = *s;
            }
            out.name_len = u32::try_from(n).unwrap_or(0);
            out
        }
        Ok(Reply::Mtu { v4, v6 }) => NicmReply {
            v4_mtu: v4,
            v6_mtu: v6,
            ..NicmReply::failed(status::OK)
        },
        Ok(Reply::Done) => NicmReply::failed(status::OK),
        Err(e) => NicmReply::failed(error_status(e)),
    }
}

/// The reply of the readiness query: whether the daemon says it is ready.
pub fn ready_reply(ready: Option<bool>) -> NicmReply {
    let code = if ready == Some(true) {
        status::OK
    } else {
        u32::from(ResultCode::NotReady.code())
    };
    NicmReply::failed(code)
}

fn family_code(f: Family) -> u32 {
    match f {
        Family::V4 => 4,
        Family::V6 => 6,
    }
}

fn reason_fields(r: EndReason) -> (u32, u32, i32) {
    match r {
        EndReason::Network { kind, reason } => (0, u32::from(kind), i32::from(reason)),
        EndReason::NetworkBasic(v) => (1, u32::from(v), 0),
        EndReason::Qmi(v) => (2, u32::from(v), 0),
        EndReason::Local(l) => (
            3,
            match l {
                LocalReason::UserRequested => 0,
                LocalReason::ModemRestart => 1,
                LocalReason::NoQmiClient => 2,
                LocalReason::Timeout => 3,
                LocalReason::BindFailed => 4,
                LocalReason::LinkFailed => 5,
                LocalReason::BadSettings => 6,
                LocalReason::Malformed => 7,
                LocalReason::DaemonLost => 8,
            },
            0,
        ),
    }
}

fn addr_bytes(addr: std::net::IpAddr) -> [u8; 16] {
    match addr {
        std::net::IpAddr::V4(a) => {
            let mut out = [0u8; 16];
            for (d, s) in out.iter_mut().zip(a.octets()) {
                *d = s;
            }
            out
        }
        std::net::IpAddr::V6(a) => a.octets(),
    }
}

pub fn event_of(n: Notice) -> NicmEvent {
    let mut e = NicmEvent::new(0);
    match n {
        Notice::RestartStart => e.kind = event::RESTART_START,
        Notice::RestartDone => e.kind = event::RESTART_DONE,
        Notice::Iface { link, slot, event } => {
            e.link = u32::from(link);
            e.slot = u32::from(slot);
            match event {
                IfaceEvent::Up => e.kind = event::UP,
                IfaceEvent::Reconfigured => e.kind = event::RECONFIGURED,
                IfaceEvent::Down(r) | IfaceEvent::OpFailed(r) => {
                    e.kind = if matches!(event, IfaceEvent::Down(_)) {
                        event::DOWN
                    } else {
                        event::OP_FAILED
                    };
                    (e.reason_kind, e.reason_a, e.reason_b) = reason_fields(r);
                }
                IfaceEvent::NewAddr {
                    family,
                    addr,
                    prefix,
                }
                | IfaceEvent::DelAddr {
                    family,
                    addr,
                    prefix,
                } => {
                    e.kind = if matches!(event, IfaceEvent::NewAddr { .. }) {
                        event::NEW_ADDR
                    } else {
                        event::DEL_ADDR
                    };
                    e.family = family_code(family);
                    e.value = u32::from(prefix);
                    e.addr = addr_bytes(addr);
                }
                IfaceEvent::MtuUpdate { family, mtu } => {
                    e.kind = event::MTU_UPDATE;
                    e.family = family_code(family);
                    e.value = mtu;
                }
            }
        }
    }
    e
}
