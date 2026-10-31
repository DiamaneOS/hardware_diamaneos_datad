// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Messages. One per SOCK_SEQPACKET datagram: version byte, type byte, 32-bit
//! little-endian number (the transaction of a request and its reply, or the
//! link of an event), 16-bit payload length, payload. Every length is checked,
//! every string is bounded, unknown types are errors, trailing bytes are errors.
use crate::codec::{split, DecodeError, EncodeError, R, W};
use crate::limits::*;
use crate::types::{EndReason, Family, IfaceEvent, LocalReason, MatchHint, RouteRequest};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// What the closed data module can ask. `Hello` is the registration and the
/// question whether the daemon is ready. The others carry the transaction of
/// the module, which the reply repeats.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Hello,
    RouteLookup {
        txn: u32,
        req: RouteRequest,
    },
    /// Is there a call for this request that the module can use again? Answered with a `RouteReply`
    /// naming its link, or with `NoMatch` when there is none. The hint is what nicmd passes on to the modem.
    MatchingCall {
        txn: u32,
        req: RouteRequest,
        hint: MatchHint,
    },
    LinkRelease {
        txn: u32,
        link: u8,
    },
    QueryMtu {
        txn: u32,
        link: u8,
    },
    ScreenState {
        txn: u32,
        on: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultCode {
    Ok,
    Invalid,
    NoLink,
    NoSuchLink,
    TooMany,
    BadState,
    /// Bring-up has not finished, or the modem restarted.
    NotReady,
    /// The daemon does not do this one.
    Unsupported,
    /// No call the module can use again.
    NoMatch,
}

impl ResultCode {
    /// The number the protocol and the structs between the libraries carry.
    pub fn code(self) -> u8 {
        match self {
            ResultCode::Ok => 0,
            ResultCode::Invalid => 1,
            ResultCode::NoLink => 2,
            ResultCode::NoSuchLink => 3,
            ResultCode::TooMany => 4,
            ResultCode::BadState => 5,
            ResultCode::NotReady => 6,
            ResultCode::Unsupported => 7,
            ResultCode::NoMatch => 8,
        }
    }

    pub fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            0 => ResultCode::Ok,
            1 => ResultCode::Invalid,
            2 => ResultCode::NoLink,
            3 => ResultCode::NoSuchLink,
            4 => ResultCode::TooMany,
            5 => ResultCode::BadState,
            6 => ResultCode::NotReady,
            7 => ResultCode::Unsupported,
            8 => ResultCode::NoMatch,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notify {
    HelloAck {
        ready: bool,
    },
    /// The daemon became ready, or stopped being ready (modem restart).
    Ready {
        ready: bool,
    },
    RouteReply {
        txn: u32,
        code: ResultCode,
        link: u8,
        /// The modem has a call for this request already (nicmd found an instance).
        existing: bool,
        /// That call is the other IP family of the same request.
        companion: bool,
        ifname: String,
    },
    /// The answer to a request that has nothing to return but a result.
    Done {
        txn: u32,
        code: ResultCode,
    },
    MtuReply {
        txn: u32,
        code: ResultCode,
        v4: u32,
        v6: u32,
    },
    Event {
        link: u8,
        slot: u8,
        event: IfaceEvent,
    },
}

mod ty {
    pub const HELLO: u8 = 1;
    pub const ROUTE_LOOKUP: u8 = 2;
    pub const LINK_RELEASE: u8 = 3;
    pub const QUERY_MTU: u8 = 4;
    // 5, 6 and 8 were the network handle, port forwarding and the OEM proxy, which the daemon
    // never did and the libraries now answer themselves. They are no types.
    pub const SCREEN_STATE: u8 = 7;
    pub const MATCHING_CALL: u8 = 9;
    pub const HELLO_ACK: u8 = 0x81;
    pub const ROUTE_REPLY: u8 = 0x82;
    pub const DONE: u8 = 0x83;
    pub const MTU_REPLY: u8 = 0x84;
    pub const READY: u8 = 0x85;
    pub const EVENT: u8 = 0x86;
}

impl Request {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = W::new();
        let (t, txn) = match self {
            Request::Hello => (ty::HELLO, 0),
            Request::RouteLookup { txn, req } => {
                put_route_request(&mut w, req)?;
                (ty::ROUTE_LOOKUP, *txn)
            }
            Request::MatchingCall { txn, req, hint } => {
                put_route_request(&mut w, req)?;
                put_hint(&mut w, hint)?;
                (ty::MATCHING_CALL, *txn)
            }
            Request::LinkRelease { txn, link } => {
                w.u8(*link);
                (ty::LINK_RELEASE, *txn)
            }
            Request::QueryMtu { txn, link } => {
                w.u8(*link);
                (ty::QUERY_MTU, *txn)
            }
            Request::ScreenState { txn, on } => {
                w.u8(u8::from(*on));
                (ty::SCREEN_STATE, *txn)
            }
        };
        w.frame(t, txn)
    }

    pub fn decode(bytes: &[u8]) -> Result<Request, DecodeError> {
        let (t, txn, payload) = split(bytes)?;
        let mut r = R::new(payload);
        let req = match t {
            ty::HELLO => {
                if txn != 0 {
                    return Err(DecodeError::Value);
                }
                Request::Hello
            }
            ty::ROUTE_LOOKUP => Request::RouteLookup {
                txn,
                req: get_route_request(&mut r)?,
            },
            ty::MATCHING_CALL => Request::MatchingCall {
                txn,
                req: get_route_request(&mut r)?,
                hint: get_hint(&mut r)?,
            },
            ty::LINK_RELEASE => Request::LinkRelease { txn, link: r.u8()? },
            ty::QUERY_MTU => Request::QueryMtu { txn, link: r.u8()? },
            ty::SCREEN_STATE => Request::ScreenState {
                txn,
                on: flag(r.u8()?)?,
            },
            _ => return Err(DecodeError::Type),
        };
        r.done()?;
        Ok(req)
    }
}

fn put_route_request(w: &mut W, req: &RouteRequest) -> Result<(), EncodeError> {
    w.u8(req.slot);
    put_family(w, req.family);
    w.opt(&req.apn, |w, a| w.str(a, MAX_APN))?;
    w.u32(req.apn_type);
    w.u64(req.apn_type_mask);
    Ok(())
}

fn put_hint(w: &mut W, h: &MatchHint) -> Result<(), EncodeError> {
    w.opt(&h.profile_3gpp, |w, v| {
        w.u8(*v);
        Ok(())
    })?;
    w.opt(&h.profile_3gpp2, |w, v| {
        w.u8(*v);
        Ok(())
    })?;
    w.opt(&h.xt_pref, |w, v| {
        w.u16(*v);
        Ok(())
    })?;
    w.opt(&h.backup_name, |w, v| {
        w.u8(*v);
        Ok(())
    })?;
    w.opt(&h.backup_type, |w, v| {
        w.u8(*v);
        Ok(())
    })
}

fn get_hint(r: &mut R<'_>) -> Result<MatchHint, DecodeError> {
    Ok(MatchHint {
        profile_3gpp: r.opt(|r| r.u8())?,
        profile_3gpp2: r.opt(|r| r.u8())?,
        xt_pref: r.opt(|r| r.u16())?,
        backup_name: r.opt(|r| r.u8())?,
        backup_type: r.opt(|r| r.u8())?,
    })
}

fn get_route_request(r: &mut R<'_>) -> Result<RouteRequest, DecodeError> {
    Ok(RouteRequest {
        slot: r.u8()?,
        family: get_family(r)?,
        apn: r.opt(|r| r.str(MAX_APN))?,
        apn_type: r.u32()?,
        apn_type_mask: r.u64()?,
    })
}

fn put_family(w: &mut W, f: Family) {
    w.u8(u8::from(matches!(f, Family::V6)));
}

fn get_family(r: &mut R<'_>) -> Result<Family, DecodeError> {
    match r.u8()? {
        0 => Ok(Family::V4),
        1 => Ok(Family::V6),
        _ => Err(DecodeError::Value),
    }
}

fn put_reason(w: &mut W, r: &EndReason) -> Result<(), EncodeError> {
    match *r {
        EndReason::Network { kind, reason } => {
            w.u8(0);
            w.u16(kind);
            w.i16(reason);
        }
        EndReason::NetworkBasic(v) => {
            w.u8(1);
            w.u16(v);
        }
        EndReason::Qmi(v) => {
            w.u8(2);
            w.u16(v);
        }
        EndReason::Local(l) => {
            w.u8(3);
            w.u8(l.code());
        }
    }
    Ok(())
}

fn get_reason(r: &mut R<'_>) -> Result<EndReason, DecodeError> {
    Ok(match r.u8()? {
        0 => EndReason::Network {
            kind: r.u16()?,
            reason: r.i16()?,
        },
        1 => EndReason::NetworkBasic(r.u16()?),
        2 => EndReason::Qmi(r.u16()?),
        3 => EndReason::Local(LocalReason::from_code(r.u8()?).ok_or(DecodeError::Value)?),
        _ => return Err(DecodeError::Value),
    })
}

/// An address of the family of its slot: a tag and the octets.
fn put_ip(w: &mut W, ip: &IpAddr, fam: Family) -> Result<(), EncodeError> {
    match (ip, fam) {
        (IpAddr::V4(a), Family::V4) => {
            w.u8(4);
            w.raw(&a.octets());
        }
        (IpAddr::V6(a), Family::V6) => {
            w.u8(6);
            w.raw(&a.octets());
        }
        _ => return Err(EncodeError::Value),
    }
    Ok(())
}

fn get_ip(r: &mut R<'_>, fam: Family) -> Result<IpAddr, DecodeError> {
    match (r.u8()?, fam) {
        (4, Family::V4) => Ok(IpAddr::V4(Ipv4Addr::from(r.array::<4>()?))),
        (6, Family::V6) => Ok(IpAddr::V6(Ipv6Addr::from(r.array::<16>()?))),
        _ => Err(DecodeError::Value),
    }
}

fn max_prefix(fam: Family) -> u8 {
    match fam {
        Family::V4 => 32,
        Family::V6 => 128,
    }
}

fn bounded(v: u8, max: u8) -> Result<u8, DecodeError> {
    if v > max {
        Err(DecodeError::Value)
    } else {
        Ok(v)
    }
}

/// Family, address of that family and prefix no longer than the family allows.
fn put_addr(w: &mut W, fam: Family, addr: &IpAddr, prefix: u8) -> Result<(), EncodeError> {
    if prefix > max_prefix(fam) {
        return Err(EncodeError::Value);
    }
    put_family(w, fam);
    put_ip(w, addr, fam)?;
    w.u8(prefix);
    Ok(())
}

fn get_addr(r: &mut R<'_>) -> Result<(Family, IpAddr, u8), DecodeError> {
    let fam = get_family(r)?;
    let addr = get_ip(r, fam)?;
    Ok((fam, addr, bounded(r.u8()?, max_prefix(fam))?))
}

fn put_event(w: &mut W, e: &IfaceEvent) -> Result<(), EncodeError> {
    match e {
        IfaceEvent::Up => w.u8(0),
        IfaceEvent::Down(r) => {
            w.u8(1);
            put_reason(w, r)?;
        }
        IfaceEvent::Reconfigured => w.u8(2),
        IfaceEvent::NewAddr {
            family,
            addr,
            prefix,
        } => {
            w.u8(3);
            put_addr(w, *family, addr, *prefix)?;
        }
        IfaceEvent::DelAddr {
            family,
            addr,
            prefix,
        } => {
            w.u8(4);
            put_addr(w, *family, addr, *prefix)?;
        }
        IfaceEvent::MtuUpdate { family, mtu } => {
            w.u8(5);
            put_family(w, *family);
            w.u32(*mtu);
        }
        IfaceEvent::OpFailed(r) => {
            w.u8(6);
            put_reason(w, r)?;
        }
    }
    Ok(())
}

fn get_event(r: &mut R<'_>) -> Result<IfaceEvent, DecodeError> {
    Ok(match r.u8()? {
        0 => IfaceEvent::Up,
        1 => IfaceEvent::Down(get_reason(r)?),
        2 => IfaceEvent::Reconfigured,
        3 => {
            let (family, addr, prefix) = get_addr(r)?;
            IfaceEvent::NewAddr {
                family,
                addr,
                prefix,
            }
        }
        4 => {
            let (family, addr, prefix) = get_addr(r)?;
            IfaceEvent::DelAddr {
                family,
                addr,
                prefix,
            }
        }
        5 => IfaceEvent::MtuUpdate {
            family: get_family(r)?,
            mtu: r.u32()?,
        },
        6 => IfaceEvent::OpFailed(get_reason(r)?),
        _ => return Err(DecodeError::Value),
    })
}

impl Notify {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = W::new();
        match self {
            Notify::HelloAck { ready } => {
                w.u8(u8::from(*ready));
                w.frame(ty::HELLO_ACK, 0)
            }
            Notify::Ready { ready } => {
                w.u8(u8::from(*ready));
                w.frame(ty::READY, 0)
            }
            Notify::RouteReply {
                txn,
                code,
                link,
                existing,
                companion,
                ifname,
            } => {
                w.u8(code.code());
                w.u8(*link);
                w.u8(u8::from(*existing) | (u8::from(*companion) << 1));
                w.str(ifname, MAX_IFNAME)?;
                w.frame(ty::ROUTE_REPLY, *txn)
            }
            Notify::Done { txn, code } => {
                w.u8(code.code());
                w.frame(ty::DONE, *txn)
            }
            Notify::MtuReply { txn, code, v4, v6 } => {
                w.u8(code.code());
                w.u32(*v4);
                w.u32(*v6);
                w.frame(ty::MTU_REPLY, *txn)
            }
            Notify::Event { link, slot, event } => {
                w.u8(*slot);
                put_event(&mut w, event)?;
                w.frame(ty::EVENT, u32::from(*link))
            }
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Notify, DecodeError> {
        let (t, number, payload) = split(bytes)?;
        let mut r = R::new(payload);
        let code = |r: &mut R<'_>| ResultCode::from_code(r.u8()?).ok_or(DecodeError::Value);
        let n = match t {
            ty::HELLO_ACK => Notify::HelloAck {
                ready: flag(r.u8()?)?,
            },
            ty::READY => Notify::Ready {
                ready: flag(r.u8()?)?,
            },
            ty::ROUTE_REPLY => {
                let code = code(&mut r)?;
                let link = r.u8()?;
                let flags = r.u8()?;
                if flags > 3 {
                    return Err(DecodeError::Value);
                }
                Notify::RouteReply {
                    txn: number,
                    code,
                    link,
                    existing: flags & 1 != 0,
                    companion: flags & 2 != 0,
                    ifname: r.str(MAX_IFNAME)?,
                }
            }
            ty::DONE => Notify::Done {
                txn: number,
                code: code(&mut r)?,
            },
            ty::MTU_REPLY => Notify::MtuReply {
                txn: number,
                code: code(&mut r)?,
                v4: r.u32()?,
                v6: r.u32()?,
            },
            ty::EVENT => Notify::Event {
                link: u8::try_from(number).map_err(|_| DecodeError::Value)?,
                slot: r.u8()?,
                event: get_event(&mut r)?,
            },
            _ => return Err(DecodeError::Type),
        };
        r.done()?;
        Ok(n)
    }
}

fn flag(v: u8) -> Result<bool, DecodeError> {
    match v {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(DecodeError::Value),
    }
}
