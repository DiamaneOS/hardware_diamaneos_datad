// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! What a `DsiAbi` needs besides reading the closed structs: the commands for
//! `libnicm.so` with every value checked, and the replies in plain terms.
use dataos_nicm_abi::{hint, kind, status, NicmCmd, NicmReply, MAX_APN};

/// Sends a command through `libnicm.so`. None: no connection, no answer, or the
/// handle is not a live one.
pub trait Sender {
    fn send(&self, hndl: usize, cmd: &NicmCmd) -> Option<NicmReply>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

/// Why a request got no usable answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The command was refused before it was sent (a value outside its bound).
    BadArgument,
    /// The daemon cannot be reached, or did not answer in time.
    NoAnswer,
    /// The daemon is not ready (its bring-up has not finished, or the modem restarted).
    NotReady,
    /// The daemon answered with this result code of the protocol.
    Refused(u32),
}

fn failure(status: u32) -> Failure {
    match status {
        6 => Failure::NotReady,
        status::BAD_ARGUMENT => Failure::BadArgument,
        status::TRANSPORT | status::TIMEOUT | status::NOT_REGISTERED | status::BUSY => {
            Failure::NoAnswer
        }
        other => Failure::Refused(other),
    }
}

fn run(s: &dyn Sender, hndl: usize, cmd: &NicmCmd) -> Result<NicmReply, Failure> {
    let r = s.send(hndl, cmd).ok_or(Failure::NoAnswer)?;
    if r.status == status::OK {
        Ok(r)
    } else {
        Err(failure(r.status))
    }
}

/// The link a route lookup chose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    pub number: u32,
    pub ifname: String,
    /// The modem has the call already.
    pub existing: bool,
    /// That call is the other IP family's.
    pub companion: bool,
}

/// What the data module wants a link for. Only what the daemon uses.
#[derive(Clone, Debug)]
pub struct Lookup<'a> {
    pub slot: u32,
    pub family: Family,
    pub apn: Option<&'a str>,
    pub apn_type: u32,
    pub apn_type_mask: u64,
    /// The other values of the request, for the matching call question.
    pub profile_3gpp: Option<u8>,
    pub profile_3gpp2: Option<u8>,
    pub xt_tech_pref: Option<u32>,
    pub bu_apn_name: Option<u32>,
    pub bu_apn_type: Option<u32>,
}

pub fn route_lookup(s: &dyn Sender, hndl: usize, l: &Lookup<'_>) -> Result<Link, Failure> {
    link_for(s, hndl, kind::ROUTE_LOOKUP, l)
}

/// The call that is up already for this request, if the daemon finds one.
pub fn matching_call(s: &dyn Sender, hndl: usize, l: &Lookup<'_>) -> Result<Link, Failure> {
    link_for(s, hndl, kind::MATCHING_CALL, l)
}

fn link_for(s: &dyn Sender, hndl: usize, k: u32, l: &Lookup<'_>) -> Result<Link, Failure> {
    let mut cmd = NicmCmd::new(k);
    cmd.slot = l.slot;
    cmd.family = match l.family {
        Family::V4 => 4,
        Family::V6 => 6,
    };
    cmd.apn_type = l.apn_type;
    cmd.apn_type_mask = l.apn_type_mask;
    for (bit, v) in [
        (hint::PROFILE_3GPP, l.profile_3gpp.map(u32::from)),
        (hint::PROFILE_3GPP2, l.profile_3gpp2.map(u32::from)),
        (hint::XT_PREF, l.xt_tech_pref),
        (hint::BACKUP_NAME, l.bu_apn_name),
        (hint::BACKUP_TYPE, l.bu_apn_type),
    ] {
        if let Some(v) = v {
            cmd.hint_mask |= bit;
            match bit {
                hint::PROFILE_3GPP => cmd.profile_3gpp = v,
                hint::PROFILE_3GPP2 => cmd.profile_3gpp2 = v,
                hint::XT_PREF => cmd.xt_pref = v,
                hint::BACKUP_NAME => cmd.backup_name = v,
                _ => cmd.backup_type = v,
            }
        }
    }
    if let Some(apn) = l.apn {
        let b = apn.as_bytes();
        if b.len() > MAX_APN || b.contains(&0) {
            return Err(Failure::BadArgument);
        }
        for (d, x) in cmd.apn.iter_mut().zip(b) {
            *d = *x;
        }
        cmd.apn_len = u32::try_from(b.len()).map_err(|_| Failure::BadArgument)?;
    }
    let r = run(s, hndl, &cmd)?;
    let n = usize::try_from(r.name_len).map_err(|_| Failure::BadArgument)?;
    let name = r.ifname.get(..n).ok_or(Failure::BadArgument)?;
    let ifname = String::from_utf8(name.to_vec()).map_err(|_| Failure::BadArgument)?;
    Ok(Link {
        number: r.link,
        ifname,
        existing: r.existing == 1,
        companion: r.companion == 1,
    })
}

fn on_link(
    s: &dyn Sender,
    hndl: usize,
    k: u32,
    link: u32,
    flag: bool,
) -> Result<NicmReply, Failure> {
    let mut cmd = NicmCmd::new(k);
    cmd.link = link;
    cmd.flag = u32::from(flag);
    run(s, hndl, &cmd)
}

pub fn link_release(s: &dyn Sender, hndl: usize, link: u32) -> Result<(), Failure> {
    on_link(s, hndl, kind::LINK_RELEASE, link, false).map(|_| ())
}

/// The MTU of the IPv4 and the IPv6 side of a link.
pub fn link_mtu(s: &dyn Sender, hndl: usize, link: u32) -> Result<(u32, u32), Failure> {
    on_link(s, hndl, kind::QUERY_MTU, link, false).map(|r| (r.v4_mtu, r.v6_mtu))
}

pub fn screen_state(s: &dyn Sender, hndl: usize, on: bool) -> Result<(), Failure> {
    on_link(s, hndl, kind::SCREEN_STATE, 0, on).map(|_| ())
}

/// The readiness query: Ok when the daemon says it is ready.
pub fn ready(s: &dyn Sender, hndl: usize) -> Result<(), Failure> {
    run(s, hndl, &NicmCmd::new(kind::READY)).map(|_| ())
}
