// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Wireless Data Service (QMI service 1) messages for one data call.
//!
//! TLV layouts are the ones libqmi publishes as data (data/qmi-service-wds.json
//! and src/libqmi-glib/qmi-enums-wds.h), and they fit the IDL tables of the stock
//! libqmiservices.so (`tests/idl/idl-expected.txt`, tested). They have not been exchanged with a
//! modem yet. Types that carry addresses, APNs or credentials have no derived
//! Debug, so they cannot reach a log by accident.
use crate::frame::{u16_value, u32_value, u8_value, Builder, Error, Frame};
use std::net::{Ipv4Addr, Ipv6Addr};

/// QMI service number of WDS.
pub const SERVICE: u8 = 0x01;

pub mod id {
    pub const SET_EVENT_REPORT: u16 = 0x0001;
    pub const INDICATION_REGISTER: u16 = 0x0003;
    pub const START_NETWORK: u16 = 0x0020;
    pub const STOP_NETWORK: u16 = 0x0021;
    pub const PACKET_SERVICE_STATUS: u16 = 0x0022;
    pub const GET_RUNTIME_SETTINGS: u16 = 0x002d;
    pub const SET_IP_FAMILY: u16 = 0x004d;
    pub const EXTENDED_IP_CONFIG: u16 = 0x008c;
    pub const BIND_MUX_DATA_PORT: u16 = 0x00a2;
    pub const BIND_SUBSCRIPTION: u16 = 0x00af;
    /// The route lookup of the modem (`QmiWdsClient::routeLookup`, 0x50d24, and the DSI library at 0x7fdf4).
    /// It is in no IDL table: the stock code sends it as a raw message, with the TLV numbers of Start Network.
    pub const ROUTE_LOOKUP: u16 = 0xfff2;
}

/// Bounds of what the parser keeps and the builder accepts. The data daemon
/// protocol (`dataos-wire`) uses the same numbers, and a test in `dataos-datad`
/// fails to compile if the two sets drift apart.
pub mod limits {
    /// Entries kept per address list.
    pub const MAX_ADDRS: usize = 8;
    /// Entries kept per name list.
    pub const MAX_NAMES: usize = 8;
    /// Longest name kept (the DNS limit).
    pub const MAX_NAME_LEN: usize = 253;
    /// The APN, as long as the stock Start Network TLV 0x14 allows (the stock IDL table and the stock daemon).
    pub const MAX_APN: usize = 150;
    pub const MAX_CRED: usize = 127;
    /// Extra Start Network TLVs per call and the longest value of one. 167 is the largest TLV of the stock
    /// Start Network request that the engine does not set itself (0x3f).
    pub const MAX_EXTRA_TLVS: usize = 8;
    pub const MAX_EXTRA_TLV_LEN: usize = 167;
}

/// Requested-settings bits of Get Runtime Settings.
pub mod settings {
    pub const DNS: u32 = 1 << 4;
    pub const IP_ADDRESS: u32 = 1 << 8;
    pub const GATEWAY: u32 = 1 << 9;
    pub const PCSCF_SERVER_LIST: u32 = 1 << 11;
    pub const PCSCF_DOMAIN_LIST: u32 = 1 << 12;
    pub const MTU: u32 = 1 << 13;
    pub const DOMAIN_LIST: u32 = 1 << 14;
    pub const IP_FAMILY: u32 = 1 << 15;
    /// Everything the AP needs to configure an interface.
    pub const INTERFACE: u32 = DNS | IP_ADDRESS | GATEWAY | MTU | DOMAIN_LIST | IP_FAMILY;
    /// Plus the IMS signalling servers.
    pub const IMS: u32 = INTERFACE | PCSCF_SERVER_LIST | PCSCF_DOMAIN_LIST;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpFamily {
    V4,
    V6,
    Unspecified,
}

impl IpFamily {
    pub fn to_u8(self) -> u8 {
        match self {
            IpFamily::V4 => 4,
            IpFamily::V6 => 6,
            IpFamily::Unspecified => 8,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            4 => Some(IpFamily::V4),
            6 => Some(IpFamily::V6),
            8 => Some(IpFamily::Unspecified),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auth {
    None,
    Pap,
    Chap,
    PapOrChap,
}

impl Auth {
    fn bits(self) -> u8 {
        match self {
            Auth::None => 0,
            Auth::Pap => 1,
            Auth::Chap => 2,
            Auth::PapOrChap => 3,
        }
    }
}

fn text(value: &str, max: usize) -> Result<&[u8], Error> {
    let b = value.as_bytes();
    if b.len() > max || b.contains(&0) {
        return Err(Error::Value);
    }
    Ok(b)
}

/// Start Network tags the engine sets itself. An extra TLV may not use them.
pub const START_TYPED_TAGS: [u8; 7] = [0x14, 0x16, 0x17, 0x18, 0x19, 0x30, 0x31];

/// Check one extra Start Network TLV before it is accepted for a call.
pub fn check_extra_tlv(tag: u8, value: &[u8]) -> Result<(), Error> {
    if tag == crate::frame::TAG_RESULT || START_TYPED_TAGS.contains(&tag) {
        return Err(Error::Duplicate);
    }
    if value.len() > limits::MAX_EXTRA_TLV_LEN {
        return Err(Error::TooLarge);
    }
    Ok(())
}

/// Start Network request.
#[derive(Clone, Default)]
pub struct StartNetwork {
    pub apn: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub auth: Option<Auth>,
    pub ip_family: Option<IpFamily>,
    pub profile_3gpp: Option<u8>,
    /// Bit 0 = 3GPP, bit 1 = 3GPP2.
    pub technology_preference: Option<u8>,
    /// Further TLVs sent as they are, in this order. This is how call setup
    /// parameters this crate has no name for (APN type, APN type mask,
    /// handoff context, SSC mode) reach the modem unchanged. The tags and
    /// encodings come from the stock DSI behaviour.
    pub extra: Vec<(u8, Vec<u8>)>,
}

impl std::fmt::Debug for StartNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartNetwork")
            .field("ip_family", &self.ip_family)
            .field("profile_3gpp", &self.profile_3gpp)
            .field("extra", &self.extra.len())
            .finish_non_exhaustive()
    }
}

impl StartNetwork {
    pub fn encode(&self, txn: u16) -> Result<Vec<u8>, Error> {
        let mut b = Builder::request(txn, id::START_NETWORK);
        if let Some(apn) = &self.apn {
            b = b.tlv(0x14, text(apn, limits::MAX_APN)?)?;
        }
        if let Some(u) = &self.username {
            b = b.tlv(0x17, text(u, limits::MAX_CRED)?)?;
        }
        if let Some(p) = &self.password {
            b = b.tlv(0x18, text(p, limits::MAX_CRED)?)?;
        }
        if let Some(a) = self.auth {
            b = b.u8(0x16, a.bits())?;
        }
        if let Some(f) = self.ip_family {
            b = b.u8(0x19, f.to_u8())?;
        }
        if let Some(t) = self.technology_preference {
            b = b.u8(0x30, t)?;
        }
        if let Some(p) = self.profile_3gpp {
            b = b.u8(0x31, p)?;
        }
        if self.extra.len() > limits::MAX_EXTRA_TLVS {
            return Err(Error::TooLarge);
        }
        for (tag, value) in &self.extra {
            check_extra_tlv(*tag, value)?;
            b = b.tlv(*tag, value)?;
        }
        b.build()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartOutcome {
    Started {
        handle: u32,
    },
    Failed {
        qmi_error: u16,
        call_end_reason: Option<u16>,
        verbose: Option<(u16, i16)>,
    },
}

fn verbose(f: &Frame<'_>) -> Result<Option<(u16, i16)>, Error> {
    match f.tlv(0x11) {
        None => Ok(None),
        Some(v) => {
            let [a, b, c, d]: [u8; 4] = v.try_into().map_err(|_| Error::Length)?;
            Ok(Some((
                u16::from_le_bytes([a, b]),
                i16::from_le_bytes([c, d]),
            )))
        }
    }
}

pub fn parse_start_network_response(f: &Frame<'_>) -> Result<StartOutcome, Error> {
    let st = f.status()?;
    if st.is_ok() {
        return Ok(StartOutcome::Started {
            handle: u32_value(f.required(0x01)?)?,
        });
    }
    Ok(StartOutcome::Failed {
        qmi_error: st.error,
        call_end_reason: f.tlv(0x10).map(u16_value).transpose()?,
        verbose: verbose(f)?,
    })
}

pub fn stop_network(txn: u16, handle: u32) -> Result<Vec<u8>, Error> {
    Builder::request(txn, id::STOP_NETWORK)
        .u32(0x01, handle)?
        .build()
}

pub fn set_ip_family(txn: u16, family: IpFamily) -> Result<Vec<u8>, Error> {
    match family {
        IpFamily::V4 | IpFamily::V6 => Builder::request(txn, id::SET_IP_FAMILY)
            .u8(0x01, family.to_u8())?
            .build(),
        IpFamily::Unspecified => Err(Error::Value),
    }
}

/// The subscription value for "don't care" (`WDS_DONT_CARE_SUBS`). The radio layer gives it for a
/// call that belongs to no SIM, and the stock daemon binds it as it is.
pub const DONT_CARE_SUBS: u32 = 0xff;

/// Bind this client to a subscription (SIM slot). 0 default, 1 primary, 2 secondary, 3 tertiary,
/// or `DONT_CARE_SUBS`.
pub fn bind_subscription(txn: u16, subscription: u32) -> Result<Vec<u8>, Error> {
    if subscription > 3 && subscription != DONT_CARE_SUBS {
        return Err(Error::Value);
    }
    Builder::request(txn, id::BIND_SUBSCRIPTION)
        .u32(0x01, subscription)?
        .build()
}

/// Endpoint type of the data transport (libqmi QmiDataEndpointType).
pub const EP_EMBEDDED: u32 = 4;

/// Bind this client to one multiplexed data port. `mux_id` is the rmnet mux ID.
pub fn bind_mux_data_port(
    txn: u16,
    ep_type: u32,
    iface_number: u32,
    mux_id: u8,
    client_type: u32,
) -> Result<Vec<u8>, Error> {
    let mut ep = [0u8; 8];
    let (a, b) = ep.split_at_mut(4);
    a.copy_from_slice(&ep_type.to_le_bytes());
    b.copy_from_slice(&iface_number.to_le_bytes());
    Builder::request(txn, id::BIND_MUX_DATA_PORT)
        .tlv(0x10, &ep)?
        .u8(0x11, mux_id)?
        .u32(0x13, client_type)?
        .build()
}

/// Ask for extended IP configuration change indications. Without this the
/// modem sends none, so the engine sends it before Start Network.
pub fn indication_register(txn: u16, report_extended_ip: bool) -> Result<Vec<u8>, Error> {
    Builder::request(txn, id::INDICATION_REGISTER)
        .u8(0x12, u8::from(report_extended_ip))?
        .build()
}

pub fn get_runtime_settings(txn: u16, requested: u32) -> Result<Vec<u8>, Error> {
    Builder::request(txn, id::GET_RUNTIME_SETTINGS)
        .u32(0x10, requested)?
        .build()
}

/// What a route lookup asks the modem: whether a call for this APN is up already, and where. The
/// TLVs are those of the stock `processRouteLookupReqParam` (0x5042c) **[V]**.
#[derive(Clone, PartialEq, Eq)]
pub struct RouteLookup {
    pub family: IpFamily,
    pub apn: Option<String>,
    pub apn_type: Option<u32>,
    pub apn_type_mask: Option<u64>,
    /// 3GPP profile index (TLV 0x31), 3GPP2 profile index (0x32), extended technology preference
    /// (0x34), and the two backup APN values (0x3c, 0x3d), which the module's request may carry.
    pub profile_3gpp: Option<u8>,
    pub profile_3gpp2: Option<u8>,
    pub xt_pref: Option<u16>,
    pub backup_name: Option<u8>,
    pub backup_type: Option<u8>,
}

impl std::fmt::Debug for RouteLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteLookup")
            .field("family", &self.family)
            .field("apn", &self.apn.as_ref().map(|_| "<set>"))
            .finish_non_exhaustive()
    }
}

/// Ask the modem where the call for this request runs, with the TLVs in the order of nicmd's
/// builder: 0x01 the lookup type (1), 0x31 and 0x32 the profile indexes, 0x14 the APN, 0x34 the
/// extended technology preference, 0x19 the IP family preference, 0x35 the origin (1), 0x3c and
/// 0x3d the backup APN values, 0x38 the APN type and 0x3e the mask.
pub fn route_lookup(txn: u16, req: &RouteLookup) -> Result<Vec<u8>, Error> {
    if req.family == IpFamily::Unspecified {
        return Err(Error::Value);
    }
    let mut b = Builder::request(txn, id::ROUTE_LOOKUP).u8(0x01, 1)?;
    if let Some(v) = req.profile_3gpp {
        b = b.u8(0x31, v)?;
    }
    if let Some(v) = req.profile_3gpp2 {
        b = b.u8(0x32, v)?;
    }
    if let Some(apn) = &req.apn {
        b = b.tlv(0x14, text(apn, limits::MAX_APN)?)?;
    }
    if let Some(v) = req.xt_pref {
        b = b.u16(0x34, v)?;
    }
    b = b.u8(0x19, req.family.to_u8())?.u8(0x35, 1)?;
    if let Some(v) = req.backup_name {
        b = b.u8(0x3c, v)?;
    }
    if let Some(v) = req.backup_type {
        b = b.u8(0x3d, v)?;
    }
    if let Some(t) = req.apn_type {
        b = b.u32(0x38, t)?;
    }
    if let Some(m) = req.apn_type_mask {
        b = b.tlv(0x3e, &m.to_le_bytes())?;
    }
    b.build()
}

/// Where the modem says the call is. `instance` is the number of the data port (TLV 0x10), `mux` the
/// mux ID of it (TLV 0x13), `endpoint` the data transport it is on (TLV 0x12: type, interface).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteAnswer {
    pub instance: Option<u8>,
    pub mux: Option<u8>,
    pub endpoint: Option<(u32, u32)>,
}

/// The answer to a route lookup. A refusal of the modem is an error, an answer without an
/// instance is a call that is not there.
pub fn parse_route_lookup(f: &Frame<'_>) -> Result<RouteAnswer, Error> {
    if f.id != id::ROUTE_LOOKUP {
        return Err(Error::Value);
    }
    if !f.status()?.is_ok() {
        return Err(Error::Value);
    }
    // nicmd takes the answer for good only with the block of TLV 0x01 (`processRouteLookupRespParam`
    // 0x507ec to 0x50850, the only place its result becomes 0), 10 bytes of which it keeps
    if f.required(0x01)?.len() != 10 {
        return Err(Error::Length);
    }
    let endpoint = match f.tlv(0x12) {
        None => None,
        Some(v) => {
            let (a, b) = v.split_at_checked(4).ok_or(Error::Length)?;
            Some((u32_value(a)?, u32_value(b)?))
        }
    };
    Ok(RouteAnswer {
        instance: f.tlv(0x10).map(u8_value).transpose()?,
        mux: f.tlv(0x13).map(u8_value).transpose()?,
        endpoint,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionStatus {
    Disconnected,
    Connected,
    Suspended,
    Authenticating,
    Unknown(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketServiceStatus {
    pub status: ConnectionStatus,
    pub reconfiguration_required: bool,
    pub call_end_reason: Option<u16>,
    pub verbose: Option<(u16, i16)>,
    pub ip_family: Option<IpFamily>,
    pub bearer_id: Option<u8>,
}

pub fn parse_packet_service_status(f: &Frame<'_>) -> Result<PacketServiceStatus, Error> {
    if f.id != id::PACKET_SERVICE_STATUS {
        return Err(Error::Value);
    }
    let [status, reconfiguration]: [u8; 2] =
        f.required(0x01)?.try_into().map_err(|_| Error::Length)?;
    let status = match status {
        1 => ConnectionStatus::Disconnected,
        2 => ConnectionStatus::Connected,
        3 => ConnectionStatus::Suspended,
        4 => ConnectionStatus::Authenticating,
        other => ConnectionStatus::Unknown(other),
    };
    Ok(PacketServiceStatus {
        status,
        reconfiguration_required: reconfiguration != 0,
        call_end_reason: f.tlv(0x10).map(u16_value).transpose()?,
        verbose: verbose(f)?,
        ip_family: f
            .tlv(0x12)
            .map(u8_value)
            .transpose()?
            .and_then(IpFamily::from_u8),
        bearer_id: f.tlv(0x14).map(u8_value).transpose()?,
    })
}

/// Extended IP configuration change: which settings changed (bit mask of TLV 0x10, 0 when it is not there).
/// The stock table marks 0x10 and 0x11 optional, so an indication without them still says the configuration
/// changed. A TLV that is there must be 4 bytes wide.
pub fn parse_extended_ip_config(f: &Frame<'_>) -> Result<u32, Error> {
    if f.id != id::EXTENDED_IP_CONFIG {
        return Err(Error::Value);
    }
    f.tlv(0x11).map(u32_value).transpose()?;
    Ok(f.tlv(0x10).map(u32_value).transpose()?.unwrap_or(0))
}

/// Network settings of one connected call.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RuntimeSettings {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv4_gateway: Option<Ipv4Addr>,
    pub ipv4_mask: Option<Ipv4Addr>,
    pub ipv4_dns: Vec<Ipv4Addr>,
    pub ipv6: Option<(Ipv6Addr, u8)>,
    pub ipv6_gateway: Option<(Ipv6Addr, u8)>,
    pub ipv6_dns: Vec<Ipv6Addr>,
    pub mtu: Option<u32>,
    pub pcscf_v4: Vec<Ipv4Addr>,
    pub pcscf_domains: Vec<String>,
    pub domains: Vec<String>,
    pub ip_family: Option<IpFamily>,
    /// Optional entries that were malformed or over a limit and were left out.
    pub dropped: u16,
}

// Counts only: addresses and names never enter a log through Debug.
impl std::fmt::Debug for RuntimeSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeSettings")
            .field("has_v4", &self.ipv4.is_some())
            .field("has_v6", &self.ipv6.is_some())
            .field(
                "dns",
                &self.ipv4_dns.len().saturating_add(self.ipv6_dns.len()),
            )
            .field("mtu", &self.mtu)
            .field("dropped", &self.dropped)
            .finish_non_exhaustive()
    }
}

fn ipv4_value(v: &[u8]) -> Result<Ipv4Addr, Error> {
    // QMI sends IPv4 as a 32-bit little-endian integer holding the host-order address.
    Ok(Ipv4Addr::from(u32_value(v)?))
}

fn ipv6_value(v: &[u8]) -> Result<Ipv6Addr, Error> {
    let a: [u8; 16] = v.try_into().map_err(|_| Error::Length)?;
    Ok(Ipv6Addr::from(a))
}

fn ipv6_with_prefix(v: &[u8]) -> Result<(Ipv6Addr, u8), Error> {
    let (addr, prefix) = v.split_at_checked(16).ok_or(Error::Length)?;
    let [prefix] = prefix else {
        return Err(Error::Length);
    };
    if *prefix > 128 {
        return Err(Error::Value);
    }
    Ok((ipv6_value(addr)?, *prefix))
}

/// Count one dropped optional entry.
fn note(dropped: &mut u16) {
    *dropped = dropped.saturating_add(1);
}

/// A malformed optional value is left out and counted.
fn lenient<T>(r: Result<T, Error>, dropped: &mut u16) -> Option<T> {
    match r {
        Ok(v) => Some(v),
        Err(_) => {
            note(dropped);
            None
        }
    }
}

/// Name list: a count byte, then entries with a 16-bit little-endian length.
/// Entries that are too long, not UTF-8 or contain NUL are dropped one by one.
/// A damaged tail ends the list.
fn name_list(v: &[u8], dropped: &mut u16) -> Vec<String> {
    let mut out = Vec::new();
    let Some((&count, mut rest)) = v.split_first() else {
        note(dropped);
        return out;
    };
    for _ in 0..count {
        let Some((len, tail)) = rest.split_first_chunk::<2>() else {
            note(dropped);
            return out;
        };
        let n = usize::from(u16::from_le_bytes(*len));
        let Some((raw, after)) = tail.split_at_checked(n) else {
            note(dropped);
            return out;
        };
        rest = after;
        match std::str::from_utf8(raw) {
            Ok(s) if n <= limits::MAX_NAME_LEN && !s.contains('\0') => {
                if out.len() < limits::MAX_NAMES {
                    out.push(s.to_owned());
                } else {
                    note(dropped);
                }
            }
            _ => note(dropped),
        }
    }
    if !rest.is_empty() {
        note(dropped);
    }
    out
}

/// IPv4 list: a count byte, then 32-bit addresses. A count that disagrees with
/// the data keeps what is complete and counts the mismatch once.
fn v4_list(v: &[u8], dropped: &mut u16) -> Vec<Ipv4Addr> {
    let Some((&count, rest)) = v.split_first() else {
        note(dropped);
        return Vec::new();
    };
    let chunks = rest.chunks_exact(4);
    let complete = chunks.len();
    if usize::from(count) != complete || !chunks.remainder().is_empty() {
        note(dropped);
    }
    let wanted = usize::from(count).min(complete);
    if wanted > limits::MAX_ADDRS {
        note(dropped);
    }
    chunks
        .take(wanted.min(limits::MAX_ADDRS))
        .filter_map(|c| u32_value(c).ok())
        .map(Ipv4Addr::from)
        .collect()
}

fn nonzero_v4(a: Ipv4Addr) -> Option<Ipv4Addr> {
    (!a.is_unspecified()).then_some(a)
}

/// Parse a Get Runtime Settings response for a call of `family`. The address
/// and prefix of that family are required and strict. Everything else is
/// optional: a malformed or over-limit entry is left out and counted in
/// `dropped`, so one odd gateway, name or DNS entry cannot fail a call.
pub fn parse_runtime_settings(f: &Frame<'_>, family: IpFamily) -> Result<RuntimeSettings, Error> {
    if f.id != id::GET_RUNTIME_SETTINGS {
        return Err(Error::Value);
    }
    if !f.status()?.is_ok() {
        return Err(Error::Value);
    }
    let mut s = RuntimeSettings::default();
    let mut dropped = 0u16;
    let want_v4 = family == IpFamily::V4;
    let want_v6 = family == IpFamily::V6;

    for tag in [0x15u8, 0x16] {
        if let Some(v) = f.tlv(tag) {
            if let Some(a) = lenient(ipv4_value(v), &mut dropped).and_then(nonzero_v4) {
                s.ipv4_dns.push(a);
            }
        }
    }
    if let Some(v) = f.tlv(0x1e) {
        let a = if want_v4 {
            Some(ipv4_value(v)?)
        } else {
            lenient(ipv4_value(v), &mut dropped)
        };
        s.ipv4 = a.and_then(nonzero_v4);
    }
    if let Some(v) = f.tlv(0x20) {
        s.ipv4_gateway = lenient(ipv4_value(v), &mut dropped).and_then(nonzero_v4);
    }
    if let Some(v) = f.tlv(0x21) {
        s.ipv4_mask = if want_v4 {
            Some(ipv4_value(v)?)
        } else {
            lenient(ipv4_value(v), &mut dropped)
        };
    }
    if let Some(v) = f.tlv(0x23) {
        s.pcscf_v4 = v4_list(v, &mut dropped);
    }
    if let Some(v) = f.tlv(0x24) {
        s.pcscf_domains = name_list(v, &mut dropped);
    }
    if let Some(v) = f.tlv(0x25) {
        s.ipv6 = if want_v6 {
            Some(ipv6_with_prefix(v)?)
        } else {
            lenient(ipv6_with_prefix(v), &mut dropped)
        };
    }
    if let Some(v) = f.tlv(0x26) {
        s.ipv6_gateway = lenient(ipv6_with_prefix(v), &mut dropped);
    }
    for tag in [0x27u8, 0x28] {
        if let Some(v) = f.tlv(tag) {
            if let Some(a) = lenient(ipv6_value(v), &mut dropped) {
                if !a.is_unspecified() {
                    s.ipv6_dns.push(a);
                }
            }
        }
    }
    if let Some(v) = f.tlv(0x29) {
        s.mtu = lenient(u32_value(v), &mut dropped);
    }
    if let Some(v) = f.tlv(0x2a) {
        s.domains = name_list(v, &mut dropped);
    }
    if let Some(v) = f.tlv(0x2b) {
        s.ip_family = lenient(u8_value(v), &mut dropped).and_then(IpFamily::from_u8);
    }
    s.dropped = dropped;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{Builder, Kind};

    fn v4(a: [u8; 4]) -> u32 {
        u32::from_be_bytes(a)
    }

    fn names(list: &[&[u8]]) -> Vec<u8> {
        let mut v = vec![list.len() as u8];
        for n in list {
            v.extend_from_slice(&(n.len() as u16).to_le_bytes());
            v.extend_from_slice(n);
        }
        v
    }

    fn settings_with(tlv: impl FnOnce(Builder) -> Builder) -> Vec<u8> {
        tlv(Builder::response(1, id::GET_RUNTIME_SETTINGS).ok().unwrap())
            .build()
            .unwrap()
    }

    fn parse(bytes: &[u8], family: IpFamily) -> Result<RuntimeSettings, Error> {
        parse_runtime_settings(&Frame::parse(bytes).unwrap(), family)
    }

    #[test]
    fn start_network_encodes_and_redacts() {
        let req = StartNetwork {
            apn: Some("apn.example".into()),
            username: Some("user".into()),
            password: Some("pw-test".into()),
            auth: Some(Auth::Chap),
            ip_family: Some(IpFamily::V6),
            profile_3gpp: Some(1),
            technology_preference: Some(1),
            extra: Vec::new(),
        };
        let bytes = req.encode(9).unwrap();
        let f = Frame::parse(&bytes).unwrap();
        assert_eq!(f.id, id::START_NETWORK);
        assert_eq!(f.tlv(0x14), Some(&b"apn.example"[..]));
        assert_eq!(f.tlv(0x17), Some(&b"user"[..]));
        assert_eq!(f.tlv(0x18), Some(&b"pw-test"[..]));
        assert_eq!(f.tlv(0x16), Some(&[2u8][..]));
        assert_eq!(f.tlv(0x19), Some(&[6u8][..]));
        assert_eq!(f.tlv(0x30), Some(&[1u8][..]));
        assert_eq!(f.tlv(0x31), Some(&[1u8][..]));
        assert_eq!(f.tlvs().count(), 7);
        let dbg = format!("{:?}", req);
        assert!(!dbg.contains("apn.example") && !dbg.contains("pw-test"));
    }

    #[test]
    fn extra_tlvs_are_sent_unchanged_and_in_order() {
        let req = StartNetwork {
            apn: Some("sos.example".into()),
            extra: vec![
                (0x41, vec![0x10, 0, 0, 0]),
                (0x40, vec![]),
                (0x55, vec![9, 8, 7]),
            ],
            ..Default::default()
        };
        let bytes = req.encode(1).unwrap();
        let f = Frame::parse(&bytes).unwrap();
        let tlvs: Vec<_> = f.tlvs().collect();
        assert_eq!(
            tlvs,
            vec![
                (0x14, &b"sos.example"[..]),
                (0x41, &[0x10u8, 0, 0, 0][..]),
                (0x40, &[][..]),
                (0x55, &[9u8, 8, 7][..]),
            ]
        );
    }

    #[test]
    fn extra_tlvs_cannot_shadow_typed_ones_or_exceed_limits() {
        for tag in START_TYPED_TAGS.into_iter().chain([0x02]) {
            let r = StartNetwork {
                extra: vec![(tag, vec![1])],
                ..Default::default()
            };
            assert_eq!(r.encode(1).unwrap_err(), Error::Duplicate, "tag {tag:#x}");
        }
        let dup = StartNetwork {
            extra: vec![(0x50, vec![1]), (0x50, vec![2])],
            ..Default::default()
        };
        assert_eq!(dup.encode(1).unwrap_err(), Error::Duplicate);
        let long = StartNetwork {
            extra: vec![(0x50, vec![0; limits::MAX_EXTRA_TLV_LEN + 1])],
            ..Default::default()
        };
        assert_eq!(long.encode(1).unwrap_err(), Error::TooLarge);
        let edge = StartNetwork {
            extra: vec![(0x50, vec![0; limits::MAX_EXTRA_TLV_LEN])],
            ..Default::default()
        };
        assert!(edge.encode(1).is_ok());
        let many = StartNetwork {
            extra: (0..=limits::MAX_EXTRA_TLVS as u8)
                .map(|i| (0x50 + i, vec![]))
                .collect(),
            ..Default::default()
        };
        assert_eq!(many.encode(1).unwrap_err(), Error::TooLarge);
    }

    #[test]
    fn start_network_rejects_bad_text() {
        let r = StartNetwork {
            apn: Some("a\0b".into()),
            ..Default::default()
        };
        assert_eq!(r.encode(1).unwrap_err(), Error::Value);
        let r = StartNetwork {
            apn: Some("x".repeat(limits::MAX_APN + 1)),
            ..Default::default()
        };
        assert_eq!(r.encode(1).unwrap_err(), Error::Value);
        let r = StartNetwork {
            apn: Some("x".repeat(limits::MAX_APN)),
            password: Some("y".repeat(limits::MAX_CRED)),
            ..Default::default()
        };
        assert!(r.encode(1).is_ok());
    }

    #[test]
    fn start_network_response_ok_and_failed() {
        let ok = Builder::response(1, id::START_NETWORK)
            .ok()
            .unwrap()
            .u32(0x01, 0xdead_beef)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            parse_start_network_response(&Frame::parse(&ok).unwrap()).unwrap(),
            StartOutcome::Started {
                handle: 0xdead_beef
            }
        );
        let mut vb = Vec::new();
        vb.extend_from_slice(&3u16.to_le_bytes());
        vb.extend_from_slice(&(-5i16).to_le_bytes());
        let bad = Builder::response(1, id::START_NETWORK)
            .fail(0x000e)
            .unwrap()
            .u16(0x10, 14)
            .unwrap()
            .tlv(0x11, &vb)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            parse_start_network_response(&Frame::parse(&bad).unwrap()).unwrap(),
            StartOutcome::Failed {
                qmi_error: 0x000e,
                call_end_reason: Some(14),
                verbose: Some((3, -5))
            }
        );
        // success without a handle is malformed
        let broken = Builder::response(1, id::START_NETWORK)
            .ok()
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            parse_start_network_response(&Frame::parse(&broken).unwrap()).unwrap_err(),
            Error::Missing
        );
    }

    #[test]
    fn packet_service_status_parses() {
        let ind = Builder::indication(id::PACKET_SERVICE_STATUS)
            .tlv(0x01, &[2, 0])
            .unwrap()
            .u8(0x12, 6)
            .unwrap()
            .u8(0x14, 5)
            .unwrap()
            .build()
            .unwrap();
        let p = parse_packet_service_status(&Frame::parse(&ind).unwrap()).unwrap();
        assert_eq!(p.status, ConnectionStatus::Connected);
        assert!(!p.reconfiguration_required);
        assert_eq!(p.ip_family, Some(IpFamily::V6));
        assert_eq!(p.bearer_id, Some(5));

        let down = Builder::indication(id::PACKET_SERVICE_STATUS)
            .tlv(0x01, &[1, 1])
            .unwrap()
            .u16(0x10, 0x20)
            .unwrap()
            .build()
            .unwrap();
        let p = parse_packet_service_status(&Frame::parse(&down).unwrap()).unwrap();
        assert_eq!(p.status, ConnectionStatus::Disconnected);
        assert!(p.reconfiguration_required);
        assert_eq!(p.call_end_reason, Some(0x20));
    }

    #[test]
    fn packet_service_status_rejects_bad_width() {
        let ind = Builder::indication(id::PACKET_SERVICE_STATUS)
            .tlv(0x01, &[2])
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            parse_packet_service_status(&Frame::parse(&ind).unwrap()).unwrap_err(),
            Error::Length
        );
    }

    fn settings_response() -> Vec<u8> {
        // Documentation addresses only (RFC 5737 and RFC 3849).
        let mut v6 = Vec::new();
        v6.extend_from_slice(&"2001:db8:1:2::5".parse::<Ipv6Addr>().unwrap().octets());
        v6.push(64);
        let mut gw6 = Vec::new();
        gw6.extend_from_slice(&"fe80::1".parse::<Ipv6Addr>().unwrap().octets());
        gw6.push(64);
        let dns6 = "2001:db8::53".parse::<Ipv6Addr>().unwrap().octets();
        let mut pcscf = vec![1u8];
        pcscf.extend_from_slice(&v4([198, 51, 100, 7]).to_le_bytes());
        Builder::response(4, id::GET_RUNTIME_SETTINGS)
            .ok()
            .unwrap()
            .u32(0x15, v4([192, 0, 2, 53]))
            .unwrap()
            .u32(0x16, 0)
            .unwrap()
            .u32(0x1e, v4([192, 0, 2, 10]))
            .unwrap()
            .u32(0x20, v4([192, 0, 2, 9]))
            .unwrap()
            .u32(0x21, v4([255, 255, 255, 252]))
            .unwrap()
            .tlv(0x23, &pcscf)
            .unwrap()
            .tlv(0x24, &names(&[b"ims.tld"]))
            .unwrap()
            .tlv(0x25, &v6)
            .unwrap()
            .tlv(0x26, &gw6)
            .unwrap()
            .tlv(0x27, &dns6)
            .unwrap()
            .u32(0x29, 1400)
            .unwrap()
            .u8(0x2b, 4)
            .unwrap()
            .build()
            .unwrap()
    }

    #[test]
    fn runtime_settings_parse() {
        let bytes = settings_response();
        let s = parse(&bytes, IpFamily::V4).unwrap();
        assert_eq!(s.ipv4, Some("192.0.2.10".parse().unwrap()));
        assert_eq!(s.ipv4_gateway, Some("192.0.2.9".parse().unwrap()));
        assert_eq!(s.ipv4_mask, Some("255.255.255.252".parse().unwrap()));
        assert_eq!(s.ipv4_dns, vec!["192.0.2.53".parse::<Ipv4Addr>().unwrap()]);
        assert_eq!(s.ipv6.unwrap().1, 64);
        assert_eq!(s.ipv6_dns.len(), 1);
        assert_eq!(s.mtu, Some(1400));
        assert_eq!(
            s.pcscf_v4,
            vec!["198.51.100.7".parse::<Ipv4Addr>().unwrap()]
        );
        assert_eq!(s.pcscf_domains, vec!["ims.tld".to_string()]);
        assert_eq!(s.ip_family, Some(IpFamily::V4));
        assert_eq!(s.dropped, 0);
        let dbg = format!("{:?}", s);
        assert!(!dbg.contains("192.0.2") && !dbg.contains("2001"));
    }

    #[test]
    fn required_fields_of_the_calls_family_stay_strict() {
        // IPv6 prefix above 128 on an IPv6 call
        let mut v6 = vec![0u8; 16];
        v6.push(200);
        let b = settings_with(|b| b.tlv(0x25, &v6).unwrap());
        assert_eq!(parse(&b, IpFamily::V6).unwrap_err(), Error::Value);
        // the same bytes on an IPv4 call are an unused optional field
        let s = parse(&b, IpFamily::V4).unwrap();
        assert_eq!((s.ipv6, s.dropped), (None, 1));
        // short IPv4 address and a broken mask on an IPv4 call
        let b = settings_with(|b| b.tlv(0x1e, &[1, 2, 3]).unwrap());
        assert_eq!(parse(&b, IpFamily::V4).unwrap_err(), Error::Length);
        assert_eq!(parse(&b, IpFamily::V6).unwrap().dropped, 1);
        let b = settings_with(|b| b.tlv(0x21, &[1]).unwrap());
        assert_eq!(parse(&b, IpFamily::V4).unwrap_err(), Error::Length);
        // failed result is not settings
        let b = Builder::response(1, id::GET_RUNTIME_SETTINGS)
            .fail(1)
            .unwrap()
            .build()
            .unwrap();
        assert!(parse(&b, IpFamily::V4).is_err());
    }

    #[test]
    fn optional_fields_are_dropped_and_counted_not_fatal() {
        let b = settings_with(|b| {
            b.tlv(0x15, &[1, 2]) // DNS of the wrong width
                .unwrap()
                .tlv(0x20, &[1]) // gateway of the wrong width
                .unwrap()
                .tlv(0x23, &[3, 1, 2, 3, 4]) // count larger than the data
                .unwrap()
                .tlv(0x24, &names(&[b"ok.tld", &[0xff, 0xfe], b"nul\0.tld"]))
                .unwrap()
                .tlv(0x26, &[0; 3])
                .unwrap()
                .tlv(0x27, &[0; 5])
                .unwrap()
                .tlv(0x29, &[1])
                .unwrap()
                .tlv(0x2a, &[200]) // count of entries that are not there
                .unwrap()
                .tlv(0x2b, &[1, 2])
                .unwrap()
        });
        let s = parse(&b, IpFamily::V4).unwrap();
        assert_eq!(s.pcscf_domains, vec!["ok.tld".to_string()]);
        assert!(s.ipv4_dns.is_empty() && s.ipv4_gateway.is_none() && s.mtu.is_none());
        assert!(s.ipv6_gateway.is_none() && s.ipv6_dns.is_empty() && s.domains.is_empty());
        assert_eq!(s.ip_family, None);
        // dns 1, gateway 1, pcscf list 1, two bad names 2, v6 gateway 1, v6 dns 1,
        // mtu 1, short domain list 1, family 1
        assert_eq!(s.dropped, 10);
    }

    #[test]
    fn name_lists_stop_exactly_at_the_limits() {
        let at_limit = "a".repeat(limits::MAX_NAME_LEN);
        let list: Vec<&[u8]> = (0..limits::MAX_NAMES)
            .map(|_| at_limit.as_bytes())
            .collect();
        let b = settings_with(|b| b.tlv(0x2a, &names(&list)).unwrap());
        let s = parse(&b, IpFamily::V4).unwrap();
        assert_eq!(s.domains.len(), limits::MAX_NAMES);
        assert!(s.domains.iter().all(|d| d.len() == limits::MAX_NAME_LEN));
        assert_eq!(s.dropped, 0);

        // one entry more than the limit
        let mut more = list.clone();
        more.push(b"extra.tld");
        let b = settings_with(|b| b.tlv(0x2a, &names(&more)).unwrap());
        let s = parse(&b, IpFamily::V4).unwrap();
        assert_eq!((s.domains.len(), s.dropped), (limits::MAX_NAMES, 1));

        // one byte too long
        let long = "a".repeat(limits::MAX_NAME_LEN + 1);
        let b = settings_with(|b| {
            b.tlv(0x2a, &names(&[long.as_bytes(), b"kept.tld"]))
                .unwrap()
        });
        let s = parse(&b, IpFamily::V4).unwrap();
        assert_eq!((s.domains, s.dropped), (vec!["kept.tld".to_string()], 1));
    }

    #[test]
    fn address_lists_stop_at_the_limit() {
        let mut list = vec![limits::MAX_ADDRS as u8 + 3];
        for i in 0..limits::MAX_ADDRS as u32 + 3 {
            list.extend_from_slice(&(0xc633_6400 + i).to_le_bytes());
        }
        let b = settings_with(|b| b.tlv(0x23, &list).unwrap());
        let s = parse(&b, IpFamily::V4).unwrap();
        assert_eq!(s.pcscf_v4.len(), limits::MAX_ADDRS);
        assert_eq!(s.dropped, 1);
    }

    fn lookup(family: IpFamily) -> RouteLookup {
        RouteLookup {
            family,
            apn: Some("internet.example".into()),
            apn_type: Some(0x11),
            apn_type_mask: Some(0x0102_0304_0506_0708),
            profile_3gpp: None,
            profile_3gpp2: None,
            xt_pref: None,
            backup_name: None,
            backup_type: None,
        }
    }

    #[test]
    fn the_route_lookup_request_carries_the_tlvs_of_the_stock_one() {
        let b = route_lookup(7, &lookup(IpFamily::V6)).unwrap();
        let fr = Frame::parse(&b).unwrap();
        assert_eq!((fr.id, fr.txn, fr.kind), (0xfff2, 7, Kind::Request));
        assert_eq!(fr.tlv(0x01), Some(&[1u8][..]));
        assert_eq!(fr.tlv(0x14), Some(&b"internet.example"[..]));
        assert_eq!(fr.tlv(0x19), Some(&[6u8][..]));
        assert_eq!(fr.tlv(0x35), Some(&[1u8][..]));
        assert_eq!(fr.tlv(0x38), Some(&[0x11u8, 0, 0, 0][..]));
        assert_eq!(fr.tlv(0x3e), Some(&[8u8, 7, 6, 5, 4, 3, 2, 1][..]));
        assert_eq!(fr.tlvs().count(), 6);
        let bare = RouteLookup {
            apn: None,
            apn_type: None,
            apn_type_mask: None,
            ..lookup(IpFamily::V4)
        };
        let bytes = route_lookup(1, &bare).unwrap();
        let fr = Frame::parse(&bytes).unwrap();
        assert_eq!(
            fr.tlvs().map(|(t, _)| t).collect::<Vec<_>>(),
            [0x01, 0x19, 0x35]
        );
        assert_eq!(fr.tlv(0x19), Some(&[4u8][..]));
    }

    #[test]
    fn the_other_tlvs_of_the_module_s_request_go_in_the_order_of_the_stock_builder() {
        let full = RouteLookup {
            profile_3gpp: Some(3),
            profile_3gpp2: Some(4),
            xt_pref: Some(0x0102),
            backup_name: Some(1),
            backup_type: Some(2),
            ..lookup(IpFamily::V4)
        };
        let b = route_lookup(1, &full).unwrap();
        let fr = Frame::parse(&b).unwrap();
        let tags: Vec<u8> = fr.tlvs().map(|(t, _)| t).collect();
        assert_eq!(
            tags,
            [0x01, 0x31, 0x32, 0x14, 0x34, 0x19, 0x35, 0x3c, 0x3d, 0x38, 0x3e]
        );
        assert_eq!(fr.tlv(0x31), Some(&[3u8][..]));
        assert_eq!(fr.tlv(0x32), Some(&[4u8][..]));
        assert_eq!(fr.tlv(0x34), Some(&[2u8, 1][..]));
        assert_eq!(fr.tlv(0x3c), Some(&[1u8][..]));
        assert_eq!(fr.tlv(0x3d), Some(&[2u8][..]));
        // each one alone
        for (tag, one) in [
            (
                0x31u8,
                RouteLookup {
                    profile_3gpp: Some(9),
                    ..lookup(IpFamily::V4)
                },
            ),
            (
                0x32,
                RouteLookup {
                    profile_3gpp2: Some(9),
                    ..lookup(IpFamily::V4)
                },
            ),
            (
                0x34,
                RouteLookup {
                    xt_pref: Some(9),
                    ..lookup(IpFamily::V4)
                },
            ),
            (
                0x3c,
                RouteLookup {
                    backup_name: Some(9),
                    ..lookup(IpFamily::V4)
                },
            ),
            (
                0x3d,
                RouteLookup {
                    backup_type: Some(9),
                    ..lookup(IpFamily::V4)
                },
            ),
        ] {
            let b = route_lookup(1, &one).unwrap();
            let fr = Frame::parse(&b).unwrap();
            assert!(fr.tlv(tag).is_some(), "{tag:#x}");
            assert_eq!(fr.tlvs().count(), 7, "{tag:#x}");
        }
    }

    #[test]
    fn a_route_lookup_the_modem_could_not_read_is_not_built() {
        assert!(route_lookup(1, &lookup(IpFamily::Unspecified)).is_err());
        let nul = RouteLookup {
            apn: Some("a\0b".into()),
            ..lookup(IpFamily::V4)
        };
        assert!(route_lookup(1, &nul).is_err());
        let long = RouteLookup {
            apn: Some("a".repeat(limits::MAX_APN + 1)),
            ..lookup(IpFamily::V4)
        };
        assert!(route_lookup(1, &long).is_err());
        let edge = RouteLookup {
            apn: Some("a".repeat(limits::MAX_APN)),
            ..lookup(IpFamily::V4)
        };
        assert!(route_lookup(1, &edge).is_ok());
        let shown = format!("{:?}", lookup(IpFamily::V4));
        assert!(!shown.contains("internet"), "{shown}");
    }

    fn answer(build: impl FnOnce(Builder) -> Builder) -> Vec<u8> {
        build(
            Builder::response(3, id::ROUTE_LOOKUP)
                .ok()
                .unwrap()
                .tlv(0x01, &[0; 10])
                .unwrap(),
        )
        .build()
        .unwrap()
    }

    #[test]
    fn the_route_lookup_answer_names_an_instance_a_mux_and_an_endpoint() {
        let none = answer(|b| b);
        assert_eq!(
            parse_route_lookup(&Frame::parse(&none).unwrap()).unwrap(),
            RouteAnswer {
                instance: None,
                mux: None,
                endpoint: None
            }
        );
        let full = answer(|b| {
            b.u8(0x10, 4)
                .unwrap()
                .u8(0x13, 5)
                .unwrap()
                .tlv(0x12, &[4, 0, 0, 0, 1, 0, 0, 0])
                .unwrap()
        });
        assert_eq!(
            parse_route_lookup(&Frame::parse(&full).unwrap()).unwrap(),
            RouteAnswer {
                instance: Some(4),
                mux: Some(5),
                endpoint: Some((4, 1))
            }
        );
    }

    #[test]
    fn a_route_lookup_answer_that_is_refused_or_malformed_is_an_error() {
        let wrong_id = Builder::response(3, id::BIND_SUBSCRIPTION)
            .ok()
            .unwrap()
            .build()
            .unwrap();
        assert!(parse_route_lookup(&Frame::parse(&wrong_id).unwrap()).is_err());
        let refused = Builder::response(3, id::ROUTE_LOOKUP)
            .fail(3)
            .unwrap()
            .tlv(0x01, &[0; 10])
            .unwrap()
            .u8(0x10, 1)
            .unwrap()
            .build()
            .unwrap();
        assert!(parse_route_lookup(&Frame::parse(&refused).unwrap()).is_err());
        let no_result = Builder::response(3, id::ROUTE_LOOKUP)
            .u8(0x10, 1)
            .unwrap()
            .build()
            .unwrap();
        assert!(parse_route_lookup(&Frame::parse(&no_result).unwrap()).is_err());
        // without the block of TLV 0x01, or with another size of it, nicmd does not take the answer
        for block in [None, Some(9usize), Some(11), Some(0)] {
            let b = Builder::response(3, id::ROUTE_LOOKUP).ok().unwrap();
            let b = match block {
                Some(n) => b.tlv(0x01, &vec![0u8; n]).unwrap(),
                None => b,
            };
            let b = b.u8(0x10, 1).unwrap().build().unwrap();
            assert!(
                parse_route_lookup(&Frame::parse(&b).unwrap()).is_err(),
                "block {block:?}"
            );
        }
        for (tag, len) in [(0x10u8, 2usize), (0x13, 0), (0x12, 7), (0x12, 9)] {
            let b = answer(|b| b.tlv(tag, &vec![1u8; len]).unwrap());
            assert!(
                parse_route_lookup(&Frame::parse(&b).unwrap()).is_err(),
                "tag {tag:#x} length {len}"
            );
        }
    }

    #[test]
    fn small_requests_encode() {
        let b = stop_network(1, 0x0102_0304).unwrap();
        let fr = Frame::parse(&b).unwrap();
        assert_eq!(fr.tlv(0x01), Some(&[4u8, 3, 2, 1][..]));
        assert!(set_ip_family(1, IpFamily::Unspecified).is_err());
        assert!(bind_subscription(1, 4).is_err());
        for bad in [0x80, 0xfe, 0x100, 0x1ff] {
            assert!(bind_subscription(1, bad).is_err(), "{bad:#x}");
        }
        let dont_care = bind_subscription(1, DONT_CARE_SUBS).unwrap();
        let fr = Frame::parse(&dont_care).unwrap();
        assert_eq!(fr.tlv(0x01), Some(&[0xffu8, 0, 0, 0][..]));
        let b = bind_mux_data_port(2, EP_EMBEDDED, 1, 5, 0xff).unwrap();
        let fr = Frame::parse(&b).unwrap();
        assert_eq!(fr.tlv(0x11), Some(&[5u8][..]));
        assert_eq!(fr.tlv(0x10), Some(&[4u8, 0, 0, 0, 1, 0, 0, 0][..]));
        let b = indication_register(3, true).unwrap();
        let fr = Frame::parse(&b).unwrap();
        assert_eq!(
            (fr.id, fr.tlv(0x12)),
            (id::INDICATION_REGISTER, Some(&[1u8][..]))
        );
        let b = get_runtime_settings(3, settings::INTERFACE).unwrap();
        assert_eq!(
            u32_value(Frame::parse(&b).unwrap().tlv(0x10).unwrap()).unwrap(),
            settings::INTERFACE
        );
        let ind = Builder::indication(id::EXTENDED_IP_CONFIG)
            .u32(0x10, settings::MTU)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            parse_extended_ip_config(&Frame::parse(&ind).unwrap()).unwrap(),
            settings::MTU
        );
    }
}
