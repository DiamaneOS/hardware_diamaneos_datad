// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Value types shared by the engine, the daemon protocol and the DSI layer.
use dataos_qmi::wds::{Auth, IpFamily, RuntimeSettings};

/// Engine-wide call identifier. Never reused while the call exists.
pub type CallId = u32;
/// One QMI client (one QRTR socket) as seen by the engine.
pub type ClientId = u32;

/// SIM slot, zero based.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Slot(pub u8);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn wds(self) -> IpFamily {
        match self {
            Family::V4 => IpFamily::V4,
            Family::V6 => IpFamily::V6,
        }
    }
}

/// Requested IP version of a call, as in the DSI call parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
    V4V6,
}

impl IpVersion {
    pub fn families(self) -> &'static [Family] {
        match self {
            IpVersion::V4 => &[Family::V4],
            IpVersion::V6 => &[Family::V6],
            IpVersion::V4V6 => &[Family::V4, Family::V6],
        }
    }
}

/// Who asks. An emergency call may take the links reserved for it and is not
/// counted against a connection's quota. The engine treats it no differently
/// otherwise: parameters reach the modem unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Priority {
    #[default]
    Normal,
    Emergency,
}

/// A Start Network TLV the engine has no name for, sent to the modem as it is.
#[derive(Clone, PartialEq, Eq)]
pub struct RawTlv {
    pub tag: u8,
    pub value: Vec<u8>,
}

/// Parameters of one call. Passed to the modem unchanged: the engine does not
/// look at the APN, so it cannot treat an emergency APN differently.
#[derive(Clone)]
pub struct CallParams {
    pub slot: Slot,
    /// The WDS subscription to bind, when the module's value is passed on as it is (0 default,
    /// 1 the first SIM, 2 the second). None: the one after the slot.
    pub subscription: Option<u8>,
    pub apn: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub auth: Option<Auth>,
    pub profile_index: Option<u8>,
    pub ip_version: IpVersion,
    /// WDS technology preference bits (1 = 3GPP).
    pub technology_preference: Option<u8>,
    pub priority: Priority,
    /// Call setup parameters without a typed field (APN type, APN type mask,
    /// handoff context, SSC mode), in the order the caller gave them.
    pub start_tlvs: Vec<RawTlv>,
    /// The closed data module starts the network call itself. The engine only
    /// follows the call: it binds a client of its own to the link, waits for the
    /// packet status of the call, reads its settings and configures the link. It
    /// never sends Start Network, and the link stays held until it is released.
    pub attach: bool,
}

impl Default for CallParams {
    fn default() -> Self {
        CallParams {
            slot: Slot(0),
            subscription: None,
            apn: None,
            username: None,
            password: None,
            auth: None,
            profile_index: None,
            ip_version: IpVersion::V4,
            technology_preference: None,
            priority: Priority::Normal,
            start_tlvs: Vec::new(),
            attach: false,
        }
    }
}

// No derived Debug: APN and credentials stay out of logs.
impl std::fmt::Debug for CallParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallParams")
            .field("slot", &self.slot)
            .field("ip_version", &self.ip_version)
            .field("priority", &self.priority)
            .field("start_tlvs", &self.start_tlvs.len())
            .finish_non_exhaustive()
    }
}

impl CallParams {
    /// Everything that can be refused before a link is taken or anything is sent.
    pub fn validate(&self, slots: u8) -> Result<(), StartError> {
        use dataos_qmi::wds::{check_extra_tlv, limits};
        if self.slot.0 >= slots {
            return Err(StartError::Invalid);
        }
        let text_ok = |t: &Option<String>, max: usize| {
            t.as_ref()
                .is_none_or(|s| s.len() <= max && !s.as_bytes().contains(&0))
        };
        if !text_ok(&self.apn, limits::MAX_APN)
            || !text_ok(&self.username, limits::MAX_CRED)
            || !text_ok(&self.password, limits::MAX_CRED)
        {
            return Err(StartError::Invalid);
        }
        if self.start_tlvs.len() > limits::MAX_EXTRA_TLVS {
            return Err(StartError::Invalid);
        }
        for (i, t) in self.start_tlvs.iter().enumerate() {
            let dup = self.start_tlvs.iter().take(i).any(|o| o.tag == t.tag);
            if dup || check_extra_tlv(t.tag, &t.value).is_err() {
                return Err(StartError::Invalid);
            }
        }
        Ok(())
    }
}

/// Why a leg or a call ended. Network reasons keep the modem's numbers so the
/// DSI layer can hand them back unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndReason {
    /// Verbose call end reason (type, reason) from the modem.
    Network { kind: u16, reason: i16 },
    /// Basic call end reason only.
    NetworkBasic(u16),
    /// The modem refused the request without a call end reason.
    Qmi(u16),
    /// Local failure.
    Local(LocalReason),
}

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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartError {
    /// More calls than links.
    NoLink,
    /// Parameters rejected before anything was sent.
    Invalid,
    /// Unknown call identifier.
    NoSuchCall,
    /// The modem side cannot take the request now: too many wait already, or no QMI client.
    Unavailable,
}

/// What the layer above asks the modem when it wants to know whether a call for a request is up
/// already (`Engine::start_lookup`). The APN stays out of the debug output.
#[derive(Clone, PartialEq, Eq)]
pub struct LookupQuery {
    /// The value the subscription is bound to, as the module gave it.
    pub subscription: u8,
    pub family: Family,
    pub apn: Option<String>,
    pub apn_type: Option<u32>,
    pub apn_type_mask: Option<u64>,
    pub hint: LookupHint,
}

/// The other values of the module's request that nicmd passes on to the modem's route lookup.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LookupHint {
    pub profile_3gpp: Option<u8>,
    pub profile_3gpp2: Option<u8>,
    pub xt_pref: Option<u16>,
    pub backup_name: Option<u8>,
    pub backup_type: Option<u8>,
}

impl std::fmt::Debug for LookupQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LookupQuery")
            .field("subscription", &self.subscription)
            .field("family", &self.family)
            .finish_non_exhaustive()
    }
}

/// What the layer above is told. One-to-one with the DSI network events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// Every requested family is up.
    Connected { call: CallId },
    /// Some requested families are up and the others failed.
    PartiallyConnected { call: CallId },
    /// Nothing is up any more (or never was).
    Disconnected { call: CallId, reason: EndReason },
    /// Addresses, DNS or a family changed on a connected call.
    Reconfigured { call: CallId },
    /// MTU changed.
    MtuChanged {
        call: CallId,
        family: Family,
        mtu: u32,
    },
    /// An attached call: the family came up and its link is configured.
    LegUp { call: CallId, family: Family },
    /// An attached call: the family went down, the call and its link stay.
    LegDown {
        call: CallId,
        family: Family,
        reason: EndReason,
    },
    /// An attached call: the family could not be followed at all.
    LegFailed {
        call: CallId,
        family: Family,
        reason: EndReason,
    },
    /// A lookup ended. `link` is the link the modem named, if it named a usable one. `companion`:
    /// it was found by asking for the other IP family. `answered`: the modem gave a well-formed answer
    /// to the last question, so no link means it has no call, where an unanswered question (a timeout,
    /// a refusal, an unusable answer, the modem gone) says nothing.
    LookupDone {
        token: u32,
        link: Option<usize>,
        companion: bool,
        answered: bool,
        /// The technology in the first answer of the modem.
        technology: Option<u16>,
    },
}

/// Read-only view of one connected family.
#[derive(Clone, PartialEq, Eq)]
pub struct FamilyInfo {
    pub settings: RuntimeSettings,
    pub mtu: Option<u32>,
}

impl std::fmt::Debug for FamilyInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FamilyInfo")
            .field("settings", &self.settings)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallInfo {
    pub ifname: String,
    /// The MTU set on the link: what the data module must apply, so it can
    /// differ from the family values (never below 1280 with IPv6).
    pub link_mtu: Option<u32>,
    pub v4: Option<FamilyInfo>,
    pub v6: Option<FamilyInfo>,
    pub end_v4: Option<EndReason>,
    pub end_v6: Option<EndReason>,
}

/// Prefix length of a contiguous IPv4 netmask, or None.
pub fn prefix_from_mask(mask: std::net::Ipv4Addr) -> Option<u8> {
    let m = u32::from(mask);
    let ones = m.leading_ones();
    if ones == 32 || m << ones == 0 {
        Some(ones as u8)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks() {
        assert_eq!(
            prefix_from_mask("255.255.255.252".parse().unwrap()),
            Some(30)
        );
        assert_eq!(
            prefix_from_mask("255.255.255.255".parse().unwrap()),
            Some(32)
        );
        assert_eq!(prefix_from_mask("0.0.0.0".parse().unwrap()), Some(0));
        assert_eq!(prefix_from_mask("255.0.255.0".parse().unwrap()), None);
    }

    #[test]
    fn params_debug_is_redacted() {
        let p = CallParams {
            slot: Slot(0),
            subscription: None,
            apn: Some("apn.example".into()),
            username: Some("u".into()),
            password: Some("pw".into()),
            auth: None,
            profile_index: None,
            ip_version: IpVersion::V4V6,
            technology_preference: None,
            priority: Priority::Normal,
            start_tlvs: vec![RawTlv {
                tag: 0x50,
                value: b"secret-value".to_vec(),
            }],
            attach: false,
        };
        let s = format!("{p:?}");
        assert!(!s.contains("apn.example") && !s.contains("pw") && !s.contains("secret"));
    }

    #[test]
    fn validation_refuses_what_could_not_be_sent() {
        use dataos_qmi::wds::limits;
        let ok = CallParams {
            apn: Some("a".repeat(limits::MAX_APN)),
            password: Some("p".repeat(limits::MAX_CRED)),
            start_tlvs: vec![RawTlv {
                tag: 0x50,
                value: vec![0; limits::MAX_EXTRA_TLV_LEN],
            }],
            ..Default::default()
        };
        assert_eq!(ok.validate(2), Ok(()));
        let bad = |f: &dyn Fn(&mut CallParams)| {
            let mut p = ok.clone();
            f(&mut p);
            p.validate(2)
        };
        assert_eq!(bad(&|p| p.slot = Slot(2)), Err(StartError::Invalid));
        assert_eq!(
            bad(&|p| p.apn = Some("a".repeat(limits::MAX_APN + 1))),
            Err(StartError::Invalid)
        );
        assert_eq!(
            bad(&|p| p.apn = Some("a\0".into())),
            Err(StartError::Invalid)
        );
        assert_eq!(
            bad(&|p| p.username = Some("u".repeat(limits::MAX_CRED + 1))),
            Err(StartError::Invalid)
        );
        assert_eq!(
            bad(&|p| p.start_tlvs[0].value = vec![0; limits::MAX_EXTRA_TLV_LEN + 1]),
            Err(StartError::Invalid)
        );
        // a typed tag, the result tag, a repeated tag and too many extras
        for tag in [0x14u8, 0x31, 0x02] {
            assert_eq!(
                bad(&|p| p.start_tlvs[0].tag = tag),
                Err(StartError::Invalid)
            );
        }
        assert_eq!(
            bad(&|p| p.start_tlvs.push(RawTlv {
                tag: 0x50,
                value: vec![]
            })),
            Err(StartError::Invalid)
        );
        assert_eq!(
            bad(&|p| p.start_tlvs = (0..9)
                .map(|i| RawTlv {
                    tag: 0x60 + i,
                    value: vec![]
                })
                .collect()),
            Err(StartError::Invalid)
        );
    }
}
