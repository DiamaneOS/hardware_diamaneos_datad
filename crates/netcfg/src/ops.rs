// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The operations a data call needs from the kernel, as a trait so that call
//! logic runs in host tests against `FakeNet`.
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetError {
    /// Interface or address does not exist.
    NotFound,
    /// Interface or address already exists.
    Exists,
    /// Argument rejected before it reached the kernel.
    Invalid,
    /// The kernel did not answer in time.
    TimedOut,
    /// The kernel refused with this errno.
    Os(i32),
}

/// rmnet link flags (`struct ifla_rmnet_flags`: the flags asked for and the mask of the bits that count).
///
/// The bits are the ones of `datarmnet`, the module of this tree (`core/rmnet_private.h`), and they are not upstream's
/// from bit 4 on: upstream has the v5 checksum bits at 4 and 5, datarmnet has the coalescing bit at 4 and its own
/// v5 bits at 5 and 6. Stock nicmd's port has the value of `qmap_default` plus bit 27.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RmnetFlags {
    pub flags: u32,
    pub mask: u32,
}

impl RmnetFlags {
    /// Split the QMAP frames of a received aggregate.
    pub const INGRESS_DEAGGREGATION: u32 = 1 << 0;
    /// QMAP command frames are handled by the module. Stock does not set it (flow commands go through the
    /// DL marker bits), and `datad` leaves it off too.
    pub const INGRESS_MAP_COMMANDS: u32 = 1 << 1;
    /// The v4 checksum trailer and header. IPA with checksum offload writes the v5 header, so these stay off.
    pub const INGRESS_MAP_CKSUMV4: u32 = 1 << 2;
    pub const EGRESS_MAP_CKSUMV4: u32 = 1 << 3;
    /// Frames of the coalescing pipe (RSC), which carry several packets under one header.
    pub const INGRESS_COALESCE: u32 = 1 << 4;
    /// The v5 header with the checksum result on the way in and the v5 checksum header on the way out.
    pub const INGRESS_MAP_CKSUMV5: u32 = 1 << 5;
    pub const EGRESS_MAP_CKSUMV5: u32 = 1 << 6;
    /// The module tells the QMI side that the port takes power save notifications. Read by the power save
    /// code of datarmnet only, which does nothing without a QMI client for flow control.
    pub const FORMAT_PS_NOTIF: u32 = 1 << 26;
    /// The port is in the power save format. This is a state, and datarmnet sets it itself when a flow control
    /// client with power save is registered for the port (`qmi_rmnet_change_link` with the power save flag, then
    /// `rmnet_set_powersave_format`), and every new link keeps it (`rmnet_newlink`). The flags read from the phone show
    /// the port's state, not what nicmd asked for. `datad` has no such client and does not ask for it, so a port
    /// that does not have it is not made to claim it. The paths that read it restart the power save work of the
    /// QMI client (`qmi_rmnet_work_maybe_restart`), which returns at once without one.
    pub const INGRESS_FORMAT_PS: u32 = 1 << 27;
    /// Priority marks on the uplink: a packet whose `skb->priority` is the low latency mark (0xDA001A) or an APS
    /// low latency bearer packet gets the priority bit in its v5 checksum header and is sent at once, past the
    /// uplink aggregation (`rmnet_map_v5_check_priority`, `rmnet_map_tx_aggregate`). Every other packet is as without
    /// the bit. Only qmipriod's marked packets have an effect.
    pub const EGRESS_FORMAT_PRIORITY: u32 = 1 << 28;
    /// Downlink flow markers, version 2: command frames with flow start and end go to the flow control code
    /// of datarmnet. The modem sends none unless flow control is set up with it, which `datad` does not.
    pub const INGRESS_FORMAT_DL_MARKER_V2: u32 = 1 << 29;
    pub const INGRESS_FORMAT_DL_MARKER_V1: u32 = 1 << 30;
    /// The module aggregates uplink packets itself before they reach the IPA pipe (up to the aggregation
    /// parameters of the link, 20 packets by default).
    pub const EGRESS_FORMAT_AGGREGATION: u32 = 1 << 31;

    /// The port of stock on the FP6 reads 0xbc000071 with the mask 0xffffffff on every link (read from a stock phone). This is
    /// that value without bit 27, 0xb4000071, because bit 27 is a state datarmnet sets by itself (see
    /// `INGRESS_FORMAT_PS`) and not a flag to ask for, and a newlink keeps it where it is set. The rest: deaggregation,
    /// coalescing, and the v5 headers both ways (bits 0, 4, 5, 6), and the module's own uplink aggregation, the uplink
    /// priority marks, the power save notification and flow marker version 2 (bits 31, 28, 26, 29). The commands bit,
    /// the v4 bits and marker version 1 are off.
    pub fn qmap_default() -> Self {
        RmnetFlags {
            flags: Self::INGRESS_DEAGGREGATION
                | Self::INGRESS_COALESCE
                | Self::INGRESS_MAP_CKSUMV5
                | Self::EGRESS_MAP_CKSUMV5
                | Self::FORMAT_PS_NOTIF
                | Self::EGRESS_FORMAT_PRIORITY
                | Self::INGRESS_FORMAT_DL_MARKER_V2
                | Self::EGRESS_FORMAT_AGGREGATION,
            mask: u32::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct AddrFlags {
    /// Skip duplicate address detection. The network assigned the address.
    pub no_dad: bool,
    /// Do not add an on-link prefix route. A 3GPP prefix is not on-link.
    pub no_prefix_route: bool,
}

/// Per-interface IPv6 sysctl the data path sets: IPv6 is on while a call runs on the link and off when it
/// ends, and nothing else. `accept_ra` and `autoconf` stay as the system has them (2 and 1 on the stock
/// phone), because the kernel's own autoconfiguration from the modem's router advertisement is what
/// gives a working IPv6 address and default route there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6Settings {
    pub disable_ipv6: bool,
}

/// One endpoint of the uplink format (`struct rmnet_egress_param`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EgressPipe {
    pub ep_type: u32,
    pub cs_offload: bool,
    pub aggregation: bool,
    pub ulso: bool,
    pub ipid_min_max_idx: u32,
    pub int_modt: u32,
    pub int_modc: u32,
}

impl EgressPipe {
    pub const DEFAULT: u32 = 0;
    pub const LOW_LAT_CTRL: u32 = 1;
}

/// One endpoint of the downlink format (`struct rmnet_ingress_param`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IngressPipe {
    pub ep_type: u32,
    pub cs_offload: bool,
    pub buff_size: u32,
    pub agg_byte_limit: u32,
    pub agg_time_limit: u32,
    pub agg_pkt_limit: u32,
    pub int_modt: u32,
    pub int_modc: u32,
}

impl IngressPipe {
    pub const COALESCING: u32 = 0;
    pub const DEFAULT: u32 = 1;
    pub const LOW_LAT_CTRL: u32 = 2;
}

/// What the driver says about one endpoint after a format request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipeStatus {
    /// Set up now.
    Set,
    /// Up already, from an earlier request: nothing was changed.
    Existed,
    /// Not set up.
    Failed,
}

/// The pipes of the physical device as the driver reports them: the endpoint (interface) number for the data
/// path, and the numbers of the consumer and producer pipes that the modem's port mapper is told.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub epid: u32,
    pub consumer: u32,
    pub producer: u32,
}

/// How far the setup of one IPA pipe got, as an instance left it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipeState {
    /// Nothing was started.
    Missing,
    /// The ioctl was about to be sent. It may have worked, and the instance may
    /// have died before it could say so.
    Pending,
    /// The ioctl worked.
    Done,
}

impl PipeState {
    fn code(self) -> u8 {
        match self {
            PipeState::Missing => 0,
            PipeState::Pending => 1,
            PipeState::Done => 2,
        }
    }

    fn from_code(c: &str) -> Option<Self> {
        match c {
            "0" => Some(PipeState::Missing),
            "1" => Some(PipeState::Pending),
            "2" => Some(PipeState::Done),
            _ => None,
        }
    }
}

/// What a daemon instance leaves behind while it sets up the physical device,
/// so the next instance can tell what is already there. The IPA driver does not
/// set a pipe up twice and says so in the status of its answer (`PipeStatus::Existed`),
/// and it frees the pipes only when the modem shuts down, which also gives the
/// device a new interface index. So the marker saves a request and tells whether the
/// modem side was set up as well (the data format and the port request may be
/// refused a second time). A repeated ingress request is answered with `EPERM` after the driver wrote
/// `EXISTS` into the status of each pipe, which `ipa::ingress_result` takes for the pipes being up. The marker is written before
/// each ioctl (`Pending`) and after it (`Done`), so a crash in between leaves a
/// trace. It is good only for the same interface index, and for the same boot
/// when the boot ID could be read at both times. `-` stands for an unknown boot
/// ID. The directory is on tmpfs, so a marker cannot outlive a boot anyway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupMarker {
    pub boot_id: String,
    pub ifindex: i32,
    pub egress: PipeState,
    pub ingress: PipeState,
}

impl SetupMarker {
    /// One line: boot ID, interface index, egress state, ingress state.
    pub fn to_text(&self) -> String {
        format!(
            "{} {} {} {}\n",
            self.boot_id,
            self.ifindex,
            self.egress.code(),
            self.ingress.code()
        )
    }

    pub fn parse(text: &str) -> Option<SetupMarker> {
        let mut it = text.split_whitespace();
        let boot_id = it.next()?.to_string();
        let ifindex = it.next()?.parse().ok()?;
        let egress = PipeState::from_code(it.next()?)?;
        let ingress = PipeState::from_code(it.next()?)?;
        if it.next().is_some() || boot_id.len() > 64 || ifindex <= 0 {
            return None;
        }
        Some(SetupMarker {
            boot_id,
            ifindex,
            egress,
            ingress,
        })
    }
}

/// The most the table of links may be, read or written.
pub const MAX_LINKS_FILE: usize = 8192;

/// Device features by the name ethtool gives them (the strings of `ETH_SS_FEATURES`). The driver of `rmnet_ipa0` and
/// `datarmnet` for the rmnet links put offloads in `hw_features` only, and the kernel does not switch those on
/// at register, so nothing is on until someone asks. Stock nicmd asks for this set on `rmnet_ipa0` and on every
/// rmnet link (`Nicm::Ethtool::setFeature`). Read from a stock phone: all twelve active on
/// `rmnet_ipa0`, `rmnet_data0` and `rmnet_data1`, and `tx-nocache-copy`, `rx-gro-list` and
/// `rx-udp-gro-forwarding` available and off.
///
/// All twelve are needed on `rmnet_ipa0`, and not only the ones the first pipe request depends on (`rx-gro-hw`,
/// which the kernel drops without `rx-checksum`, and a transmit checksum for the checksum header of the uplink
/// pipe). The uplink pipe is a ULSO pipe only when `rmnet_ipa0` has scatter-gather or a TSO feature on at the egress
/// request (`rmnet_ipa.c`, `RMNET_IPA_ULSO_FEATURE`), and datarmnet always offers TSO and USO on the links,
/// so a link that segments for a pipe that cannot take it is a link that sends damaged frames. Stock has all
/// twelve on the device, so the daemon asks for them and does not go on without them.
pub const STOCK_FEATURES: [&str; 12] = [
    "tx-scatter-gather",
    "tx-checksum-ipv4",
    "tx-checksum-ipv6",
    "tx-generic-segmentation",
    "rx-gro",
    "tx-tcp-segmentation",
    "tx-tcp-ecn-segmentation",
    "tx-tcp-mangleid-segmentation",
    "tx-tcp6-segmentation",
    "tx-udp-segmentation",
    "rx-checksum",
    "rx-gro-hw",
];

pub trait NetOps {
    fn create_rmnet_link(
        &mut self,
        parent: &str,
        name: &str,
        mux_id: u8,
        flags: RmnetFlags,
    ) -> Result<(), NetError>;
    fn delete_link(&mut self, name: &str) -> Result<(), NetError>;
    fn set_link(&mut self, name: &str, up: bool, mtu: Option<u32>) -> Result<(), NetError>;
    fn add_address(
        &mut self,
        name: &str,
        addr: IpAddr,
        prefix: u8,
        flags: AddrFlags,
    ) -> Result<(), NetError>;
    fn del_address(&mut self, name: &str, addr: IpAddr, prefix: u8) -> Result<(), NetError>;
    fn set_ipv6(&mut self, name: &str, cfg: Ipv6Settings) -> Result<(), NetError>;
    /// Index of an interface. `NotFound` when there is none.
    fn ifindex(&mut self, name: &str) -> Result<i32, NetError>;
    /// The kernel's boot ID, different at every boot.
    fn boot_id(&mut self) -> Result<String, NetError>;
    /// The marker an earlier instance stored, if any and readable.
    fn load_marker(&mut self) -> Option<SetupMarker>;
    fn store_marker(&mut self, marker: &SetupMarker) -> Result<(), NetError>;
    /// The table of the links handed out, as an earlier instance stored it: a small file in the same
    /// directory as the marker. At most `MAX_LINKS_FILE` bytes are read, anything else is None.
    fn load_links(&mut self) -> Option<Vec<u8>>;
    fn store_links(&mut self, bytes: &[u8]) -> Result<(), NetError>;
    /// The endpoint number and the pipe pair of the physical device (`RMNET_IOCTL_GET_EPID` and
    /// `RMNET_IOCTL_GET_EP_PAIR`).
    fn ipa_endpoint(&mut self, device: &str) -> Result<Endpoint, NetError>;
    /// Uplink pipe format of the physical device (the egress request of `RMNET_IOCTL_EXTENDED_V2`). Every
    /// endpoint must come back set up or up already, `Existed` when all of them were up before.
    fn ipa_set_egress_format(
        &mut self,
        device: &str,
        pipes: &[EgressPipe],
    ) -> Result<PipeStatus, NetError>;
    /// Downlink pipe format of the physical device (the ingress request of `RMNET_IOCTL_EXTENDED_V2`).
    fn ipa_set_ingress_format(
        &mut self,
        device: &str,
        pipes: &[IngressPipe],
    ) -> Result<PipeStatus, NetError>;
    /// Register a mux ID and link name with the physical device (`RMNET_IOCTL_ADD_MUX_CHANNEL`).
    fn ipa_add_mux_channel(&mut self, device: &str, mux_id: u8, link: &str)
        -> Result<(), NetError>;
    /// Turn device features on by name and read them back (`SIOCETHTOOL`: the names of `ETH_SS_FEATURES`, then
    /// `ETHTOOL_SFEATURES` and `ETHTOOL_GFEATURES`). The answer is the names among `wanted` that are not
    /// active afterwards: unknown to the kernel, not offered by the device, or dropped by the kernel (it drops
    /// `rx-gro-hw` without `rx-checksum`). An error is a request that failed.
    fn set_features(&mut self, name: &str, wanted: &[&str]) -> Result<Vec<String>, NetError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flag_bits_are_those_of_datarmnet_and_the_default_is_what_stock_sets() {
        // core/rmnet_private.h of the 6.18 modem-data tree and the UAPI bits 0 to 3
        assert_eq!(
            [
                RmnetFlags::INGRESS_DEAGGREGATION,
                RmnetFlags::INGRESS_MAP_COMMANDS,
                RmnetFlags::INGRESS_MAP_CKSUMV4,
                RmnetFlags::EGRESS_MAP_CKSUMV4,
                RmnetFlags::INGRESS_COALESCE,
                RmnetFlags::INGRESS_MAP_CKSUMV5,
                RmnetFlags::EGRESS_MAP_CKSUMV5,
            ],
            [1, 2, 4, 8, 0x10, 0x20, 0x40]
        );
        assert_eq!(
            [
                RmnetFlags::FORMAT_PS_NOTIF,
                RmnetFlags::INGRESS_FORMAT_PS,
                RmnetFlags::EGRESS_FORMAT_PRIORITY,
                RmnetFlags::INGRESS_FORMAT_DL_MARKER_V2,
                RmnetFlags::INGRESS_FORMAT_DL_MARKER_V1,
                RmnetFlags::EGRESS_FORMAT_AGGREGATION,
            ],
            [
                0x0400_0000,
                0x0800_0000,
                0x1000_0000,
                0x2000_0000,
                0x4000_0000,
                0x8000_0000
            ]
        );
        // read from every link of a stock FP6: 0xbc000071 with the mask 0xffffffff, of which bit 27 is
        // the state datarmnet sets itself and is not asked for
        let d = RmnetFlags::qmap_default();
        assert_eq!((d.flags, d.mask), (0xb400_0071, 0xffff_ffff));
        assert_eq!(d.flags | RmnetFlags::INGRESS_FORMAT_PS, 0xbc00_0071);
        for off in [
            RmnetFlags::INGRESS_MAP_COMMANDS,
            RmnetFlags::INGRESS_MAP_CKSUMV4,
            RmnetFlags::EGRESS_MAP_CKSUMV4,
            RmnetFlags::INGRESS_FORMAT_DL_MARKER_V1,
        ] {
            assert_eq!(d.flags & off, 0);
        }
    }

    #[test]
    fn the_stock_features_are_twelve_distinct_names() {
        let mut names = STOCK_FEATURES.to_vec();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 12);
        for n in STOCK_FEATURES {
            assert!(n.starts_with("tx-") || n.starts_with("rx-"));
        }
    }

    #[test]
    fn markers_round_trip_and_bad_text_is_refused() {
        for (e, i) in [
            (PipeState::Done, PipeState::Pending),
            (PipeState::Missing, PipeState::Missing),
            (PipeState::Pending, PipeState::Done),
        ] {
            let m = SetupMarker {
                boot_id: "0a1b2c3d-0000-4000-8000-000000000001".into(),
                ifindex: 17,
                egress: e,
                ingress: i,
            };
            assert_eq!(SetupMarker::parse(&m.to_text()), Some(m));
        }
        let unknown_boot = SetupMarker::parse("- 5 2 2").unwrap();
        assert_eq!(unknown_boot.boot_id, "-");
        for bad in [
            "",
            "boot",
            "boot 5",
            "boot 5 1",
            "boot x 1 1",
            "boot 0 1 1",
            "boot -3 1 1",
            "boot 5 3 1",
            "boot 5 1 9",
            "boot 5 1 1 extra",
        ] {
            assert_eq!(SetupMarker::parse(bad), None, "{bad:?}");
        }
        assert_eq!(
            SetupMarker::parse(&format!("{} 5 1 1", "a".repeat(65))),
            None
        );
    }
}
