// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! A recording fake of the kernel for host tests. It keeps the state the real
//! kernel keeps and that matters here: which links exist on which device, which
//! IPA pipes are set up, and which mux channels are registered. A modem restart
//! makes it forget all of that, like `rmnet_ipa0` being freed and registered again.
//! Not part of production builds (feature `fake`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use crate::ipa;
use crate::ops::{
    AddrFlags, EgressPipe, Endpoint, IngressPipe, Ipv6Settings, NetError, NetOps, PipeStatus,
    RmnetFlags, SetupMarker, STOCK_FEATURES,
};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::rc::Rc;

/// One recorded call. Addresses are kept so tests can assert on them. The
/// type has no Debug, so a failing assertion cannot print them into a log.
#[derive(Clone, PartialEq, Eq)]
pub enum Call {
    CreateLink {
        name: String,
        mux_id: u8,
    },
    DeleteLink(String),
    SetLink {
        name: String,
        up: bool,
        mtu: Option<u32>,
    },
    AddAddr {
        name: String,
        addr: IpAddr,
        prefix: u8,
        flags: AddrFlags,
    },
    DelAddr {
        name: String,
        addr: IpAddr,
        prefix: u8,
    },
    SetIpv6 {
        name: String,
        cfg: Ipv6Settings,
    },
    IpaEndpoint {
        device: String,
    },
    IpaEgress {
        device: String,
        pipes: Vec<EgressPipe>,
    },
    IpaIngress {
        device: String,
        pipes: Vec<IngressPipe>,
    },
    IpaAddMux {
        device: String,
        mux_id: u8,
        link: String,
    },
    SetFeatures {
        name: String,
        wanted: Vec<String>,
    },
}

struct FakeLink {
    name: String,
    parent: String,
    mux_id: u8,
    ifindex: i32,
    flags: RmnetFlags,
}

/// The state of `rmnet_ipa0` that the driver (`rmnet_ipa.c`) keeps and the data path depends on.
#[derive(Default)]
struct FakeDevice {
    name: String,
    ifindex: i32,
    /// The uplink pipe is up, and with the 8 byte checksum header (`hdr_len` 8) or without.
    egress: bool,
    egress_csum_header: bool,
    egress_ll: bool,
    /// The default downlink pipe is up, and with the 8 byte checksum header.
    ingress: bool,
    ingress_csum_header: bool,
    /// The coalescing pipe, which the driver sets up only with `rx-gro-hw` on.
    coal: bool,
    ingress_ll: bool,
    /// The default WAN routing tables (`wan_rt_table_setup`), set up by the first ingress request that has a
    /// data pipe, and the reason a later one answers `EPERM`.
    wan_rt: bool,
    mux: Vec<(u8, String)>,
}

pub struct FakeNet {
    pub calls: Vec<Call>,
    /// Fail the next call whose kind matches with this error. Kinds: create,
    /// set, add, ipa_endpoint, ipa_egress, ipa_ingress, ipa_mux, features.
    pub fail_next: Option<(&'static str, NetError)>,
    /// The features the devices offer (`hw_features`). A feature that is not here cannot be switched on.
    pub offered_features: Vec<String>,
    /// Features the links do not offer although the physical device does (the part of `offered_features`
    /// that the virtual devices of datarmnet lack).
    pub links_lack_features: Vec<String>,
    /// The driver fails the low latency control pipes and goes on, as it does when the pipe cannot be made.
    pub refuse_low_latency_ctrl: bool,
    /// Distinct mux IDs one device accepts (the driver's `MAX_NUM_OF_MUX_CHANNEL`).
    pub mux_limit: usize,
    /// Pipe setups the driver answered with "up already" because the pipe existed.
    pub pipe_refusals: u32,
    /// What the driver reports for the endpoint: the interface number and the pipe pair of the stock phone.
    pub endpoint: Endpoint,
    /// The marker file of the daemon. It survives a daemon restart and a reboot.
    pub marker: Option<SetupMarker>,
    /// Fail storing the marker.
    pub marker_unwritable: bool,
    /// Let this many more stores work, then fail them (a crash, a full disk).
    pub marker_stores_left: Option<u32>,
    /// The boot ID cannot be read.
    pub boot_id_unreadable: bool,
    /// The table of links an instance stored, and what goes wrong with it.
    pub links_file: Option<Vec<u8>>,
    pub links_unwritable: bool,
    /// How many times the table was written.
    pub links_stores: u32,
    /// Fail every interface lookup with this error (not `NotFound`).
    pub ifindex_error: Option<NetError>,
    /// The features that are on, by device or link name.
    features: BTreeMap<String, Vec<String>>,
    boot: u32,
    next_ifindex: i32,
    links: Vec<FakeLink>,
    devices: Vec<FakeDevice>,
}

impl Default for FakeNet {
    fn default() -> Self {
        let mut n = FakeNet {
            calls: Vec::new(),
            fail_next: None,
            offered_features: STOCK_FEATURES.iter().map(|f| f.to_string()).collect(),
            links_lack_features: Vec::new(),
            refuse_low_latency_ctrl: false,
            mux_limit: crate::ipa::MAX_MUX_CHANNELS,
            pipe_refusals: 0,
            endpoint: Endpoint {
                epid: 1,
                consumer: 2,
                producer: 18,
            },
            marker: None,
            marker_unwritable: false,
            marker_stores_left: None,
            boot_id_unreadable: false,
            links_file: None,
            links_unwritable: false,
            links_stores: 0,
            ifindex_error: None,
            features: BTreeMap::new(),
            boot: 1,
            next_ifindex: 3,
            links: Vec::new(),
            devices: Vec::new(),
        };
        n.add_device("rmnet_ipa0");
        n
    }
}

impl FakeNet {
    pub fn new() -> Self {
        Self::default()
    }

    /// The physical device appears (driver registered it).
    pub fn add_device(&mut self, name: &str) {
        if !self.devices.iter().any(|d| d.name == name) {
            let ifindex = self.take_ifindex();
            self.devices.push(FakeDevice {
                name: name.into(),
                ifindex,
                ..Default::default()
            });
            self.reset_features(name);
        }
    }

    /// A new net device has the soft features on and the offloads off, whatever it offers.
    fn reset_features(&mut self, name: &str) {
        let soft = ["tx-generic-segmentation", "rx-gro"];
        self.features
            .insert(name.into(), soft.iter().map(|f| f.to_string()).collect());
    }

    /// The features that are on for a device or a link.
    pub fn features_of(&self, name: &str) -> Vec<String> {
        self.features.get(name).cloned().unwrap_or_default()
    }

    /// The uplink pipe has the checksum header.
    pub fn egress_has_csum_header(&self, device: &str) -> bool {
        self.devices
            .iter()
            .any(|d| d.name == device && d.egress && d.egress_csum_header)
    }

    fn take_ifindex(&mut self) -> i32 {
        self.next_ifindex += 1;
        self.next_ifindex
    }

    /// The phone restarted: every device and link is new, the boot ID changed.
    /// Files, like the marker, stay. Devices register in the same order, so
    /// `rmnet_ipa0` gets the interface index it had before.
    pub fn reboot(&mut self) {
        let names: Vec<String> = self.devices.iter().map(|d| d.name.clone()).collect();
        self.devices.clear();
        self.links.clear();
        self.features.clear();
        self.boot += 1;
        self.next_ifindex = 3;
        // the directory is on tmpfs
        self.links_file = None;
        for n in names {
            self.add_device(&n);
        }
    }

    /// The physical device disappears and the kernel deletes every link on it.
    pub fn remove_device(&mut self, name: &str) {
        self.devices.retain(|d| d.name != name);
        let gone: Vec<String> = self
            .links
            .iter()
            .filter(|l| l.parent == name)
            .map(|l| l.name.clone())
            .collect();
        self.links.retain(|l| l.parent != name);
        self.features.remove(name);
        for l in gone {
            self.features.remove(&l);
        }
    }

    /// Modem shutdown and power-up: the device is freed and registered again,
    /// so links, pipes and mux channels are gone.
    pub fn modem_restart(&mut self) {
        let names: Vec<String> = self.devices.iter().map(|d| d.name.clone()).collect();
        for n in names {
            self.remove_device(&n);
            self.add_device(&n);
        }
    }

    pub fn has_link(&self, name: &str) -> bool {
        self.links.iter().any(|l| l.name == name)
    }

    /// The address was added to the link and not deleted since.
    pub fn has_address(&self, link: &str, ip: IpAddr) -> bool {
        let mut present = false;
        for c in &self.calls {
            match c {
                Call::AddAddr { name, addr, .. } if name == link && *addr == ip => present = true,
                Call::DelAddr { name, addr, .. } if name == link && *addr == ip => present = false,
                _ => {}
            }
        }
        present
    }

    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// A packet could flow on this link: it exists, both pipes of its device are set up (the downlink with the
    /// WAN routing tables and, where the device has the coalescing pipe, with that pipe), its mux channel is
    /// registered, and the module reads the frames the pipes write. The headers must agree. With the checksum header
    /// on the pipe the module needs the v5 bit of that direction and no v4 bit (the v4 path misreads a v5 header),
    /// without it the v5 bit is wrong, and a coalescing pipe needs the coalescing bit.
    pub fn data_path_ok(&self, link: &str) -> bool {
        let Some(l) = self.links.iter().find(|l| l.name == link) else {
            return false;
        };
        let f = l.flags.flags & l.flags.mask;
        let v4 = RmnetFlags::INGRESS_MAP_CKSUMV4 | RmnetFlags::EGRESS_MAP_CKSUMV4;
        let has = |bit: u32| f & bit != 0;
        self.devices.iter().any(|d| {
            d.name == l.parent
                && d.egress
                && d.ingress
                && d.wan_rt
                && d.mux.iter().any(|(m, n)| *m == l.mux_id && n == link)
                && f & v4 == 0
                && has(RmnetFlags::EGRESS_MAP_CKSUMV5) == d.egress_csum_header
                && has(RmnetFlags::INGRESS_MAP_CKSUMV5) == d.ingress_csum_header
                && (!d.coal || has(RmnetFlags::INGRESS_COALESCE))
                && has(RmnetFlags::INGRESS_DEAGGREGATION)
        })
    }

    pub fn mux_channels(&self, device: &str) -> usize {
        self.devices
            .iter()
            .find(|d| d.name == device)
            .map_or(0, |d| d.mux.len())
    }

    fn has_feature(&self, device: &str, feature: &str) -> bool {
        self.features
            .get(device)
            .is_some_and(|on| on.iter().any(|f| f == feature))
    }

    /// How many pipes of the device are up, to tell a request that set something up from one that did not.
    fn pipes_up(&self, device: &str) -> usize {
        self.devices
            .iter()
            .find(|d| d.name == device)
            .map_or(0, |d| {
                [d.egress, d.egress_ll, d.ingress, d.coal, d.ingress_ll]
                    .iter()
                    .filter(|p| **p)
                    .count()
            })
    }

    /// A request that set up a pipe is recorded. One that found every pipe up is a refusal of the driver.
    fn record_format(&mut self, device: &str, before: usize, call: impl FnOnce() -> Call) {
        if self.pipes_up(device) > before {
            self.calls.push(call());
        } else {
            self.pipe_refusals += 1;
        }
    }

    /// `handle3_egress_format_v2` of `rmnet_ipa.c`, on the bytes of the request. The status of each endpoint
    /// starts as a failure and is set by what the driver does. A pipe that is up says `EXISTS`. The uplink pipe
    /// has the checksum header only when the request asks for the offload and the device has a transmit
    /// checksum on (`RMNET_IPA_ULCS_FEATURE`), and the low latency control pipe does not need anything.
    fn driver_egress(&mut self, device: &str, params: &mut [u8]) -> Result<(), NetError> {
        let csum = self.has_feature(device, "tx-checksum-ipv4")
            || self.has_feature(device, "tx-checksum-ipv6");
        let refuse_ll = self.refuse_low_latency_ctrl;
        let dev = self.device(device)?;
        for p in params.chunks_exact_mut(ipa::EGRESS_PARAM_LEN) {
            let word =
                |p: &[u8], at: usize| u32::from_ne_bytes([p[at], p[at + 1], p[at + 2], p[at + 3]]);
            let (ty, cs, ulso) = (word(p, 0), word(p, 8) != 0, word(p, 16) != 0);
            let status: u32 = match ty {
                0 if dev.egress => 2,
                // cs offload has to be on for ULSO
                0 if !cs && ulso => 1,
                0 => {
                    dev.egress = true;
                    dev.egress_csum_header = cs && csum;
                    0
                }
                1 if dev.egress_ll => 2,
                1 if refuse_ll => 1,
                1 => {
                    dev.egress_ll = true;
                    0
                }
                _ => 1,
            };
            p[4..8].copy_from_slice(&status.to_ne_bytes());
        }
        Ok(())
    }

    /// `handle3_ingress_format_v2` of `rmnet_ipa.c`, on the bytes of the request. The default pipe is refused
    /// with `EFAULT` before anything is written back when the device has `rx-gro-hw` on and the coalescing pipe is
    /// not up. The coalescing pipe is skipped without `rx-gro-hw`: the status stays a failure and the ioctl
    /// goes on. Then the WAN routing tables are made once, by the first request that has a data pipe, and a later
    /// one answers `EPERM` after the statuses were written back.
    fn driver_ingress(&mut self, device: &str, params: &mut [u8]) -> Result<(), NetError> {
        let gro = self.has_feature(device, "rx-gro-hw");
        let refuse_ll = self.refuse_low_latency_ctrl;
        let dev = self.device(device)?;
        let mut out = params.to_vec();
        for p in out.chunks_exact_mut(ipa::INGRESS_PARAM_LEN) {
            let word =
                |p: &[u8], at: usize| u32::from_ne_bytes([p[at], p[at + 1], p[at + 2], p[at + 3]]);
            let (ty, cs) = (word(p, 0), word(p, 8) != 0);
            let status: u32 = match ty {
                1 if dev.ingress => 2,
                1 if gro && !dev.coal => return Err(NetError::Os(14)),
                1 => {
                    dev.ingress = true;
                    dev.ingress_csum_header = cs;
                    0
                }
                0 if dev.coal => 2,
                0 if gro => {
                    dev.coal = true;
                    dev.ingress_csum_header = cs;
                    0
                }
                0 => 1,
                2 if dev.ingress_ll => 2,
                2 if refuse_ll => 1,
                2 => {
                    dev.ingress_ll = true;
                    0
                }
                _ => 1,
            };
            p[4..8].copy_from_slice(&status.to_ne_bytes());
        }
        params.copy_from_slice(&out);
        let data_pipe = if gro {
            dev.ingress || dev.coal
        } else {
            dev.ingress
        };
        if data_pipe {
            if dev.wan_rt {
                return Err(NetError::Os(1));
            }
            dev.wan_rt = true;
        }
        Ok(())
    }

    fn check(&mut self, kind: &'static str) -> Result<(), NetError> {
        if let Some((k, e)) = self.fail_next {
            if k == kind {
                self.fail_next = None;
                return Err(e);
            }
        }
        Ok(())
    }

    fn device(&mut self, name: &str) -> Result<&mut FakeDevice, NetError> {
        self.devices
            .iter_mut()
            .find(|d| d.name == name)
            .ok_or(NetError::NotFound)
    }
}

impl NetOps for FakeNet {
    fn create_rmnet_link(
        &mut self,
        parent: &str,
        name: &str,
        mux_id: u8,
        flags: RmnetFlags,
    ) -> Result<(), NetError> {
        self.check("create")?;
        self.device(parent)?;
        if self.has_link(name) {
            return Err(NetError::Exists);
        }
        let ifindex = self.take_ifindex();
        self.links.push(FakeLink {
            name: name.into(),
            parent: parent.into(),
            mux_id,
            ifindex,
            flags,
        });
        self.reset_features(name);
        self.calls.push(Call::CreateLink {
            name: name.into(),
            mux_id,
        });
        Ok(())
    }

    fn delete_link(&mut self, name: &str) -> Result<(), NetError> {
        if !self.has_link(name) {
            return Err(NetError::NotFound);
        }
        self.links.retain(|l| l.name != name);
        self.features.remove(name);
        self.calls.push(Call::DeleteLink(name.into()));
        Ok(())
    }

    fn set_link(&mut self, name: &str, up: bool, mtu: Option<u32>) -> Result<(), NetError> {
        self.check("set")?;
        if !self.has_link(name) && !self.devices.iter().any(|d| d.name == name) {
            return Err(NetError::NotFound);
        }
        self.calls.push(Call::SetLink {
            name: name.into(),
            up,
            mtu,
        });
        Ok(())
    }

    fn add_address(
        &mut self,
        name: &str,
        addr: IpAddr,
        prefix: u8,
        flags: AddrFlags,
    ) -> Result<(), NetError> {
        self.check("add")?;
        if !self.has_link(name) {
            return Err(NetError::NotFound);
        }
        self.calls.push(Call::AddAddr {
            name: name.into(),
            addr,
            prefix,
            flags,
        });
        Ok(())
    }

    fn del_address(&mut self, name: &str, addr: IpAddr, prefix: u8) -> Result<(), NetError> {
        if !self.has_link(name) {
            return Err(NetError::NotFound);
        }
        self.calls.push(Call::DelAddr {
            name: name.into(),
            addr,
            prefix,
        });
        Ok(())
    }

    fn set_ipv6(&mut self, name: &str, cfg: Ipv6Settings) -> Result<(), NetError> {
        if !self.has_link(name) {
            return Err(NetError::NotFound);
        }
        self.calls.push(Call::SetIpv6 {
            name: name.into(),
            cfg,
        });
        Ok(())
    }

    fn ifindex(&mut self, name: &str) -> Result<i32, NetError> {
        if let Some(e) = self.ifindex_error {
            return Err(e);
        }
        let dev = self
            .devices
            .iter()
            .find(|d| d.name == name)
            .map(|d| d.ifindex);
        let link = self
            .links
            .iter()
            .find(|l| l.name == name)
            .map(|l| l.ifindex);
        dev.or(link).ok_or(NetError::NotFound)
    }

    fn boot_id(&mut self) -> Result<String, NetError> {
        if self.boot_id_unreadable {
            return Err(NetError::Os(13));
        }
        Ok(format!("boot-{}", self.boot))
    }

    fn load_marker(&mut self) -> Option<SetupMarker> {
        self.marker.clone()
    }

    fn store_marker(&mut self, marker: &SetupMarker) -> Result<(), NetError> {
        if self.marker_unwritable {
            return Err(NetError::Os(13));
        }
        match &mut self.marker_stores_left {
            Some(0) => return Err(NetError::Os(5)),
            Some(n) => *n -= 1,
            None => {}
        }
        self.marker = Some(marker.clone());
        Ok(())
    }

    fn load_links(&mut self) -> Option<Vec<u8>> {
        self.links_file.clone()
    }

    fn store_links(&mut self, bytes: &[u8]) -> Result<(), NetError> {
        if self.links_unwritable || bytes.len() > crate::ops::MAX_LINKS_FILE {
            return Err(NetError::Os(13));
        }
        self.links_stores = self.links_stores.saturating_add(1);
        self.links_file = Some(bytes.to_vec());
        Ok(())
    }

    fn ipa_endpoint(&mut self, device: &str) -> Result<Endpoint, NetError> {
        self.check("ipa_endpoint")?;
        self.device(device)?;
        self.calls.push(Call::IpaEndpoint {
            device: device.into(),
        });
        Ok(self.endpoint)
    }

    fn ipa_set_egress_format(
        &mut self,
        device: &str,
        pipes: &[EgressPipe],
    ) -> Result<PipeStatus, NetError> {
        self.check("ipa_egress")?;
        self.device(device)?;
        let mut params: Vec<u8> = pipes.iter().flat_map(ipa::egress_param).collect();
        let before = self.pipes_up(device);
        let rc = self.driver_egress(device, &mut params);
        self.record_format(device, before, || Call::IpaEgress {
            device: device.into(),
            pipes: pipes.to_vec(),
        });
        ipa::egress_result(rc, &params)
    }

    fn ipa_set_ingress_format(
        &mut self,
        device: &str,
        pipes: &[IngressPipe],
    ) -> Result<PipeStatus, NetError> {
        self.check("ipa_ingress")?;
        self.device(device)?;
        let mut params: Vec<u8> = pipes.iter().flat_map(ipa::ingress_param).collect();
        let before = self.pipes_up(device);
        let rc = self.driver_ingress(device, &mut params);
        self.record_format(device, before, || Call::IpaIngress {
            device: device.into(),
            pipes: pipes.to_vec(),
        });
        ipa::ingress_result(rc, &params)
    }

    fn ipa_add_mux_channel(
        &mut self,
        device: &str,
        mux_id: u8,
        link: &str,
    ) -> Result<(), NetError> {
        self.check("ipa_mux")?;
        let limit = self.mux_limit;
        let dev = self.device(device)?;
        // like the driver: a mux ID it already knows is accepted again
        if !dev.mux.iter().any(|(m, _)| *m == mux_id) {
            if dev.mux.len() >= limit {
                return Err(NetError::Os(14));
            }
            dev.mux.push((mux_id, link.to_string()));
        }
        self.calls.push(Call::IpaAddMux {
            device: device.into(),
            mux_id,
            link: link.into(),
        });
        Ok(())
    }

    fn set_features(&mut self, name: &str, wanted: &[&str]) -> Result<Vec<String>, NetError> {
        self.check("features")?;
        if !self.has_link(name) && !self.devices.iter().any(|d| d.name == name) {
            return Err(NetError::NotFound);
        }
        self.calls.push(Call::SetFeatures {
            name: name.into(),
            wanted: wanted.iter().map(|f| f.to_string()).collect(),
        });
        let mut offered = self.offered_features.clone();
        if self.has_link(name) {
            offered.retain(|f| !self.links_lack_features.contains(f));
        }
        let on = self.features.entry(name.into()).or_default();
        for f in wanted {
            if offered.iter().any(|o| o == f) && !on.iter().any(|x| x == f) {
                on.push(f.to_string());
            }
        }
        // the kernel fixes the set after the request: rx-gro-hw needs rx-checksum
        if !on.iter().any(|f| f == "rx-checksum") {
            on.retain(|f| f != "rx-gro-hw");
        }
        Ok(wanted
            .iter()
            .filter(|f| !on.iter().any(|x| x == *f))
            .map(|f| f.to_string())
            .collect())
    }
}

/// One fake kernel for two engines in turn, like a daemon that is restarted
/// on the same phone.
#[derive(Clone)]
pub struct SharedNet(pub Rc<RefCell<FakeNet>>);

impl SharedNet {
    pub fn new() -> Self {
        SharedNet(Rc::new(RefCell::new(FakeNet::new())))
    }
}

impl Default for SharedNet {
    fn default() -> Self {
        Self::new()
    }
}

impl NetOps for SharedNet {
    fn create_rmnet_link(
        &mut self,
        parent: &str,
        name: &str,
        mux_id: u8,
        flags: RmnetFlags,
    ) -> Result<(), NetError> {
        self.0
            .borrow_mut()
            .create_rmnet_link(parent, name, mux_id, flags)
    }
    fn delete_link(&mut self, name: &str) -> Result<(), NetError> {
        self.0.borrow_mut().delete_link(name)
    }
    fn set_link(&mut self, name: &str, up: bool, mtu: Option<u32>) -> Result<(), NetError> {
        self.0.borrow_mut().set_link(name, up, mtu)
    }
    fn add_address(
        &mut self,
        name: &str,
        addr: IpAddr,
        prefix: u8,
        flags: AddrFlags,
    ) -> Result<(), NetError> {
        self.0.borrow_mut().add_address(name, addr, prefix, flags)
    }
    fn del_address(&mut self, name: &str, addr: IpAddr, prefix: u8) -> Result<(), NetError> {
        self.0.borrow_mut().del_address(name, addr, prefix)
    }
    fn set_ipv6(&mut self, name: &str, cfg: Ipv6Settings) -> Result<(), NetError> {
        self.0.borrow_mut().set_ipv6(name, cfg)
    }
    fn ifindex(&mut self, name: &str) -> Result<i32, NetError> {
        self.0.borrow_mut().ifindex(name)
    }
    fn boot_id(&mut self) -> Result<String, NetError> {
        self.0.borrow_mut().boot_id()
    }
    fn load_marker(&mut self) -> Option<SetupMarker> {
        self.0.borrow_mut().load_marker()
    }
    fn store_marker(&mut self, marker: &SetupMarker) -> Result<(), NetError> {
        self.0.borrow_mut().store_marker(marker)
    }
    fn load_links(&mut self) -> Option<Vec<u8>> {
        self.0.borrow_mut().load_links()
    }
    fn store_links(&mut self, bytes: &[u8]) -> Result<(), NetError> {
        self.0.borrow_mut().store_links(bytes)
    }
    fn ipa_endpoint(&mut self, device: &str) -> Result<Endpoint, NetError> {
        self.0.borrow_mut().ipa_endpoint(device)
    }
    fn ipa_set_egress_format(
        &mut self,
        device: &str,
        pipes: &[EgressPipe],
    ) -> Result<PipeStatus, NetError> {
        self.0.borrow_mut().ipa_set_egress_format(device, pipes)
    }
    fn ipa_set_ingress_format(
        &mut self,
        device: &str,
        pipes: &[IngressPipe],
    ) -> Result<PipeStatus, NetError> {
        self.0.borrow_mut().ipa_set_ingress_format(device, pipes)
    }
    fn ipa_add_mux_channel(
        &mut self,
        device: &str,
        mux_id: u8,
        link: &str,
    ) -> Result<(), NetError> {
        self.0
            .borrow_mut()
            .ipa_add_mux_channel(device, mux_id, link)
    }
    fn set_features(&mut self, name: &str, wanted: &[&str]) -> Result<Vec<String>, NetError> {
        self.0.borrow_mut().set_features(name, wanted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipa::IpaFormat;

    fn all_features(n: &mut FakeNet, name: &str) {
        let missing = n.set_features(name, &STOCK_FEATURES).unwrap();
        assert!(missing.is_empty());
    }

    #[test]
    fn a_coalescing_pipe_without_rx_gro_hw_fails_while_the_default_pipe_and_the_tables_are_made() {
        // The driver skips the coalescing pipe and the ioctl goes on, so every later request answers EPERM
        let f = IpaFormat::default();
        let mut n = FakeNet::new();
        assert_eq!(
            n.ipa_set_ingress_format("rmnet_ipa0", &f.ingress),
            Err(NetError::Os(5))
        );
        assert_eq!(
            n.ipa_set_ingress_format("rmnet_ipa0", &f.ingress),
            Err(NetError::Os(1))
        );
        // switching the features on afterwards does not help: the tables are there
        all_features(&mut n, "rmnet_ipa0");
        assert_eq!(
            n.ipa_set_ingress_format("rmnet_ipa0", &f.ingress),
            Err(NetError::Os(1))
        );
        // only a new device does
        n.modem_restart();
        all_features(&mut n, "rmnet_ipa0");
        assert_eq!(
            n.ipa_set_ingress_format("rmnet_ipa0", &f.ingress),
            Ok(PipeStatus::Set)
        );
        assert_eq!(
            n.ipa_set_ingress_format("rmnet_ipa0", &f.ingress),
            Ok(PipeStatus::Existed)
        );
    }

    #[test]
    fn the_default_pipe_before_the_coalescing_pipe_is_refused_with_efault() {
        let f = IpaFormat::default();
        let mut n = FakeNet::new();
        all_features(&mut n, "rmnet_ipa0");
        let default_first = [f.ingress[1], f.ingress[0]];
        assert_eq!(
            n.ipa_set_ingress_format("rmnet_ipa0", &default_first),
            Err(NetError::Os(14))
        );
        // nothing was made, so the right order works
        assert_eq!(
            n.ipa_set_ingress_format("rmnet_ipa0", &f.ingress),
            Ok(PipeStatus::Set)
        );
    }

    #[test]
    fn the_uplink_pipe_has_the_checksum_header_only_with_a_transmit_checksum_on() {
        let f = IpaFormat::default();
        let mut n = FakeNet::new();
        assert_eq!(
            n.ipa_set_egress_format("rmnet_ipa0", &f.egress),
            Ok(PipeStatus::Set)
        );
        assert!(!n.egress_has_csum_header("rmnet_ipa0"));
        n.modem_restart();
        n.set_features("rmnet_ipa0", &["tx-checksum-ipv6"]).unwrap();
        n.ipa_set_egress_format("rmnet_ipa0", &f.egress).unwrap();
        assert!(n.egress_has_csum_header("rmnet_ipa0"));
    }

    #[test]
    fn rx_gro_hw_goes_off_without_rx_checksum_and_a_feature_not_offered_stays_off() {
        let mut n = FakeNet::new();
        n.offered_features.retain(|f| f != "rx-checksum");
        let missing = n
            .set_features("rmnet_ipa0", &["rx-gro-hw", "rx-checksum"])
            .unwrap();
        assert_eq!(missing, ["rx-gro-hw", "rx-checksum"]);
        assert!(!n
            .features_of("rmnet_ipa0")
            .iter()
            .any(|f| f.starts_with("rx-") && f != "rx-gro"));
    }

    #[test]
    fn a_link_with_the_v4_flags_or_the_upstream_v5_bits_does_not_carry_data_on_a_v5_device() {
        let f = IpaFormat::default();
        let mut n = FakeNet::new();
        all_features(&mut n, "rmnet_ipa0");
        n.ipa_set_egress_format("rmnet_ipa0", &f.egress).unwrap();
        n.ipa_set_ingress_format("rmnet_ipa0", &f.ingress).unwrap();
        let try_flags = |n: &mut FakeNet, name: &str, mux: u8, flags: u32| {
            let fl = RmnetFlags {
                flags,
                mask: u32::MAX,
            };
            n.create_rmnet_link("rmnet_ipa0", name, mux, fl).unwrap();
            n.ipa_add_mux_channel("rmnet_ipa0", mux, name).unwrap();
            n.data_path_ok(name)
        };
        let good = RmnetFlags::qmap_default().flags;
        assert!(try_flags(&mut n, "good", 1, good));
        // the flags of an older version of the daemon: deaggregation, commands and the v4 checksum bits
        assert!(!try_flags(&mut n, "v4", 2, 0b1111));
        // upstream's numbering: v5 at bits 4 and 5, which for datarmnet are coalescing and the ingress v5 bit
        assert!(!try_flags(&mut n, "up", 3, 0b11_0001));
        // the v4 bits next to the right ones
        assert!(!try_flags(
            &mut n,
            "mixed",
            4,
            good | RmnetFlags::INGRESS_MAP_CKSUMV4
        ));
        // without coalescing, on a device that has the coalescing pipe
        assert!(!try_flags(
            &mut n,
            "nocoal",
            5,
            good & !RmnetFlags::INGRESS_COALESCE
        ));
        // without the egress v5 bit, on a pipe with the checksum header
        assert!(!try_flags(
            &mut n,
            "noul",
            6,
            good & !RmnetFlags::EGRESS_MAP_CKSUMV5
        ));
    }
}
