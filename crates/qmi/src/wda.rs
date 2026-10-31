// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Wireless Data Administrative service (QMI service 0x1a): data format of
//! the physical data port. Layouts from libqmi data/qmi-service-wda.json.
use crate::frame::{u32_value, Builder, Error, Frame};

pub const SERVICE: u8 = 0x1a;
pub const SET_DATA_FORMAT: u16 = 0x0020;

pub const LINK_LAYER_RAW_IP: u32 = 2;
pub const AGGREGATION_DISABLED: u32 = 0;
pub const AGGREGATION_QMAP: u32 = 5;
/// The data aggregation protocol that stock nicmd sends in both directions on the FP6: 9 in its default
/// configuration (`ConfigurationManager`), read in the binary. Its strings have no name for the number. The code that
/// builds the request accepts 5, 7, 8 and 9 and sends the extension TLV 0x1d with the downlink value 9 only. It is
/// the QMAP version 5 that the pipes and the links of the daemon use (the v5 headers with the checksum result,
/// frames of the coalescing pipe), and the downlink limits of stock (64844 bytes, 63 datagrams) are those of the
/// ingress pipe.
pub const AGGREGATION_STOCK: u32 = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetDataFormat {
    pub link_layer: u32,
    pub ul_aggregation: u32,
    pub dl_aggregation: u32,
    pub dl_max_datagrams: u32,
    pub dl_max_size: u32,
    pub ul_max_datagrams: u32,
    pub ul_max_size: u32,
    /// Endpoint type and interface number of the data port.
    pub endpoint: (u32, u32),
    /// TLV 0x1d, two flags, which stock sends with the downlink protocol 9: both 1 on the FP6.
    pub extension: Option<(u8, u8)>,
}

impl SetDataFormat {
    /// What stock nicmd requests on the FP6 (read in `ConfigurationManager` of libnicm_internal): raw IP,
    /// protocol 9 both ways, uplink 32 datagrams of up to 16384 bytes, and the extension flags 1 and 1. The downlink
    /// limits are the caller's (stock: 63 datagrams, 64844 bytes).
    pub fn stock(endpoint: (u32, u32), dl_max_size: u32, dl_max_datagrams: u32) -> Self {
        SetDataFormat {
            link_layer: LINK_LAYER_RAW_IP,
            ul_aggregation: AGGREGATION_STOCK,
            dl_aggregation: AGGREGATION_STOCK,
            dl_max_datagrams,
            dl_max_size,
            ul_max_datagrams: 32,
            ul_max_size: 16384,
            endpoint,
            extension: Some((1, 1)),
        }
    }

    pub fn encode(&self, txn: u16) -> Result<Vec<u8>, Error> {
        if self.link_layer != LINK_LAYER_RAW_IP && self.link_layer != 1 {
            return Err(Error::Value);
        }
        let mut ep = [0u8; 8];
        ep[..4].copy_from_slice(&self.endpoint.0.to_le_bytes());
        ep[4..].copy_from_slice(&self.endpoint.1.to_le_bytes());
        let b = Builder::request(txn, SET_DATA_FORMAT)
            .u32(0x11, self.link_layer)?
            .u32(0x12, self.ul_aggregation)?
            .u32(0x13, self.dl_aggregation)?
            .u32(0x15, self.dl_max_datagrams)?
            .u32(0x16, self.dl_max_size)?
            .tlv(0x17, &ep)?
            .u32(0x1b, self.ul_max_datagrams)?
            .u32(0x1c, self.ul_max_size)?;
        match self.extension {
            Some((a, b2)) => b.tlv(0x1d, &[a, b2])?.build(),
            None => b.build(),
        }
    }
}

/// What the modem accepted. Fields the response omits stay None.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataFormatResult {
    pub link_layer: Option<u32>,
    pub ul_aggregation: Option<u32>,
    pub dl_aggregation: Option<u32>,
    pub dl_max_size: Option<u32>,
}

pub fn parse_set_data_format_response(f: &Frame<'_>) -> Result<DataFormatResult, Error> {
    if !f.status()?.is_ok() {
        return Err(Error::Value);
    }
    let get = |t| f.tlv(t).map(u32_value).transpose();
    Ok(DataFormatResult {
        link_layer: get(0x11)?,
        ul_aggregation: get(0x12)?,
        dl_aggregation: get(0x13)?,
        dl_max_size: get(0x16)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_data_format_round_trip() {
        let req = SetDataFormat::stock((4, 1), 64844, 63);
        let b = req.encode(5).unwrap();
        let f = Frame::parse(&b).unwrap();
        assert_eq!(f.id, SET_DATA_FORMAT);
        assert_eq!(u32_value(f.tlv(0x11).unwrap()).unwrap(), LINK_LAYER_RAW_IP);
        assert_eq!(u32_value(f.tlv(0x16).unwrap()).unwrap(), 64844);
        // What stock sends (ConfigurationManager of libnicm_internal): protocol 9 both ways, the
        // downlink limits of the caller, uplink 32 datagrams of 16384 bytes, and the two flags of TLV 0x1d
        assert_eq!(u32_value(f.tlv(0x12).unwrap()).unwrap(), 9);
        assert_eq!(u32_value(f.tlv(0x13).unwrap()).unwrap(), 9);
        assert_eq!(u32_value(f.tlv(0x15).unwrap()).unwrap(), 63);
        assert_eq!(u32_value(f.tlv(0x1b).unwrap()).unwrap(), 32);
        assert_eq!(u32_value(f.tlv(0x1c).unwrap()).unwrap(), 16384);
        assert_eq!(f.tlv(0x1d).unwrap(), &[1, 1]);
        assert_eq!(AGGREGATION_STOCK, 9);
        // without the extension the TLV is left out
        let mut plain = req;
        plain.extension = None;
        let b = plain.encode(5).unwrap();
        assert!(Frame::parse(&b).unwrap().tlv(0x1d).is_none());

        let resp = Builder::response(5, SET_DATA_FORMAT)
            .ok()
            .unwrap()
            .u32(0x11, LINK_LAYER_RAW_IP)
            .unwrap()
            .u32(0x13, AGGREGATION_QMAP)
            .unwrap()
            .u32(0x16, 16384)
            .unwrap()
            .build()
            .unwrap();
        let r = parse_set_data_format_response(&Frame::parse(&resp).unwrap()).unwrap();
        assert_eq!(r.dl_aggregation, Some(AGGREGATION_QMAP));
        assert_eq!(r.ul_aggregation, None);
    }

    #[test]
    fn rejects_unknown_link_layer() {
        let mut req = SetDataFormat::stock((4, 1), 1, 1);
        req.link_layer = 77;
        assert_eq!(req.encode(1).unwrap_err(), Error::Value);
    }
}
