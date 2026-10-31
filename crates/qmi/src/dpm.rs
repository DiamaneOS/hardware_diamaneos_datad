// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Data Port Mapper (QMI service 0x2f): open the hardware data endpoints.
//! Layout from libqmi data/qmi-service-dpm.json, and the same in the IDL table of the stock
//! libqmiservices.so (`tests/idl/idl-expected.txt`): TLV 0x11 is a list of at most 32 ports with a one
//! byte count, each four 32-bit numbers (endpoint type, interface, consumer and producer pipe). The names of
//! the other two lists have a one byte length too, and this crate sends no name.
use crate::frame::{Builder, Error};

pub const SERVICE: u8 = 0x2f;
pub const OPEN_PORT: u16 = 0x0020;

/// One hardware data port: endpoint type, interface, and the numbers of the consumer and producer pipes of
/// the IPA, which the driver reports (`RMNET_IOCTL_GET_EP_PAIR`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardwarePort {
    pub ep_type: u32,
    pub iface: u32,
    pub consumer: u32,
    pub producer: u32,
}

pub fn open_hardware_ports(txn: u16, ports: &[HardwarePort]) -> Result<Vec<u8>, Error> {
    if ports.is_empty() || ports.len() > 16 {
        return Err(Error::Value);
    }
    let mut v = vec![u8::try_from(ports.len()).map_err(|_| Error::Value)?];
    for p in ports {
        for x in [p.ep_type, p.iface, p.consumer, p.producer] {
            v.extend_from_slice(&x.to_le_bytes());
        }
    }
    Builder::request(txn, OPEN_PORT).tlv(0x11, &v)?.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::Frame;

    #[test]
    fn encodes_one_port() {
        let b = open_hardware_ports(
            1,
            &[HardwarePort {
                ep_type: 4,
                iface: 1,
                consumer: 2,
                producer: 18,
            }],
        )
        .unwrap();
        let f = Frame::parse(&b).unwrap();
        let v = f.tlv(0x11).unwrap();
        assert_eq!(v.len(), 1 + 16);
        assert_eq!(v[0], 1);
        // endpoint type, interface, consumer pipe, producer pipe
        let words: Vec<u32> = v[1..]
            .chunks_exact(4)
            .map(|w| u32::from_le_bytes(w.try_into().unwrap()))
            .collect();
        assert_eq!(words, [4, 1, 2, 18]);
        assert!(open_hardware_ports(1, &[]).is_err());
    }
}
