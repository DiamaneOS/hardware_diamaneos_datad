// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The ESP states of a tunnel: their segments put together, and the kernel's names for the modem's numbers.
use dataos_netcfg::xfrm::{self, Encap, NewState, SaId, STATE_AF_UNSPEC, STATE_NOPMTUDISC};
use dataos_qmi::reverse::{SaFields, SaSegment};
use dataos_qmi::secret::Secret;
use std::net::IpAddr;

/// The UDP port of the far end of an encapsulated tunnel, as its network order bytes.
pub const IKE_NATT_PORT: [u8; 2] = 4500u16.to_be_bytes();

/// What a segment did to the assembly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Added {
    Waiting,
    Complete,
    /// It did not fit, and everything held so far is gone.
    Dropped,
}

/// The segments of one answer. The modem numbers them in a way that is not known, so a segment counts by being
/// different from the others. The bound is the width of the number.
#[derive(Default)]
pub struct Assembly {
    expected: Option<u32>,
    head: Option<(u16, u8)>,
    seen: [u64; 4],
    fields: SaFields,
}

impl Assembly {
    fn count(&self) -> u32 {
        self.seen.iter().map(|w| w.count_ones()).sum()
    }

    fn drop_all(&mut self) -> Added {
        self.head = None;
        self.seen = [0; 4];
        self.fields = SaFields::default();
        Added::Dropped
    }

    pub fn is_complete(&self) -> bool {
        self.expected.is_some()
            && self
                .head
                .is_some_and(|(_, size)| self.count() == u32::from(size))
    }

    /// The request ID of the response. Segments that came first must have it.
    pub fn expect(&mut self, id: u32) {
        self.expected = Some(id);
        if self.head.is_some_and(|(have, _)| u32::from(have) != id) {
            self.drop_all();
        }
    }

    pub fn add(&mut self, seg: SaSegment) -> Added {
        let h = seg.head;
        if h.size == 0 || self.expected.is_some_and(|e| e != u32::from(h.id)) {
            return self.drop_all();
        }
        if self.head.is_some_and(|have| have != (h.id, h.size)) {
            return self.drop_all();
        }
        let word = usize::from(h.segment / 64);
        let bit = 1u64 << (h.segment % 64);
        if self.seen.get(word).is_none_or(|w| w & bit != 0) {
            return self.drop_all();
        }
        if self.fields.merge(seg.fields).is_err() {
            return self.drop_all();
        }
        if let Some(w) = self.seen.get_mut(word) {
            *w |= bit;
        }
        self.head = Some((h.id, h.size));
        if self.is_complete() {
            Added::Complete
        } else {
            Added::Waiting
        }
    }

    pub fn take_fields(&mut self) -> SaFields {
        std::mem::take(&mut self.fields)
    }
}

/// A whole answer of the modem, with every value checked. No Debug: it holds the keys.
pub struct IpsecSa {
    pub rx_spi: u32,
    pub tx_spi: u32,
    pub proto: u8,
    pub mode: u8,
    pub remote: IpAddr,
    pub local: IpAddr,
    pub crypt_name: &'static str,
    pub auth_name: &'static str,
    pub auth_trunc_bits: u32,
    pub rx_crypt: Secret,
    pub tx_crypt: Secret,
    pub rx_auth: Secret,
    pub tx_auth: Secret,
    /// Network order, when the tunnel runs over UDP.
    pub encap_port: Option<[u8; 2]>,
}

/// Replay window of an incoming state, in packets.
pub const RX_REPLAY_WINDOW: u8 = 32;

/// The kernel's name and the allowed key sizes in bytes. Single DES (9) is refused, and a counter mode key
/// carries its nonce.
fn crypt_name(alg: u32, aes_mode: Option<u32>) -> Option<(&'static str, &'static [usize])> {
    match (alg, aes_mode) {
        (10, _) => Some(("cbc(des3_ede)", &[24])),
        (12 | 19, None | Some(1)) => Some(("cbc(aes)", &[16, 24, 32])),
        (12 | 19, Some(2)) => Some(("rfc3686(ctr(aes))", &[20, 28, 36])),
        _ => None,
    }
}

/// The kernel's name, the truncation in bits and the key size in bytes.
fn auth_name(alg: u32) -> Option<(&'static str, u32, usize)> {
    match alg {
        5 => Some(("hmac(sha1)", 96, 20)),
        6 => Some(("hmac(sha256)", 128, 32)),
        7 => Some(("hmac(md5)", 96, 16)),
        12 => Some(("xcbc(aes)", 96, 16)),
        20 => Some(("hmac(sha384)", 192, 48)),
        21 => Some(("hmac(sha512)", 256, 64)),
        _ => None,
    }
}

/// An address the modem may name for a tunnel: no unspecified, loopback, multicast, broadcast or link local one.
pub fn usable_address(a: IpAddr) -> bool {
    !a.is_unspecified()
        && !a.is_loopback()
        && !a.is_multicast()
        && match a {
            IpAddr::V4(v) => !v.is_link_local() && !v.is_broadcast(),
            IpAddr::V6(v) => !v.is_unicast_link_local(),
        }
}

impl IpsecSa {
    /// Check what the segments gave. The error says which part is wrong, for the log.
    pub fn from_fields(f: SaFields) -> Result<IpsecSa, &'static str> {
        let proto = match f.proto {
            Some(3) => xfrm::IPPROTO_ESP,
            Some(2) => xfrm::IPPROTO_AH,
            _ => return Err("protocol"),
        };
        let mode = match f.mode {
            Some(1) => xfrm::MODE_TUNNEL,
            Some(2) => xfrm::MODE_TRANSPORT,
            _ => return Err("mode"),
        };
        let (Some(remote), Some(local)) = (f.remote, f.local) else {
            return Err("tunnel addresses");
        };
        if remote.is_ipv4() != local.is_ipv4() {
            return Err("families of the tunnel addresses");
        }
        if !usable_address(remote) || !usable_address(local) {
            return Err("tunnel addresses");
        }
        let (crypt, crypt_sizes) = f
            .crypt_alg
            .and_then(|a| crypt_name(a, f.aes_mode))
            .ok_or("crypto algorithm")?;
        let (auth, trunc, auth_size) = f.auth_alg.and_then(auth_name).ok_or("auth algorithm")?;
        let (Some(rx_spi), Some(tx_spi)) = (f.rx_spi, f.tx_spi) else {
            return Err("SPI");
        };
        if rx_spi == 0 || tx_spi == 0 {
            return Err("SPI");
        }
        let (Some(rx_crypt), Some(tx_crypt)) = (f.rx_crypt, f.tx_crypt) else {
            return Err("crypto key");
        };
        if !crypt_sizes.contains(&rx_crypt.bytes().len())
            || tx_crypt.bytes().len() != rx_crypt.bytes().len()
        {
            return Err("crypto key");
        }
        let (Some(rx_auth), Some(tx_auth)) = (f.rx_auth, f.tx_auth) else {
            return Err("auth key");
        };
        if rx_auth.bytes().len() != auth_size || tx_auth.bytes().len() != auth_size {
            return Err("auth key");
        }
        let encap_port = f
            .encap_port
            .filter(|_| f.udp_encap.is_some_and(|flag| flag != 0));
        if encap_port == Some([0, 0]) {
            return Err("UDP port");
        }
        Ok(IpsecSa {
            rx_spi,
            tx_spi,
            proto,
            mode,
            remote,
            local,
            crypt_name: crypt,
            auth_name: auth,
            auth_trunc_bits: trunc,
            rx_crypt,
            tx_crypt,
            rx_auth,
            tx_auth,
            encap_port,
        })
    }

    pub fn tx_id(&self) -> SaId {
        SaId {
            proto: self.proto,
            spi: self.tx_spi,
            src: self.local,
            dst: self.remote,
        }
    }

    pub fn rx_id(&self) -> SaId {
        SaId {
            proto: self.proto,
            spi: self.rx_spi,
            src: self.remote,
            dst: self.local,
        }
    }

    /// The outgoing state. `mark` is the output mark of the technology.
    pub fn tx_state(&self, mark: Option<u32>) -> NewState<'_> {
        NewState {
            id: self.tx_id(),
            mode: self.mode,
            flags: STATE_AF_UNSPEC | STATE_NOPMTUDISC,
            replay_window: 0,
            crypt_name: self.crypt_name,
            crypt_key: self.tx_crypt.bytes(),
            auth_name: self.auth_name,
            auth_trunc_bits: self.auth_trunc_bits,
            auth_key: self.tx_auth.bytes(),
            encap: self.encap_port.map(|sport| Encap {
                sport,
                dport: IKE_NATT_PORT,
            }),
            mark,
        }
    }

    pub fn rx_state(&self, mark: Option<u32>) -> NewState<'_> {
        NewState {
            id: self.rx_id(),
            mode: self.mode,
            flags: STATE_AF_UNSPEC,
            replay_window: RX_REPLAY_WINDOW,
            crypt_name: self.crypt_name,
            crypt_key: self.rx_crypt.bytes(),
            auth_name: self.auth_name,
            auth_trunc_bits: self.auth_trunc_bits,
            auth_key: self.rx_auth.bytes(),
            encap: self.encap_port.map(|dport| Encap {
                sport: IKE_NATT_PORT,
                dport,
            }),
            mark,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dataos_qmi::reverse::SaHead;

    #[test]
    fn weak_or_empty_values_of_the_modem_are_refused() {
        assert!(IpsecSa::from_fields(fields()).is_ok());
        type Spoil = fn(&mut SaFields);
        let bad: Vec<(Spoil, &str)> = vec![
            (|f| f.crypt_alg = Some(9), "crypto algorithm"),
            (|f| f.rx_spi = Some(0), "SPI"),
            (|f| f.tx_spi = Some(0), "SPI"),
            (
                |f| f.rx_crypt = Some(Secret::copy_of(&[1; 15])),
                "crypto key",
            ),
            (
                |f| f.tx_crypt = Some(Secret::copy_of(&[1; 32])),
                "crypto key",
            ),
            (|f| f.rx_auth = Some(Secret::copy_of(&[])), "auth key"),
            (|f| f.tx_auth = Some(Secret::copy_of(&[1; 20])), "auth key"),
            (
                |f| {
                    f.udp_encap = Some(1);
                    f.encap_port = Some([0, 0]);
                },
                "UDP port",
            ),
            (|f| f.remote = "0.0.0.0".parse().ok(), "tunnel addresses"),
            (|f| f.local = "224.0.0.1".parse().ok(), "tunnel addresses"),
        ];
        for (spoil, what) in bad {
            let mut f = fields();
            spoil(&mut f);
            assert_eq!(IpsecSa::from_fields(f).err(), Some(what));
        }
        // hmac(md5) stays: nothing shows that no carrier needs it, and the log line names what a tunnel uses
        let mut f = fields();
        f.auth_alg = Some(7);
        f.rx_auth = Some(Secret::copy_of(&[3; 16]));
        f.tx_auth = Some(Secret::copy_of(&[4; 16]));
        assert_eq!(
            IpsecSa::from_fields(f).ok().map(|s| s.auth_name),
            Some("hmac(md5)")
        );
    }

    fn seg(id: u16, size: u8, segment: u8, rx_spi: Option<u32>) -> SaSegment {
        SaSegment {
            head: SaHead { id, size, segment },
            fields: SaFields {
                rx_spi,
                ..SaFields::default()
            },
        }
    }

    #[test]
    fn segments_complete_in_any_order_with_or_before_the_response() {
        let mut a = Assembly::default();
        a.expect(7);
        assert_eq!(a.add(seg(7, 3, 2, Some(1))), Added::Waiting);
        assert_eq!(a.add(seg(7, 3, 0, None)), Added::Waiting);
        assert_eq!(a.add(seg(7, 3, 1, None)), Added::Complete);
        assert_eq!(a.take_fields().rx_spi, Some(1));

        let mut a = Assembly::default();
        assert_eq!(a.add(seg(7, 1, 0, None)), Added::Waiting);
        assert!(!a.is_complete());
        a.expect(7);
        assert!(a.is_complete());
    }

    #[test]
    fn a_segment_that_does_not_fit_drops_everything() {
        for bad in [
            seg(8, 2, 1, None),
            seg(7, 3, 1, None),
            seg(7, 2, 0, None),
            seg(7, 2, 1, Some(2)),
            seg(7, 0, 1, None),
        ] {
            let mut a = Assembly::default();
            a.expect(7);
            assert_eq!(a.add(seg(7, 2, 0, Some(1))), Added::Waiting);
            assert_eq!(a.add(bad), Added::Dropped);
            assert!(a.take_fields().rx_spi.is_none());
            assert_eq!(a.add(seg(7, 1, 0, None)), Added::Complete);
        }
        // segments held before the response, with another ID
        let mut a = Assembly::default();
        a.add(seg(9, 1, 0, Some(1)));
        a.expect(7);
        assert!(!a.is_complete());
        assert!(a.take_fields().rx_spi.is_none());
    }

    #[test]
    fn the_last_segment_number_fits() {
        let mut a = Assembly::default();
        a.expect(1);
        assert_eq!(a.add(seg(1, 2, 255, None)), Added::Waiting);
        assert_eq!(a.add(seg(1, 2, 0, None)), Added::Complete);
    }

    fn fields() -> SaFields {
        SaFields {
            rx_spi: Some(1),
            tx_spi: Some(2),
            proto: Some(3),
            mode: Some(1),
            remote: Some("198.51.100.1".parse().unwrap()),
            local: Some("192.0.2.1".parse().unwrap()),
            auth_alg: Some(6),
            crypt_alg: Some(12),
            rx_crypt: Some(Secret::copy_of(&[1; 16])),
            tx_crypt: Some(Secret::copy_of(&[2; 16])),
            rx_auth: Some(Secret::copy_of(&[3; 32])),
            tx_auth: Some(Secret::copy_of(&[4; 32])),
            ..SaFields::default()
        }
    }

    #[test]
    fn the_numbers_become_the_names_of_the_kernel() {
        let s = IpsecSa::from_fields(fields()).unwrap();
        assert_eq!((s.proto, s.mode), (50, 1));
        assert_eq!(
            (s.crypt_name, s.auth_name, s.auth_trunc_bits),
            ("cbc(aes)", "hmac(sha256)", 128)
        );
        let crypt = |a, m| crypt_name(a, m).map(|c| c.0);
        assert_eq!(crypt(19, Some(2)), Some("rfc3686(ctr(aes))"));
        assert_eq!(crypt(9, None), None);
        assert_eq!(crypt(10, Some(9)), Some("cbc(des3_ede)"));
        assert_eq!(crypt(12, Some(9)), None);
        assert_eq!(crypt(1, None), None);
        for (alg, name, bits, size) in [
            (5, "hmac(sha1)", 96, 20),
            (7, "hmac(md5)", 96, 16),
            (12, "xcbc(aes)", 96, 16),
            (20, "hmac(sha384)", 192, 48),
            (21, "hmac(sha512)", 256, 64),
        ] {
            assert_eq!(auth_name(alg), Some((name, bits, size)));
        }
        assert_eq!(auth_name(0), None);
    }

    #[test]
    fn each_required_field_is_required() {
        type Cut = fn(&mut SaFields);
        let cuts: [(Cut, &str); 8] = [
            (|f| f.rx_spi = None, "SPI"),
            (|f| f.proto = None, "protocol"),
            (|f| f.mode = None, "mode"),
            (|f| f.local = None, "tunnel addresses"),
            (|f| f.crypt_alg = None, "crypto algorithm"),
            (|f| f.auth_alg = None, "auth algorithm"),
            (|f| f.tx_crypt = None, "crypto key"),
            (|f| f.rx_auth = None, "auth key"),
        ];
        for (cut, why) in cuts {
            let mut f = fields();
            cut(&mut f);
            assert_eq!(IpsecSa::from_fields(f).err(), Some(why));
        }
        let mut f = fields();
        f.local = Some("2001:db8::1".parse().unwrap());
        assert!(IpsecSa::from_fields(f).is_err());
    }

    #[test]
    fn the_two_states_mirror_each_other_and_encap_needs_the_flag_and_the_port() {
        let mut f = fields();
        f.encap_port = Some([0x90, 0x01]);
        assert!(IpsecSa::from_fields(f).unwrap().encap_port.is_none());
        let mut f = fields();
        f.encap_port = Some([0x90, 0x01]);
        f.udp_encap = Some(0);
        assert!(IpsecSa::from_fields(f).unwrap().encap_port.is_none());
        let mut f = fields();
        f.encap_port = Some([0x90, 0x01]);
        f.udp_encap = Some(1);
        let s = IpsecSa::from_fields(f).unwrap();
        let tx = s.tx_state(Some(0x20000));
        assert_eq!(tx.flags, 0x24);
        assert_eq!((tx.id.spi, tx.id.src, tx.id.dst), (2, s.local, s.remote));
        assert_eq!(tx.crypt_key, &[2; 16]);
        assert_eq!(tx.auth_key, &[4; 32]);
        assert_eq!(
            tx.encap,
            Some(Encap {
                sport: [0x90, 0x01],
                dport: [0x11, 0x94]
            })
        );
        let rx = s.rx_state(None);
        assert_eq!(rx.flags, 0x20);
        assert_eq!((rx.id.spi, rx.id.src, rx.id.dst), (1, s.remote, s.local));
        assert_eq!(rx.crypt_key, &[1; 16]);
        assert_eq!(rx.auth_key, &[3; 32]);
        assert_eq!(
            rx.encap,
            Some(Encap {
                sport: [0x11, 0x94],
                dport: [0x90, 0x01]
            })
        );
    }
}
