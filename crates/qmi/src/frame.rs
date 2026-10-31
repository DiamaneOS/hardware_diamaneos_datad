// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! QMI service framing over QRTR (no QMUX header): one type byte, a 16-bit
//! little-endian transaction ID, a 16-bit message ID and a 16-bit body length,
//! then TLVs with an 8-bit tag and a 16-bit length.

/// Service header length in bytes.
pub const HEADER_LEN: usize = 7;
/// Default upper bound for one datagram (header plus body). The largest answer read here is Get Runtime
/// Settings with every TLV it can carry at the maximum of the stock table, 7970 bytes (tested).
pub const MAX_DATAGRAM: usize = 8192;
/// TLV tag of the result code in every response.
pub const TAG_RESULT: u8 = 0x02;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Fewer bytes than the header or a TLV claims.
    Truncated,
    /// Declared body length differs from the datagram, or a field has a wrong width.
    Length,
    /// The same tag appears twice. Parsers must not disagree on first or last.
    Duplicate,
    /// A required TLV is absent.
    Missing,
    /// A field holds a value outside its allowed range.
    Value,
    /// Unknown message type byte.
    Kind,
    /// The datagram would exceed the bound.
    TooLarge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Request = 0,
    Response = 2,
    Indication = 4,
}

/// Result TLV (0x02) of a response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmiStatus {
    pub result: u16,
    pub error: u16,
}

impl QmiStatus {
    pub const ERR_CALL_FAILED: u16 = 0x000e;
    /// QMI_ERR_OUT_OF_CALL, what a modem answers to a question about a call that is not there **[I]**
    /// (libqmi's list, not seen on this modem).
    pub const ERR_OUT_OF_CALL: u16 = 0x000f;
    pub fn is_ok(&self) -> bool {
        self.result == 0
    }
    /// A failure of the QMI stack or of the request, not an answer about the call: malformed message, no
    /// memory, internal error, aborted, no client ID left, an unabortable transaction, an invalid client ID
    /// (libqmi's numbers 1 to 7). Any other error code is taken for an answer.
    pub fn is_stack_failure(&self) -> bool {
        self.result != 0 && (1..=7).contains(&self.error)
    }
}

#[derive(Clone, Copy)]
pub struct Frame<'a> {
    pub kind: Kind,
    pub txn: u16,
    pub id: u16,
    body: &'a [u8],
}

// Deliberately no derived Debug: TLV bodies can carry addresses and APNs.
impl std::fmt::Debug for Frame<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Frame {{ kind: {:?}, txn: {}, id: {:#06x}, body_len: {} }}",
            self.kind,
            self.txn,
            self.id,
            self.body.len()
        )
    }
}

/// Split the first TLV off `rest`: tag, value, remainder.
fn next_tlv(rest: &[u8]) -> Result<(u8, &[u8], &[u8]), Error> {
    let [tag, l0, l1, tail @ ..] = rest else {
        return Err(Error::Truncated);
    };
    let n = usize::from(u16::from_le_bytes([*l0, *l1]));
    let (value, after) = tail.split_at_checked(n).ok_or(Error::Truncated)?;
    Ok((*tag, value, after))
}

/// Set the bit of `tag`. False when it was already set.
fn mark(seen: &mut [bool; 256], tag: u8) -> bool {
    match seen.get_mut(usize::from(tag)) {
        Some(slot) if !*slot => {
            *slot = true;
            true
        }
        _ => false,
    }
}

impl<'a> Frame<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        Self::parse_bounded(bytes, MAX_DATAGRAM)
    }

    pub fn parse_bounded(bytes: &'a [u8], max_datagram: usize) -> Result<Self, Error> {
        let (head, body) = bytes.split_at_checked(HEADER_LEN).ok_or(Error::Truncated)?;
        if bytes.len() > max_datagram {
            return Err(Error::TooLarge);
        }
        let [kind, t0, t1, i0, i1, l0, l1]: [u8; HEADER_LEN] =
            head.try_into().map_err(|_| Error::Truncated)?;
        let kind = match kind {
            0 => Kind::Request,
            2 => Kind::Response,
            4 => Kind::Indication,
            _ => return Err(Error::Kind),
        };
        if usize::from(u16::from_le_bytes([l0, l1])) != body.len() {
            return Err(Error::Length);
        }
        // Validate the whole TLV chain once so later lookups cannot fail on framing.
        let mut seen = [false; 256];
        let mut rest = body;
        while !rest.is_empty() {
            let (tag, _, after) = next_tlv(rest)?;
            if !mark(&mut seen, tag) {
                return Err(Error::Duplicate);
            }
            rest = after;
        }
        Ok(Frame {
            kind,
            txn: u16::from_le_bytes([t0, t1]),
            id: u16::from_le_bytes([i0, i1]),
            body,
        })
    }

    pub fn tlv(&self, tag: u8) -> Option<&'a [u8]> {
        self.tlvs().find(|(t, _)| *t == tag).map(|(_, v)| v)
    }

    pub fn required(&self, tag: u8) -> Result<&'a [u8], Error> {
        self.tlv(tag).ok_or(Error::Missing)
    }

    pub fn tlvs(&self) -> impl Iterator<Item = (u8, &'a [u8])> {
        let mut rest = self.body;
        std::iter::from_fn(move || {
            let (tag, value, after) = next_tlv(rest).ok()?;
            rest = after;
            Some((tag, value))
        })
    }

    /// The result TLV. Responses must carry it.
    pub fn status(&self) -> Result<QmiStatus, Error> {
        let v = self.required(TAG_RESULT)?;
        let [r0, r1, e0, e1]: [u8; 4] = v.try_into().map_err(|_| Error::Length)?;
        Ok(QmiStatus {
            result: u16::from_le_bytes([r0, r1]),
            error: u16::from_le_bytes([e0, e1]),
        })
    }
}

pub fn u8_value(b: &[u8]) -> Result<u8, Error> {
    match b {
        [x] => Ok(*x),
        _ => Err(Error::Length),
    }
}

pub fn u16_value(b: &[u8]) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(b.try_into().map_err(|_| Error::Length)?))
}

pub fn u32_value(b: &[u8]) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(b.try_into().map_err(|_| Error::Length)?))
}

/// Builds a datagram. Tags are unique and the total size is bounded.
pub struct Builder {
    kind: Kind,
    txn: u16,
    id: u16,
    body: Vec<u8>,
    seen: [bool; 256],
}

impl Builder {
    pub fn request(txn: u16, id: u16) -> Self {
        Self::new(Kind::Request, txn, id)
    }

    pub fn response(txn: u16, id: u16) -> Self {
        Self::new(Kind::Response, txn, id)
    }

    pub fn indication(id: u16) -> Self {
        Self::new(Kind::Indication, 0, id)
    }

    fn new(kind: Kind, txn: u16, id: u16) -> Self {
        Builder {
            kind,
            txn,
            id,
            body: Vec::new(),
            seen: [false; 256],
        }
    }

    pub fn tlv(mut self, tag: u8, value: &[u8]) -> Result<Self, Error> {
        let len = u16::try_from(value.len()).map_err(|_| Error::TooLarge)?;
        let total = HEADER_LEN
            .checked_add(self.body.len())
            .and_then(|n| n.checked_add(3))
            .and_then(|n| n.checked_add(value.len()))
            .ok_or(Error::TooLarge)?;
        if total > MAX_DATAGRAM {
            return Err(Error::TooLarge);
        }
        if !mark(&mut self.seen, tag) {
            return Err(Error::Duplicate);
        }
        self.body.push(tag);
        self.body.extend_from_slice(&len.to_le_bytes());
        self.body.extend_from_slice(value);
        Ok(self)
    }

    pub fn u8(self, tag: u8, v: u8) -> Result<Self, Error> {
        self.tlv(tag, &[v])
    }

    pub fn u16(self, tag: u8, v: u16) -> Result<Self, Error> {
        self.tlv(tag, &v.to_le_bytes())
    }

    pub fn u32(self, tag: u8, v: u32) -> Result<Self, Error> {
        self.tlv(tag, &v.to_le_bytes())
    }

    /// Add a success result TLV (responses only).
    pub fn ok(self) -> Result<Self, Error> {
        self.tlv(TAG_RESULT, &[0, 0, 0, 0])
    }

    /// Add a failure result TLV (responses only).
    pub fn fail(self, error: u16) -> Result<Self, Error> {
        let e = error.to_le_bytes();
        self.tlv(TAG_RESULT, &[1, 0, e[0], e[1]])
    }

    pub fn build(self) -> Result<Vec<u8>, Error> {
        let len = u16::try_from(self.body.len()).map_err(|_| Error::TooLarge)?;
        let mut out = Vec::with_capacity(HEADER_LEN.saturating_add(self.body.len()));
        out.push(self.kind as u8);
        out.extend_from_slice(&self.txn.to_le_bytes());
        out.extend_from_slice(&self.id.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&self.body);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let bytes = Builder::request(7, 0x20)
            .u8(0x19, 4)
            .unwrap()
            .tlv(0x14, b"internet.example")
            .unwrap()
            .build()
            .unwrap();
        let f = Frame::parse(&bytes).unwrap();
        assert_eq!((f.kind, f.txn, f.id), (Kind::Request, 7, 0x20));
        assert_eq!(f.tlv(0x19), Some(&[4u8][..]));
        assert_eq!(f.tlv(0x14), Some(&b"internet.example"[..]));
        assert_eq!(f.tlv(0x99), None);
        assert_eq!(f.tlvs().count(), 2);
    }

    #[test]
    fn rejects_bad_framing() {
        assert_eq!(Frame::parse(&[0; 3]).unwrap_err(), Error::Truncated);
        let mut ok = Builder::response(1, 2).ok().unwrap().build().unwrap();
        ok[0] = 9;
        assert_eq!(Frame::parse(&ok).unwrap_err(), Error::Kind);
        ok[0] = 2;
        ok[5] = 99; // body length lies
        assert_eq!(Frame::parse(&ok).unwrap_err(), Error::Length);
    }

    #[test]
    fn rejects_duplicate_and_truncated_tlv() {
        // two TLVs with tag 5
        let body = [5u8, 1, 0, 1, 5, 1, 0, 2];
        let mut d = vec![0u8, 1, 0, 0x20, 0, body.len() as u8, 0];
        d.extend_from_slice(&body);
        assert_eq!(Frame::parse(&d).unwrap_err(), Error::Duplicate);
        // TLV claims 9 bytes but only 1 follows
        let body = [5u8, 9, 0, 1];
        let mut d = vec![0u8, 1, 0, 0x20, 0, body.len() as u8, 0];
        d.extend_from_slice(&body);
        assert_eq!(Frame::parse(&d).unwrap_err(), Error::Truncated);
        // a tag byte alone is not a TLV
        let mut d = vec![0u8, 1, 0, 0x20, 0, 1, 0];
        d.push(5);
        assert_eq!(Frame::parse(&d).unwrap_err(), Error::Truncated);
    }

    #[test]
    fn datagram_bound_is_exact() {
        // header plus body of exactly MAX_DATAGRAM bytes is fine, one more is not
        let fill = MAX_DATAGRAM - HEADER_LEN - 3;
        let ok = Builder::request(1, 1)
            .tlv(1, &vec![0u8; fill])
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(ok.len(), MAX_DATAGRAM);
        assert!(Frame::parse(&ok).is_ok());
        assert_eq!(
            Builder::request(1, 1).tlv(1, &vec![0u8; fill + 1]).err(),
            Some(Error::TooLarge)
        );
        let mut big = ok.clone();
        big.push(0);
        assert_eq!(Frame::parse(&big).unwrap_err(), Error::TooLarge);
    }

    #[test]
    fn builder_refuses_duplicates_and_oversize() {
        let b = Builder::request(1, 1).u8(1, 0).unwrap();
        assert_eq!(b.u8(1, 0).err(), Some(Error::Duplicate));
        let big = vec![0u8; MAX_DATAGRAM];
        assert_eq!(
            Builder::request(1, 1).tlv(1, &big).err(),
            Some(Error::TooLarge)
        );
    }

    #[test]
    fn status_parses() {
        let ok = Builder::response(3, 0x20).ok().unwrap().build().unwrap();
        let st = Frame::parse(&ok).unwrap().status().unwrap();
        assert!(st.is_ok());
        let bad = Builder::response(3, 0x20)
            .fail(QmiStatus::ERR_CALL_FAILED)
            .unwrap()
            .build()
            .unwrap();
        let st = Frame::parse(&bad).unwrap().status().unwrap();
        assert!(!st.is_ok());
        assert_eq!(st.error, 0x000e);
    }

    #[test]
    fn debug_does_not_print_body() {
        let b = Builder::request(1, 0x20)
            .tlv(0x14, b"secret.apn")
            .unwrap()
            .build()
            .unwrap();
        let s = format!("{:?}", Frame::parse(&b).unwrap());
        assert!(!s.contains("secret"));
    }
}
