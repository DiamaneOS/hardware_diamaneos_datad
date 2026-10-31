// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Bounded reader and writer. Nothing here indexes a slice or panics.
use crate::limits::{HEADER_LEN, MAX_MESSAGE, MAX_PAYLOAD, VERSION};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    Version,
    Type,
    Length,
    Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// A string, name or value is longer than its bound.
    TooLong,
    /// A list has more entries than its bound.
    TooMany,
    /// A value cannot be represented (NUL in a string, address of the wrong family).
    Value,
}

pub(crate) struct W(Vec<u8>);

impl W {
    pub(crate) fn new() -> Self {
        W(Vec::new())
    }

    pub(crate) fn u8(&mut self, v: u8) {
        self.0.push(v);
    }

    pub(crate) fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn i16(&mut self, v: i16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn raw(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }

    /// Length byte and the bytes. Refuses what would be cut.
    pub(crate) fn bytes(&mut self, b: &[u8], max: usize) -> Result<(), EncodeError> {
        if b.len() > max {
            return Err(EncodeError::TooLong);
        }
        self.u8(u8::try_from(b.len()).map_err(|_| EncodeError::TooLong)?);
        self.raw(b);
        Ok(())
    }

    /// Text without NUL, so the reader's checks pass for everything written.
    pub(crate) fn str(&mut self, s: &str, max: usize) -> Result<(), EncodeError> {
        if s.as_bytes().contains(&0) {
            return Err(EncodeError::Value);
        }
        self.bytes(s.as_bytes(), max)
    }

    pub(crate) fn opt<T>(
        &mut self,
        v: &Option<T>,
        mut f: impl FnMut(&mut W, &T) -> Result<(), EncodeError>,
    ) -> Result<(), EncodeError> {
        match v {
            Some(x) => {
                self.u8(1);
                f(self, x)
            }
            None => {
                self.u8(0);
                Ok(())
            }
        }
    }

    /// Header and payload as one datagram.
    pub(crate) fn frame(self, ty: u8, handle: u32) -> Result<Vec<u8>, EncodeError> {
        if self.0.len() > MAX_PAYLOAD {
            return Err(EncodeError::TooLong);
        }
        let len = u16::try_from(self.0.len()).map_err(|_| EncodeError::TooLong)?;
        let mut out = Vec::with_capacity(HEADER_LEN.saturating_add(self.0.len()));
        out.push(VERSION);
        out.push(ty);
        out.extend_from_slice(&handle.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&self.0);
        Ok(out)
    }
}

pub(crate) struct R<'a>(&'a [u8]);

impl<'a> R<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        R(b)
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let (a, b) = self.0.split_at_checked(n).ok_or(DecodeError::Truncated)?;
        self.0 = b;
        Ok(a)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        self.take(N)?.try_into().map_err(|_| DecodeError::Truncated)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, DecodeError> {
        let [b] = self.array::<1>()?;
        Ok(b)
    }

    pub(crate) fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub(crate) fn i16(&mut self) -> Result<i16, DecodeError> {
        Ok(i16::from_le_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub(crate) fn bytes(&mut self, max: usize) -> Result<&'a [u8], DecodeError> {
        let n = usize::from(self.u8()?);
        if n > max {
            return Err(DecodeError::Length);
        }
        self.take(n)
    }

    pub(crate) fn str(&mut self, max: usize) -> Result<String, DecodeError> {
        let b = self.bytes(max)?;
        if b.contains(&0) {
            return Err(DecodeError::Value);
        }
        String::from_utf8(b.to_vec()).map_err(|_| DecodeError::Value)
    }

    pub(crate) fn opt<T>(
        &mut self,
        mut f: impl FnMut(&mut R<'a>) -> Result<T, DecodeError>,
    ) -> Result<Option<T>, DecodeError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(f(self)?)),
            _ => Err(DecodeError::Value),
        }
    }

    pub(crate) fn done(&self) -> Result<(), DecodeError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::Length)
        }
    }
}

/// Check the header and return type, handle and payload.
pub(crate) fn split(bytes: &[u8]) -> Result<(u8, u32, &[u8]), DecodeError> {
    let (head, payload) = bytes
        .split_at_checked(HEADER_LEN)
        .ok_or(DecodeError::Truncated)?;
    if bytes.len() > MAX_MESSAGE {
        return Err(DecodeError::Length);
    }
    let [ver, ty, h0, h1, h2, h3, l0, l1]: [u8; HEADER_LEN] =
        head.try_into().map_err(|_| DecodeError::Truncated)?;
    if ver != VERSION {
        return Err(DecodeError::Version);
    }
    if usize::from(u16::from_le_bytes([l0, l1])) != payload.len() {
        return Err(DecodeError::Length);
    }
    Ok((ty, u32::from_le_bytes([h0, h1, h2, h3]), payload))
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    fn datagram(payload_len: usize) -> Vec<u8> {
        let mut b = vec![VERSION, 1, 0, 0, 0, 0];
        b.extend_from_slice(&(payload_len as u16).to_le_bytes());
        b.resize(HEADER_LEN + payload_len, 0);
        b
    }

    #[test]
    fn the_reader_refuses_a_message_over_the_bound_even_with_a_matching_header() {
        // no message type can be this large, but the header check alone would let it in
        assert!(split(&datagram(MAX_PAYLOAD)).is_ok());
        assert_eq!(
            split(&datagram(MAX_PAYLOAD + 1)).unwrap_err(),
            DecodeError::Length
        );
        assert_eq!(
            split(&datagram(u16::MAX as usize)).unwrap_err(),
            DecodeError::Length
        );
    }

    #[test]
    fn the_writer_refuses_a_payload_over_the_bound() {
        let mut w = W::new();
        w.raw(&vec![0u8; MAX_PAYLOAD]);
        assert_eq!(w.frame(1, 0).unwrap().len(), MAX_MESSAGE);
        let mut w = W::new();
        w.raw(&vec![0u8; MAX_PAYLOAD + 1]);
        assert_eq!(w.frame(1, 0).unwrap_err(), EncodeError::TooLong);
    }

    #[test]
    fn strings_stop_at_their_bounds() {
        let mut w = W::new();
        assert_eq!(w.bytes(&[1; 5], 4).unwrap_err(), EncodeError::TooLong);
        assert!(w.bytes(&[1; 4], 4).is_ok());
        assert_eq!(
            R::new(&[5, 1, 1, 1, 1, 1]).bytes(4).unwrap_err(),
            DecodeError::Length
        );
    }
}
