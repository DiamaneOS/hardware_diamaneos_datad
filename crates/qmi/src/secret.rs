// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Bytes that must not outlive their use: the ESP keys and the buffers that held them. A `Secret` has no
//! Debug, Display or Clone, sits on the heap so a move copies only the pointer, and is zeroed on drop.
use std::hint::black_box;
use std::sync::atomic::{compiler_fence, Ordering};

/// Zero the bytes. `black_box` makes the optimiser treat the result as read, so the writes stay.
pub fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
    black_box(&mut *bytes);
    compiler_fence(Ordering::SeqCst);
}

pub struct Secret(Vec<u8>);

impl Secret {
    pub fn copy_of(bytes: &[u8]) -> Self {
        // exactly this size, so no growth ever leaves a copy behind
        let mut v = Vec::with_capacity(bytes.len());
        v.extend_from_slice(bytes);
        Secret(v)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Do two secrets hold the same bytes? Not for a comparison with anything from outside.
    pub fn same(&self, other: &Secret) -> bool {
        self.0 == other.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    trait NotDebug<A> {
        fn check() {}
    }
    impl<T: ?Sized> NotDebug<()> for T {}
    impl<T: ?Sized + std::fmt::Debug> NotDebug<u8> for T {}
    trait NotDisplay<A> {
        fn check() {}
    }
    impl<T: ?Sized> NotDisplay<()> for T {}
    impl<T: ?Sized + std::fmt::Display> NotDisplay<u8> for T {}

    /// With Debug or Display on `Secret` the inference below has two answers and this stops compiling.
    #[test]
    fn a_secret_has_no_debug_and_no_display() {
        <Secret as NotDebug<_>>::check();
        <Secret as NotDisplay<_>>::check();
    }

    #[test]
    fn wipe_zeroes_all_of_it() {
        let mut b = [7u8; 32];
        wipe(&mut b);
        assert_eq!(b, [0; 32]);
    }

    #[test]
    fn a_secret_keeps_its_bytes_until_dropped() {
        let a = Secret::copy_of(&[1, 2, 3]);
        assert_eq!(a.bytes(), &[1, 2, 3]);
        assert_eq!(a.len(), 3);
        assert!(!a.is_empty());
        assert!(a.same(&Secret::copy_of(&[1, 2, 3])));
        assert!(!a.same(&Secret::copy_of(&[1, 2, 4])));
    }
}
