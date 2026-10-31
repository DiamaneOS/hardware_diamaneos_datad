// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The only place that names the standard maps. `BTreeMap` panics on `m[&k]`
//! and clippy's indexing lint does not cover it. This wrapper has no `Index`,
//! so a lookup can only be `get`. `tests/no_panic.rs` keeps the raw type out of
//! every other file.
use std::collections::BTreeMap;

/// An ordered map that can only be read with `get`.
#[derive(Debug)]
pub(crate) struct Table<K, V>(BTreeMap<K, V>);

impl<K, V> Default for Table<K, V> {
    fn default() -> Self {
        Table(BTreeMap::new())
    }
}

impl<K: Ord, V> Table<K, V> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn get(&self, k: &K) -> Option<&V> {
        self.0.get(k)
    }

    pub fn get_mut(&mut self, k: &K) -> Option<&mut V> {
        self.0.get_mut(k)
    }

    pub fn contains(&self, k: &K) -> bool {
        self.0.contains_key(k)
    }

    pub fn insert(&mut self, k: K, v: V) -> Option<V> {
        self.0.insert(k, v)
    }

    pub fn remove(&mut self, k: &K) -> Option<V> {
        self.0.remove(k)
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&K, &mut V)> {
        self.0.iter_mut()
    }
}
