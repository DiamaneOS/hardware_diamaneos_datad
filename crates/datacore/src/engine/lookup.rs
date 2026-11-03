// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The question whether the modem has a call for a request already, which the stock nicmd asks
//! for a matching call (`matchingCallIface`, 0x84174): a client bound to the subscription asks
//! the modem's route lookup for the requested IP family, and when that finds nothing for the
//! companion family. The engine only reports which link the modem named. Whether the layer above
//! follows that link, whether it is up and whether it is the right call is the layer's to check.
//!
//! Each lookup has a client of its own and a deadline for the whole of it, because the module
//! waits for the answer on a thread of the radio daemon.
use super::{Engine, Owner, Qmi};
use crate::model::{ClientId, Event, Family, LookupQuery, StartError};
use dataos_netcfg::NetOps;
use dataos_qmi::wds::{self, RouteAnswer};
use dataos_qmi::{Frame, Kind};

/// Lookups that may wait at the same time.
pub const MAX_LOOKUPS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    BindSub,
    First,
    Companion,
}

impl Step {
    fn answers(self) -> u16 {
        match self {
            Step::BindSub => wds::id::BIND_SUBSCRIPTION,
            Step::First | Step::Companion => wds::id::ROUTE_LOOKUP,
        }
    }
}

pub(super) struct Lookup {
    query: LookupQuery,
    client: ClientId,
    step: Step,
    txn: u16,
    technology: Option<u16>,
    pub(super) deadline: u64,
}

fn other(f: Family) -> Family {
    match f {
        Family::V4 => Family::V6,
        Family::V6 => Family::V4,
    }
}

impl<Q: Qmi, N: NetOps> Engine<Q, N> {
    /// Ask the modem whether a call for this request is up. The answer is an `Event::LookupDone`
    /// with the same token, after at most `Config::lookup_timeout_ms`.
    pub fn start_lookup(
        &mut self,
        now: u64,
        token: u32,
        query: LookupQuery,
    ) -> Result<(), StartError> {
        self.now = now;
        if !self.ready || self.lookups.len() >= MAX_LOOKUPS || self.lookups.contains_key(&token) {
            return Err(StartError::Unavailable);
        }
        let txn = self.next_txn();
        let bytes = wds::bind_subscription(txn, u32::from(query.subscription))
            .map_err(|_| StartError::Invalid)?;
        let client = self
            .qmi
            .open_client(wds::SERVICE)
            .map_err(|_| StartError::Unavailable)?;
        if self.qmi.send(client, &bytes).is_err() {
            self.qmi.close_client(client);
            return Err(StartError::Unavailable);
        }
        self.clients.insert(client, Owner::Lookup(token));
        let deadline = now.saturating_add(self.cfg.lookup_timeout_ms);
        self.lookups.insert(
            token,
            Lookup {
                query,
                client,
                step: Step::BindSub,
                txn,
                technology: None,
                deadline,
            },
        );
        Ok(())
    }

    /// How many more lookups the table has room for.
    pub fn lookup_room(&self) -> usize {
        MAX_LOOKUPS.saturating_sub(self.lookups.len())
    }

    /// The layer above does not want the answer any more (its connection closed). Nothing is reported.
    pub fn cancel_lookup(&mut self, token: u32) {
        if let Some(l) = self.lookups.remove(&token) {
            self.clients.remove(&l.client);
            self.qmi.close_client(l.client);
        }
    }

    pub(super) fn lookup_deadlines(&mut self) {
        let now = self.now;
        let due: Vec<u32> = self
            .lookups
            .iter()
            .filter(|(_, l)| now >= l.deadline)
            .map(|(t, _)| *t)
            .collect();
        for token in due {
            self.stats.lookup_timeouts = self.stats.lookup_timeouts.saturating_add(1);
            self.finish_lookup(token, None, false, false);
        }
    }

    /// The modem went away: nothing it was asked will be answered.
    pub(super) fn end_lookups(&mut self) {
        let all: Vec<u32> = self.lookups.keys().copied().collect();
        for token in all {
            self.finish_lookup(token, None, false, false);
        }
    }

    fn finish_lookup(&mut self, token: u32, link: Option<usize>, companion: bool, answered: bool) {
        if let Some(l) = self.lookups.remove(&token) {
            self.clients.remove(&l.client);
            self.qmi.close_client(l.client);
            self.emit(Event::LookupDone {
                token,
                link,
                companion,
                answered,
                technology: l.technology,
            });
        }
    }

    fn bad_lookup(&mut self, token: u32) {
        self.stats.lookup_bad = self.stats.lookup_bad.saturating_add(1);
        self.finish_lookup(token, None, false, false);
    }

    pub(super) fn lookup_rx(&mut self, token: u32, bytes: &[u8]) {
        let Some((step, txn)) = self.lookups.get(&token).map(|l| (l.step, l.txn)) else {
            return;
        };
        let f = match Frame::parse(bytes) {
            Ok(f) => f,
            // not a QMI message at all (the zero-length notice the qcom module queues after a
            // flow control resume is one): counted, and the question goes on until its deadline
            Err(_) => {
                self.stats.malformed = self.stats.malformed.saturating_add(1);
                return;
            }
        };
        if f.kind != Kind::Response {
            return;
        }
        if f.txn != txn || f.id != step.answers() {
            self.stats.stale = self.stats.stale.saturating_add(1);
            return;
        }
        match step {
            Step::BindSub => {
                if f.status().is_ok_and(|s| s.is_ok()) {
                    self.send_lookup(token, Step::First);
                } else {
                    self.bad_lookup(token);
                }
            }
            Step::First | Step::Companion => {
                let Ok(answer) = wds::parse_route_lookup(&f) else {
                    return self.bad_lookup(token);
                };
                if let Some(l) = self.lookups.get_mut(&token) {
                    l.technology.get_or_insert(answer.technology);
                }
                match (self.link_named(&answer), step) {
                    (Some(link), _) => {
                        self.finish_lookup(token, Some(link), step == Step::Companion, true)
                    }
                    (None, Step::First) => self.send_lookup(token, Step::Companion),
                    (None, _) => self.finish_lookup(token, None, false, true),
                }
            }
        }
    }

    /// Send the route lookup of a step. The companion step asks for the other family.
    fn send_lookup(&mut self, token: u32, step: Step) {
        let Some(l) = self.lookups.get(&token) else {
            return;
        };
        let family = if step == Step::Companion {
            other(l.query.family)
        } else {
            l.query.family
        };
        let req = wds::RouteLookup {
            family: family.wds(),
            apn: l.query.apn.clone(),
            apn_type: l.query.apn_type,
            apn_type_mask: l.query.apn_type_mask,
            profile_3gpp: l.query.hint.profile_3gpp,
            profile_3gpp2: l.query.hint.profile_3gpp2,
            xt_pref: l.query.hint.xt_pref,
            backup_name: l.query.hint.backup_name,
            backup_type: l.query.hint.backup_type,
        };
        let client = l.client;
        let txn = self.next_txn();
        let sent = wds::route_lookup(txn, &req)
            .ok()
            .is_some_and(|b| self.qmi.send(client, &b).is_ok());
        if !sent {
            return self.bad_lookup(token);
        }
        if let Some(l) = self.lookups.get_mut(&token) {
            l.step = step;
            l.txn = txn;
        }
    }

    /// The link an answer names, when it names one of ours on our data transport. An instance
    /// is the number of the link, a mux ID is the mux of the link. Two that disagree name nothing.
    fn link_named(&self, a: &RouteAnswer) -> Option<usize> {
        if a.endpoint.is_some_and(|e| e != self.endpoint) {
            return None;
        }
        let by_mux = match a.mux {
            None => None,
            Some(m) => Some(usize::from(m.checked_sub(self.cfg.base_mux_id)?)),
        };
        let link = match (a.instance.map(usize::from), by_mux) {
            (Some(i), Some(m)) if i != m => return None,
            (Some(i), _) => i,
            (None, Some(m)) => m,
            (None, None) => return None,
        };
        (link < self.links.len()).then_some(link)
    }
}
