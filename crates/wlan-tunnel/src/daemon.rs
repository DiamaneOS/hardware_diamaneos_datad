// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The main loop of the tunnel daemon. One thread hears the name service, reads what the modem sends and runs the
//! timers of the engine. A datagram is zeroed by the engine as soon as it was read, as it may hold keys.
use crate::engine::Engine;
use crate::kernel::Kernel;
use dataos_datad::daemon::{Clock, Poller};
use dataos_datad::transport::{QmiLink, Qrtr};

const CONTROL_PER_STEP: usize = 32;
const BUSY_WAIT_MS: u64 = 25;
const MAX_WAIT_MS: u64 = 1_000;

pub struct Tunnel<Q: Qrtr, K: Kernel> {
    engine: Engine<QmiLink<Q>, K>,
}

impl<Q: Qrtr, K: Kernel> Tunnel<Q, K> {
    pub fn new(engine: Engine<QmiLink<Q>, K>) -> Self {
        Tunnel { engine }
    }

    pub fn engine(&mut self) -> &mut Engine<QmiLink<Q>, K> {
        &mut self.engine
    }

    /// One pass over everything, without waiting. True: there may be more to do right away.
    pub fn step(&mut self, now: u64) -> bool {
        let (events, mut more) = self.engine.qmi_mut().poll_control(now, CONTROL_PER_STEP);
        for ev in events {
            self.engine.on_service(now, ev);
        }
        let (datagrams, left) = self.engine.qmi_mut().poll_clients(now);
        more |= left;
        for (client, mut bytes) in datagrams {
            self.engine.on_qmi(now, client, &mut bytes);
        }
        if self.engine.next_deadline().is_some_and(|d| d <= now) {
            self.engine.tick(now);
        }
        self.engine.qmi_mut().flush(now);
        more
    }

    pub fn wait_ms(&mut self, now: u64) -> u64 {
        let from_engine = self.engine.next_deadline();
        let link = self.engine.qmi_mut();
        let blocked = link.blocked();
        let deadline = from_engine.into_iter().chain(link.next_deadline()).min();
        let until = deadline.map_or(MAX_WAIT_MS, |d| d.saturating_sub(now).clamp(1, MAX_WAIT_MS));
        if blocked {
            until.min(BUSY_WAIT_MS)
        } else {
            until
        }
    }

    /// Run until `stop` says so. Every line of the engine goes to `line`.
    pub fn run(
        &mut self,
        clock: &mut impl Clock,
        poller: &mut impl Poller,
        stop: &dyn Fn() -> bool,
        line: &mut dyn FnMut(String),
    ) {
        self.engine.start(clock.now_ms());
        while !stop() {
            let now = clock.now_ms();
            let wait = if self.step(now) { 0 } else { self.wait_ms(now) };
            for l in self.engine.take_lines() {
                line(l);
            }
            let fds = self.engine.qmi_mut().fds();
            // a failed poll has waited as long as it could, and the next pass finds out what is wrong
            let _ = poller.wait(&fds, wait);
        }
    }
}
