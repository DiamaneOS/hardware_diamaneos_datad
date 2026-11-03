// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The Wi-Fi tunnel daemon. It opens its netlink sockets, puts the syscall filter on and runs the engine until it
//! is told to stop. A failure at start writes one line without an identifier and ends the process with 1, and init
//! starts it again. It has its own user and domain, so nothing that happens here reaches the data daemon.
#![deny(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]
mod filter;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod sys;

#[cfg(any(target_os = "linux", target_os = "android"))]
fn main() {
    if let Err(e) = linux::run() {
        dataos_datad_rt::log::error(&format!("stopped: {e}"));
        std::process::exit(1);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn main() {
    eprintln!("wlantunneld: runs on Linux only");
    std::process::exit(1);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux {
    use super::{filter, sys};
    use dataos_datad::transport::QmiLink;
    use dataos_datad_rt::clock::MonotonicClock;
    use dataos_datad_rt::poll::SysPoller;
    use dataos_datad_rt::qrtr::QrtrSockets;
    use dataos_datad_rt::report::Reporter;
    use dataos_datad_rt::{ids, log, seccomp, signals};
    use dataos_wlan_tunnel::daemon::Tunnel;
    use dataos_wlan_tunnel::engine::{Config, Engine, MAX_CLIENTS, MAX_DATAGRAM, WANTED};
    use std::cell::RefCell;
    use std::io;

    /// A tmpfs directory that init makes (`wlantunneld.rc`), so a reboot clears it.
    const STATE_DIR: &str = "/dev/wlantunnel";

    /// Until a log-mode run on the phone has shown which syscalls the daemon makes, the filter logs what it would
    /// refuse. Set to `Action::Errno` after that run.
    const SECCOMP: seccomp::Action = seccomp::Action::Log;

    pub fn run() -> io::Result<()> {
        log::set_tag(b"wlantunneld\0");
        let report = RefCell::new(Reporter::named(STATE_DIR, "wlantunneld"));
        report.borrow_mut().open("starting");
        stage(&report, "identity", ids::refuse_root())?;
        // the keys of the tunnels are in this process's memory
        stage(&report, "no core dumps", sys::not_dumpable())?;
        stage(&report, "no crash handler", sys::no_crash_handler())?;
        let kernel = stage(
            &report,
            "netlink sockets",
            sys::LinuxKernel::open(STATE_DIR.into()),
        )?;
        let link = QmiLink::for_services(
            QrtrSockets::with_max_datagram(MAX_DATAGRAM),
            &WANTED,
            MAX_CLIENTS,
        );
        let mut tunnel = Tunnel::new(Engine::new(Config::default(), link, kernel));
        stage(&report, "signals", signals::install())?;
        stage(
            &report,
            "syscall filter",
            seccomp::install_program(&filter::program(SECCOMP)),
        )?;
        report.borrow_mut().say(match SECCOMP {
            seccomp::Action::Log => "running, syscall filter in log mode",
            _ => "running, syscall filter enforcing",
        });
        tunnel.run(
            &mut MonotonicClock::new(),
            &mut SysPoller,
            &signals::stop_requested,
            &mut |line| report.borrow_mut().say(&line),
        );
        Ok(())
    }

    /// One stage of the start: its result is said, and a failure ends the start.
    fn stage<T>(report: &RefCell<Reporter>, what: &str, result: io::Result<T>) -> io::Result<T> {
        match &result {
            Ok(_) => report.borrow_mut().say(&format!("{what}: ok")),
            Err(e) => report.borrow_mut().say(&format!("{what}: failed: {e}")),
        }
        result
    }
}
