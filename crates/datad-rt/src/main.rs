// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The data daemon. It takes the socket init made for it, opens the netlink socket and the QRTR
//! sockets, puts the syscall filter on, and runs the main loop until it is told to stop. A failure
//! at start writes one line without any identifier to the log (`logcat`, see `log.rs`) and ends the process with 1.
//! init starts it again.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn main() {
    if let Err(e) = linux::run() {
        dataos_datad_rt::log::error(&format!("stopped: {e}"));
        std::process::exit(1);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn main() {
    eprintln!("datad: runs on Linux only");
    std::process::exit(1);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux {
    use dataos_datacore::engine::{Config, Engine};
    use dataos_datad::daemon::Daemon;
    use dataos_datad::server::{Server, ServerConfig};
    use dataos_datad::transport::QmiLink;
    use dataos_datad_rt::clock::MonotonicClock;
    use dataos_datad_rt::poll::SysPoller;
    use dataos_datad_rt::qrtr::QrtrSockets;
    use dataos_datad_rt::report::Reporter;
    use dataos_datad_rt::unix::UnixIpc;
    use dataos_datad_rt::{ids, kernel, log, seccomp, signals};
    use dataos_netcfg::linux::{LinuxNet, DEFAULT_STATE_DIR};
    use std::cell::RefCell;
    use std::io;

    /// The name of the socket in the rc file (`socket datad seqpacket ...`).
    const SOCKET: &str = "datad";

    /// Until a log-mode run on the phone has shown which syscalls the daemon makes, the filter
    /// logs what it would refuse. Set to `Action::Errno` after that run.
    const SECCOMP: seccomp::Action = seccomp::Action::Log;

    pub fn run() -> io::Result<()> {
        let report = RefCell::new(Reporter::new(DEFAULT_STATE_DIR));
        // the first line opens the socket to logd, which the filter would not let the daemon open later, and it does
        // so whatever log.tag properties say
        report.borrow_mut().open("starting");
        // real, effective and saved IDs, user and group: none may be root's
        stage(&report, "identity", ids::refuse_root())?;
        // the identity of a peer is its pidfd, which has an inode of its own from Linux 6.9
        stage(
            &report,
            "kernel",
            kernel::refuse_before(kernel::PIDFD_IDENTITY),
        )?;
        // everything that needs a socket of a kind the filter will not allow later
        let ipc = stage(&report, "control socket", UnixIpc::inherited(SOCKET))?;
        let net = stage(&report, "device netlink socket", LinuxNet::open())?;
        let link = QmiLink::new(QrtrSockets::new());
        let engine = Engine::new(Config::default(), link, net);
        let mut daemon = Daemon::new(Server::new(ServerConfig::default(), engine), ipc);
        stage(&report, "signals", signals::install())?;
        stage(&report, "syscall filter", seccomp::install(SECCOMP))?;
        report.borrow_mut().say(match SECCOMP {
            seccomp::Action::Log => "running, syscall filter in log mode",
            _ => "running, syscall filter enforcing",
        });
        daemon.run(
            &mut MonotonicClock::new(),
            &mut SysPoller,
            &signals::stop_requested,
            &mut |note| log::warn(&format!("note: {note:?}")),
            &mut |trace| report.borrow_mut().trace(trace),
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
