// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! What the daemon says about itself while it runs: the start, the modem, every step of the bring-up, the
//! handshake with the data module and every request it refuses (`Trace` of the engine). A line has no
//! identifier in it (see `log.rs`).
//!
//! Each line goes to the log at the information level, and the last lines are kept in a file of the state
//! directory, `/dev/datad/status`. The directory is tmpfs and the file mode 0600, so it is read as root over
//! adb (`cat /dev/datad/status`). It is there because the first minutes of a run are what a failure needs, and
//! the log buffer of a phone that is busy holds a few minutes. Every line starts with the time in seconds of the
//! monotonic clock, the same as the kernel log (`dmesg`), so the two can be laid side by side.
use crate::clock::MonotonicClock;
use crate::log;
use dataos_datacore::Trace;
use dataos_datad::daemon::Clock;
use std::collections::VecDeque;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

/// Lines kept in the file.
const KEEP: usize = 48;

pub struct Reporter {
    dir: PathBuf,
    name: &'static str,
    clock: MonotonicClock,
    lines: VecDeque<String>,
    /// Lines that were left out of the file because it could not be written, for the next line to say.
    write_failures: u32,
}

impl Reporter {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self::named(dir, "datad")
    }

    /// The reporter of another daemon: the first line of the file has its name.
    pub fn named(dir: impl Into<PathBuf>, name: &'static str) -> Self {
        Reporter {
            dir: dir.into(),
            name,
            clock: MonotonicClock::new(),
            lines: VecDeque::new(),
            write_failures: 0,
        }
    }

    /// The first line of the process, which opens the socket to logd (see `log::open`).
    pub fn open(&mut self, text: &str) {
        log::open(text);
        self.keep(text);
    }

    /// A line of the daemon's own, such as a stage of the start.
    pub fn say(&mut self, text: &str) {
        log::info(text);
        self.keep(text);
    }

    /// A trace of the engine or the server.
    pub fn trace(&mut self, t: Trace) {
        self.say(&t.line());
    }

    fn keep(&mut self, text: &str) {
        let now = self.clock.now_ms();
        let line = format!("[{:>6}.{:03}] {text}", now / 1_000, now % 1_000);
        if self.lines.len() >= KEEP {
            self.lines.pop_front();
        }
        self.lines.push_back(line);
        if self.write().is_err() {
            self.write_failures = self.write_failures.saturating_add(1);
        }
    }

    fn write(&self) -> std::io::Result<()> {
        let mut text = format!("{} status, newest last\n", self.name);
        for l in &self.lines {
            text.push_str(l);
            text.push('\n');
        }
        let tmp = self.dir.join("status.tmp");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(text.as_bytes())?;
        drop(f);
        std::fs::rename(&tmp, self.dir.join("status"))
    }

    #[cfg(test)]
    fn lines(&self) -> Vec<String> {
        self.lines.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dataos_datacore::{Answer, BringupStep};

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("datad-report-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_last_lines_are_in_the_file_with_the_time_of_the_kernel_log() {
        let dir = temp_dir("lines");
        let mut r = Reporter::new(&dir);
        r.say("starting");
        r.trace(Trace::StepAnswered(
            BringupStep::Format,
            Answer::Refused(0x46),
        ));
        let text = std::fs::read_to_string(dir.join("status")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("status"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let rows: Vec<&str> = text.lines().collect();
        assert_eq!(rows[0], "datad status, newest last");
        assert!(
            rows[1].starts_with('[') && rows[1].ends_with("] starting"),
            "{}",
            rows[1]
        );
        assert!(
            rows[2].ends_with("] bring-up: set data format: refused by the modem, QMI error 0x46"),
            "{}",
            rows[2]
        );
        assert_eq!(rows.len(), 3);
        assert!(!dir.join("status.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_the_newest_lines_are_kept() {
        let dir = temp_dir("keep");
        let mut r = Reporter::new(&dir);
        for n in 0..(KEEP + 10) {
            r.say(&format!("line {n}"));
        }
        let lines = r.lines();
        assert_eq!(lines.len(), KEEP);
        assert!(lines[0].ends_with("line 10"));
        assert!(lines[KEEP - 1].ends_with(&format!("line {}", KEEP + 9)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_directory_that_cannot_be_written_does_not_stop_the_log() {
        let mut r = Reporter::new("/nonexistent-datad-directory");
        r.say("starting");
        r.say("running");
        assert_eq!(r.lines().len(), 2);
        assert_eq!(r.write_failures, 2);
    }
}
