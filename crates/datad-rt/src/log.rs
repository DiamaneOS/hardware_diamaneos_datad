// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The daemon's own lines. init gives the daemon no standard output (`datad.rc` has no stdio), so what goes to
//! stderr is lost. On Android the lines go to liblog, which hands them to logd (`logcat`), on user builds too.
//! Elsewhere they go to stderr, for a run on a host.
//!
//! A line has no identifier in it: no number, name or address of a phone, a SIM, a network or a peer. The
//! callers pass fixed text and the daemon's own error and note types, and this module adds nothing.
//!
//! liblog opens its socket to logd at the first line and keeps it. The daemon writes a line before it puts the
//! syscall filter on (`main`), so the filter needs neither `socket` for a Unix socket nor `connect`: later lines
//! are `writev` on the open socket. That first line goes through `__android_log_write_log_message` (`open`), which
//! has no level check: `__android_log_write` looks at the minimum priority first, and a `log.tag` property that
//! filters out information lines would stop it before the socket was opened. If logd restarts, liblog connects
//! again, which the filter does not allow (in log mode the kernel logs the `connect`, number 203, and the call
//! goes through). With the filter enforcing, the lines that follow are lost until the daemon restarts, which costs a
//! log and nothing else.
#![allow(unsafe_code)]

/// The most bytes of a line. logd cuts at about four thousand, and a line of the daemon is short.
const MAX_LINE: usize = 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

impl Level {
    /// `android_LogPriority`: ANDROID_LOG_INFO 4, ANDROID_LOG_WARN 5, ANDROID_LOG_ERROR 6.
    pub fn priority(self) -> i32 {
        match self {
            Level::Info => 4,
            Level::Warn => 5,
            Level::Error => 6,
        }
    }
}

/// The line as liblog takes it: a C string. A NUL in the text would cut the line, so it is left out, and a long
/// line is cut at `MAX_LINE` bytes.
pub fn c_line(msg: &str) -> Vec<u8> {
    let mut v: Vec<u8> = msg.bytes().filter(|b| *b != 0).take(MAX_LINE).collect();
    v.push(0);
    v
}

#[cfg(target_os = "android")]
extern "C" {
    fn __android_log_write(
        prio: libc::c_int,
        tag: *const libc::c_char,
        text: *const libc::c_char,
    ) -> libc::c_int;
}

/// The tag of every line, as a C string.
#[cfg(target_os = "android")]
const TAG: &[u8] = b"datad\0";

/// `struct __android_log_message` of `android/log.h` (API 30).
#[cfg(target_os = "android")]
#[repr(C)]
struct AndroidLogMessage {
    struct_size: usize,
    buffer_id: i32,
    priority: i32,
    tag: *const libc::c_char,
    file: *const libc::c_char,
    line: u32,
    message: *const libc::c_char,
}

#[cfg(all(target_os = "android", target_pointer_width = "64"))]
const _: () = assert!(std::mem::size_of::<AndroidLogMessage>() == 48);

#[cfg(target_os = "android")]
extern "C" {
    fn __android_log_write_log_message(log_message: *mut AndroidLogMessage);
}

/// The first line of the process. It opens the socket to logd, whatever the minimum priority is.
pub fn open(msg: &str) {
    #[cfg(target_os = "android")]
    {
        let line = c_line(msg);
        let mut m = AndroidLogMessage {
            struct_size: std::mem::size_of::<AndroidLogMessage>(),
            // LOG_ID_MAIN
            buffer_id: 0,
            priority: Level::Info.priority(),
            tag: TAG.as_ptr().cast(),
            file: std::ptr::null(),
            line: 0,
            message: line.as_ptr().cast(),
        };
        // SAFETY: the structure is the one liblog documents, with the size in it. The tag and the message are
        // NUL-terminated and live until the call returns, and liblog only reads them.
        unsafe { __android_log_write_log_message(&mut m) };
    }
    #[cfg(not(target_os = "android"))]
    eprintln!("datad: {msg}");
}

/// Write one line.
pub fn write(level: Level, msg: &str) {
    #[cfg(target_os = "android")]
    {
        let line = c_line(msg);
        // SAFETY: the tag and the line are NUL-terminated and live until the call returns, and liblog only
        // reads them. The result is not needed: a line that could not be written is lost.
        let _ = unsafe {
            __android_log_write(level.priority(), TAG.as_ptr().cast(), line.as_ptr().cast())
        };
    }
    #[cfg(not(target_os = "android"))]
    {
        eprintln!("datad: {msg}");
        let _ = level;
    }
}

pub fn info(msg: &str) {
    write(Level::Info, msg);
}

pub fn warn(msg: &str) {
    write(Level::Warn, msg);
}

pub fn error(msg: &str) {
    write(Level::Error, msg);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_is_a_c_string_without_a_nul_inside_and_is_cut_when_it_is_long() {
        assert_eq!(c_line("stopped: x"), b"stopped: x\0");
        assert_eq!(c_line("a\0b"), b"ab\0");
        assert_eq!(c_line(""), b"\0");
        let long = "x".repeat(5000);
        let c = c_line(&long);
        assert_eq!(c.len(), 1001);
        assert_eq!(c.last(), Some(&0));
        assert!(c[..1000].iter().all(|b| *b == b'x'));
    }

    #[test]
    fn the_priorities_are_those_of_android() {
        assert_eq!(
            [Level::Info, Level::Warn, Level::Error].map(Level::priority),
            [4, 5, 6]
        );
    }
}
