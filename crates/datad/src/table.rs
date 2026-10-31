// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The table of the links handed out, as it is kept in the state directory (tmpfs, next to the setup
//! marker). The data module keeps its calls when the daemon restarts, and the wire has no message
//! for it to name them again, so the daemon remembers which process holds which link and for what.
//! A restarted daemon reads the table back and takes the links as orphans of that process.
//!
//! One text line per link (`L`), and one per link whose call ended while its process was away and
//! has not been told yet (`T`, a tombstone). The file is read with strict rules: a line it does not
//! understand, a link twice, a boot ID that is not this boot's, or anything over the limits makes
//! the whole table no table. The APN is written in hex, so no character in it can end a field.
//! A process is its PID and its identity (the inode of the pidfd the kernel gives for the peer of the socket),
//! because a new radio daemon can get an old PID.
use dataos_wire::limits::MAX_APN;
use dataos_wire::{EndReason, LocalReason};
use std::fmt::Write;

const MAGIC: &str = "datad-links 3";
/// Links the pool has at most (the mux limit).
pub const MAX_ROWS: usize = 16;

/// A process: its number and its identity, the inode of the pidfd the kernel gives for it. pidfs numbers
/// its inodes with a 64-bit counter that does not repeat within a boot, so a radio daemon that comes back
/// with the number of an earlier one has another identity and inherits nothing. 0 is no identity (a test
/// that does not care).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Proc {
    pub pid: u32,
    pub ino: u64,
}

/// One link: who holds it and what it was handed out for.
#[derive(Clone, PartialEq, Eq)]
pub struct Row {
    pub link: u8,
    pub proc: Proc,
    pub slot: u8,
    pub apn: Option<String>,
    pub apn_type: u32,
    pub apn_type_mask: u64,
    pub emergency: bool,
    /// The module was told the link is up and has not been told it is down.
    pub told: bool,
    /// The families the module asked a link for (v4, v6).
    pub requested: [bool; 2],
}

// No derived Debug: the APN stays out of logs.
impl std::fmt::Debug for Row {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Row")
            .field("link", &self.link)
            .field("pid", &self.proc.pid)
            .finish_non_exhaustive()
    }
}

/// A link whose call ended while its process was away, and the Down the process is still owed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dead {
    pub link: u8,
    pub proc: Proc,
    pub slot: u8,
    pub reason: EndReason,
    /// Until when the number is kept (the clock of the daemon, which runs on through a restart).
    pub until: u64,
}

/// What the file holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    pub rows: Vec<Row>,
    pub dead: Vec<Dead>,
}

fn local_name(l: LocalReason) -> &'static str {
    match l {
        LocalReason::UserRequested => "user",
        LocalReason::ModemRestart => "restart",
        LocalReason::NoQmiClient => "noqmi",
        LocalReason::Timeout => "timeout",
        LocalReason::BindFailed => "bind",
        LocalReason::LinkFailed => "link",
        LocalReason::BadSettings => "settings",
        LocalReason::Malformed => "malformed",
        LocalReason::DaemonLost => "lost",
    }
}

fn local_from(name: &str) -> Option<LocalReason> {
    Some(match name {
        "user" => LocalReason::UserRequested,
        "restart" => LocalReason::ModemRestart,
        "noqmi" => LocalReason::NoQmiClient,
        "timeout" => LocalReason::Timeout,
        "bind" => LocalReason::BindFailed,
        "link" => LocalReason::LinkFailed,
        "settings" => LocalReason::BadSettings,
        "malformed" => LocalReason::Malformed,
        "lost" => LocalReason::DaemonLost,
        _ => return None,
    })
}

fn reason_text(r: EndReason) -> String {
    match r {
        EndReason::Network { kind, reason } => format!("n{kind}.{reason}"),
        EndReason::NetworkBasic(v) => format!("b{v}"),
        EndReason::Qmi(v) => format!("q{v}"),
        EndReason::Local(l) => format!("l{}", local_name(l)),
    }
}

fn parse_reason(text: &str) -> Option<EndReason> {
    let (kind, rest) = (text.get(..1)?, text.get(1..)?);
    match kind {
        "n" => {
            let (k, r) = rest.split_once('.')?;
            Some(EndReason::Network {
                kind: k.parse().ok()?,
                reason: r.parse().ok()?,
            })
        }
        "b" => Some(EndReason::NetworkBasic(rest.parse().ok()?)),
        "q" => Some(EndReason::Qmi(rest.parse().ok()?)),
        "l" => Some(EndReason::Local(local_from(rest)?)),
        _ => None,
    }
}

fn hex(text: &str) -> String {
    let mut out = String::with_capacity(text.len().saturating_mul(2));
    for b in text.bytes() {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn unhex(text: &str) -> Option<String> {
    if text.len() & 1 != 0 || !text.is_ascii() {
        return None;
    }
    let mut bytes = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(pair).ok()?;
        bytes.push(u8::from_str_radix(pair, 16).ok()?);
    }
    String::from_utf8(bytes).ok()
}

fn flag(b: bool) -> char {
    if b {
        '1'
    } else {
        '0'
    }
}

fn parse_flag(s: &str) -> Option<bool> {
    match s {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

pub fn encode(boot: &str, rows: &[Row], dead: &[Dead]) -> Vec<u8> {
    let mut out = format!("{MAGIC}\nboot {boot}\n");
    for r in rows {
        let apn = r.apn.as_deref().map_or_else(|| "-".to_string(), hex);
        let _ = writeln!(
            out,
            "L {} {} {} {} {} {} {}{}{}{} {}",
            r.link,
            r.proc.pid,
            r.proc.ino,
            r.slot,
            r.apn_type,
            r.apn_type_mask,
            flag(r.emergency),
            flag(r.told),
            flag(r.requested[0]),
            flag(r.requested[1]),
            apn
        );
    }
    for d in dead {
        let _ = writeln!(
            out,
            "T {} {} {} {} {} {}",
            d.link,
            d.proc.pid,
            d.proc.ino,
            d.slot,
            reason_text(d.reason),
            d.until
        );
    }
    out.into_bytes()
}

fn parse_row(line: &str) -> Option<Row> {
    let mut f = line.split(' ');
    if f.next()? != "L" {
        return None;
    }
    let link = f.next()?.parse().ok()?;
    let pid = f.next()?.parse().ok()?;
    let ino = f.next()?.parse().ok()?;
    let slot = f.next()?.parse().ok()?;
    let apn_type = f.next()?.parse().ok()?;
    let apn_type_mask = f.next()?.parse().ok()?;
    let flags: Vec<char> = f.next()?.chars().collect();
    let apn = match f.next()? {
        "-" => None,
        h => Some(unhex(h)?),
    };
    if f.next().is_some() {
        return None;
    }
    let [e, t, r4, r6] = flags.as_slice() else {
        return None;
    };
    let bit = |c: &char| parse_flag(&c.to_string());
    let requested = [bit(r4)?, bit(r6)?];
    // a link is handed out for a family
    if !requested[0] && !requested[1] {
        return None;
    }
    if apn
        .as_ref()
        .is_some_and(|t| t.len() > MAX_APN || t.contains('\0'))
    {
        return None;
    }
    Some(Row {
        link,
        proc: Proc { pid, ino },
        slot,
        apn,
        apn_type,
        apn_type_mask,
        emergency: bit(e)?,
        told: bit(t)?,
        requested,
    })
}

fn parse_dead(line: &str) -> Option<Dead> {
    let mut f = line.split(' ');
    if f.next()? != "T" {
        return None;
    }
    let link = f.next()?.parse().ok()?;
    let pid = f.next()?.parse().ok()?;
    let ino = f.next()?.parse().ok()?;
    let slot = f.next()?.parse().ok()?;
    let reason = parse_reason(f.next()?)?;
    let until = f.next()?.parse().ok()?;
    if f.next().is_some() {
        return None;
    }
    Some(Dead {
        link,
        proc: Proc { pid, ino },
        slot,
        reason,
        until,
    })
}

/// The table of a file that is this boot's and well formed, or None.
pub fn decode(bytes: &[u8], boot: &str) -> Option<Table> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.strip_suffix('\n')?.split('\n');
    if lines.next()? != MAGIC {
        return None;
    }
    if lines.next()?.strip_prefix("boot ")? != boot {
        return None;
    }
    let mut table = Table {
        rows: Vec::new(),
        dead: Vec::new(),
    };
    for line in lines {
        let link = if line.starts_with("T ") {
            let d = parse_dead(line)?;
            table.dead.push(d);
            d.link
        } else {
            let row = parse_row(line)?;
            let link = row.link;
            table.rows.push(row);
            link
        };
        // a link is a row or a tombstone, once, and the file has no more than the pool has
        let seen = table.rows.iter().filter(|r| r.link == link).count()
            + table.dead.iter().filter(|d| d.link == link).count();
        if table.rows.len() + table.dead.len() > MAX_ROWS || seen != 1 {
            return None;
        }
    }
    Some(table)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(link: u8) -> Row {
        Row {
            link,
            proc: Proc {
                pid: 4242,
                ino: 777,
            },
            slot: 1,
            apn: Some("internet.example".into()),
            apn_type: 1,
            apn_type_mask: 0x41,
            emergency: false,
            told: true,
            requested: [true, false],
        }
    }

    fn dead(link: u8) -> Dead {
        Dead {
            link,
            proc: Proc {
                pid: 4242,
                ino: 777,
            },
            slot: 1,
            reason: EndReason::Local(LocalReason::LinkFailed),
            until: 123_456,
        }
    }

    fn table(rows: Vec<Row>, dead: Vec<Dead>) -> Table {
        Table { rows, dead }
    }

    #[test]
    fn a_table_comes_back_as_it_went() {
        let mut other = row(3);
        other.apn = None;
        other.emergency = true;
        other.told = false;
        other.requested = [false, true];
        other.apn_type_mask = u64::MAX;
        other.apn_type = 0x8000_0001;
        other.proc.ino = u64::MAX;
        let t = table(vec![row(0), other], vec![dead(5)]);
        let bytes = encode("boot-1", &t.rows, &t.dead);
        assert_eq!(decode(&bytes, "boot-1"), Some(t));
        assert_eq!(
            decode(&encode("b", &[], &[]), "b"),
            Some(table(vec![], vec![]))
        );
    }

    #[test]
    fn every_kind_of_reason_comes_back() {
        let reasons = [
            EndReason::Network {
                kind: 3,
                reason: -5,
            },
            EndReason::Network {
                kind: u16::MAX,
                reason: i16::MIN,
            },
            EndReason::NetworkBasic(26),
            EndReason::Qmi(u16::MAX),
            EndReason::Local(LocalReason::UserRequested),
            EndReason::Local(LocalReason::ModemRestart),
            EndReason::Local(LocalReason::NoQmiClient),
            EndReason::Local(LocalReason::Timeout),
            EndReason::Local(LocalReason::BindFailed),
            EndReason::Local(LocalReason::LinkFailed),
            EndReason::Local(LocalReason::BadSettings),
            EndReason::Local(LocalReason::Malformed),
            EndReason::Local(LocalReason::DaemonLost),
        ];
        for (i, reason) in reasons.iter().enumerate() {
            let mut d = dead(u8::try_from(i).unwrap());
            d.reason = *reason;
            let bytes = encode("b", &[], &[d]);
            assert_eq!(
                decode(&bytes, "b"),
                Some(table(vec![], vec![d])),
                "{reason:?}"
            );
        }
    }

    #[test]
    fn the_apn_is_written_in_hex() {
        let bytes = encode("b", &[row(0)], &[]);
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("internet"));
        assert!(text.contains("696e7465726e65742e6578616d706c65"));
    }

    #[test]
    fn a_table_of_another_boot_is_no_table() {
        let bytes = encode("boot-1", &[row(0)], &[dead(1)]);
        assert_eq!(decode(&bytes, "boot-2"), None);
        assert_eq!(decode(&bytes, "boot-"), None);
    }

    #[test]
    fn anything_it_does_not_understand_makes_the_table_no_table() {
        let good = String::from_utf8(encode("b", &[row(0), row(1)], &[dead(2)])).unwrap();
        assert!(decode(good.as_bytes(), "b").is_some());
        let bad = [
            // no end of line, a wrong magic, no boot line, an extra line
            good.trim_end().to_string(),
            good.replace("datad-links 3", "datad-links 2"),
            good.replace("datad-links 3", "datad-links 4"),
            good.replace("boot b\n", ""),
            format!("{good}junk\n"),
            format!("{good}\n"),
            // a field too many, in the middle or at the end of a row and of a tombstone
            good.replace("L 0 4242 777", "L 0 4242 777 9"),
            good.replacen("\nL 1", " extra\nL 1", 1),
            good.replacen("\nT 2", " extra\nT 2", 1),
            format!("{} extra\n", good.trim_end()),
            format!("{} 9\n", good.trim_end()),
            // a field too few
            good.replace(" 696e7465726e65742e6578616d706c65\nL 1", "\nL 1"),
            good.replace("T 2 4242 777 1 llink 123456", "T 2 4242 777 1 llink"),
            good.replace("T 2 4242 777 1 ", "T 2 4242 777 "),
            // a number that is not one, out of range for its type
            good.replace("L 0 ", "L x "),
            good.replace("L 0 ", "L 256 "),
            good.replace("4242 777", "4294967296 777"),
            good.replace("4242 777", "4242 x"),
            good.replace("4242 777", "4242 18446744073709551616"),
            good.replace("T 2 ", "T 256 "),
            good.replace("123456", "x"),
            // flags: a wrong digit, a wrong count, no family requested
            good.replacen("0110", "0210", 1),
            good.replacen("0110", "011", 1),
            good.replacen("0110", "0100", 1),
            // an APN that is not hex, not UTF-8, with a NUL, too long
            good.replace("696e", "69zz"),
            good.replace(
                "696e7465726e65742e6578616d706c65",
                "696e7465726e65742e6578616d706c6",
            ),
            good.replace("696e7465726e65742e6578616d706c65", "ff"),
            good.replace("696e7465726e65742e6578616d706c65", "6100"),
            good.replace("696e7465726e65742e6578616d706c65", &"61".repeat(151)),
            // a reason that is none: unknown kind, unknown local name, a half network reason
            good.replace("llink", "lweird"),
            good.replace("llink", "x5"),
            good.replace("llink", "n1"),
            good.replace("llink", "n1.x"),
            good.replace("llink", "b-1"),
            good.replace("llink", "l"),
            good.replace("llink", ""),
            // the same link twice: two rows, a row and a tombstone, two tombstones
            good.replace("L 1 ", "L 0 "),
            good.replace("T 2 ", "T 1 "),
            format!("{}T 2 4242 777 1 llink 1\n", good),
        ];
        for (i, b) in bad.iter().enumerate() {
            assert_eq!(decode(b.as_bytes(), "b"), None, "case {i}: {b}");
        }
        assert_eq!(decode(&[0xff, 0xfe], "b"), None);
        assert_eq!(decode(b"", "b"), None);
    }

    #[test]
    fn a_row_with_a_field_after_the_apn_is_refused_alone() {
        // the check for fields after the last one is its own: a row that is right up to its APN
        let one = String::from_utf8(encode("b", &[row(0)], &[])).unwrap();
        assert!(decode(one.as_bytes(), "b").is_some());
        let longer = one.replacen('\n', " 1\n", 2).replace("boot b 1", "boot b");
        assert_eq!(decode(longer.as_bytes(), "b"), None, "{longer}");
    }

    #[test]
    fn an_apn_of_the_longest_size_is_kept_and_the_table_has_a_limit_of_rows() {
        let mut long = row(0);
        long.apn = Some("a".repeat(150));
        assert_eq!(
            decode(&encode("b", &[long.clone()], &[]), "b"),
            Some(table(vec![long], vec![]))
        );
        let rows: Vec<Row> = (0..16).map(row).collect();
        assert_eq!(
            decode(&encode("b", &rows, &[]), "b").map(|t| t.rows.len()),
            Some(16)
        );
        let rows: Vec<Row> = (0..17).map(row).collect();
        assert_eq!(decode(&encode("b", &rows, &[]), "b"), None);
        // rows and tombstones share the limit
        let rows: Vec<Row> = (0..10).map(row).collect();
        let tombs: Vec<Dead> = (10..16).map(dead).collect();
        assert!(decode(&encode("b", &rows, &tombs), "b").is_some());
        let tombs: Vec<Dead> = (10..17).map(dead).collect();
        assert_eq!(decode(&encode("b", &rows, &tombs), "b"), None);
    }

    #[test]
    fn a_full_table_fits_the_file() {
        let mut long = row(0);
        long.apn = Some("a".repeat(150));
        let rows: Vec<Row> = (0..16)
            .map(|i| {
                let mut r = long.clone();
                r.link = i;
                r.proc.ino = u64::MAX;
                r
            })
            .collect();
        assert!(encode("0123456789abcdef0123456789abcdef0123", &rows, &[]).len() < 8192);
    }

    #[test]
    fn debug_leaves_the_apn_out() {
        assert!(!format!("{:?}", row(0)).contains("internet"));
    }
}
