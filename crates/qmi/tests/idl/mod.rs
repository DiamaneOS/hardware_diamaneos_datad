// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The layouts of the stock IDL tables, read from `idl-expected.txt` next to this file, and a checker for bytes against them.
//! A dump of the IDL tables of the stock library holds the file to the library, these tests hold the code to the file.
#![allow(dead_code)]
use dataos_qmi::Frame;
use std::collections::BTreeMap;

/// A type as the dump of the IDL tables writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ty {
    Int(usize),
    Enum(usize),
    Str,
    Struct(Vec<Ty>),
    /// `max` items. `prefix` is the width of the count in front of a variable array, 0 for none.
    Array {
        item: Box<Ty>,
        max: usize,
        variable: bool,
        prefix: usize,
    },
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn eat(&mut self, text: &str) -> bool {
        if self.s[self.i..].starts_with(text.as_bytes()) {
            self.i += text.len();
            true
        } else {
            false
        }
    }

    fn number(&mut self) -> usize {
        let start = self.i;
        while self.i < self.s.len() && self.s[self.i].is_ascii_digit() {
            self.i += 1;
        }
        std::str::from_utf8(&self.s[start..self.i])
            .unwrap()
            .parse()
            .unwrap()
    }

    fn ty(&mut self) -> Ty {
        let base = if self.eat("struct{") {
            let mut members = vec![self.ty()];
            while self.eat(",") {
                members.push(self.ty());
            }
            assert!(self.eat("}"), "closing brace in {:?}", self.s);
            Ty::Struct(members)
        } else if self.eat("enum16") {
            self.eat("u");
            Ty::Enum(2)
        } else if self.eat("enum8") {
            self.eat("u");
            Ty::Enum(1)
        } else if self.eat("str") {
            Ty::Str
        } else if self.eat("u64") {
            Ty::Int(8)
        } else if self.eat("u32") {
            Ty::Int(4)
        } else if self.eat("u16") {
            Ty::Int(2)
        } else if self.eat("u8") {
            Ty::Int(1)
        } else {
            panic!("type text not understood at {:?}", &self.s[self.i..]);
        };
        if !self.eat("[") {
            return base;
        }
        let variable = self.eat("<=");
        let max = self.number();
        assert!(self.eat("]"));
        let prefix = if self.eat("/") { self.number() } else { 0 };
        Ty::Array {
            item: Box::new(base),
            max,
            variable,
            prefix,
        }
    }
}

impl Ty {
    pub fn parse(text: &str) -> Ty {
        let mut p = Parser {
            s: text.as_bytes(),
            i: 0,
        };
        let t = p.ty();
        assert_eq!(p.i, text.len(), "trailing text in {text:?}");
        t
    }

    /// Smallest and largest number of bytes on the wire. A string at the top of a TLV has no count in front.
    pub fn size(&self, top: bool) -> (usize, usize) {
        match self {
            Ty::Int(w) | Ty::Enum(w) => (*w, *w),
            Ty::Str => (1, 1),
            Ty::Struct(m) => m.iter().fold((0, 0), |(lo, hi), t| {
                let (a, b) = t.size(false);
                (lo + a, hi + b)
            }),
            Ty::Array {
                item,
                max,
                variable,
                prefix,
            } => {
                let (lo, hi) = item.size(false);
                if !variable {
                    (lo * max, hi * max)
                } else if top && **item == Ty::Str {
                    (0, *max)
                } else {
                    (*prefix, prefix + hi * max)
                }
            }
        }
    }

    /// Does `b` hold exactly one value of this type? For a nested value `top` is false and the answer is
    /// the number of bytes it takes, which may be less than `b.len()`.
    pub fn check(&self, b: &[u8], top: bool) -> Result<usize, String> {
        let used = self.take(b, top)?;
        if top && used != b.len() {
            return Err(format!("{} bytes left over", b.len() - used));
        }
        Ok(used)
    }

    fn take(&self, b: &[u8], top: bool) -> Result<usize, String> {
        match self {
            Ty::Int(w) | Ty::Enum(w) => {
                if b.len() < *w {
                    return Err(format!("{} bytes, {w} needed", b.len()));
                }
                Ok(*w)
            }
            Ty::Str => Err("a lone string".into()),
            Ty::Struct(members) => {
                let mut at = 0;
                for m in members {
                    at += m.take(b.get(at..).unwrap_or(&[]), false)?;
                }
                Ok(at)
            }
            Ty::Array {
                item,
                max,
                variable,
                prefix,
            } => {
                let (count, mut at) = if !variable {
                    (*max, 0)
                } else if top && **item == Ty::Str {
                    (b.len(), 0)
                } else {
                    let n = match (prefix, b) {
                        (1, [n, ..]) => usize::from(*n),
                        (2, [lo, hi, ..]) => usize::from(u16::from_le_bytes([*lo, *hi])),
                        _ => return Err("count missing".into()),
                    };
                    (n, *prefix)
                };
                if count > *max {
                    return Err(format!("{count} items, at most {max}"));
                }
                for _ in 0..count {
                    at += if **item == Ty::Str {
                        if b.len() < at + 1 {
                            return Err("string cut".into());
                        }
                        1
                    } else {
                        item.take(b.get(at..).unwrap_or(&[]), false)?
                    };
                }
                Ok(at)
            }
        }
    }

    /// A value of the largest size (`max`) or the smallest (`!max`). Every integer is 1 and every character
    /// is `a`, which no parser of ours has a reason to refuse.
    pub fn sample(&self, max: bool, top: bool) -> Vec<u8> {
        match self {
            Ty::Int(w) | Ty::Enum(w) => {
                let mut v = vec![0; *w];
                v[0] = 1;
                v
            }
            Ty::Str => vec![b'a'],
            Ty::Struct(m) => m.iter().flat_map(|t| t.sample(max, false)).collect(),
            Ty::Array {
                item,
                max: limit,
                variable,
                prefix,
            } => {
                let count = if !variable || max { *limit } else { 0 };
                let mut v = Vec::new();
                if *variable && !(top && **item == Ty::Str) {
                    match prefix {
                        1 => v.push(u8::try_from(count).unwrap()),
                        2 => v.extend_from_slice(&u16::try_from(count).unwrap().to_le_bytes()),
                        _ => panic!("no count width"),
                    }
                }
                for _ in 0..count {
                    v.extend(item.sample(max, false));
                }
                v
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Request,
    Response,
    Indication,
}

#[derive(Clone, Debug)]
pub struct Tlv {
    pub tag: u8,
    pub required: bool,
    pub ty: Ty,
}

pub struct Spec {
    /// (service name, kind, message ID) to its TLVs.
    pub messages: BTreeMap<(String, Kind, u16), Vec<Tlv>>,
    /// Service name to its ID.
    pub services: BTreeMap<String, u8>,
    /// Messages the tables must not define.
    pub absent: Vec<(String, Kind, u16)>,
}

fn number(text: &str) -> u64 {
    u64::from_str_radix(text.trim_start_matches("0x"), 16).unwrap()
}

impl Spec {
    pub fn load() -> Spec {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../qmi/tests/idl/idl-expected.txt"
        );
        let text = std::fs::read_to_string(path).unwrap();
        let mut spec = Spec {
            messages: BTreeMap::new(),
            services: BTreeMap::new(),
            absent: Vec::new(),
        };
        let mut service = String::new();
        let mut current: Option<(String, Kind, u16)> = None;
        for line in text.lines() {
            let line = line.split('#').next().unwrap().trim();
            let words: Vec<&str> = line.split_whitespace().collect();
            let kind = |w: &str| match w {
                "request" => Kind::Request,
                "response" => Kind::Response,
                "indication" => Kind::Indication,
                other => panic!("kind {other}"),
            };
            match words.as_slice() {
                [] => {}
                ["service", name, id] => {
                    service = (*name).to_owned();
                    spec.services
                        .insert(service.clone(), u8::try_from(number(id)).unwrap());
                }
                ["absent", k, id] => {
                    spec.absent.push((
                        service.clone(),
                        kind(k),
                        u16::try_from(number(id)).unwrap(),
                    ));
                }
                [k @ ("request" | "response" | "indication"), id] => {
                    let key = (service.clone(), kind(k), u16::try_from(number(id)).unwrap());
                    spec.messages.insert(key.clone(), Vec::new());
                    current = Some(key);
                }
                ["tlv", tag, req, ty] => {
                    let key = current.clone().unwrap();
                    spec.messages.get_mut(&key).unwrap().push(Tlv {
                        tag: u8::try_from(number(tag)).unwrap(),
                        required: *req == "req",
                        ty: Ty::parse(ty),
                    });
                }
                other => panic!("line not understood: {other:?}"),
            }
        }
        spec
    }

    pub fn message(&self, service: &str, kind: Kind, id: u16) -> &[Tlv] {
        self.messages
            .get(&(service.to_owned(), kind, id))
            .unwrap_or_else(|| panic!("{service} {kind:?} {id:#x} is not in the expected file"))
    }

    /// Does this frame fit the table for its message? Every TLV must be a listed one of the right type and
    /// size, and every required TLV must be there (the result alone, in a response that reports a failure). A TLV the file does not list fails the check, so an
    /// addition to a builder has to be added to the file, which a dump of the library's tables then holds to the library.
    pub fn check_frame(&self, service: &str, f: &Frame<'_>) -> Result<(), String> {
        let kind = match f.kind {
            dataos_qmi::Kind::Request => Kind::Request,
            dataos_qmi::Kind::Response => Kind::Response,
            dataos_qmi::Kind::Indication => Kind::Indication,
        };
        let key = (service.to_owned(), kind, f.id);
        let Some(tlvs) = self.messages.get(&key) else {
            return Err(format!(
                "{service} {kind:?} {:#06x} is not in the file",
                f.id
            ));
        };
        for (tag, value) in f.tlvs() {
            let Some(t) = tlvs.iter().find(|t| t.tag == tag) else {
                return Err(format!("tlv {tag:#04x} is not in the table"));
            };
            t.ty.check(value, true)
                .map_err(|e| format!("tlv {tag:#04x}: {e}"))?;
        }
        // The stock decoder does not look for the other mandatory TLVs of a response that reports a failure.
        let failed = kind == Kind::Response && f.status().is_ok_and(|s| !s.is_ok());
        for t in tlvs.iter().filter(|t| t.required) {
            if f.tlv(t.tag).is_none() && !(failed && t.tag != 0x02) {
                return Err(format!("required tlv {:#04x} is missing", t.tag));
            }
        }
        Ok(())
    }

    /// A message of this kind with every listed TLV at its largest (or only the required ones at their smallest).
    pub fn build(&self, service: &str, kind: Kind, id: u16, all: bool, txn: u16) -> Vec<u8> {
        use dataos_qmi::frame::Builder;
        let tlvs = self.message(service, kind, id);
        let mut b = match kind {
            Kind::Request => Builder::request(txn, id),
            Kind::Response => Builder::response(txn, id),
            Kind::Indication => Builder::indication(id),
        };
        for t in tlvs {
            if t.required || all {
                // the result TLV carries success
                let value = if t.tag == 0x02 && kind == Kind::Response {
                    vec![0, 0, 0, 0]
                } else {
                    t.ty.sample(all, true)
                };
                b = b.tlv(t.tag, &value).unwrap();
            }
        }
        b.build().unwrap()
    }
}
