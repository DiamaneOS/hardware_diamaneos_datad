// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Soong builds device Rust with `panic=abort`, so a panic in the code that
//! runs inside `qcrilNrd` kills voice and emergency calls with it. Three things
//! keep that code free of panics: the forbid list in each lib.rs (an `allow` or
//! `expect` cannot switch a forbidden lint off), the `clippy.toml` list of
//! methods that can panic, and these tests, which fail if either is weakened,
//! a forbidden construct is added, or a new dependency is pulled into the shim.
#![allow(clippy::disallowed_methods)] // test code, the list is for the shipped crates
use std::fs;
use std::path::{Path, PathBuf};

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// The crates linked into the radio daemon where no unsafe code is allowed at all.
const STRICT_CRATES: [&str; 3] = ["wire", "nicm-compat", "nicm-abi"];

/// The two libraries with the C exports. They may use unsafe code in the files
/// below, and only there, and every unsafe block says why it is sound.
const VENEER_CRATES: [&str; 2] = ["libnicm", "libnicm-dsi"];
const UNSAFE_FILES: [&str; 2] = ["abi.rs", "sys.rs"];

fn shim_crates() -> Vec<&'static str> {
    STRICT_CRATES
        .iter()
        .chain(&VENEER_CRATES)
        .copied()
        .collect()
}

fn is_veneer(krate: &str) -> bool {
    VENEER_CRATES.contains(&krate)
}

/// A file of a veneer crate where unsafe code is allowed.
fn may_use_unsafe(krate: &str, file: &str) -> bool {
    is_veneer(krate) && UNSAFE_FILES.contains(&file)
}

/// Lints that must be forbidden (not only denied) outside tests.
const FORBIDDEN_LINTS: [&str; 15] = [
    "clippy::unwrap_used",
    "clippy::expect_used",
    "clippy::panic",
    "clippy::unreachable",
    "clippy::todo",
    "clippy::unimplemented",
    "clippy::indexing_slicing",
    "clippy::string_slice",
    "clippy::unwrap_in_result",
    "clippy::get_unwrap",
    "clippy::panic_in_result_fn",
    "clippy::print_stdout",
    "clippy::print_stderr",
    "clippy::dbg_macro",
    "clippy::exit",
];

/// Denied: the compile-time limits need an allow for it.
const DENIED_LINTS: [&str; 1] = ["clippy::arithmetic_side_effects"];

/// Methods `clippy.toml` must keep disallowed, at least.
const DISALLOWED: [&str; 16] = [
    "core::ops::Index::index",
    "core::ops::IndexMut::index_mut",
    "slice::split_at",
    "slice::copy_from_slice",
    "alloc::vec::Vec::remove",
    "alloc::vec::Vec::insert",
    "alloc::vec::Vec::drain",
    "u32::pow",
    "u64::pow",
    "i16::abs",
    "i32::abs",
    "std::iter::Iterator::sum",
    "core::cell::RefCell::borrow_mut",
    "std::process::exit",
    "std::process::abort",
    "std::thread::spawn",
];

/// Constructs that can panic or skip the checks. Comments are not looked at.
/// The method names are those only the panicking standard methods have, for the
/// builds where clippy.toml is not read (Soong has no mention of it).
const FORBIDDEN: [&str; 38] = [
    ".unwrap()",
    ".expect(",
    "unwrap_unchecked",
    "panic!",
    "unreachable!",
    "todo!",
    "unimplemented!",
    "assert!",
    "assert_eq!",
    "assert_ne!",
    "debug_assert",
    "unsafe",
    "get_unchecked",
    "process::abort",
    "process::exit",
    "println!",
    "eprintln!",
    "dbg!",
    "#[path",
    "include!(",
    "thread::spawn",
    ".pow(",
    ".abs()",
    ".sum(",
    ".sum::<",
    ".product(",
    ".split_at(",
    ".split_at_mut(",
    ".copy_from_slice(",
    ".clone_from_slice(",
    ".copy_within(",
    ".borrow_mut(",
    ".step_by(",
    ".swap_remove(",
    ".split_off(",
    ".rotate_left(",
    ".rotate_right(",
    ".div_euclid(",
];

/// Words that make an attribute change a lint level, however it is wrapped: a
/// `cfg_attr` can carry an `allow` into any module. Only the lib.rs block and the
/// named exceptions in `attribute_violations` may have them.
const LEVEL_WORDS: [&str; 6] = [
    "allow(",
    "expect(",
    "warn(",
    "deny(",
    "forbid(",
    "cfg_attr(",
];

/// The standard maps and queues panic on `m[&k]` and `q[i]` and no clippy lint
/// covers that. Only `coll.rs`, whose wrappers have no `Index`, may name them.
const RAW_COLLECTIONS: [&str; 4] = ["BTreeMap", "HashMap", "VecDeque", "collections::"];

/// Ways to get an indexing operator back, or to call it by name.
const INDEX_TOKENS: [&str; 4] = ["Index<", "IndexMut", ".index(", ".index_mut("];

fn sources(krate: &str) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let mut stack = vec![crates_dir().join(krate).join("src")];
    while let Some(dir) = stack.pop() {
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let text = fs::read_to_string(&p).unwrap();
                out.push((p, text));
            }
        }
    }
    assert!(!out.is_empty(), "no sources found for {krate}");
    out
}

/// Index just after the brace that closes the block opened at `open` (the byte
/// index of a `{`). Braces inside strings, character literals and comments do
/// not count.
fn block_end(text: &str, open: usize) -> usize {
    let b = text.as_bytes();
    let (mut i, mut depth) = (open, 0usize);
    while i < b.len() {
        match b[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
            }
            b'\'' => {
                // 'x' or '\n' is a character, 'a is a lifetime
                if b.get(i + 2) == Some(&b'\'') {
                    i += 2;
                } else if b.get(i + 1) == Some(&b'\\') {
                    i += 3;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    b.len()
}

/// The text without the items marked `#[cfg(test)]`: a block up to its closing
/// brace, any other item up to its semicolon. Code that follows such an item
/// stays, so a violation after an early test module is still seen. The cut
/// items leave their line breaks, so line numbers stay.
fn without_test_code(text: &str) -> String {
    const MARK: &str = "#[cfg(test)]";
    let mut out = String::new();
    let mut rest = text;
    while let Some(i) = rest.find(MARK) {
        out.push_str(&rest[..i]);
        let after = &rest[i + MARK.len()..];
        let (open, semi) = (after.find('{'), after.find(';'));
        let end = match (open, semi) {
            (Some(o), Some(s)) if s < o => s + 1,
            (Some(o), _) => block_end(after, o),
            (None, Some(s)) => s + 1,
            (None, None) => after.len(),
        };
        out.push_str(&"\n".repeat(after[..end].matches('\n').count()));
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

/// The text with comments and the inside of string and character literals
/// turned into spaces (line breaks stay), so a scan for attributes or for
/// type names is not fooled by what they say.
fn blanked(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = b.to_vec();
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for c in out.iter_mut().take(to).skip(from) {
            if *c != b'\n' {
                *c = b' ';
            }
        }
    };
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                let end = text[i..].find('\n').map_or(b.len(), |n| i + n);
                blank(&mut out, i, end);
                i = end;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let (mut depth, mut k) = (1, i + 2);
                while k < b.len() && depth > 0 {
                    if b[k] == b'/' && b.get(k + 1) == Some(&b'*') {
                        depth += 1;
                        k += 1;
                    } else if b[k] == b'*' && b.get(k + 1) == Some(&b'/') {
                        depth -= 1;
                        k += 1;
                    }
                    k += 1;
                }
                blank(&mut out, i, k);
                i = k;
            }
            b'r' | b'b' if i == 0 || !ident(b[i - 1]) => {
                // r"..", r#".."#, br#".."#
                let mut k = i + 1;
                if b[i] == b'b' && b.get(k) == Some(&b'r') {
                    k += 1;
                } else if b[i] == b'b' {
                    i += 1;
                    continue;
                }
                let hashes = b[k..].iter().take_while(|c| **c == b'#').count();
                if b.get(k + hashes) == Some(&b'"') {
                    let close = format!("\"{}", "#".repeat(hashes));
                    let from = k + hashes + 1;
                    let end = text[from..]
                        .find(&close)
                        .map_or(b.len(), |n| from + n + close.len());
                    blank(&mut out, from, end.saturating_sub(close.len()));
                    i = end;
                } else {
                    i += 1;
                }
            }
            b'"' => {
                let mut k = i + 1;
                while k < b.len() && b[k] != b'"' {
                    k += if b[k] == b'\\' { 2 } else { 1 };
                }
                blank(&mut out, i + 1, k);
                i = k + 1;
            }
            b'\'' => {
                // 'x' and '\n' are characters, 'a is a lifetime
                let rest = &text[i + 1..];
                let len = if rest.starts_with('\\') {
                    rest[2..].find('\'').map_or(0, |n| n + 3)
                } else {
                    rest.chars().next().map_or(0, |c| {
                        if rest[c.len_utf8()..].starts_with('\'') {
                            c.len_utf8() + 1
                        } else {
                            0
                        }
                    })
                };
                if len > 0 {
                    blank(&mut out, i + 1, i + len);
                    i += len + 1;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    String::from_utf8(out).unwrap()
}

/// Code of a line without its comment.
fn code_of(line: &str) -> String {
    let code = line.split("//").next().unwrap_or("");
    // the lint attributes are checked by `attribute_violations`
    code.replace("forbid(unsafe_code)", "")
        .replace("deny(unsafe_code)", "")
        .replace("allow(unsafe_code)", "")
}

/// Every attribute of a text that was run through `blanked`, as (line,
/// content without whitespace). Attributes over several lines are one attribute.
fn attributes(blank: &str) -> Vec<(usize, String)> {
    let b = blank.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'#' {
            let mut j = i + 1;
            if b.get(j) == Some(&b'!') {
                j += 1;
            }
            while b.get(j).is_some_and(|c| c.is_ascii_whitespace()) {
                j += 1;
            }
            if b.get(j) == Some(&b'[') {
                let (mut depth, mut k) = (0, j);
                while k < b.len() {
                    match b[k] {
                        b'[' => depth += 1,
                        b']' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    k += 1;
                }
                let body: String = blank[j + 1..k.min(blank.len())]
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect();
                out.push((blank[..i].matches('\n').count() + 1, body));
                i = k;
            }
        }
        i += 1;
    }
    out
}

/// What is wrong with the attributes of one source file outside its test items.
/// `file` is the file name. The one block in lib.rs that sets the lints is checked
/// by `every_shim_crate_forbids_the_panicking_constructs`, here it is only
/// allowed once.
fn attribute_violations(file: &str, text: &str, veneer: bool) -> Vec<String> {
    let is_lib = file == "lib.rs";
    let mut seen_block = false;
    let mut out = Vec::new();
    for (line, a) in attributes(&without_test_code(&blanked(text))) {
        let unsafe_attr = if veneer {
            "deny(unsafe_code)"
        } else {
            "forbid(unsafe_code)"
        };
        let exception = (is_lib && a == unsafe_attr)
            || (veneer && UNSAFE_FILES.contains(&file) && a == "allow(unsafe_code)")
            || (veneer && file == "abi.rs" && a == "allow(non_snake_case)")
            || a == "allow(clippy::large_enum_variant)"
            || (file == "limits.rs" && a == "allow(clippy::arithmetic_side_effects)");
        if is_lib && !seen_block && a.starts_with("cfg_attr(not(test),forbid(") {
            seen_block = true;
        } else if !exception && LEVEL_WORDS.iter().any(|w| a.contains(w)) {
            out.push(format!("line {line}: a lint level is changed: {a}"));
        }
    }
    out
}

/// What is wrong with the collection types a source file names.
fn collection_violations(file: &str, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (n, line) in without_test_code(&blanked(text)).lines().enumerate() {
        let mut bad: Vec<&str> = INDEX_TOKENS.to_vec();
        if file != "coll.rs" {
            bad.extend(RAW_COLLECTIONS);
        }
        for t in bad {
            if line.contains(t) {
                out.push(format!("line {}: `{t}` in `{}`", n + 1, line.trim()));
            }
        }
    }
    out
}

/// The attribute that sets the lints in a crate's lib.rs, without whitespace.
fn lib_block(krate: &str) -> String {
    let lib = fs::read_to_string(crates_dir().join(krate).join("src/lib.rs")).unwrap();
    let attrs = attributes(&blanked(&lib));
    let unsafe_attr = if is_veneer(krate) {
        "deny(unsafe_code)"
    } else {
        "forbid(unsafe_code)"
    };
    assert!(
        attrs.iter().any(|(_, a)| a == unsafe_attr),
        "{krate}: unsafe code is not {unsafe_attr}"
    );
    attrs
        .into_iter()
        .map(|(_, a)| a)
        .find(|a| a.starts_with("cfg_attr("))
        .unwrap_or_else(|| panic!("{krate}: no lint attribute in lib.rs"))
}

#[test]
fn every_shim_crate_forbids_the_panicking_constructs() {
    for k in shim_crates() {
        let block = lib_block(k);
        let inner = block
            .strip_prefix("cfg_attr(not(test),forbid(")
            .unwrap_or_else(|| panic!("{k}: the lints must be forbid, and apply outside tests"));
        let (forbid, deny) = inner
            .split_once("),deny(")
            .unwrap_or_else(|| panic!("{k}: no deny list for arithmetic"));
        let deny = deny
            .strip_suffix("))")
            .expect("the block ends after the deny list");
        let names = |list: &str| {
            list.split(',')
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        let (forbid, deny) = (names(forbid), names(deny));
        for lint in FORBIDDEN_LINTS {
            assert!(
                forbid.iter().any(|l| l == lint),
                "{k}: {lint} is not forbidden"
            );
        }
        for lint in DENIED_LINTS {
            assert!(deny.iter().any(|l| l == lint), "{k}: {lint} is not denied");
        }
    }
}

#[test]
fn every_shim_crate_keeps_the_disallowed_methods_list() {
    for k in shim_crates() {
        let toml = fs::read_to_string(crates_dir().join(k).join("clippy.toml")).unwrap();
        assert!(
            toml.contains("disallowed-methods"),
            "{k}: no disallowed-methods"
        );
        for m in DISALLOWED {
            assert!(
                toml.contains(&format!("path = \"{m}\"")),
                "{k}: {m} is not disallowed"
            );
        }
    }
}

#[test]
fn the_shim_sources_contain_no_forbidden_construct() {
    for k in shim_crates() {
        for (path, text) in sources(k) {
            let file = path.file_name().unwrap().to_str().unwrap();
            for (n, line) in without_test_code(&text).lines().enumerate() {
                let code = code_of(line);
                // a compile-time check is evaluated by the compiler, it cannot run
                if code.trim_start().starts_with("const _: () = assert!(") {
                    continue;
                }
                for bad in FORBIDDEN {
                    if bad == "unsafe" && may_use_unsafe(k, file) {
                        continue;
                    }
                    assert!(
                        !code.contains(bad),
                        "{}:{}: `{bad}` in code that runs inside qcrilNrd",
                        path.display(),
                        n + 1
                    );
                }
            }
        }
    }
}

/// Lines with unsafe code that have no reason within the six lines before them: a
/// `SAFETY` comment for a block or an impl, a `Safety` section for a function.
fn unsafe_without_reason(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let code = without_test_code(&blanked(text));
    let mut out = Vec::new();
    for (n, line) in code.lines().enumerate() {
        if !line.contains("unsafe") || line.contains("unsafe_code") {
            continue;
        }
        let from = n.saturating_sub(6);
        let explained = lines[from..=n.min(lines.len() - 1)]
            .iter()
            .any(|l| l.contains("SAFETY:") || l.contains("# Safety"));
        if !explained {
            out.push(format!(
                "line {}: unsafe without a reason: {}",
                n + 1,
                line.trim()
            ));
        }
    }
    out
}

#[test]
fn every_unsafe_block_of_the_veneer_says_why_it_is_sound_and_only_two_files_have_any() {
    for k in VENEER_CRATES {
        for (path, text) in sources(k) {
            let file = path.file_name().unwrap().to_str().unwrap();
            if may_use_unsafe(k, file) {
                let bad = unsafe_without_reason(&text);
                assert!(bad.is_empty(), "{}: {bad:?}", path.display());
            } else {
                let code = without_test_code(&blanked(&text));
                assert!(
                    !code
                        .lines()
                        .any(|l| l.contains("unsafe") && !l.contains("unsafe_code")),
                    "{}: unsafe outside the two files",
                    path.display()
                );
            }
        }
    }
    // the check itself
    assert!(unsafe_without_reason("fn f() {\n    unsafe { g() }\n}\n").len() == 1);
    assert!(unsafe_without_reason(
        "fn f() {\n    // SAFETY: g needs nothing.\n    unsafe { g() }\n}\n"
    )
    .is_empty());
    assert!(unsafe_without_reason(
        "/// # Safety\n/// p is valid.\npub unsafe fn f(p: *const u8) {}\n"
    )
    .is_empty());
    assert!(
        unsafe_without_reason("// SAFETY: far above\n\n\n\n\n\n\n\nunsafe impl Send for X {}\n")
            .len()
            == 1
    );
    assert!(unsafe_without_reason("#![deny(unsafe_code)]\n").is_empty());
}

#[test]
fn no_lint_level_is_changed_inside_the_shim_except_where_named() {
    for k in shim_crates() {
        for (path, text) in sources(k) {
            let file = path.file_name().unwrap().to_str().unwrap();
            let bad = attribute_violations(file, &text, is_veneer(k));
            assert!(bad.is_empty(), "{}: {bad:?}", path.display());
        }
    }
}

#[test]
fn the_shim_names_no_raw_collection_and_implements_no_index() {
    for k in shim_crates() {
        for (path, text) in sources(k) {
            let file = path.file_name().unwrap().to_str().unwrap();
            let bad = collection_violations(file, &text);
            assert!(bad.is_empty(), "{}: {bad:?}", path.display());
        }
    }
}

#[test]
fn planted_violations_are_found_and_clean_code_is_not_flagged() {
    // An inner cfg_attr that switches a lint off
    let inner = "#![cfg_attr(not(test), allow(clippy::arithmetic_side_effects))]\nfn f(a: u32, b: u32) -> u32 { a + b }\n";
    assert!(!attribute_violations("api.rs", inner, false).is_empty());
    for planted in [
        // over several lines, with a comment between
        "#![cfg_attr(\n    not(test),\n    // fine\n    allow(clippy::unwrap_used)\n)]\n",
        "#[cfg_attr(not(test), allow(clippy::indexing_slicing))]\nfn f() {}\n",
        "#[ allow ( clippy::arithmetic_side_effects ) ]\nfn f() {}\n",
        "#[expect(clippy::unwrap_used)]\nfn f() {}\n",
        "#![warn(clippy::all)]\n",
        // the named exception with one more lint beside it
        "#[allow(clippy::large_enum_variant, clippy::unwrap_used)]\nenum E {}\n",
        // the arithmetic exception is for limits.rs only
        "#![allow(clippy::arithmetic_side_effects)]\n",
        // after a test module, the code that follows is still looked at
        "#[cfg(test)]\nmod t { fn x() {} }\n#![cfg_attr(not(test), allow(clippy::panic))]\n",
    ] {
        assert!(
            !attribute_violations("client.rs", planted, false).is_empty(),
            "{planted}"
        );
    }
    // a second block in lib.rs is not the sanctioned one
    let two = "#![cfg_attr(not(test), forbid(clippy::panic), deny(clippy::arithmetic_side_effects))]\n#![cfg_attr(not(test), allow(clippy::arithmetic_side_effects))]\n";
    assert_eq!(attribute_violations("lib.rs", two, false).len(), 1);
    // what is fine
    let fine = "#[derive(Debug)]\nstruct A;\n// #![allow(clippy::panic)]\nconst S: &str = \"#![allow(clippy::panic)]\";\nconst R: &str = r#\"#[allow(x)]\"#;\n#[cfg(test)]\n#[allow(clippy::unwrap_used)]\nmod t {}\n#[allow(clippy::large_enum_variant)]\nenum E {}\n";
    assert_eq!(
        attribute_violations("client.rs", fine, false),
        Vec::<String>::new()
    );
    assert!(attribute_violations(
        "limits.rs",
        "#![allow(clippy::arithmetic_side_effects)]\n",
        false
    )
    .is_empty());
    // the veneer: unsafe_code is denied in lib.rs and allowed in the two files, nowhere else
    assert!(attribute_violations("lib.rs", "#![deny(unsafe_code)]\n", true).is_empty());
    assert!(attribute_violations("abi.rs", "#![allow(unsafe_code)]\n", true).is_empty());
    assert!(attribute_violations("sys.rs", "#![allow(unsafe_code)]\n", true).is_empty());
    for (file, text, veneer) in [
        ("conn.rs", "#![allow(unsafe_code)]\n", true),
        ("abi.rs", "#![allow(unsafe_code)]\n", false),
        ("lib.rs", "#![forbid(unsafe_code)]\n", true),
        ("lib.rs", "#![deny(unsafe_code)]\n", false),
        ("abi.rs", "#![allow(clippy::unwrap_used)]\n", true),
        ("abi.rs", "#[allow(dead_code)]\nfn f() {}\n", true),
    ] {
        assert!(
            !attribute_violations(file, text, veneer).is_empty(),
            "{file} {text}"
        );
    }

    // indexing a map or a queue, and the ways around the wrappers
    for planted in [
        "use std::collections::BTreeMap;\nfn f(m: &BTreeMap<u8, u8>) -> u8 { m[&1] }\n",
        "fn f(q: &std::collections::VecDeque<u8>) -> u8 { q[0] }\n",
        "use std::collections::*;\n",
        "type T = std::collections::HashMap<u8, u8>;\n",
        "impl core::ops::Index<u8> for X {}\n",
        "fn f(t: &T) -> &u8 { t.index(0) }\n",
    ] {
        assert!(
            !collection_violations("client.rs", planted).is_empty(),
            "{planted}"
        );
    }
    // the wrappers may hold the raw types, and still not implement Index
    assert!(
        collection_violations("coll.rs", "use std::collections::{BTreeMap, VecDeque};\n")
            .is_empty()
    );
    assert!(!collection_violations("coll.rs", "impl<T> Index<usize> for Queue<T> {}\n").is_empty());
    assert!(collection_violations(
        "client.rs",
        "// a BTreeMap in a comment\nconst S: &str = \"VecDeque\";\n"
    )
    .is_empty());
}

#[test]
fn test_code_is_cut_out_by_its_braces_and_what_follows_is_still_checked() {
    let text = "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() { let _ = \"{\"; x.unwrap(); }\n}\nfn b() { y.unwrap() }\n#[cfg(test)]\nuse z::q;\nfn c() {}\n";
    let kept = without_test_code(text);
    assert!(kept.contains("fn a()") && kept.contains("fn b()") && kept.contains("fn c()"));
    assert!(
        kept.contains("y.unwrap()"),
        "code after a test module is kept"
    );
    assert!(!kept.contains("x.unwrap()"), "the test module is cut out");
    assert!(!kept.contains("use z::q"), "a gated use is cut out");
}

/// What each crate may link. The libraries only use each other, the wire
/// types and libc (the sockets).
fn shipped_dependencies(krate: &str) -> &'static [&'static str] {
    match krate {
        "nicm-compat" => &["dataos-wire"],
        "libnicm" => &[
            "dataos-wire",
            "dataos-nicm-compat",
            "dataos-nicm-abi",
            "libc",
        ],
        "libnicm-dsi" => &["dataos-nicm-abi"],
        _ => &[],
    }
}

/// Names under every dependency-like section of a crate's Cargo.toml.
fn dependency_sections(krate: &str) -> Vec<(String, Vec<String>)> {
    let toml = fs::read_to_string(crates_dir().join(krate).join("Cargo.toml")).unwrap();
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for line in toml.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            out.push((line.to_string(), Vec::new()));
        } else if !line.is_empty() && !line.starts_with('#') {
            if let Some((_, names)) = out.last_mut() {
                if let Some(name) = line.split('=').next() {
                    names.push(name.trim().to_string());
                }
            }
        }
    }
    out
}

#[test]
fn the_shim_pulls_in_only_what_is_named_for_each_crate() {
    for k in shim_crates() {
        for (section, names) in dependency_sections(k) {
            let is_dep = section.contains("dependencies") || section.starts_with("[patch");
            if !is_dep {
                continue;
            }
            // dev-dependencies are tests only, everything else is shipped
            if section == "[dev-dependencies]" {
                continue;
            }
            let mut allowed: Vec<String> = if section == "[dependencies]" {
                shipped_dependencies(k)
                    .iter()
                    .map(|d| d.to_string())
                    .collect()
            } else {
                Vec::new()
            };
            allowed.sort();
            let mut names = names;
            names.sort();
            assert_eq!(
                names, allowed,
                "{k}: unexpected shipped dependency section {section}"
            );
        }
        // no build script can run code at build time
        assert!(
            !crates_dir().join(k).join("build.rs").exists(),
            "{k}: build.rs"
        );
    }
}

#[test]
fn the_release_profile_checks_overflow_and_aborts() {
    // overflow checks stay on in release builds, so an overflow that slipped
    // past the lint is at least not silent. Soong sets its own flags.
    let root = fs::read_to_string(crates_dir().parent().unwrap().join("Cargo.toml")).unwrap();
    assert!(root.contains("overflow-checks = true") && root.contains("panic = \"abort\""));
}

/// The modules of an Android.bp as (kind, body without comments). A module
/// starts with `kind {` in the first column and ends with `}` in the first column.
fn bp_modules(bp: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut open: Option<(String, String)> = None;
    for line in bp.lines() {
        let code = line.split("//").next().unwrap_or("");
        match &mut open {
            None => {
                if !line.starts_with(char::is_whitespace) && code.trim_end().ends_with('{') {
                    let kind = code.trim_end().trim_end_matches('{').trim().to_string();
                    open = Some((kind, String::new()));
                }
            }
            Some((_, body)) => {
                if code.trim_end() == "}" && !line.starts_with(char::is_whitespace) {
                    out.extend(open.take());
                } else {
                    body.push_str(&code.split_whitespace().collect::<Vec<_>>().join(" "));
                    body.push('\n');
                }
            }
        }
    }
    out
}

/// The Soong properties every module that holds shim code needs. Without the first,
/// Soong runs no clippy under hardware/ and vendor/, without the third the
/// clippy-driver does not find clippy.toml, and the second keeps the relaxed rustc set.
const SOONG_PROPERTIES: [&str; 3] = [
    "clippy_lints: \"android\",",
    "lints: \"vendor\",",
    "cargo_env_compat: true,",
];

fn missing_soong_properties(bp: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (kind, body) in bp_modules(bp) {
        if !kind.starts_with("rust_") {
            continue;
        }
        let name = body
            .lines()
            .find_map(|l| l.strip_prefix("name: "))
            .unwrap_or("?");
        for prop in SOONG_PROPERTIES {
            if !body.lines().any(|l| l == prop) {
                out.push(format!("{kind} {name}: no `{prop}`"));
            }
        }
    }
    out
}

/// The Rust modules of an Android.bp that do not take the default which switches them off unless the
/// device turns the data stack on (android/Android.bp). A module without it would install the
/// replacement libraries next to the stock ones in every build.
fn modules_without_the_switch(bp: &str) -> Vec<String> {
    bp_modules(bp)
        .into_iter()
        .filter(|(kind, body)| {
            kind.starts_with("rust_")
                && !body
                    .lines()
                    .any(|l| l == "defaults: [\"diamaneos_datad_defaults\"],")
        })
        .map(|(kind, body)| {
            let name = body.lines().find_map(|l| l.strip_prefix("name: "));
            format!("{kind} {}", name.unwrap_or("?"))
        })
        .collect()
}

/// (crate directory, module kind, crate_name) of the Soong module each crate has.
const SOONG_MODULES: [(&str, &str, &str); 5] = [
    ("wire", "rust_library", "dataos_wire"),
    ("nicm-compat", "rust_library", "dataos_nicm_compat"),
    ("nicm-abi", "rust_library", "dataos_nicm_abi"),
    ("libnicm", "rust_ffi_shared", "nicm"),
    ("libnicm-dsi", "rust_ffi_shared", "nicm_dsi"),
];

#[test]
fn the_soong_sketches_ask_for_the_wall_in_every_module_that_holds_shim_code() {
    let root = crates_dir().parent().unwrap().to_path_buf();
    // one Android.bp next to each shim crate's clippy.toml
    let files: Vec<String> = shim_crates()
        .iter()
        .map(|k| format!("crates/{k}/Android.bp"))
        .collect();
    for rel in files {
        let bp =
            fs::read_to_string(root.join(&rel)).unwrap_or_else(|_| panic!("{rel}: no Android.bp"));
        assert!(!bp_modules(&bp).is_empty(), "{rel}: no module found");
        let missing = missing_soong_properties(&bp);
        assert!(missing.is_empty(), "{rel}: {missing:?}");
        assert_eq!(
            modules_without_the_switch(&bp),
            Vec::<String>::new(),
            "{rel}"
        );
    }
    assert_eq!(SOONG_MODULES.len(), shim_crates().len());
    for (k, kind_wanted, crate_name) in SOONG_MODULES {
        assert!(shim_crates().contains(&k), "{k} is not a shim crate");
        let dir = crates_dir().join(k);
        assert!(dir.join("clippy.toml").exists(), "{k}: no clippy.toml");
        let bp = fs::read_to_string(dir.join("Android.bp")).unwrap();
        let lib = format!("crate_name: \"{crate_name}\",");
        assert!(
            bp_modules(&bp)
                .iter()
                .any(|(kind, body)| kind == kind_wanted
                    && body.lines().any(|l| l == lib)
                    && body.lines().any(|l| l == "crate_root: \"src/lib.rs\",")
                    // clippy reads clippy.toml, and Soong stops a build for a file it did not list as an input
                    && body
                        .lines()
                        .any(|l| l == "srcs: [\"src/lib.rs\", \"clippy.toml\"],")),
            "{k}: no {kind_wanted} for the crate in its Android.bp"
        );
    }
    // the libraries and the daemon bring their Rust libraries and std in, no dylib is installed next to them
    for k in ["libnicm", "libnicm-dsi"] {
        let bp = fs::read_to_string(crates_dir().join(k).join("Android.bp")).unwrap();
        assert!(
            bp_modules(&bp)
                .iter()
                .any(|(_, b)| b.lines().any(|l| l == "prefer_rlib: true,")),
            "{k}: no prefer_rlib"
        );
    }
    // the two libraries keep the soname the closed ones have
    for (k, stem) in [("libnicm", "libnicm"), ("libnicm-dsi", "libnicm_dsi")] {
        let bp = fs::read_to_string(crates_dir().join(k).join("Android.bp")).unwrap();
        let want = format!("stem: \"{stem}\",");
        assert!(
            bp_modules(&bp)
                .iter()
                .any(|(_, b)| b.lines().any(|l| l == want)),
            "{k}: no {want}"
        );
    }
}

#[test]
fn a_rust_module_without_the_switch_default_is_found() {
    let bad = "rust_library {\n    name: \"libx\",\n}\nrust_binary {\n    name: \"y\",\n    defaults: [\"diamaneos_datad_defaults\"],\n}\ncc_library {\n    name: \"z\",\n}\n";
    assert_eq!(
        modules_without_the_switch(bad),
        vec!["rust_library \"libx\",".to_string()]
    );
}

#[test]
fn the_default_turns_the_modules_off_unless_the_device_turns_them_on() {
    let root = crates_dir().parent().unwrap().to_path_buf();
    let bp = fs::read_to_string(root.join("android/Android.bp")).unwrap();
    let modules = bp_modules(&bp);
    let (_, defaults) = modules
        .iter()
        .find(|(kind, b)| {
            kind == "diamaneos_datad_rust_defaults"
                && b.lines()
                    .any(|l| l == "name: \"diamaneos_datad_defaults\",")
        })
        .expect("no diamaneos_datad_defaults");
    // on when the variable is set, off in every other case
    let flat = defaults.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains("datad_enabled: { enabled: true, conditions_default: { enabled: false,"),
        "{flat}"
    );
    // the make file that sets it is what the board file of the device includes, and nothing else sets it
    let soong = fs::read_to_string(root.join("android/datad-soong.mk")).unwrap();
    assert!(soong.contains("SOONG_CONFIG_diamaneos_datad_datad_enabled := true"));
    let board = fs::read_to_string(root.join("android/datad-board.mk")).unwrap();
    assert!(board.contains("include hardware/diamaneos/datad/android/datad-soong.mk"));
    for other in ["datad-product.mk", "datad.rc", "config.fs"] {
        let text = fs::read_to_string(root.join("android").join(other)).unwrap();
        assert!(!text.contains("datad_enabled := true"), "{other}");
    }
}

#[test]
fn a_soong_module_without_the_wall_properties_is_found() {
    let bad = "// comment\nrust_library {\n    name: \"libx\",\n    clippy_lints: \"android\",\n    // cargo_env_compat: true,\n    lints: \"vendor\",\n}\n";
    assert_eq!(
        missing_soong_properties(bad),
        vec!["rust_library \"libx\",: no `cargo_env_compat: true,`".to_string()]
    );
    let none = "rust_binary {\n    name: \"x\",\n}\ncc_library {\n    name: \"y\",\n}\n";
    assert_eq!(
        missing_soong_properties(none).len(),
        3,
        "a cc module is not looked at"
    );
}

/// (crate directory, crate_name) of the library each crate of the daemon has.
const DAEMON_MODULES: [(&str, &str); 6] = [
    ("qmi", "dataos_qmi"),
    ("netcfg", "dataos_netcfg"),
    ("datacore", "dataos_datacore"),
    ("datad", "dataos_datad"),
    ("datad-rt", "dataos_datad_rt"),
    ("wlan-tunnel", "dataos_wlan_tunnel"),
];

/// The dependencies a Cargo.toml names outside the dev-dependencies, as Soong module names:
/// `dataos-foo-bar` is `libdataos_foo_bar` and `libc` is `liblibc`.
fn cargo_deps_as_soong(krate: &str) -> Vec<String> {
    let toml = fs::read_to_string(crates_dir().join(krate).join("Cargo.toml")).unwrap();
    let mut live = false;
    let mut out = Vec::new();
    for line in toml.lines() {
        if line.starts_with('[') {
            live = line.trim_end().ends_with("dependencies]") && !line.contains("dev-");
        } else if live {
            if let Some((name, _)) = line.split_once(" = ") {
                out.push(format!("lib{}", name.trim().replace('-', "_")));
            }
        }
    }
    out.sort();
    out
}

fn rustlibs_of(body: &str) -> Vec<String> {
    // a list may span lines: from `rustlibs: [` to the line with the closing bracket
    let mut list = String::new();
    let mut open = false;
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("rustlibs: [") {
            open = true;
            list.push_str(rest);
        } else if open {
            list.push_str(line);
        }
        if open && line.contains(']') {
            break;
        }
    }
    let mut out: Vec<String> = list
        .trim_end_matches([',', ']'])
        .split(',')
        .map(|n| n.trim().trim_matches(['"', ']']).to_string())
        .filter(|n| !n.is_empty())
        .collect();
    out.sort();
    out
}

#[test]
fn the_soong_modules_of_the_daemon_match_the_crates() {
    for (k, crate_name) in DAEMON_MODULES {
        let bp = fs::read_to_string(crates_dir().join(k).join("Android.bp"))
            .unwrap_or_else(|_| panic!("{k}: no Android.bp"));
        assert!(
            missing_soong_properties(&bp).is_empty(),
            "{k}: {:?}",
            missing_soong_properties(&bp)
        );
        assert_eq!(modules_without_the_switch(&bp), Vec::<String>::new(), "{k}");
        let lib = format!("crate_name: \"{crate_name}\",");
        let modules = bp_modules(&bp);
        let (_, body) = modules
            .iter()
            .find(|(kind, b)| {
                kind == "rust_library"
                    && b.lines().any(|l| l == lib)
                    && b.lines().any(|l| l == "srcs: [\"src/lib.rs\"],")
            })
            .unwrap_or_else(|| panic!("{k}: no rust_library for the crate"));
        assert!(
            body.lines().any(|l| l == "vendor: true,"),
            "{k}: not vendor"
        );
        // the Soong dependencies are the Cargo ones, so the two builds link the same crates
        assert_eq!(rustlibs_of(body), cargo_deps_as_soong(k), "{k}: rustlibs");
    }
}

#[test]
fn the_tunnel_daemon_is_built_from_main_and_brings_its_rc() {
    let bp = fs::read_to_string(crates_dir().join("wlantunneld/Android.bp")).unwrap();
    assert!(missing_soong_properties(&bp).is_empty());
    assert_eq!(modules_without_the_switch(&bp), Vec::<String>::new());
    let modules = bp_modules(&bp);
    let (_, bin) = modules
        .iter()
        .find(|(kind, b)| kind == "rust_binary" && b.lines().any(|l| l == "name: \"wlantunneld\","))
        .expect("no rust_binary wlantunneld");
    for want in [
        "srcs: [\"src/main.rs\"],",
        "vendor: true,",
        "required: [\"wlantunneld.rc\"],",
        "prefer_rlib: true,",
    ] {
        assert!(bin.lines().any(|l| l == want), "no {want}");
    }
    assert_eq!(rustlibs_of(bin), cargo_deps_as_soong("wlantunneld"));
    let rc = fs::read_to_string(crates_dir().parent().unwrap().join("android/Android.bp")).unwrap();
    let rc_modules = bp_modules(&rc);
    let (_, etc) = rc_modules
        .iter()
        .find(|(kind, b)| {
            kind == "diamaneos_datad_prebuilt_etc"
                && b.lines().any(|l| l == "name: \"wlantunneld.rc\",")
        })
        .expect("no switchable prebuilt_etc wlantunneld.rc");
    let flat = etc.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(flat.contains("datad_enabled: { enabled: true, conditions_default: { enabled: false,"));
}

#[test]
fn the_daemon_binary_is_built_from_main_and_brings_its_rc() {
    let bp = fs::read_to_string(crates_dir().join("datad-rt/Android.bp")).unwrap();
    let modules = bp_modules(&bp);
    let (_, bin) = modules
        .iter()
        .find(|(kind, b)| kind == "rust_binary" && b.lines().any(|l| l == "name: \"datad\","))
        .expect("no rust_binary datad");
    assert!(bin.lines().any(|l| l == "srcs: [\"src/main.rs\"],"));
    assert!(bin.lines().any(|l| l == "vendor: true,"));
    // the init rc comes with the binary, the way the IMS daemon's does
    assert!(bin.lines().any(|l| l == "required: [\"datad.rc\"],"));
    assert!(
        bin.lines().any(|l| l == "prefer_rlib: true,"),
        "no prefer_rlib"
    );
    // it links the runtime and only crates the runtime itself links
    let (_, lib) = modules
        .iter()
        .find(|(kind, _)| kind == "rust_library")
        .unwrap();
    let allowed = rustlibs_of(lib);
    for dep in rustlibs_of(bin) {
        assert!(
            dep == "libdataos_datad_rt" || allowed.contains(&dep),
            "the binary links {dep}"
        );
    }
    assert!(rustlibs_of(bin).contains(&"libdataos_datad_rt".to_string()));
    let rc = fs::read_to_string(crates_dir().parent().unwrap().join("android/Android.bp")).unwrap();
    let rc_modules = bp_modules(&rc);
    let (_, etc) = rc_modules
        .iter()
        .find(|(kind, b)| {
            kind == "diamaneos_datad_prebuilt_etc" && b.lines().any(|l| l == "name: \"datad.rc\",")
        })
        .expect("no switchable prebuilt_etc datad.rc");
    let flat = etc.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains("datad_enabled: { enabled: true, conditions_default: { enabled: false,"),
        "the rc is not switched off: {flat}"
    );
    for want in ["src: \"datad.rc\",", "sub_dir: \"init\",", "vendor: true,"] {
        assert!(etc.lines().any(|l| l == want), "datad.rc module: no {want}");
    }
}
