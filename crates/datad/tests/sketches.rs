// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! The Android sketches agree with each other. Nothing here runs on a device.
use std::fs;
use std::path::Path;

fn sketch(name: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../android")
        .join(name);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

#[test]
fn the_domain_that_makes_the_marker_directory_may_make_it() {
    let rc = sketch("datad.rc");
    let te = sketch("sepolicy/vendor/datad.te");
    // the rc file makes the directory at early boot (init runs a vendor rc file in vendor_init) ...
    assert!(
        rc.lines()
            .any(|l| l.trim_start().starts_with("mkdir /dev/datad")),
        "the marker directory is made in datad.rc"
    );
    // ... so that domain needs the permissions to create it and to set its owner and mode
    let allowed: Vec<&str> = te
        .lines()
        .filter(|l| l.starts_with("allow vendor_init diamaneos_datad_state:dir"))
        .collect();
    assert!(
        !allowed.is_empty(),
        "vendor_init is allowed nothing on the marker directory"
    );
    for perm in ["create", "setattr", "getattr"] {
        assert!(
            allowed.iter().any(|l| l
                .split_whitespace()
                .any(|w| w.trim_matches(|c| c == '{' || c == '}' || c == ';') == perm)),
            "vendor_init lacks {perm} on the marker directory"
        );
    }
    // and it is allowed no more than that: no rename, no removal of what the daemon wrote
    for l in &allowed {
        for bad in ["rename", "rmdir", "reparent", "remove_name"] {
            assert!(!l.contains(bad), "{l}");
        }
    }
}

#[test]
fn the_device_build_sets_the_cfg_that_refuses_a_library_pair_with_the_flag_off() {
    // nicm-abi fails to build under this cfg while STOCK_ABI_VERIFIED is false, so the three
    // modules of the pair must all set it, and the sketches are where a device build is described
    for dir in ["nicm-abi", "libnicm", "libnicm-dsi"] {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../")
            .join(dir)
            .join("Android.bp");
        let bp = fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        assert!(
            bp.contains("cfgs: [\"device_build\"]"),
            "{dir}/Android.bp does not set the device_build cfg"
        );
    }
    let abi =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../nicm-abi/src/lib.rs"))
            .unwrap();
    assert!(
        abi.contains("cfg!(device_build)") && abi.contains("STOCK_ABI_VERIFIED"),
        "nicm-abi has no build guard on the flag"
    );
}
