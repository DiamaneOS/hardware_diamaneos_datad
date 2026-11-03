# datad: the open data daemon and nicm libraries

An open replacement for the closed Qualcomm `nicmd` daemon and for the two small libraries that connect the
radio daemon to it, `libnicm.so` and `libnicm_dsi.so`. Written in Rust, for the Fairphone 6 (FP6) vendor
image. It is meant to be checked out at `hardware/diamaneos/datad` in an Android build tree.

## Why

On the stock image mobile data goes through three closed parts: the data call layer inside the radio daemon
(`qcrilNrd`, with `libdsi_netctrl.so` and `libqdi.so`), a small translation layer (`libnicm_dsi.so` and
`libnicm.so`) and the interface manager `nicmd`, which owns the network interfaces and the IPA pipes. The last
two talk to each other over TIPC, a Linux kernel protocol that nothing else on the phone uses. This repository
replaces the two libraries and `nicmd` with open code that talks over a Unix socket instead, so the kernel can be
built without TIPC and the code that sets up interfaces and parses modem messages is Rust
that can be read and tested.

`libdsi_netctrl.so`, `libqdi.so` and the rest of QCRIL stay as they are and keep call setup, the emergency
call path included. The open daemon does what `nicmd` did for them: it answers their route lookups, creates
the rmnet links, tells them when an interface comes up, goes down or changes, and keeps the calls of the data
module alive across a restart of the daemon.

A Wi-Fi call through the modem has a second daemon, `wlantunneld`. The closed IWLAN app and QCRIL keep call control
and the modem negotiates IKE. The modem then asks the AP to carry the tunnel: `wlantunneld` makes the reverse links
`r_rmnet_data0` to `3`, installs the ESP states and policies the modem names, configures the kernel module `rmnet_wlan`
and holds the ports the modem asks for. It has its own user and SELinux domain, so a fault in the path of the ESP keys
cannot take down cellular data or the emergency path, and the data daemon has no XFRM, TCP or UDP at all. Keys are held
in a type that cannot be printed, and are zeroed with every buffer that held them.

## What is in it

| Path | What |
|---|---|
| `crates/qmi` | QMI framing over QRTR and the WDS, WDA, DPM and DFS messages with the reverse transport of WDS. The parsers cannot panic |
| `crates/netcfg` | rtnetlink, XFRM and `rmnet_wlan` builders, ethtool features, control of the IPA device `rmnet_ipa0`, the `NetOps` seam, a stateful fake kernel (feature `fake`) and the Linux backend |
| `crates/datacore` | The data call engine. A simulated modem sits behind the feature `sim` |
| `crates/wire` | The protocol between the libraries and the daemon, with its own types and limits. No dependencies |
| `crates/datad` | The server of the daemon: route lookup, links, interface events, restart handling. No unsafe code |
| `crates/datad-rt` | The libc calls of the daemon: QRTR and Unix sockets, poll, signals, the syscall filter, the log, and `main` (the binary `datad`) |
| `crates/wlan-tunnel` | The logic of the Wi-Fi tunnel daemon: reverse links, ESP states and policies, `rmnet_wlan`, the ports of the modem. No unsafe code. A simulated modem and a fake kernel sit behind the feature `fake` |
| `crates/wlantunneld` | The netlink and UDP sockets of the Wi-Fi tunnel daemon, its syscall table and `main` (the binary `wlantunneld`) |
| `crates/nicm-compat` | The client of the interface manager requests over the protocol. Depends on `wire` only |
| `crates/nicm-abi` | The structs between the two libraries and the switch for the stock layouts (`STOCK_ABI_VERIFIED`) |
| `crates/libnicm` | The replacement for `libnicm.so`: the connection to the daemon |
| `crates/libnicm-dsi` | The replacement for `libnicm_dsi.so`: the exports the closed data module calls, with the stock prototypes and layouts |
| `crates/qmi/tests/idl/idl-expected.txt` | The message layouts the code builds or parses, as the IDL tables of the stock `libqmiservices.so` give them |
| `android/` | The Soong modules (next to the crates), the init rc, the SELinux policy, the vendor UID, the device switch, the pins of the closed peers and the list of stock files that leave the vendor image. See `android/README.md` |

`wire`, `nicm-compat`, `nicm-abi`, `libnicm` and `libnicm-dsi` run inside `qcrilNrd`, the process that carries
voice and emergency calls, and the Android build compiles Rust with `panic=abort`. They forbid `unwrap`, `expect`,
`panic`, indexing and unchecked arithmetic by lint, confine `unsafe` to a few files, and a test scans the source
to hold that.

## Build and test

```
cargo test --offline
cargo clippy --offline --all-targets -- -D warnings
cargo check --offline --target aarch64-unknown-linux-gnu -p dataos-netcfg -p dataos-libnicm -p dataos-libnicm-dsi -p dataos-datad-rt -p dataos-wlantunneld
```

The host tests use a simulated modem, a fake of the kernel (links, IPA pipes, mux channels, ethtool features, the
driver's answers) and documentation address ranges. Nothing logs APNs, credentials, addresses or identifiers.
The Linux backend, the sockets and the process setup compile and lint for aarch64 Linux and are not run by
these commands. The Soong modules are built by the platform build, see below. `STOCK_ABI_VERIFIED` is a constant
of `crates/nicm-abi` that says the stock layouts are checked, and a device build cannot be made while it is false.

The daemon needs Linux 6.9 or later (it identifies a peer process by the inode of its pidfd, which is the
process's own only from 6.9) and stops at start on an older kernel. It runs as the vendor user `vendor_datad`
with `NET_ADMIN` only, behind a syscall filter and its own SELinux domain.

## Selecting it in a device build

Everything is behind one build switch of the device, `DIAMANEOS_DATAD`. Without it the build is
the stock data stack: the Soong modules do not exist, the policy is not added and the product does not change.
With it on, the device build sets the Soong config that enables the modules, adds the policy directory and the
vendor UID, installs `datad` with its init rc, and replaces `libnicm.so` and `libnicm_dsi.so` at the stock paths.
The product makefile stops the build when one of the closed peers the layouts were read from (`libdsi_netctrl.so`,
`libqdi.so`, `libqcrilDataModule.so`) is not the pinned file, or when the vendor tree still has a stock nicm file.
The files and what each does are in `android/README.md` and `android/vendor-selection.md`.

## License

Apache License 2.0, see `LICENSE`.
