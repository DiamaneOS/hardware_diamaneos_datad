# Stock files that leave the vendor image, and the two that are replaced

`libdsi_netctrl.so` and `libqdi.so` stay as they are, `libnicm.so` and
`libnicm_dsi.so` are replaced by the open libraries of the same soname, and `nicmd` goes with everything
only it used. Names are from the FP6 vendor generation 23400 listing. Check each against the vendor file
selection tool's dependency closure before removal, and keep the stock files in the tree until the open stack has
been qualified on a device.

Replaced by open libraries (same path, same soname, same exported names, `crates/libnicm`
and `crates/libnicm-dsi`): `vendor/lib64/libnicm.so` (37,264 bytes), `vendor/lib64/libnicm_dsi.so`
(33,824 bytes). `libdsi_netctrl.so` has NEEDED entries for both.

Removed. Nothing else in the image links them (`grep -l -a <name>` over `vendor/lib64`, `vendor/bin`,
`vendor/bin/hw`, `system_ext/lib64` and `product/lib64` of the generation 23400 image):

- `vendor/bin/nicmd`, `vendor/etc/init/nicmd.rc`, `vendor/etc/data/nicm_config.xml` (log settings only)
- `vendor/lib64/libnicm_internal.so`, `libnicm_modemproxy.so`, `libnicm_netlink.so`,
  `libnicm_recovery.so`, `libnicm_utils.so` (used by `libnicm.so` and the nicm libraries only)
- `vendor/lib64/librmnetctl.so` (used by `libnicm_internal.so` only), `libshsc.so` (used by
  `libnicm_modemproxy.so` only)

Kept: `libdsi_netctrl.so`, `libqdi.so` and `vendor/etc/data/dsi_config.xml` (DSI reads it), `libdsutils.so`,
`libconfigdb.so`, `libqmi_*`, `libqmiservices.so`, `libidl.so`, `libqdpr.so`, `libdiag.so`,
`libqcrilDataModule.so` and everything else of QCRIL. Code removed: nicmd and its libraries. Closed code left
in `qcrilNrd`: DSI and QDI, 1,575,040 bytes less than E would remove.

`nicmd.rc` also loads `rmnet_shs`, `rmnet_perf` and `rmnet_offload` on properties. `datad.rc` keeps those
triggers as they are, see there for who sets the properties.

How they leave: the project tools take them out (`datad_selection.py` in `diamaneos_tools`, used by `diamaneos build vendor`
and `diamaneos vendor product`). They make the pair from the selected-file recipe and the ELF selection of the stock
files. They drop the twelve files from both, turn the two edges of
`libdsi_netctrl.so` to `libnicm.so` and `libnicm_dsi.so` into edges of kind `source-module`, and stop when the stock files
are not the ones this list was read from. The renderer accepts a source module only when its reviewed list
(`SOURCE_MODULE_DEPENDENCIES` in `vendor_product.py`) names it, and it names `libnicm` and `libnicm_dsi`. On the real
FP6.QREL.16.111.0 files 12 files and 86 edges leave, and the tools render the result: no module of a dropped file, and
`libdsi_netctrl` linking `libnicm` and `libnicm_dsi`. One more library, `android.system.net.netd-V1-ndk`, is no longer
pulled into the vendor image: it is a source-built interface library, the stock file is never installed, and only the
dropped `libnicm_modemproxy.so` linked it.

The device build refuses a vendor tree that still has one of the twelve files: `datad-product.mk` stops with the file
names (Kati would otherwise stop on two install rules for `vendor/lib64/libnicm.so`).

The pin of the closed peers (`libdsi_netctrl.so`, `libqdi.so`, `libqcrilDataModule.so`) is
the hash of the generation 23400 files: a vendor update changes them, and the build fails until the layouts of the open
libraries are checked against the new files again.
