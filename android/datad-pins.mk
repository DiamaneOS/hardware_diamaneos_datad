# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The DiamaneOS Project
#
# The closed peers the open libraries and the daemon were written against, as path:SHA-256 under the
# vendor tree (vendor/fairphone/FP6/files). The layouts in crates/nicm-abi and crates/libnicm-dsi were read from these
# files (generation 16.111.0, the same bytes ship in 16.115.0). A different file is a different closed side: the build stops until
# the layouts are checked again and the pin is changed on purpose. The pin check reads this
# file too.
DATAD_PINS := \
    vendor/lib64/libdsi_netctrl.so:2ee1b335f19d8cea81de3cb5a0dd49c49bd47010df07b63d75852909a0aa838f \
    vendor/lib64/libqdi.so:12c0b05109d1050cb24cda5016d1c639fa724c77706cac4576bae48ad24b502e \
    vendor/lib64/libqcrilDataModule.so:6d634ef10258e5ff675de631f82c7ee9d78b749095ff2bfc0886dd20c3e11db9
