# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The DiamaneOS Project
#
# Included from the device BoardConfig.mk only when DIAMANEOS_DATAD is true. The device owns the
# switch, the QRTR inventory (qrtr.te names this domain under ifdef(`datad_enabled')) and the
# vendor tree.
BOARD_VENDOR_SEPOLICY_DIRS += hardware/diamaneos/datad/android/sepolicy/vendor
BOARD_SEPOLICY_M4DEFS += datad_enabled=true
TARGET_FS_CONFIG_GEN += hardware/diamaneos/datad/android/config.fs
include hardware/diamaneos/datad/android/datad-soong.mk
