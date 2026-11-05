# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The DiamaneOS Project
#
# Included from the device BoardConfig.mk. The device owns the QRTR inventory (its qrtr.te names
# these domains) and the vendor tree.
BOARD_VENDOR_SEPOLICY_DIRS += hardware/diamaneos/datad/android/sepolicy/vendor
TARGET_FS_CONFIG_GEN += hardware/diamaneos/datad/android/config.fs
include hardware/diamaneos/datad/android/datad-soong.mk
