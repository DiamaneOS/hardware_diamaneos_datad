# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The DiamaneOS Project
#
# Turns the Soong modules of the data stack on (android/Android.bp, diamaneos_datad_defaults). Only the
# device board file includes this, so the modules do not exist for any other target in the tree.
SOONG_CONFIG_NAMESPACES += diamaneos_datad
SOONG_CONFIG_diamaneos_datad += datad_enabled
SOONG_CONFIG_diamaneos_datad_datad_enabled := true
