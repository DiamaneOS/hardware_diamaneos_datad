# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The DiamaneOS Project
#
# Turns the Soong modules of the data stack on (android/Android.bp, diamaneos_datad_defaults). Without
# this file they do not exist, so the install rules of libnicm and libnicm_dsi cannot meet the stock ones.
SOONG_CONFIG_NAMESPACES += diamaneos_datad
SOONG_CONFIG_diamaneos_datad += datad_enabled
SOONG_CONFIG_diamaneos_datad_datad_enabled := true
