# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The DiamaneOS Project
#
# Inherited from the device telephony.mk only when DIAMANEOS_DATAD is true (after datad-board.mk
# was included). Two checks first, so a product that would ship the wrong data stack does not
# build, then the packages.
#
# 1. The closed peers are the ones the layouts were read from (datad-pins.mk).
# 2. The vendor tree has none of the stock nicm files. Soong installs the shared libraries a module
#    links, so a tree that still renders libnicm.so and libnicm_dsi.so would install the stock pair
#    next to ours at the same path. The tree is made for this switch by the project tools,
#    diamaneos build vendor --datad.
DATAD_PINS_MK ?= hardware/diamaneos/datad/android/datad-pins.mk
include $(DATAD_PINS_MK)

DATAD_VENDOR_FILES ?= vendor/fairphone/FP6/files
DATAD_SHA256 := $(shell command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo shasum -a 256)

define datad_check_pin
ifneq ($$(firstword $$(shell $$(DATAD_SHA256) $$(DATAD_VENDOR_FILES)/$(word 1,$(subst :, ,$(1))) 2>/dev/null)),$(word 2,$(subst :, ,$(1))))
$$(error datad: $(word 1,$(subst :, ,$(1))) is not the file the open data stack was written against, SHA-256 $(word 2,$(subst :, ,$(1))). Check the layouts of the open libraries against the new closed side, then change datad-pins.mk on purpose)
endif
endef
$(foreach pin,$(DATAD_PINS),$(eval $(call datad_check_pin,$(pin))))

DATAD_STOCK_NICM := \
    vendor/bin/nicmd \
    vendor/etc/init/nicmd.rc \
    vendor/etc/data/nicm_config.xml \
    vendor/lib64/libnicm.so \
    vendor/lib64/libnicm_dsi.so \
    vendor/lib64/libnicm_internal.so \
    vendor/lib64/libnicm_modemproxy.so \
    vendor/lib64/libnicm_netlink.so \
    vendor/lib64/libnicm_recovery.so \
    vendor/lib64/libnicm_utils.so \
    vendor/lib64/librmnetctl.so \
    vendor/lib64/libshsc.so
ifneq ($(wildcard $(addprefix $(DATAD_VENDOR_FILES)/,$(DATAD_STOCK_NICM))),)
$(error datad: the vendor tree still has stock nicm files: $(wildcard $(addprefix $(DATAD_VENDOR_FILES)/,$(DATAD_STOCK_NICM))). Make it with diamaneos build vendor --datad)
endif

# The daemon, the two libraries that take the place of libnicm.so and libnicm_dsi.so, its init rc
# (through the binary's required:), and the vendor user and group databases for the UID of
# config.fs (the same pair the IMS daemon adds).
PRODUCT_PACKAGES += datad libnicm libnicm_dsi passwd_vendor group_vendor
