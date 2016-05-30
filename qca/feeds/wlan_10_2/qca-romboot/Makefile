#
# Copyright (c) 2013 Qualcomm Atheros, Inc.
#
# All Rights Reserved.
# Qualcomm Atheros Confidential and Proprietary.
#


include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=qca-romboot
PKG_VERSION:=10.1.389
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)-$(BUILD_VARIANT)/$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)_$(PKG_VERSION).tar.bz2
PKG_BRANCH:=$(basename $(PKG_VERSION))
PKG_SOURCE_URL:=http://tritium.qca.qualcomm.com/software/$(PKG_BRANCH)/AP$(PKG_VERSION:999.999.0%=QCAMain%)/src/components

PKG_MD5SUM:=bb737c1ed9659db83617257c0fe998a5

PKG_BUILD_DEPENDS:=qca-romboot/host

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/host-build.mk

define DefineRomboot
  define Package/qca-romboot-$(1)
    TITLE:=Rom boot code for $(1)
    SECTION:=boot
    CATEGORY:=Boot Loaders
    DEPENDS:=@TARGET_ar71xx
    URL:=http://www.qca.qualcomm.com
    VARIANT:=$(1)
  endef

  define Package/qca-romboot-$(1)/description
    This package contains the assembly code requied to init the chip and
    perform specific initialization prior to the bootloader. It's mainly
    executed before the bootloader for NAND boot.
    This package generates code for the $(1) SoC.
  endef

  define Package/qca-romboot-$(1)/install
	true
  endef

  $$(eval $$(call BuildPackage,qca-romboot-$(1)))
endef

MAKEOPTS_QCA_ROMBOOT:= \
	CROSS_COMPILE=$(TARGET_CROSS) \
	UTILPATH=$(STAGING_DIR_HOST)/bin

ifeq ($(BUILD_VARIANT),ar934x)
  ROMBOOT_SUBDIR:=rom-boot-drv
endif
ifeq ($(BUILD_VARIANT),qca955x)
  ROMBOOT_SUBDIR:=rom-boot-drv-sco
endif

define Build/Compile
	($(foreach var,$(strip $(shell cat configs/$(BUILD_VARIANT).config)), export ${var};) \
	 make -C $(PKG_BUILD_DIR)/$(ROMBOOT_SUBDIR) clean all $(MAKEOPTS_QCA_ROMBOOT) \
		TOPDIR=$(PKG_BUILD_DIR)/$(ROMBOOT_SUBDIR)/ \
	)
endef

define Build/InstallDev
	$(INSTALL_DIR) $(STAGING_DIR)/boot
	$(CP) $(PKG_BUILD_DIR)/$(ROMBOOT_SUBDIR)/rombootdrv.bin $(STAGING_DIR)/boot/openwrt-$(BOARD)-$(BUILD_VARIANT)-rombootdrv.bin
endef

define Host/Compile
	$(HOSTCC) $(HOST_CFLAGS) -o $(HOST_BUILD_DIR)/bin2hex src/bin2hex.c
	$(HOSTCC) $(HOST_CFLAGS) -o $(HOST_BUILD_DIR)/checksum src/checksum.c
	$(HOSTCC) $(HOST_CFLAGS) -o $(HOST_BUILD_DIR)/array2bin src/array2bin.c
endef

define Host/Install
	$(INSTALL_DIR) $(STAGING_DIR_HOST)/bin
	$(INSTALL_BIN) $(HOST_BUILD_DIR)/bin2hex $(STAGING_DIR_HOST)/bin
	$(INSTALL_BIN) $(HOST_BUILD_DIR)/checksum $(STAGING_DIR_HOST)/bin
	$(INSTALL_BIN) $(HOST_BUILD_DIR)/array2bin $(STAGING_DIR_HOST)/bin
	$(INSTALL_BIN) $(HOST_BUILD_DIR)/rom-boot-drv/mk2stage $(STAGING_DIR_HOST)/bin/mk2stage-ar934x
	$(INSTALL_BIN) $(HOST_BUILD_DIR)/rom-boot-drv-sco/mk2stage $(STAGING_DIR_HOST)/bin/mk2stage-qca955x
endef

$(eval $(call DefineRomboot,ar934x))
$(eval $(call DefineRomboot,qca955x))
$(eval $(call HostBuild))
