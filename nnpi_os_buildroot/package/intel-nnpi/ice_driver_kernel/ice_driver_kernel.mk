################################################################################
#
# ice_driver_kernel
#
################################################################################

ICE_DRIVER_KERNEL_VERSION = 1.0
ICE_DRIVER_KERNEL_SITE = ../../../nnpi-ice_driver_kernel 
ICE_DRIVER_KERNEL_SITE_METHOD = local
ICE_DRIVER_KERNEL_LICENSE = proprietary
ICE_DRIVER_KERNEL_LICENSE_FILES = ../../../nnpi_LICENSE.txt
ICE_DRIVER_KERNEL_DEPENDENCIES = linux psw
ICE_DRIVER_KERNEL_BUILD_DIR = $(BUILD_DIR)/ice_driver_kernel-$(ICE_DRIVER_KERNEL_VERSION)
ICE_DRIVER_KERNEL_ROOT_PATH = $(ICE_DRIVER_KERNEL_BUILD_DIR)/bin/$(NNPI_PACKAGES_TARGET)/ring0/$(NNPI_PACKAGES_FLAVOR)/64/modules
NNPI_PACKAGES_FLAVOR_LOWER = $(shell echo $(NNPI_PACKAGES_FLAVOR) | tr A-Z a-z)
ICE_DRIVER_FW_PKG_VERSION = 3.0.0
BOM_FILE_PATH=$(@D)/automation/sdk/nnpi/$(NNPI_PACKAGES_TARGET)/

define ICE_DRIVER_KERNEL_BUILD_CMDS
	$(BUILD_DIR)/ice_driver_kernel-$(ICE_DRIVER_KERNEL_VERSION)/automation/builds/build.py ring0 -v ice2.9 --platform_target_dir $(NNPI_PACKAGES_TARGET) \
	--config $(NNPI_PACKAGES_FLAVOR) --sph_toolchain $(HOST_DIR)/bin/x86_64-buildroot-linux-gnu- \
	--kdir $(LINUX_DIR)
endef

define ICE_DRIVER_KERNEL_INSTALL_STAGING_CMDS
endef

define ICE_DRIVER_KERNEL_INSTALL_TARGET_CMDS
	echo ****** FW type ice_driver_fw_pkg_rtl_release-3.0.0.tar.gz
	tar -xzvf $(@D)/../release_artifacts/fw_pkgs/build_artifact/ice_driver_fw_pkg_rtl_$(NNPI_PACKAGES_FLAVOR_LOWER)-$(ICE_DRIVER_FW_PKG_VERSION).tar.gz -C $(TARGET_DIR)
	
	#installing to rootfs
	echo *** Installing to ROOTFS *****

	#pre-process BOM file to make it compatible with python INI parser 
	sed -i s/@\(TARGET\)/$(NNPI_PACKAGES_TARGET)/ $(BOM_FILE_PATH)/nnpi.ini 
	sed -i s/@\(FLAVOR\)/$(NNPI_PACKAGES_FLAVOR)/ $(BOM_FILE_PATH)/nnpi.ini 
	#Copy files to ROOTFS based on BOM
	$(BASE_DIR)/../../../automation/cp_by_bom.py  $(BOM_FILE_PATH)/nnpi.ini $(@D)/ $(TARGET_DIR)/
endef

define ICE_DRIVER_KERNEL_USERS
endef

define ICE_DRIVER_KERNEL_DEVICES
endef

define ICE_DRIVER_KERNEL_PERMISSIONS
endef

$(eval $(generic-package))
