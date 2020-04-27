################################################################################
#
# ice_driver_user
#
################################################################################

ICE_DRIVER_USER_VERSION = 1.0
ICE_DRIVER_USER_SITE = ../../../nnpi-ice_driver_user 
ICE_DRIVER_USER_SITE_METHOD = local
ICE_DRIVER_USER_LICENSE = proprietary
ICE_DRIVER_USER_LICENSE_FILES = ../../../nnpi_LICENSE.txt
ICE_DRIVER_USER_DEPENDENCIES = ice_driver_kernel


ROOT_PATH_ICE_DRIVER_USER = $(BUILD_DIR)/ice_driver_user-$(ICE_DRIVER_USER_VERSION)
ROOT_PATH_SCE = $(ROOT_PATH_ICE_DRIVER_USER)/bin/scenarios/
ROOT_PATH = $(ROOT_PATH_ICE_DRIVER_USER)/bin/$(NNPI_PACKAGES_TARGET)/ring0/$(NNPI_PACKAGES_FLAVOR)/64/
BOM_FILE_PATH=$(@D)/automation/sdk/nnpi/$(NNPI_PACKAGES_TARGET)/

#make card SPH_PLATFORM=$(NNPI_PACKAGES_TARGET) TYPE=Release
define ICE_DRIVER_USER_BUILD_CMDS
	mkdir -p $(BUILD_DIR)/sph_os/intel/sph/
	ln -sf $(HOST_DIR) $(BUILD_DIR)/sph_os/intel/sph/Toolchain
#Following defines override the hardcoded definitios in automation/builds/utils.py
	$(BUILD_DIR)/ice_driver_user-$(ICE_DRIVER_USER_VERSION)/automation/builds/build.py -v ice2.9 --target ring0 --platform_target_dir $(NNPI_PACKAGES_TARGET) \
		--config $(NNPI_PACKAGES_FLAVOR) \
		--ice_driver_user_repo_dirname $(BUILD_DIR)/ice_driver_user-$(ICE_DRIVER_USER_VERSION) \
		--ice_driver_kernel_repo_dirname $(BUILD_DIR)/ice_driver_kernel-$(ICE_DRIVER_KERNEL_VERSION)

endef


define ICE_DRIVER_USER_INSTALL_STAGING_CMDS
endef

define ICE_DRIVER_USER_INSTALL_TARGET_CMDS
	echo *** Installing to ROOTFS *****

	#pre-process BOM file to make it compatible with python INI parser 
	sed -i s/@\(TARGET\)/$(NNPI_PACKAGES_TARGET)/ $(BOM_FILE_PATH)/nnpi.ini 
	sed -i s/@\(FLAVOR\)/$(NNPI_PACKAGES_FLAVOR)/ $(BOM_FILE_PATH)/nnpi.ini 
	#Copy files to ROOTFS based on BOM
	$(BASE_DIR)/../../../automation/cp_by_bom.py  $(BOM_FILE_PATH)/nnpi.ini $(@D)/ $(TARGET_DIR)/

endef

define ICE_DRIVER_USER_USERS
endef

define ICE_DRIVER_USER_DEVICES
endef

define ICE_DRIVER_USER_PERMISSIONS
endef

$(eval $(generic-package))
