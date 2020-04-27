################################################################################
#
# runtime
#
################################################################################

RUNTIME_VERSION = 1.0
RUNTIME_SITE = ../../../nnpi-runtime 
RUNTIME_SITE_METHOD = local
RUNTIME_LICENSE = proprietary
RUNTIME_LICENSE_FILES = ../../../nnpi_LICENSE.txt

RUNTIME_DEPENDENCIES = ice_driver_kernel

BOM_FILE_PATH=$(@D)/automation/sdk/nnpi/$(NNPI_PACKAGES_TARGET)/

define RUNTIME_BUILD_CMDS
	$(BUILD_DIR)/runtime-$(RUNTIME_VERSION)/automation/Build.py --os=Buildroot --conf=$(NNPI_PACKAGES_FLAVOR) --ring3-validation=False --build_mode=$(NNPI_PACKAGES_TARGET) --step= --compiler-c=$(HOST_DIR)/bin/x86_64-buildroot-linux-gnu-gcc \
	--compiler-cxx=$(HOST_DIR)/bin/x86_64-buildroot-linux-gnu-g++ --compiler-path=$(HOST_DIR)/bin \
	--system-root=$(HOST_DIR)/x86_64-buildroot-linux-gnu/sysroot 
endef

define RUNTIME_INSTALL_STAGING_CMDS

endef

define RUNTIME_INSTALL_TARGET_CMDS
	echo *** Installing to ROOTFS *****
	#pre-process BOM file to make it compatible with python INI parser 
	sed -i s/@\(TARGET\)/$(NNPI_PACKAGES_TARGET)/ $(BOM_FILE_PATH)/nnpi.ini 
	sed -i s/@\(FLAVOR\)/$(NNPI_PACKAGES_FLAVOR)/ $(BOM_FILE_PATH)/nnpi.ini 
	#Copy files to ROOTFS based on BOM
	$(BASE_DIR)/../../../automation/cp_by_bom.py  $(BOM_FILE_PATH)/nnpi.ini $(@D)/ $(TARGET_DIR)/
endef

define RUNTIME_USERS

endef

define RUNTIME_DEVICES

endef

define RUNTIME_PERMISSIONS

endef

$(eval $(generic-package))
