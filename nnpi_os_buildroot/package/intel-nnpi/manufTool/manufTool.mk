################################################################################
#
# manufTool
#
################################################################################

MANUFTOOL_VERSION = 1.0
MANUFTOOL_SITE = ../../../nnpi-manufacturing_tools 
MANUFTOOL_SITE_METHOD = local
MANUFTOOL_LICENSE = proprietary
MANUFTOOL_LICENSE_FILES = ../../../nnpi_LICENSE.txt
MANUFTOOL_DEPENDENCIES = psw

BOM_FILE_PATH=$(@D)/automation/sdk/nnpi/$(NNPI_PACKAGES_TARGET)/

define MANUFTOOL_BUILD_CMDS
	cd $(@D) && make NNPI_INCLUDE_DIR=../release_artifacts/platform_sw/include NNPI_LIB_DIR=../release_artifacts/platform_sw/build_artifact/sph_ep/Release/card/lib TOOLCHAIN=$(HOST_DIR)
endef

define MANUFTOOL_INSTALL_TARGET_CMDS

	echo *** Installing to ROOTFS *****

	#pre-process BOM file to make it compatible with python INI parser 
	sed -i s/@\(TARGET\)/$(NNPI_PACKAGES_TARGET)/ $(BOM_FILE_PATH)/nnpi.ini 
	sed -i s/@\(FLAVOR\)/$(NNPI_PACKAGES_FLAVOR)/ $(BOM_FILE_PATH)/nnpi.ini 
	#Copy files to ROOTFS based on BOM
	$(BASE_DIR)/../../../automation/cp_by_bom.py  $(BOM_FILE_PATH)/nnpi.ini $(@D)/ $(TARGET_DIR)/

endef

define MANUFTOOL_USERS
endef

define MANUFTOOL_DEVICES
endef

define MANUFTOOL_PERMISSIONS
endef

$(eval $(generic-package))




