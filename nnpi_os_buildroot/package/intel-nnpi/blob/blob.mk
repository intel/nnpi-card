################################################################################
#
# blob
#
################################################################################

BLOB_VERSION = 1.0
BLOB_SITE = ../../../nnpi-blob 
BLOB_SITE_METHOD = local
BLOB_LICENSE = proprietary
BLOB_LICENSE_FILES = ../../../nnpi_LICENSE.txt
BLOB_DEPENDENCIES = zlib


define BLOB_BUILD_CMDS
	cd $(@D)/automation && ./Build.py --os Buildroot --conf $(NNPI_PACKAGES_FLAVOR) --build_mode $(NNPI_PACKAGES_TARGET) --compiler-path $(HOST_DIR)/bin --compiler-c x86_64-buildroot-linux-gnu-gcc --compiler-cxx x86_64-buildroot-linux-gnu-g++ --system-root $(HOST_DIR)/x86_64-buildroot-linux-gnu/sysroot --step= --build-card=True
endef

define BLOB_INSTALL_STAGING_CMDS

endef

define BLOB_INSTALL_TARGET_CMDS

	echo "before mkdir"
	mkdir -p $(TARGET_DIR)/opt/intel_nnpi/lib
	echo "after mkdir"
	cp $(@D)/build/$(NNPI_PACKAGES_TARGET)/card/$(NNPI_PACKAGES_FLAVOR)/external/libarchive/libarchive/libarchive.a $(TARGET_DIR)/opt/intel_nnpi/lib
	cp $(@D)/build/$(NNPI_PACKAGES_TARGET)/card/$(NNPI_PACKAGES_FLAVOR)/external/pugixml/libpugixml.a $(TARGET_DIR)/opt/intel_nnpi/lib
	cp $(@D)/build/$(NNPI_PACKAGES_TARGET)/card/$(NNPI_PACKAGES_FLAVOR)/external/md5/libmd5.a $(TARGET_DIR)/opt/intel_nnpi/lib
    cp $(@D)/build/$(NNPI_PACKAGES_TARGET)/card/$(NNPI_PACKAGES_FLAVOR)/serialize/libblob_serialize.a $(TARGET_DIR)/opt/intel_nnpi/lib
	cp $(@D)/build/$(NNPI_PACKAGES_TARGET)/card/$(NNPI_PACKAGES_FLAVOR)/package/libblob_package.a $(TARGET_DIR)/opt/intel_nnpi/lib

	#Prepare build results for other packages that depend on it

	mkdir -p $(@D)/../release_artifacts/blob/include
	cp $(@D)/build/install/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/card/include/*.h $(@D)/../release_artifacts/blob/include/
	cp $(@D)/build/install/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/card/include/*.hpp $(@D)/../release_artifacts/blob/include/
	mkdir -p $(@D)/../release_artifacts/blob/build_artifact/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/Lib/
	cp $(@D)/build/install/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/card/lib/libarchive.a $(@D)/../release_artifacts/blob/build_artifact/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/Lib/libarchive_card.a
	cp $(@D)/build/install/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/card/lib/libblob_package.a $(@D)/../release_artifacts/blob/build_artifact/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/Lib/libblob_package_card.a
	cp $(@D)/build/install/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/card/lib/libblob_serialize.a $(@D)/../release_artifacts/blob/build_artifact/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/Lib/libblob_serialize_card.a
	cp $(@D)/build/install/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/card/lib/libmd5.a $(@D)/../release_artifacts/blob/build_artifact/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/Lib/libmd5_card.a
	cp $(@D)/build/install/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/card/lib/libpugixml.a $(@D)/../release_artifacts/blob/build_artifact/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/Lib/libpugixml_card.a

endef

define BLOB_USERS

endef

define BLOB_DEVICES

endef

define BLOB_PERMISSIONS

endef

$(eval $(generic-package))
