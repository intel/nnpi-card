################################################################################
#
# psw
#
################################################################################

PSW_VERSION = 1.0
PSW_SITE = ../../../nnpi-platform_sw 
PSW_SITE_METHOD = local
PSW_LICENSE = proprietary
PSW_LICENSE_FILES = ../../../nnpi_LICENSE.txt
PSW_DEPENDENCIES = linux blob

BOM_FILE_PATH=$(@D)/automation/sdk/nnpi/$(NNPI_PACKAGES_TARGET)/
BOM_FILE_NAME=nnpi_$(shell echo $(NNPI_PACKAGES_FLAVOR) | tr A-Z a-z).ini

define PSW_BUILD_CMDS
#ION drivers are currently in staging area in kernel tree, hence their UAPI is not copied
#properly by buildroot to the generated toolchain where UAPI headers are stored.
#hence, we "manually" copy them from kernel tree to the toolchain UAPI location

    cp $(LINUX_DIR)/drivers/staging/android/uapi/*.h $(HOST_DIR)/x86_64-buildroot-linux-gnu/sysroot/usr/include/linux/
#    $(MAKE) -C $(@D) card SPH_PLATFORM=sph_ep TYPE=$(NNPI_PACKAGES_FLAVOR) TOOLCHAIN=$(HOST_DIR) CARD_TOOLCHAIN=$(HOST_DIR) KDIRDIR=$(BASE_DIR)/build/linux-$(LINUX_VERSION_PROBED)/
    $(MAKE) -C $(@D) card SPH_PLATFORM=$(NNPI_PACKAGES_TARGET) TYPE=$(NNPI_PACKAGES_FLAVOR) TOOLCHAIN=$(HOST_DIR) CARD_TOOLCHAIN=$(HOST_DIR) KDIRDIR=$(LINUX_DIR)

endef

define PSW_INSTALL_STAGING_CMDS
endef

define PSW_INSTALL_TARGET_CMDS

	#untar artifacts to rootfs

	tar -xvzf $(@D)/build/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/card/sph-*-$(NNPI_PACKAGES_TARGET)-card_driver.tar.gz -C $(TARGET_DIR)
	tar -xvzf $(@D)/build/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/card/sph-*-$(NNPI_PACKAGES_TARGET)-card_sdk.tar.gz -C $(TARGET_DIR)
	tar -xvzf $(@D)/build/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/card/sph-*-$(NNPI_PACKAGES_TARGET)-card_tests.tar.gz -C $(TARGET_DIR)

	#Prepare build results for other packages that depend on it

	mkdir -p $(@D)/../release_artifacts/platform_sw/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/card
        mkdir -p $(@D)/../release_artifacts/platform_sw/build_artifact/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/card
        cp -r $(@D)/build/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/card/lib $(@D)/../release_artifacts/platform_sw/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/card 
       	cp -r $(@D)/build/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/card/lib $(@D)/../release_artifacts/platform_sw/build_artifact/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/card

	cp -r $(@D)/include $(@D)/../release_artifacts/platform_sw
	cp -r $(@D)/internal/src/card/include/* $(@D)/../release_artifacts/platform_sw/include/
	cp -r $(@D)/internal/src/common/include/* $(@D)/../release_artifacts/platform_sw/include/
	cp -r $(@D)/src/common/include/* $(@D)/../release_artifacts/platform_sw/include/
	cp -r $(@D)/internal/src/card/libs/hw_access/hw_access.h $(@D)/../release_artifacts/platform_sw/include/


	mkdir -p $(@D)/../release_artifacts/platform_sw/src/driver/include
       	mkdir -p $(@D)/../release_artifacts/platform_sw/build_artifact/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/kern/objs
	cp -r $(@D)/src/card/driver/sph_power_balancer/intel_sphpb.h $(@D)/../release_artifacts/platform_sw/include/

	cp $(@D)/build/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/card/obj/src/card/driver/sph_cs/sw_counters.o $(@D)/../release_artifacts/platform_sw/build_artifact/$(NNPI_PACKAGES_TARGET)/$(NNPI_PACKAGES_FLAVOR)/kern/objs
	
	cp $(@D)/src/card/driver/include/sw_counters.h $(@D)/src/card/driver/include/sph_log.h $(@D)/src/common/include/log_category_defs.h \
	        $(@D)/../release_artifacts/platform_sw/src/driver/include

endef

define PSW_USERS
endef

define PSW_DEVICES
endef

define PSW_PERMISSIONS
endef

$(eval $(generic-package))
