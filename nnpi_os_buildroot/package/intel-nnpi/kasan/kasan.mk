################################################################################
#
# kasan
#
#    the purpose of this mk file and the kasan package under intel-nnpi packages 
#    is to copy the kasan lib's from the toolchain to the device filesystem
#
################################################################################


AUTOMATION_DIR = $(BASE_DIR)/../../../automation
KASAN_SRC_DIR=$(BASE_DIR)/host/x86_64-buildroot-linux-gnu/lib64
KASAN_DST_DIR=$(TARGET_DIR)/lib/
KASAN_VERSION = 1.0
KASAN_SITE = $(AUTOMATION_DIR)/kasan_dummy
KASAN_SITE_METHOD = local
# kasan license is derived from Linux kernel license LINUX_LICENSE = GPL-2.0
KASAN_LICENSE = GPL-2.0
KASAN_LICENSE_FILES = COPYING

define KASAN_BUILD_CMDS
endef

define KASAN_INSTALL_TARGET_CMDS
	echo *** Installing KASAN to ROOTFS *****
	mkdir -p $(KASAN_DST_DIR)
	cp $(KASAN_SRC_DIR)/liblsan.so			$(KASAN_DST_DIR)
	cp $(KASAN_SRC_DIR)/libtsan.so.0		$(KASAN_DST_DIR)
	cp $(KASAN_SRC_DIR)/libtsan.so.0.0.0	$(KASAN_DST_DIR)
	cp $(KASAN_SRC_DIR)/libasan.so.5.0.0	$(KASAN_DST_DIR)
	cp $(KASAN_SRC_DIR)/libubsan.so.1		$(KASAN_DST_DIR)
	cp $(KASAN_SRC_DIR)/liblsan.so.0		$(KASAN_DST_DIR)
	cp $(KASAN_SRC_DIR)/libtsan.so			$(KASAN_DST_DIR)
	cp $(KASAN_SRC_DIR)/libasan.so.5		$(KASAN_DST_DIR)
	cp $(KASAN_SRC_DIR)/liblsan.so.0.0.0	$(KASAN_DST_DIR)
	cp $(KASAN_SRC_DIR)/libasan.so			$(KASAN_DST_DIR)
	cp $(KASAN_SRC_DIR)/libubsan.so.1.0.0	$(KASAN_DST_DIR)
	cp $(KASAN_SRC_DIR)/libubsan.so			$(KASAN_DST_DIR)
	cp $(KASAN_SRC_DIR)/libasan_preinit.o	$(KASAN_DST_DIR)
	cp $(KASAN_SRC_DIR)/liblsan_preinit.o	$(KASAN_DST_DIR)
	cp $(KASAN_SRC_DIR)/libtsan_preinit.o	$(KASAN_DST_DIR) 
endef

$(eval $(generic-package))




