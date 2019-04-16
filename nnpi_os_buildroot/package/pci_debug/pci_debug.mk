################################################################################
#
#          pci_debug
#
################################################################################

PCI_DEBUG_VERSION = 1.0
PCI_DEBUG_SITE = ./package/pci_debug/src
PCI_DEBUG_SITE_METHOD = local
PCI_DEBUG_LICENCE = GPL-3.0+
PCI_DEBUG_LICENCE_FILES = COPYING
PCI_DEBUG_DEPENDENCIES = readline ncurses

define PCI_DEBUG_BUILD_CMDS
	$(MAKE) CC="$(TARGET_CC)" LD="$(TARGET_LD)" -C $(@D)
endef

define PCI_DEBUG_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/pci_debug $(TARGET_DIR)/usr/bin
endef

define PCI_DEBUG_PERMISSIONS
	/usr/bin/pci_debug f 4755 0 0 - - - - -
endef

$(eval $(generic-package))
