SIMICSAGENT_VERSION = 1.0.0
SIMICSAGENT_SITE = $(TOPDIR)/package/SimicsAgent
SIMICSAGENT_SITE_METHOD = local

define SIMICSAGENT_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(SIMICSAGENT_SITE)/simics_agent_x86_linux64 $(TARGET_DIR)/usr/bin/simics_agent_x86_linux64
endef

$(eval $(generic-package))
