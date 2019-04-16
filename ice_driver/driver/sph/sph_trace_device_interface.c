/*
 * NNP-I Linux Driver
 * Copyright (c) 2019, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */


#ifndef RING3_VALIDATION
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/pci.h>
#include "icedrv_uncore.h"
#endif

#include "cve_linux_internal.h"
#include "cve_device.h"
#include "cve_driver_internal.h"
#include "ice_trace.h"

#include "mmio_semaphore_regs.h"
#include "idc_device.h"
#include "cve_device_group.h"

#include "ice_mmu_inner_regs.h"
#include "sph_trace_hw_regs.h"

#ifdef RING3_VALIDATION
#include "coral.h"
#endif


#ifndef RING3_VALIDATION
struct regbar_int_descriptor {
	int (*register_regbar_uncore_p)(struct icedrv_regbar_callbacks
						**rb_callback);
} regbar_int_descriptor;

/*static struct regbar_int_descriptor rb;*/

/* sysfs related functions, structures */
static ssize_t show_dso_filter(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf);

static ssize_t store_dso_filter(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count);
static struct kobj_attribute dtf_encoder_config_attr =
__ATTR(dtf_encoder_config, 0664, show_dso_filter, store_dso_filter);

static struct kobj_attribute cfg_dtf_src_config_attr =
__ATTR(cfg_dtf_src_config, 0664, show_dso_filter, store_dso_filter);

static struct kobj_attribute cfg_ptype_filter_ch0_attr =
__ATTR(cfg_ptype_filter_ch0, 0664, show_dso_filter, store_dso_filter);

static struct kobj_attribute filter_match_low_ch0_attr =
__ATTR(filter_match_low_ch0, 0664, show_dso_filter, store_dso_filter);

static struct kobj_attribute filter_match_high_ch0_attr =
__ATTR(filter_match_high_ch0, 0664, show_dso_filter, store_dso_filter);

static struct kobj_attribute filter_mask_low_ch0_attr =
__ATTR(filter_mask_low_ch0, 0664, show_dso_filter, store_dso_filter);

static struct kobj_attribute filter_mask_high_ch0_attr =
__ATTR(filter_mask_high_ch0, 0664, show_dso_filter, store_dso_filter);

static struct kobj_attribute filter_inv_ch0_attr =
__ATTR(filter_inv_ch0, 0664, show_dso_filter, store_dso_filter);

static struct kobj_attribute cfg_ptype_filter_ch1_attr =
__ATTR(cfg_ptype_filter_ch1, 0664, show_dso_filter, store_dso_filter);

static struct kobj_attribute filter_match_low_ch1_attr =
__ATTR(filter_match_low_ch1, 0664, show_dso_filter, store_dso_filter);

static struct kobj_attribute filter_match_high_ch1_attr =
__ATTR(filter_match_high_ch1, 0664, show_dso_filter, store_dso_filter);

static struct kobj_attribute filter_mask_low_ch1_attr =
__ATTR(filter_mask_low_ch1, 0664, show_dso_filter, store_dso_filter);

static struct kobj_attribute filter_mask_high_ch1_attr =
__ATTR(filter_mask_high_ch1, 0664, show_dso_filter, store_dso_filter);

static struct kobj_attribute filter_inv_ch1_attr =
__ATTR(filter_inv_ch1, 0664, show_dso_filter, store_dso_filter);

static struct attribute *dso_filter_attrs[] = {
	&dtf_encoder_config_attr.attr,
	&cfg_dtf_src_config_attr.attr,
	&cfg_ptype_filter_ch0_attr.attr,
	&filter_match_low_ch0_attr.attr,
	&filter_match_high_ch0_attr.attr,
	&filter_mask_low_ch0_attr.attr,
	&filter_mask_high_ch0_attr.attr,
	&filter_inv_ch0_attr.attr,
	&cfg_ptype_filter_ch1_attr.attr,
	&filter_match_low_ch1_attr.attr,
	&filter_match_high_ch1_attr.attr,
	&filter_mask_low_ch1_attr.attr,
	&filter_mask_high_ch1_attr.attr,
	&filter_inv_ch1_attr.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static struct attribute_group filter_attr_group = {
		.name = "filter",
		.attrs = dso_filter_attrs,
};


struct pmoninfo_details {
	u32 index;
	const u32 reg_offset;
	const char *group_name;
	const char *name;
	const char *desc;

};
#define __PMONINFO(_index, _reg_offset, _group_name, _pmon_name, _desc) { \
	.index = _index, \
	.reg_offset = _reg_offset, \
	.group_name = __stringify(_group_name), \
	.name = __stringify(_pmon_name), \
	.desc = _desc, \
}
static struct pmoninfo_details pmon_arr[] = {
	__PMONINFO(0, MMU_ATU0_MISSES,
		ICE_PMON_MMU_ATU0_MISSES, MMU, "ATU0 Misses"),
	__PMONINFO(1, MMU_ATU1_MISSES,
		ICE_PMON_MMU_ATU1_MISSES, MMU, "ATU1 Misses"),
	__PMONINFO(2, MMU_ATU2_MISSES,
		ICE_PMON_MMU_ATU2_MISSES, MMU, "ATU2 Misses"),
	__PMONINFO(3, MMU_ATU3_MISSES,
		ICE_PMON_MMU_ATU3_MISSES, MMU, "ATU3 Misses"),
	__PMONINFO(4, ATU0_TRANSACTIONS,
		ICE_PMON_MMU_ATU0_TRANSACTIONS, MMU, "ATU0 transactions"),
	__PMONINFO(5, ATU1_TRANSACTIONS,
		ICE_PMON_MMU_ATU1_TRANSACTIONS, MMU, "ATU1 transactions"),
	__PMONINFO(6, ATU2_TRANSACTIONS,
		ICE_PMON_MMU_ATU2_TRANSACTIONS, MMU, "ATU2 transactions"),
	__PMONINFO(7, ATU3_TRANSACTIONS,
		ICE_PMON_MMU_ATU3_TRANSACTIONS, MMU, "ATU3 transactions"),
	__PMONINFO(8, READ_ISSUED,
		ICE_PMON_MMU_READ_ISSUED, MMU, "Read issued"),
	__PMONINFO(9, WRITE_ISSUED,
		ICE_PMON_WRITE_READ_ISSUED, MMU, "Write issued"),
	__PMONINFO(10, GECOE_DEC_PARTIAL_ACCESS_COUNT,
		ICE_PMON_DEC_PARTIAL_ACCESS_COUNT, GECOE,
						"Decoder Partial access"),
	__PMONINFO(11, GECOE_ENC_PARTIAL_ACCESS_COUNT,
		ICE_PMON_ENC_PARTIAL_ACCESS_COUNT, GECOE,
						"Encoder Partial access"),
	__PMONINFO(12, GECOE_DEC_META_MISS_COUNT,
		ICE_PMON_DEC_META_MISS_COUNT, GECOE,
						"Decoder Meta Miss"),
	__PMONINFO(13, GECOE_ENC_UNCOM_MODE_COUNT,
			ICE_PMON_ENC_UNCOM_MODE_COUNT, GECOE,
						"Encoder Uncompressed Mode"),
	__PMONINFO(14, GECOE_ENC_NULL_MODE_COUNT,
			ICE_PMON_ENC_NULL_MODE_COUNT, GECOE,
							"Encoder Null Mode"),
	__PMONINFO(15, GECOE_ENC_SM_MODE_COUNT,
			ICE_PMON_ENC_SM_MODE_COUNT, GECOE,
						"Encoder Significance Map"),
	__PMONINFO(16, DELPHI_PERF_CNT_1_REG,
			ICE_PMON_DELPHI_DBG_PERF_CNT_1_REG, DELPHI,
						"Per Layer Cycle Counter"),
	__PMONINFO(17, DELPHI_PERF_CNT_2_REG,
			ICE_PMON_DELPHI_DBG_PERF_CNT_2_REG, DELPHI,
						"Total Cycle Counter")
};


static ssize_t show_pmoninfo(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf);

static ssize_t show_pmon(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf);

static ssize_t store_pmon(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count);

static struct kobj_attribute pmoninfo_attr =
__ATTR(pmoninfo, 0444, show_pmoninfo, NULL);

static struct kobj_attribute pmon_attr =
__ATTR(pmon, 0664, show_pmon, store_pmon);

static struct attribute *pmon_attrs[] = {
	&pmoninfo_attr.attr,
	&pmon_attr.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static struct attribute_group pmon_attr_group = {
		.attrs = pmon_attrs,
};

static struct kobject *icedrv_kobj;
static struct kobject *hwtrace_kobj;
static int ice_trace_set_ice_observer_sysfs(u8 dso_reg_index, u32 dso_reg_val,
							u32 dev_index);


static int ice_trace_pmon_config_sysfs(u32 daemonfreq, u32 pmonindex,
							u32 dev_index);
static int  ice_trace_configure_pmonregs_sysfs(u32 dev_index);
#endif


#ifndef RING3_VALIDATION
int ice_trace_register_uncore_callbacks(struct cve_device *ice_dev)
{
	int ret = 0;

	FUNC_ENTER()

	intel_icedrv_uncore_regbar_cb(&ice_dev->dso.regbar_cbs);
	if (!ice_dev->dso.regbar_cbs) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"Error in getting regbar callback functions\n");
		ret = -ENODEV;
		goto out;
	}
	cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
			  "Uncore regbar callback functions are registered\n");
out:
	FUNC_LEAVE();
	return ret;
}
#else /* RING3_VALIDATION*/
int ice_trace_register_uncore_callbacks(struct cve_device *ice_dev)
{
	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			ice_dev->dev_index,
			"Simulation mode\n");
	return 0;
}

#endif

#ifndef RING3_VALIDATION
void ice_trace_unregister_uncore_callbacks(struct cve_device *ice_dev)
{
	FUNC_ENTER()

	ice_dev->dso.regbar_cbs = NULL;
	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			ice_dev->dev_index,
			"Uncore regbar callbacks unregistered\n");
	FUNC_LEAVE();
}
#else /* RING3_VALIDATION*/
void ice_trace_unregister_uncore_callbacks(struct cve_device *ice_dev)
{
	/* Blank function*/
}

#endif


#ifndef RING3_VALIDATION
static int write_dso_regs_sanity(struct cve_device *ice_dev)
{
	struct icedrv_regbar_callbacks *cb = ice_dev->dso.regbar_cbs;

	if (!cb) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"No regbar callback registered\n");
		return -EFAULT;
	}

	if (!cb->regbar_write) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"regbar_write() func ptr is NULL\n");
		return -EFAULT;
	}

	if (!cb->regbar_read) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"regbar_read() func ptr is NULL\n");
		return -EFAULT;
	}

	return 0;
}
#else
static int write_dso_regs_sanity(struct cve_device *ice_dev)
{
	return 0;
}
#endif

static int regbar_port_croffset_sanity(struct cve_device *ice_dev,
						u8 port, u16 crOffset)
{
	uint64_t i;
	bool found = false;
	uint8_t tmpPort;
	uint16_t tmpCroffset;

	/*verifying if the input port is within the range of DSO_PORT*/
	tmpPort = (port & (uint8_t)0xFF);

	for (i = 0; i < sizeof(icebo_port_lookup); i++) {
		if (tmpPort == icebo_port_lookup[i]) {
			found = true;
			break;
		}
	}

	if (!found) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
			"input port out of DSO port range\n");
		return -EINVAL;
	}
	found = false;

	/*verifying if the CR offset is within range of dso_offset*/
	tmpCroffset = (uint16_t)(crOffset & (uint16_t)(0xFFFF));
	for (i = 0; i < sizeof(dso_reg_offsets); i++) {
		if (tmpCroffset == dso_reg_offsets[i]
			|| (tmpCroffset == (uint64_t)(dso_reg_offsets[i] |
							(uint64_t) 0x4000))) {
			found = true;
			break;
		}
	}

	if (!found) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
			"crOffset out of DSO offset range\n");
		return -EINVAL;
	}
	return 0;
}
int ice_trace_set_ice_observers(struct ice_observer_config *dso_config,
							u32 dev_index)
{
	struct cve_device *ice_dev;
	int ret = 0;
	int i;
	u64 pe_mask, value;

	FUNC_ENTER();

	ice_dev = cve_device_get(dev_index);
	if (!ice_dev) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "NULL ice_dev pointer\n");
		ret = -ENODEV;
		goto out;
	}

	if (ice_trace_hw_debug_check(ice_dev)) {
		if (!dso_config && ((ice_dev->dso.dso_config_status ==
						TRACE_STATUS_DEFAULT) ||
				(ice_dev->dso.dso_config_status ==
				TRACE_STATUS_DEFAULT_CONFIG_WRITE_DONE))) {
			cve_os_log(CVE_LOGLEVEL_INFO, "No user dso config\n");
			ret = 0;
			goto out;
		} else {
			cve_os_log(CVE_LOGLEVEL_ERROR,
			     "User dso config not allowed as HW DBG is ON\n");
			ret = -EBUSY;
			goto out;
		}
	}

	i = 0;
	if (dso_config) {
		ice_dev->dso.reg_vals[i++] = dso_config->dtf_encoder_config;
		ice_dev->dso.reg_vals[i++] = dso_config->cfg_dtf_src_config;
		ice_dev->dso.reg_vals[i++] = dso_config->cfg_ptype_filter_ch0;
		ice_dev->dso.reg_vals[i++] = dso_config->filter_match_low_ch0;
		ice_dev->dso.reg_vals[i++] = dso_config->filter_match_high_ch0;
		ice_dev->dso.reg_vals[i++] = dso_config->filter_mask_low_ch0;
		ice_dev->dso.reg_vals[i++] = dso_config->filter_mask_high_ch0;
		ice_dev->dso.reg_vals[i++] = dso_config->filter_inv_ch0;
		ice_dev->dso.reg_vals[i++] = dso_config->cfg_ptype_filter_ch1;
		ice_dev->dso.reg_vals[i++] = dso_config->filter_match_low_ch1;
		ice_dev->dso.reg_vals[i++] = dso_config->filter_match_high_ch1;
		ice_dev->dso.reg_vals[i++] = dso_config->filter_mask_low_ch1;
		ice_dev->dso.reg_vals[i++] = dso_config->filter_mask_high_ch1;
		ice_dev->dso.reg_vals[i++] = dso_config->filter_inv_ch1;
		ice_dev->dso.dso_config_status =
					TRACE_STATUS_USER_CONFIG_WRITE_PENDING;
		ice_dev->dso.is_default_config = false;
		cve_os_dev_log(CVE_LOGLEVEL_INFO, ice_dev->dev_index,
						"DSO user config\n");
	} else {
		memcpy(ice_dev->dso.reg_vals, default_dso_reg_vals,
						sizeof(default_dso_reg_vals));
		ice_dev->dso.dso_config_status =
				      TRACE_STATUS_DEFAULT_CONFIG_WRITE_PENDING;
		ice_dev->dso.is_default_config = true;
		cve_os_dev_log(CVE_LOGLEVEL_INFO,
					ice_dev->dev_index,
					"DSO default config\n");
	}
	pe_mask = (1 << ice_dev->dev_index) << 4;
	value = cve_os_read_idc_mmio(ice_dev,
				IDC_REGS_IDC_MMIO_BAR0_MEM_ICEPE_MMOFFSET);

	/* If Device is ON */
	if ((value & pe_mask) != pe_mask) {
		cve_os_log(CVE_LOGLEVEL_INFO,
				"ICE-%d not Powered ON, Reg write not done\n",
				ice_dev->dev_index);
		if (ice_dev->dso.is_default_config == true)
			ice_dev->dso.dso_config_status = TRACE_STATUS_DEFAULT;
		goto out;
	}
	ret = ice_trace_write_dso_regs(ice_dev);
	if (ret)
		cve_os_dev_log(CVE_LOGLEVEL_ERROR,
					ice_dev->dev_index,
					"ice_trace_write_dso_regs() failed\n");

out:
	FUNC_LEAVE();

	return ret;
}

int ice_trace_set_perf_counter_setup(struct ice_perf_counter_setup *perf_ctr)
{
	struct cve_device *ice_dev;
	int ret = 0;
	u32 dev_index;
	u64 pe_mask, value;
	u32 curr_cfg;

	FUNC_ENTER();

	dev_index = ffs(perf_ctr->ice_number) - 1;
	if (dev_index >= NUM_ICE_UNIT) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
	      "Invalid dev_index %d ice_number(bitmask) 0x%x\n",
			dev_index, perf_ctr->ice_number);
		ret = -EINVAL;
		goto out;
	}
	ice_dev = cve_device_get(dev_index);
	if (!ice_dev) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "NULL ice_dev pointer\n");
		ret = -ENODEV;
		goto out;
	}

	if (perf_ctr) {
		cve_os_dev_log(CVE_LOGLEVEL_INFO,
					ice_dev->dev_index,
					"Perf Counter User config\n");
		curr_cfg = ice_dev->perf_counter.perf_counter_config_len;
		ice_dev->perf_counter.perf_counter_config_len++;

		if (ice_dev->perf_counter.perf_counter_config_len >
ICE_MAX_PMON_CONFIG) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"PMON config len is beyond limit\n");
			ret = -EINVAL;
			goto out;
		}

		ice_dev->perf_counter.conf[curr_cfg].register_offset =
					perf_ctr->register_offset;
		ice_dev->perf_counter.conf[curr_cfg].counter_value =
					perf_ctr->counter_value;
		ice_dev->perf_counter.conf[curr_cfg].counter_config_mask =
					perf_ctr->counter_config_mask;
		ice_dev->perf_counter.perf_counter_config_status =
				TRACE_STATUS_USER_CONFIG_WRITE_PENDING;

		pe_mask = (1 << ice_dev->dev_index) << 4;
		value = cve_os_read_idc_mmio(ice_dev,
				IDC_REGS_IDC_MMIO_BAR0_MEM_ICEPE_MMOFFSET);

		/* If Device is ON */
		if ((value & pe_mask) != pe_mask) {
			cve_os_log(CVE_LOGLEVEL_INFO,
				"ICE-%d not Powered ON, Reg write not done\n",
				ice_dev->dev_index);
			goto out;
		}
		ret = ice_trace_configure_one_perf_counter(ice_dev, curr_cfg);
	}
out:
	FUNC_LEAVE();
	return ret;
}

int ice_trace_set_reg_reader_daemon(struct ice_register_reader_daemon *daemon,
					u32 dev_index)
{

	struct cve_device *ice_dev;
	int ret = 0;
	u64 pe_mask, value;

	FUNC_ENTER();

	ice_dev = cve_device_get(dev_index);
	if (!ice_dev) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "NULL ice_dev pointer\n");
		ret = -ENODEV;
		goto out;
	}

	if (!daemon) { /* Default config  reset all the value*/
		ice_dev->daemon.conf.daemon_enable = 0; /* Disable */
		ice_dev->daemon.conf.daemon_control = 0;
		ice_dev->daemon.conf.daemon_table_len =
					ICE_MAX_DAEMON_TABLE_LEN;

		memset(ice_dev->daemon.conf.daemon_table, 0,
				 ICE_MAX_DAEMON_TABLE_LEN * sizeof(u32));
		ice_dev->daemon.daemon_config_status =
				TRACE_STATUS_DEFAULT_CONFIG_WRITE_PENDING;
		ice_dev->daemon.is_default_config = true;
		cve_os_dev_log(CVE_LOGLEVEL_INFO,
					ice_dev->dev_index,
					"Daemon default config\n");
		goto set_daemon;
	}

	ice_dev->daemon.conf.daemon_enable = daemon->daemon_enable;
	ice_dev->daemon.conf.daemon_control = daemon->daemon_control;

	if (daemon->daemon_table_len > ICE_MAX_DAEMON_TABLE_LEN) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "Table len is beyond limit\n");
		ret = -EINVAL;
		goto out;
	}

	ice_dev->daemon.conf.daemon_table_len = daemon->daemon_table_len;

	memcpy(ice_dev->daemon.conf.daemon_table, daemon->daemon_table,
					daemon->daemon_table_len * sizeof(u32));
	ice_dev->daemon.is_default_config = false;
	ice_dev->daemon.daemon_config_status =
				TRACE_STATUS_USER_CONFIG_WRITE_PENDING;
	cve_os_dev_log(CVE_LOGLEVEL_INFO, ice_dev->dev_index,
					"Daemon USER config\n");
set_daemon:
	pe_mask = (1 << ice_dev->dev_index) << 4;
	value = cve_os_read_idc_mmio(ice_dev,
				IDC_REGS_IDC_MMIO_BAR0_MEM_ICEPE_MMOFFSET);

	/* If Device is ON */
	if ((value & pe_mask) != pe_mask) {
		cve_os_log(CVE_LOGLEVEL_INFO,
				"ICE-%d not Powered ON, Reg write not done\n",
				ice_dev->dev_index);
		if (ice_dev->daemon.is_default_config == true)
			ice_dev->daemon.daemon_config_status =
							TRACE_STATUS_DEFAULT;
		goto out;
	}
	ret = ice_trace_configure_registers_reader_demon(ice_dev);
	if (ret)
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
					"Reader daemon restore failed\n");

out:
	FUNC_LEAVE();

	return ret;
}

int ice_trace_write_dso_regs(struct cve_device *ice_dev)
{
	unsigned int i;
	u8 port;
	u16 croffset;
	int ret;
	u32 value;
	u32 dso_reg_addr;
#ifndef RING3_VALIDATION
	struct icedrv_regbar_callbacks *cb = ice_dev->dso.regbar_cbs;
#endif

	FUNC_ENTER();
	ret = write_dso_regs_sanity(ice_dev);
	if (ret) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR,
				ice_dev->dev_index,
				"write_dso_regs_sanity() failed\n");
	}

	for (i = 0; i < ice_dev->dso.reg_num; i++) {
		port = ice_dev->dso.reg_offsets[i].port;
		croffset = ice_dev->dso.reg_offsets[i].croffset;

	ret = regbar_port_croffset_sanity(ice_dev, port, croffset);

	if (ret) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR,
				ice_dev->dev_index,
				"regbar_port_croffset_sanity() failed\n");
	}
		dso_reg_addr = (port << 16 | croffset) & 0xffffff;

		/* for DSO_CFG_DTF_SRC_CONFIG_REG shouldn't write to 30,31 bit*/
		if (croffset == dso_reg_offsets[1]
			|| croffset == (uint16_t)(dso_reg_offsets[1] |
							(uint16_t) 0x4000)) {
			ice_dev->dso.reg_vals[i] =
				(ice_dev->dso.reg_vals[i] & 0x3fffffff);
		}
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
				    ice_dev->dev_index,
				    "Writing to DSO register Addr 0x%x value 0x%x\n",
				    dso_reg_addr, ice_dev->dso.reg_vals[i]);
#ifndef RING3_VALIDATION
		cb->regbar_write(port, croffset, ice_dev->dso.reg_vals[i]);
		value = cb->regbar_read(port, croffset);

		/* for DSO_CFG_DTF_SRC_CONFIG_REG ignore
		 *30,31 bits value while reading
		 */
		if (croffset == dso_reg_offsets[1]
			|| croffset == (uint16_t)(dso_reg_offsets[1] |
							(uint16_t) 0x4000)) {
			value = value & 0x3fffffff;
		}
		if (value != ice_dev->dso.reg_vals[i]) {
			cve_os_dev_log(CVE_LOGLEVEL_ERROR,
					ice_dev->dev_index,
					"Error in writing dso,read back 0x%x\n",
					value);
			ret = -EFAULT;
			goto out;
		} else {
			cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
					ice_dev->dev_index,
					"Writing reg bar is OK\n");
		}
#else
		coral_dso_write_offset(dso_reg_addr, ice_dev->dso.reg_vals[i],
								BAR7, 0);
		coral_dso_read_offset(dso_reg_addr, &value, BAR7, 0);

		/* for DSO_CFG_DTF_SRC_CONFIG_REG ignore
		 *30,31 bits value while reading
		 */
		if (croffset == dso_reg_offsets[1]
			|| croffset == (uint16_t) (dso_reg_offsets[1] |
							(uint16_t) 0x4000)) {
			value = value & 0x3fffffff;
		}
		if (value != ice_dev->dso.reg_vals[i]) {
			cve_os_dev_log(CVE_LOGLEVEL_ERROR,
					ice_dev->dev_index,
					"Error in writing dso,readback 0x%x\n",
					value);
			ret =  -EFAULT;
			goto out;
		} else {
			cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
					ice_dev->dev_index,
					"Writing reg bar is OK\n");
		}
#endif

	}
	if (ice_dev->dso.is_default_config)
		ice_dev->dso.dso_config_status =
					TRACE_STATUS_DEFAULT_CONFIG_WRITE_DONE;
	else
		ice_dev->dso.dso_config_status =
					TRACE_STATUS_USER_CONFIG_WRITE_DONE;
out:
	FUNC_LEAVE();
	return ret;
}

int  ice_trace_configure_registers_reader_demon(struct cve_device *ice_dev)
{
	unsigned int i;
	u32 reg_offset, reg_offset_table;

	FUNC_ENTER();
	cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
				"daemon control = 0x%x\n",
				ice_dev->daemon.conf.daemon_control);
	reg_offset = CVE_SEMAPHORE_BASE +
			CVE_SEMAPHORE_MMIO_CVE_REGISTER_DEMON_CONTROL_MMOFFSET;
	cve_os_write_mmio_32(ice_dev,
				reg_offset,
				ice_dev->daemon.conf.daemon_control);

	reg_offset_table = CVE_SEMAPHORE_BASE +
			CVE_SEMAPHORE_MMIO_CVE_REGISTER_DEMON_TABLE_MMOFFSET;
	for (i = 0; i < ice_dev->daemon.conf.daemon_table_len; i++) {
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
					"daemon table[%d] = 0x%x\n", i,
					ice_dev->daemon.conf.daemon_table[i]);
		cve_os_write_mmio_32(ice_dev,
					(reg_offset_table + i * 4),
					ice_dev->daemon.conf.daemon_table[i]);
	}

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
					"daemon enable = 0x%x\n",
					ice_dev->daemon.conf.daemon_enable);

	reg_offset = CVE_SEMAPHORE_BASE +
			CVE_SEMAPHORE_MMIO_CVE_REGISTER_DEMON_ENABLE_MMOFFSET;
	cve_os_write_mmio_32(ice_dev,
				reg_offset,
				ice_dev->daemon.conf.daemon_enable);

	if (ice_dev->daemon.is_default_config)
		ice_dev->daemon.daemon_config_status =
					TRACE_STATUS_DEFAULT_CONFIG_WRITE_DONE;
	else
		ice_dev->daemon.daemon_config_status =
					TRACE_STATUS_USER_CONFIG_WRITE_DONE;
	if (ice_dev->daemon.daemon_config_status ==
				TRACE_STATUS_HW_CONFIG_WRITE_PENDING)
		ice_dev->daemon.daemon_config_status =
					TRACE_STATUS_HW_CONFIG_WRITE_DONE;

	FUNC_LEAVE();

	return 0;
}

int ice_trace_configure_perf_counter(struct cve_device *ice_dev)
{
	uint32_t i;
	int ret = 0;
	uint32_t max_len = ICE_MAX_PMON_CONFIG;

	FUNC_ENTER();

	for (i = 0; i < ice_dev->perf_counter.perf_counter_config_len; i++) {

		ret = ice_trace_configure_one_perf_counter(ice_dev, i);
		if (ret) {
			cve_os_dev_log(CVE_LOGLEVEL_ERROR,
			  ice_dev->dev_index,
			  "Problem in Perf counter setup register:%d\n", i);
			goto out;
		} else {
			cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			  ice_dev->dev_index,
			  "Perf counter setup register:%d restored\n", i);
		}
	}
	if (ice_dev->perf_counter.is_default_config) {
		ice_dev->perf_counter.perf_counter_config_len = 0;
		memset(ice_dev->perf_counter.conf, 0,
			max_len * sizeof(u32));
		ice_dev->perf_counter.is_default_config = false;
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			ice_dev->dev_index,
			"Perf counter table reset done\n");
	}
out:
	FUNC_LEAVE();

	return ret;
}

int ice_trace_configure_one_perf_counter(struct cve_device *ice_dev,
								u32 curr_cfg)
{
	uint64_t reg_value, value, count;

	FUNC_ENTER();

	count = __builtin_ctz(
		ice_dev->perf_counter.conf[curr_cfg].counter_config_mask);
	value = (ice_dev->perf_counter.conf[curr_cfg].counter_value << count);

	reg_value = cve_os_read_mmio_32(ice_dev,
			ice_dev->perf_counter.conf[curr_cfg].register_offset);

	reg_value = (reg_value &
		(~ice_dev->perf_counter.conf[curr_cfg].counter_config_mask));

	reg_value = (reg_value | value);

	cve_os_write_mmio_32(ice_dev,
			ice_dev->perf_counter.conf[curr_cfg].register_offset,
			reg_value);

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
		"Counter reg:0x%x counter_value:%u mask:0x%x reg_val:0x%llx\n",
		ice_dev->perf_counter.conf[curr_cfg].register_offset,
		ice_dev->perf_counter.conf[curr_cfg].counter_value,
		ice_dev->perf_counter.conf[curr_cfg].counter_config_mask,
		reg_value);
	ice_dev->perf_counter.perf_counter_config_status =
				TRACE_STATUS_USER_CONFIG_WRITE_DONE;

	FUNC_LEAVE();
	return 0;
}
bool  ice_trace_hw_debug_check(struct cve_device *ice_dev)
{
	uint64_t value;
	bool ret = false;

	FUNC_ENTER();
	value = cve_os_read_idc_mmio(ice_dev,
			IDC_REGS_IDC_MMIO_BAR0_MEM_IDCSPARE_MMOFFSET);
	if (value & 0x1) {
		cve_os_dev_log(CVE_LOGLEVEL_INFO, ice_dev->dev_index,
		      "ICE DBG Indication is ON\n");
		ret = true;
	}

	FUNC_LEAVE();
	return ret;
}

#ifndef RING3_VALIDATION
static uint64_t get_sr_page_addr(void)
{
	struct pci_dev *pDev = NULL;
	int where = MTB_LBAR_OFFSET;
	resource_size_t addr;
	u32 pci_dword;
	void __iomem *io_addr = NULL;
	uint64_t npk_sr_pg_adr = 0;

	FUNC_ENTER();
	while ((pDev = pci_get_device(PCI_VENDOR_ID_INTEL, PCI_ANY_ID, pDev))) {
		if (pDev->device == INTEL_TH_PCI_DEVICE_ID) {
			pci_read_config_dword(pDev, where, &pci_dword);

			addr = pci_dword;
#ifdef CONFIG_PHYS_ADDR_T_64BIT
			pci_read_config_dword(pDev, where + 4, &pci_dword);
			addr |= ((resource_size_t)pci_dword << 32);
#endif
			addr &= ~(PAGE_SIZE - 1);
			io_addr = ioremap(addr, MTB_LBAR_SIZE);
			pci_dword = ioread32(io_addr + REG_MSU_MSC0BAR);
			npk_sr_pg_adr = ((uint64_t)pci_dword - 1) << PAGE_SHIFT;
			iounmap(io_addr);
		}
	}

	FUNC_LEAVE();
	return npk_sr_pg_adr;
}

int ice_trace_init_bios_sr_page(struct cve_device *ice_dev)
{
	uint64_t npk_sr_pg_addr = 0;
	struct cve_os_device *os_dev;
	int ret = 0;
	u8 icebo_num;
	u8 port;
	u32 i;

	FUNC_ENTER();
	npk_sr_pg_addr = get_sr_page_addr();
	cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
				"SR page phy addr 0x%llx\n", npk_sr_pg_addr);
	os_dev = to_cve_os_device(ice_dev);
	ice_dev->dso.sr_addr_base = NULL;
	if (npk_sr_pg_addr) {
		ice_dev->dso.sr_addr_base = devm_ioremap(os_dev->dev,
					npk_sr_pg_addr, SR_PAGE_SIZE);
		if (ice_dev->dso.sr_addr_base == NULL) {
			cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
					"failed in ioremap\n");
			ret = -EFAULT;
			goto out;
		}
	} else {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"No valid BIOS reserved page base addr\n");
		ret = -EFAULT;
		goto out;
	}
	cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
			"SR page virt addr %p\n", ice_dev->dso.sr_addr_base);

	icebo_num = ice_dev->dev_index / 2;
	if (icebo_num > NUM_ICE_BO) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR,
			ice_dev->dev_index,
				"Invalid ICEBO number\n");
		return -EINVAL;
	}
	/*
	 * ICE OBSERVER REGISTER
	 *
	 * -----------------------------------------------------
	 * |Regbar base[39:24] | Port[23:16] | CR offset[15:0] |
	 * -----------------------------------------------------
	 *  CR offset[15:14] = b'00 -ICE0, b'01 ICE1
	 *
	 */
	port = icebo_port_lookup[icebo_num];
	for (i = 0; i < MAX_DSO_CONFIG_REG; i++) {
		ice_dev->dso.reg_offsets[i].port = port;
		/*reg_offset[15:14] = b'01 for ICE1*/
		if (ice_dev->dev_index % 2)
			ice_dev->dso.reg_offsets[i].croffset =
					0x4000 | dso_reg_offsets[i];
		else
			ice_dev->dso.reg_offsets[i].croffset =
						dso_reg_offsets[i];
	}
out:
	FUNC_LEAVE();
	return ret;
}

int ice_trace_restore_hw_dso_regs(struct cve_device *ice_dev)
{
	u64 dso_addr_offset;
	u8 i;
	int ret = 0;

	FUNC_ENTER();
	if (!ice_dev->dso.sr_addr_base) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"No valid reserved save restore page addr\n");
		ret = -EINVAL;
		goto out;
	}
	dso_addr_offset = (u64)(ice_dev->dso.sr_addr_base) +
			(sizeof(u32) * ice_dev->dev_index * MAX_DSO_CONFIG_REG);
	memcpy(ice_dev->dso.reg_vals, (u32 *)dso_addr_offset,
					sizeof(u32) * MAX_DSO_CONFIG_REG);
	ice_dev->dso.dso_config_status =
				      TRACE_STATUS_HW_CONFIG_WRITE_PENDING;

	for (i = 0; i < MAX_DSO_CONFIG_REG; i++)
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
			"dso_reg[%d] = 0x%x\n", i, ice_dev->dso.reg_vals[i]);
out:
	FUNC_LEAVE();
	return ret;
}

/* sysfs related functions.*/
static ssize_t show_dso_filter(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	cve_os_log(CVE_LOGLEVEL_DEBUG, "Not supported\n");

	return 0;
}

static ssize_t store_dso_filter(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	u32 val;
	int ret;
	u32 dev_index;
	u8 reg_index = MAX_DSO_CONFIG_REG;

	ret = kstrtouint(buf, 16, &val);
	if (ret < 0)
		return ret;

	ret = sscanf(kobj->name, "ice%d", &dev_index);
	if (ret < 1) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "failed getting ice id %s\n",
						kobj->name);
		return -EFAULT;
	}
	if (dev_index >= NUM_ICE_UNIT) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "wrong ice id %d\n", dev_index);
		return -EFAULT;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG, "user given value  0x%x\n", val);
	cve_os_log(CVE_LOGLEVEL_DEBUG, "ICE number %d\n", dev_index);
	cve_os_log(CVE_LOGLEVEL_DEBUG, "attr: %s\n", attr->attr.name);

	if (strcmp(attr->attr.name, "dtf_encoder_config") == 0) {
		reg_index = DSO_DTF_ENCODER_CONFIG_REG_INDEX;
	} else if (strcmp(attr->attr.name, "cfg_dtf_src_config") == 0) {
		reg_index = DSO_CFG_DTF_SRC_CONFIG_REG_INDEX;
	} else if (strcmp(attr->attr.name, "cfg_ptype_filter_ch0") == 0) {
		reg_index = DSO_CFG_PTYPE_FILTER_CH0_REG_INDEX;
	} else if (strcmp(attr->attr.name, "filter_match_low_ch0") == 0) {
		reg_index = DSO_FILTER_MATCH_LOW_CH0_REG_INDEX;
	} else if (strcmp(attr->attr.name, "filter_match_high_ch0") == 0) {
		reg_index = DSO_FILTER_MATCH_HIGH_CH0_REG_INDEX;
	} else if (strcmp(attr->attr.name, "filter_mask_low_ch0") == 0) {
		reg_index = DSO_FILTER_MASK_LOW_CH0_REG_INDEX;
	} else if (strcmp(attr->attr.name, "filter_mask_high_ch0") == 0) {
		reg_index = DSO_FILTER_MASK_HIGH_CH0_REG_INDEX;
	} else if (strcmp(attr->attr.name, "filter_inv_ch0") == 0) {
		reg_index = DSO_FILTER_INV_CH0_REG_INDEX;
	} else if (strcmp(attr->attr.name, "cfg_ptype_filter_ch1") == 0) {
		reg_index = DSO_CFG_PTYPE_FILTER_CH1_REG_INDEX;
	} else if (strcmp(attr->attr.name, "filter_match_low_ch1") == 0) {
		reg_index = DSO_FILTER_MATCH_LOW_CH1_REG_INDEX;
	} else if (strcmp(attr->attr.name, "filter_match_high_ch1") == 0) {
		reg_index = DSO_FILTER_MATCH_HIGH_CH1_REG_INDEX;
	} else if (strcmp(attr->attr.name, "filter_mask_low_ch1") == 0) {
		reg_index = DSO_FILTER_MASK_LOW_CH1_REG_INDEX;
	} else if (strcmp(attr->attr.name, "filter_mask_high_ch1") == 0) {
		reg_index = DSO_FILTER_MASK_HIGH_CH1_REG_INDEX;
	} else if (strcmp(attr->attr.name, "filter_inv_ch1") == 0) {
		reg_index = DSO_FILTER_INV_CH1_REG_INDEX;
	} else {
		reg_index = MAX_DSO_CONFIG_REG;
		cve_os_log(CVE_LOGLEVEL_ERROR, "bad filter param\n");
	}

	if (reg_index >= MAX_DSO_CONFIG_REG) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "bad dso reg index\n");
		return -EINVAL;
	}

	ret = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (ret != 0)
		return -ERESTARTSYS;

	ret = ice_trace_set_ice_observer_sysfs(reg_index, val, dev_index);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "set dso reg failed\n");
		cve_os_unlock(&g_cve_driver_biglock);
		return ret;
	}

	cve_os_unlock(&g_cve_driver_biglock);
	return count;
}

static ssize_t show_pmoninfo(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	int ret = 0;
	u32 i;
	u32 size;

	size = sizeof(pmon_arr) / sizeof(struct pmoninfo_details);

	ret = sprintf((buf + ret),
		"-1, -1, RESET, ICE_PMON_RSESET_CONFIG, \"Reset PMON Configuration\"\n");
	for (i = 0; i < size; i++) {
		ret += sprintf((buf + ret), "%d, 0x%x, %s, %s, \"%s\"\n",
				pmon_arr[i].index,
				pmon_arr[i].reg_offset,
				pmon_arr[i].group_name,
				pmon_arr[i].name, pmon_arr[i].desc);
	}

	return ret;
}

static ssize_t show_pmon(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	cve_os_log(CVE_LOGLEVEL_DEBUG, "Not implemented");

	return 0;
}

ssize_t store_pmon(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	char *pmonset_s, *pmonindex_s, *daemonfreq_s;
	u32 pmonindex;
	u32 daemonfreq;
	int tmp_pmonindex;
	int tmp_daemonfreq;
	u32 dev_index;
	int ret = 0;


	ret = sscanf(kobj->name, "ice%d", &dev_index);
	if (ret < 1) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "failed getting ice id %s\n",
						kobj->name);
		return -EFAULT;
	}
	if (dev_index >= NUM_ICE_UNIT) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "wrong ice id %d\n", dev_index);
		return -EFAULT;
	}

	/* TODO: Check for any side effect of const buf ptr given to strsep() */
	while ((pmonset_s = strsep((char **)&buf, ":")) != NULL) {
		pmonset_s = strim(pmonset_s);
		cve_os_log(CVE_LOGLEVEL_DEBUG, "%s\n", pmonset_s);
		pmonindex_s = strsep((char **)&pmonset_s, ",");
		if (pmonindex_s == NULL)
			return -EINVAL;

		pmonindex_s = strim(pmonindex_s);

		daemonfreq_s = strsep((char **)&pmonset_s, ",");
		if (daemonfreq_s == NULL)
			return -EINVAL;

		daemonfreq_s = strim(daemonfreq_s);
		ret = kstrtoint(pmonindex_s, 10, &tmp_pmonindex);
		if (ret < 0)
			return ret;

		ret = kstrtoint(daemonfreq_s, 10, &tmp_daemonfreq);
		if (ret < 0)
			return ret;
		cve_os_log(CVE_LOGLEVEL_DEBUG, "index: %d\t", tmp_pmonindex);
		cve_os_log(CVE_LOGLEVEL_DEBUG, "freq: %d\n", tmp_daemonfreq);
		ret = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
		if (ret != 0)
			return -ERESTARTSYS;
		if (tmp_pmonindex < 0) {
			pmonindex = 0;
			daemonfreq = 0;
		} else {
			pmonindex = tmp_pmonindex + 1;
			daemonfreq = tmp_daemonfreq;
		}
		ret = ice_trace_pmon_config_sysfs(daemonfreq, pmonindex,
								dev_index);
		cve_os_unlock(&g_cve_driver_biglock);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR, "pmon config failed\n");
			return ret;
		}
	}

	ret = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (ret != 0)
		return -ERESTARTSYS;
	ret = ice_trace_configure_pmonregs_sysfs(dev_index);
	cve_os_unlock(&g_cve_driver_biglock);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "daemon sysfs config failed\n");
		return ret;
	}
	return count;
}

static int  ice_trace_configure_pmonregs_sysfs(u32 dev_index)
{
	unsigned int i;
	u32 reg_offset, reg_offset_table;
	u64 pe_mask, value;
	struct cve_device *ice_dev;
	int ret = 0;

	FUNC_ENTER();
	ice_dev = cve_device_get(dev_index);
	if (!ice_dev) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "NULL ice_dev pointer\n");
		ret = -ENODEV;
		goto out;
	}
	pe_mask = (1 << ice_dev->dev_index) << 4;
	value = cve_os_read_idc_mmio(ice_dev,
				IDC_REGS_IDC_MMIO_BAR0_MEM_ICEPE_MMOFFSET);

	/* If Device is ON */
	if ((value & pe_mask) != pe_mask) {
		cve_os_log(CVE_LOGLEVEL_INFO,
				"ICE-%d not Powered ON, Reg write not done\n",
				ice_dev->dev_index);
		goto out;
	}
	/* config pmons */
	ret = ice_trace_configure_perf_counter(ice_dev);
	if (ret)
		goto out;

	ice_dev->perf_counter.perf_counter_config_status =
				TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_DONE;
	cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
				"daemon control = 0x%x\n",
				ice_dev->daemon.conf.daemon_control);
	reg_offset = CVE_SEMAPHORE_BASE +
			CVE_SEMAPHORE_MMIO_CVE_REGISTER_DEMON_CONTROL_MMOFFSET;
	cve_os_write_mmio_32(ice_dev,
				reg_offset,
				ice_dev->daemon.conf.daemon_control);

	reg_offset_table = CVE_SEMAPHORE_BASE +
			CVE_SEMAPHORE_MMIO_CVE_REGISTER_DEMON_TABLE_MMOFFSET;
	for (i = 0; i < ice_dev->daemon.conf.daemon_table_len; i++) {
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
					"daemon table[%d] = 0x%x\n", i,
					ice_dev->daemon.conf.daemon_table[i]);
		cve_os_write_mmio_32(ice_dev,
					(reg_offset_table + i * 4),
					ice_dev->daemon.conf.daemon_table[i]);
	}

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
					"daemon enable = 0x%x\n",
					ice_dev->daemon.conf.daemon_enable);

	reg_offset = CVE_SEMAPHORE_BASE +
			CVE_SEMAPHORE_MMIO_CVE_REGISTER_DEMON_ENABLE_MMOFFSET;
	cve_os_write_mmio_32(ice_dev,
				reg_offset,
				ice_dev->daemon.conf.daemon_enable);

	ice_dev->daemon.daemon_config_status =
				TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_DONE;

out:
	FUNC_LEAVE();

	return ret;
}

static int ice_trace_pmon_config_sysfs(u32 daemonfreq, u32 pmonindex,
							u32 dev_index)
{
	struct cve_device *ice_dev;
	int ret = 0;
	struct ice_register_reader_daemon *daemon_conf;
	u8 consecutive = 0;
	u32 curr_cfg;
	u8 freqexp = 0;
	u32 daemon_reg_offset;
	struct ice_perf_counter_setup *pmon_config_conf;
	u32 pmon_config_reg_offset;
	u32 pmon_config_value;
	u32 pmon_config_mask;
	bool configure_pmon = true;
	bool perform_reset = false;

	FUNC_ENTER();
	ice_dev = cve_device_get(dev_index);
	if (!ice_dev) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "NULL ice_dev pointer\n");
		ret = -ENODEV;
		goto out;
	}
	switch (pmonindex) {
	/*reset PMON configuration */
	case 0:
		consecutive = 0;
		perform_reset = true;
		break;
	/* MMU configuration Index */
	case 1 ... 10:
		consecutive = 0;
		{
			union ICE_MMU_INNER_MEM_MMU_CONFIG_t reg;

			pmon_config_reg_offset = ICE_MMU_BASE +
						ICE_MMU_MMU_CONFIG_MMOFFSET;


			reg.val = 0;

			/* Enable/Disable HW counters */
			reg.field.ACTIVATE_PERFORMANCE_COUNTERS = 1;
			pmon_config_value = 1;
			pmon_config_mask = reg.val;
		}
		break;

	/*GECOE configuration Index */
	case 11 ... 16:
		consecutive = 0;
		configure_pmon = false;
		break;

	/*DELPHI configuration Index */
	case 17 ... 18:
		consecutive = 0;
		configure_pmon = false;
		break;

	default:
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
						"unsupported ipmon index\n");
		ret = -EINVAL;
		goto out;
	}

	daemon_reg_offset = pmon_config_regoffset_array[pmonindex] &
							0x3FFFF; /* b'17:0 */
	switch (daemonfreq) {
	case 0:
		break;
	case 256:
	case 512:
	case 1024:
	case 2048:
	case 4096:
	case 8192:
	case 32768:
	case 65536:
	case 131072:
	case 262144:
	case 524288:
	case 1048576:
	case 2097152:
	case 4194304:
	case 8388608:
		freqexp = __builtin_ctz(daemonfreq) - 8; /*2^8 i.e.256 is base*/
		break;
	default:
		freqexp = 2; /*1024 clks as default mode is selected*/
		cve_os_dev_log(CVE_LOGLEVEL_WARNING, ice_dev->dev_index,
			"Invalid Daemon freq.Default freq 1024 will be set\n");
		break;
	}
	if (perform_reset) {
		int i;
		/*Daemon reset to default values */
		ice_dev->daemon.conf.daemon_enable = 0; /* Disable */
		ice_dev->daemon.conf.daemon_control = 0;
		ice_dev->daemon.conf.daemon_table_len =
					ICE_MAX_DAEMON_TABLE_LEN;

		memset(ice_dev->daemon.conf.daemon_table, 0,
				 ICE_MAX_DAEMON_TABLE_LEN * sizeof(u32));
		ice_dev->daemon.daemon_config_status =
				TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_PENDING;
		cve_os_dev_log(CVE_LOGLEVEL_INFO,
					ice_dev->dev_index,
					"Daemon reset configuration\n");

		/*Perf Counters to default values*/
		/*reset perf counter reg values that are set */
		for (i = 0; i < ice_dev->perf_counter.perf_counter_config_len;
							i++) {
			ice_dev->perf_counter.conf[i].counter_value = 0x0;
		}
		ice_dev->perf_counter.is_default_config = true;

	} else {
		freqexp = 0xf & freqexp;/*only 4 bit b'23:20*/
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
						"freq exponent %d\n", freqexp);

		daemon_conf = &ice_dev->daemon.conf;
		/*TODO: check if only certain bit needs to be programmed */
		/*Enable bit 0:0*/
		daemon_conf->daemon_enable = 0x1;
		/*Immediate read disabled bit 2:2 */

		if (daemon_conf->daemon_table_len > ICE_MAX_DAEMON_TABLE_LEN) {
			cve_os_dev_log(CVE_LOGLEVEL_WARNING, ice_dev->dev_index,
				"Daemon table index exceeded max limit\n");

		}
		/* Driver currently doesn't support immediate read */
		daemon_conf->daemon_control = 0x0;
		daemon_conf->daemon_table[daemon_conf->daemon_table_len] =
			(0x80000000 | (consecutive << 24) | freqexp << 20 |
							daemon_reg_offset);
		daemon_conf->daemon_table_len++;
		ice_dev->daemon.daemon_config_status =
				TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_PENDING;
		/* PMON CONFIG*/
		if (configure_pmon) {
			curr_cfg =
				ice_dev->perf_counter.perf_counter_config_len;
			if (curr_cfg >= ICE_MAX_PMON_CONFIG) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
					"PMON config len is beyond limit\n");
				ret = -EINVAL;
				goto out;
			}
			pmon_config_conf =
				&ice_dev->perf_counter.conf[curr_cfg];
			ice_dev->perf_counter.perf_counter_config_len++;

			pmon_config_conf->register_offset =
						pmon_config_reg_offset;
			pmon_config_conf->counter_value = pmon_config_value;
			pmon_config_conf->counter_config_mask =
							pmon_config_mask;
			ice_dev->perf_counter.perf_counter_config_status =
				TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_PENDING;
		}
	}
out:
	FUNC_LEAVE();
	return ret;
}

static int ice_trace_dso_sysfs_init(struct cve_device *ice_dev)
{
	int ret;
	/* Create the filter files associated with ice<n> kobject */
	ret = sysfs_create_group(ice_dev->ice_kobj, &filter_attr_group);
	if (ret)
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"dso filter sysfs group creation failed\n");

	return ret;
}

static int ice_trace_daemon_sysfs_init(struct cve_device *ice_dev)
{
	int ret;
	/* Create the pmon_info file associated with ice<n> kobject */
	ret = sysfs_create_group(ice_dev->ice_kobj, &pmon_attr_group);
	if (ret)
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"pmoninfo  sysfs group creation failed\n");

	return ret;
}

static void ice_trace_dso_sysfs_term(struct cve_device *ice_dev)
{
	/* Remove the filter files associated with ice<n> kobject */
	sysfs_remove_group(ice_dev->ice_kobj, &filter_attr_group);
}
#if 0
static void ice_trace_daemon_sysfs_term(struct cve_device *ice_dev)
{
	/* Remove the pmon_info file associated with ice<n> kobject */
	sysfs_remove_group(ice_dev->ice_kobj, &pmoninfo_attr_group);
}
#endif

int ice_trace_sysfs_init(struct cve_device *ice_dev)
{
	int ret = 0;
	struct cve_os_device *os_dev;
	char name[10]

	FUNC_ENTER();
	os_dev = to_cve_os_device(ice_dev);
	/* create base subdir once */
	if (icedrv_kobj)
		goto hwtrace_sysfs;

	icedrv_kobj = kobject_create_and_add("icedrv", kernel_kobj);
	if (!icedrv_kobj) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
					"icedrv kobj creation failed\n");
		ret = -ENOMEM;
		goto out;
	}
hwtrace_sysfs:
	if (hwtrace_kobj)
		goto ice_sysfs;

	hwtrace_kobj = kobject_create_and_add("hwtrace", icedrv_kobj);
	if (!hwtrace_kobj) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
					"hwtrace kobj creation failed\n");
		ret = -ENOMEM;
		goto icedrv_kobj_free;
	}
ice_sysfs:
	ice_dev->ice_kobj = NULL;
	snprintf(name, sizeof(name), "ice%d", ice_dev->dev_index);
	ice_dev->ice_kobj = kobject_create_and_add(name, hwtrace_kobj);
	if (!ice_dev->ice_kobj) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"ice%d kobj creation failed\n",
				ice_dev->dev_index);
		ret = -ENOMEM;
		goto hwtrace_kobj_free;
	}
	ret = ice_trace_dso_sysfs_init(ice_dev);
	if (ret) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"ice_trace_dso_sysfs_init failed\n");
		goto ice_kobj_free;
	}

	ret = ice_trace_daemon_sysfs_init(ice_dev);
	if (ret) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"ice_trace_daemon_sysfs_init failed\n");
		goto dso_filter_sysfs_free;
	} else {
		goto out;
	}



dso_filter_sysfs_free:
	ice_trace_dso_sysfs_term(ice_dev);
ice_kobj_free:
	kobject_put(ice_dev->ice_kobj);
	ice_dev->ice_kobj = NULL;
hwtrace_kobj_free:
	kobject_put(hwtrace_kobj);
	hwtrace_kobj = NULL;
icedrv_kobj_free:
	kobject_put(icedrv_kobj);
	icedrv_kobj = NULL;
out:
	FUNC_LEAVE();
	return ret;
}

void ice_trace_sysfs_term(struct cve_device *ice_dev)
{
	FUNC_ENTER();

	if (ice_dev->ice_kobj) {
		kobject_put(ice_dev->ice_kobj);
		ice_dev->ice_kobj = NULL;
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
					"ice kobj deleted\n");
	}

	if (hwtrace_kobj) {
		kobject_put(hwtrace_kobj);
		hwtrace_kobj = NULL;
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
					"hw_trace kobj deleted\n");
	}
	if (icedrv_kobj) {
		kobject_put(icedrv_kobj);
		icedrv_kobj = NULL;
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
					"icedrv sysfs  deleted\n");
	}

	FUNC_LEAVE();
}

static int ice_trace_write_dso_reg_sysfs(struct cve_device *ice_dev,
						u32 dso_reg_index)
{
	u8 port;
	u16 croffset;
	int ret;
	u32 value;
	u32 dso_reg_addr;
#ifndef RING3_VALIDATION
	struct icedrv_regbar_callbacks *cb = ice_dev->dso.regbar_cbs;
#endif

	FUNC_ENTER();
	ret = write_dso_regs_sanity(ice_dev);
	if (ret) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR,
				ice_dev->dev_index,
				"write_dso_regs_sanity() failed\n");
	}

	port = ice_dev->dso.reg_offsets[dso_reg_index].port;
	croffset = ice_dev->dso.reg_offsets[dso_reg_index].croffset;

	ret = regbar_port_croffset_sanity(ice_dev, port, croffset);

	if (ret) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR,
				ice_dev->dev_index,
				"regbar_port_croffset_sanity() failed\n");
	}
		dso_reg_addr = (port << 16 | croffset) & 0xffffff;
	dso_reg_addr = (port << 16 | croffset) & 0xffffff;

	/* for DSO_CFG_DTF_SRC_CONFIG_REG shouldn't write to 30,31 bits*/
	if (croffset == dso_reg_offsets[1]
		|| croffset == (dso_reg_offsets[1] | 0x4000)) {
		ice_dev->dso.reg_vals[dso_reg_index] =
			ice_dev->dso.reg_vals[dso_reg_index] & 0x3fffffff;
		}
	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			    ice_dev->dev_index,
			    "Writing to DSO register Addr 0x%x value 0x%x\n",
			    dso_reg_addr, ice_dev->dso.reg_vals[dso_reg_index]);
#ifndef RING3_VALIDATION
	cb->regbar_write(port, croffset, ice_dev->dso.reg_vals[dso_reg_index]);
	value = cb->regbar_read(port, croffset);

	/* for DSO_CFG_DTF_SRC_CONFIG_REG ignore
	 *30,31 bits value while reading
	 */
	if (croffset == dso_reg_offsets[1]
		|| croffset == (dso_reg_offsets[1] | 0x4000)) {
		value = value & 0x3fffffff;
	}

	if (value != ice_dev->dso.reg_vals[dso_reg_index]) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR,
				ice_dev->dev_index,
				"Error in writing dso,read back 0x%x\n",
				value);
		ret = -EFAULT;
		goto out;
	} else {
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
				ice_dev->dev_index,
				"Writing reg bar is OK\n");
	}
#endif

	ice_dev->dso.dso_config_status =
				TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_DONE;
out:
	FUNC_LEAVE();
	return ret;
}

static int ice_trace_set_ice_observer_sysfs(u8 dso_reg_index, u32 dso_reg_val,
							u32 dev_index)
{
	struct cve_device *ice_dev;
	int ret = 0;
	u8 icebo_num;
	u8 port;
	u64 pe_mask, value;

	FUNC_ENTER();

	ice_dev = cve_device_get(dev_index);
	if (!ice_dev) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "NULL ice_dev pointer\n");
		ret = -ENODEV;
		goto out;
	}

	if (ice_trace_hw_debug_check(ice_dev)) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"User dso setting allowed as HW DBG is ON\n");
		ret = -EBUSY;
		goto out;
	}

	icebo_num = ice_dev->dev_index / 2;
	if (icebo_num > NUM_ICE_BO) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR,
			ice_dev->dev_index,
				"Invalid ICEBO number\n");
		return -EINVAL;
	}
	/*
	 * ICE OBSERVER REGISTER
	 *
	 * -----------------------------------------------------
	 * |Regbar base[39:24] | Port[23:16] | CR offset[15:0] |
	 * -----------------------------------------------------
	 *  CR offset[15:14] = b'00 -ICE0, b'01 ICE1
	 *
	 */
	port = icebo_port_lookup[icebo_num];
	ice_dev->dso.reg_offsets[dso_reg_index].port = port;
	/*reg_offset[15:14] = b'01 for ICE1*/
	if (ice_dev->dev_index % 2)
		ice_dev->dso.reg_offsets[dso_reg_index].croffset =
				0x4000 | dso_reg_offsets[dso_reg_index];
	else
		ice_dev->dso.reg_offsets[dso_reg_index].croffset =
					dso_reg_offsets[dso_reg_index];

	ice_dev->dso.reg_vals[dso_reg_index] = dso_reg_val;
	ice_dev->dso.dso_config_status =
				TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_PENDING;
	pe_mask = (1 << ice_dev->dev_index) << 4;
	value = cve_os_read_idc_mmio(ice_dev,
				IDC_REGS_IDC_MMIO_BAR0_MEM_ICEPE_MMOFFSET);

	/* If Device is ON */
	if ((value & pe_mask) != pe_mask) {
		cve_os_log(CVE_LOGLEVEL_INFO,
				"ICE-%d not Powered ON, Reg write not done\n",
				ice_dev->dev_index);
		goto out;
	}
	ret = ice_trace_write_dso_reg_sysfs(ice_dev, dso_reg_index);
	if (ret)
		cve_os_dev_log(CVE_LOGLEVEL_ERROR,
					ice_dev->dev_index,
					"ice_trace_write_dso_regs() failed\n");

out:
	FUNC_LEAVE();

	return ret;
}
#endif /* !RING3_VALIDATION*/
int ice_trace_init_dso(struct cve_device *ice_dev)
{
	u8 icebo_num;
	u8 i;
	int ret = 0;
	u8 port;

	FUNC_ENTER();
	icebo_num = ice_dev->dev_index / 2;
	if (icebo_num > NUM_ICE_BO) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR,
			ice_dev->dev_index,
				"Invalid ICEBO number\n");
		ret = -EINVAL;
		goto out;
	}

	ice_dev->dso.reg_num = MAX_DSO_CONFIG_REG;
	/*
	 * ICE OBSERVER REGISTER
	 *
	 * -----------------------------------------------------
	 * |Regbar base[39:24] | Port[23:16] | CR offset[15:0] |
	 * -----------------------------------------------------
	 *  CR offset[15:14] = b'00 -ICE0, b'01 ICE1
	 *
	 */
	port = icebo_port_lookup[icebo_num];
	for (i = 0; i < MAX_DSO_CONFIG_REG; i++) {
		ice_dev->dso.reg_offsets[i].port = port;
		/*reg_offset[15:14] = b'01 for ICE1*/
		if (ice_dev->dev_index % 2)
			ice_dev->dso.reg_offsets[i].croffset =
					0x4000 | dso_reg_offsets[i];
		else
			ice_dev->dso.reg_offsets[i].croffset =
						dso_reg_offsets[i];
	}
	memcpy(ice_dev->dso.reg_vals, default_dso_reg_vals,
						sizeof(default_dso_reg_vals));
out:
	FUNC_LEAVE();
	return ret;
}
