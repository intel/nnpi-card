/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/




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

#include "idc_device.h"
#include "cve_device_group.h"

#include "sph_trace_hw_regs.h"
#include "project_device_interface.h"

#ifdef RING3_VALIDATION
#include "coral.h"
#endif

#define RESET 0
/*TODO: reg offset should come from hw header files? */
#define MAX_PMON_DAEMON 27

#ifndef RING3_VALIDATION

struct kobject *get_icedrv_kobj(void)
{
	struct kobject *kobj = NULL;

	if (!icedrv_kobj) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
					"icedrv kobj doesn't exist\n");
		goto out;
	}
	kobj = icedrv_kobj;
out:
	return kobj;
}

static u32 __get_pmon_config_regoffset(u32 index)
{
	u32 pmon_config_regoffset_array[MAX_PMON_DAEMON] = {
	RESET,
	(cfg_default.mmu_base + cfg_default.mmu_atu_misses_offset),
	(cfg_default.mmu_base + cfg_default.mmu_atu_misses_offset + 4),
	(cfg_default.mmu_base + cfg_default.mmu_atu_misses_offset + 8),
	(cfg_default.mmu_base + cfg_default.mmu_atu_misses_offset + 12),
	(cfg_default.mmu_base + cfg_default.mmu_atu_transactions_offset),
	(cfg_default.mmu_base + cfg_default.mmu_atu_transactions_offset + 4),
	(cfg_default.mmu_base + cfg_default.mmu_atu_transactions_offset + 8),
	(cfg_default.mmu_base + cfg_default.mmu_atu_transactions_offset + 12),
	(cfg_default.mmu_base + cfg_default.mmu_read_issued_offset),
	(cfg_default.mmu_base + cfg_default.mmu_write_issued_offset),
	(cfg_default.cbbid_gecoe_offset +
			cfg_default.ice_gecoe_dec_partial_access_count_offset),
	(cfg_default.cbbid_gecoe_offset +
			cfg_default.ice_gecoe_enc_partial_access_count_offset),
	(cfg_default.cbbid_gecoe_offset +
			cfg_default.ice_gecoe_dec_meta_miss_count_offset),
	(cfg_default.cbbid_gecoe_offset +
			cfg_default.ice_gecoe_enc_uncom_mode_count_offset),
	(cfg_default.cbbid_gecoe_offset +
			cfg_default.ice_gecoe_enc_null_mode_count_offset),
	(cfg_default.cbbid_gecoe_offset +
			cfg_default.ice_gecoe_enc_sm_mode_count_offset),
	(cfg_default.ice_delphi_base +
			cfg_default.ice_delphi_dbg_perf_cnt_1_reg_offset),
	(cfg_default.ice_delphi_base +
			cfg_default.ice_delphi_dbg_perf_cnt_2_reg_offset),
	(cfg_default.ice_delphi_base +
			cfg_default.ice_delphi_dbg_perf_status_reg_offset),
	(cfg_default.ice_delphi_base +
			cfg_default.ice_delphi_gemm_cnn_startup_counter_offset),
	(cfg_default.ice_delphi_base +
			cfg_default.ice_delphi_gemm_compute_cycle_offset),
	(cfg_default.ice_delphi_base +
			cfg_default.ice_delphi_gemm_output_write_cycle_offset),
	(cfg_default.ice_delphi_base +
			cfg_default.ice_delphi_cnn_compute_cycles_offset),
	(cfg_default.ice_delphi_base +
			cfg_default.ice_delphi_cnn_output_write_cycles_offset),
	(cfg_default.ice_delphi_base +
			cfg_default.ice_delphi_credit_cfg_latency_offset),
	(cfg_default.ice_delphi_base +
		cfg_default.ice_delphi_perf_cnt_ovr_flw_indication_offset)
	};

	return pmon_config_regoffset_array[index];
}
#endif

static u16 __get_dso_regoffset(u16 index)
{
	u16 dso_reg_offsets[MAX_DSO_CONFIG_REG] = {
	cfg_default.ice_dso_dtf_encoder_config_reg_offset/*0x0004*/,
	/* DSO_DTF_ENCODER_CONFIG_REG */
	cfg_default.ice_dso_cfg_dtf_src_cfg_reg_offset/*0x0014*/,
	/* DSO_CFG_DTF_SRC_CONFIG_REG */
	cfg_default.ice_dso_cfg_ptype_filter_ch0_reg_offset/*0x0018*/,
	/* DSO_CFG_PTYPE_FILTER_CH0_REG */
	cfg_default.ice_dso_filter_match_low_ch0_reg_offset/*0x001c*/,
	/* DSO_FILTER_MATCH_LOW_CH0_REG */
	cfg_default.ice_dso_filter_match_high_ch0_reg_offset/*0x0020*/,
	/* DSO_FILTER_MATCH_HIGH_CH0_REG */
	cfg_default.ice_dso_filter_mask_low_ch0_reg_offset/*0x0024*/,
	/* DSO_FILTER_MASK_LOW_CH0_REG */
	cfg_default.ice_dso_filter_mask_high_ch0_reg_offset/*0x0028*/,
	/* DSO_FILTER_MASK_HIGH_CH0_REG */
	cfg_default.ice_dso_filter_inv_ch0_reg_offset/*0x002c*/,
	/* DSO_FILTER_INV_CH0_REG */
	cfg_default.ice_dso_cfg_ptype_filter_ch1_reg_offset/*0x0030*/,
	/* DSO_CFG_PTYPE_FILTER_CH1_REG */
	cfg_default.ice_dso_filter_match_low_ch1_reg_offset/*0x0034*/,
	/* DSO_FILTER_MATCH_LOW_CH1_REG */
	cfg_default.ice_dso_filter_match_high_ch1_reg_offset/*0x0038*/,
	/* DSO_FILTER_MATCH_HIGH_CH1_REG */
	cfg_default.ice_dso_filter_mask_low_ch1_reg_offset/*0x003c*/,
	/* DSO_FILTER_MASK_LOW_CH1_REG */
	cfg_default.ice_dso_filter_mask_high_ch1_reg_offset/*0x0040*/,
	/* DSO_FILTER_MASK_HIGH_CH1_REG */
	cfg_default.ice_dso_filter_inv_ch1_reg_offset/*0x0044*/,
	/* DSO_FILTER_INV_CH1_REG */
			};
	return dso_reg_offsets[index];
}

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

static ssize_t show_pmoninfo(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf);

static ssize_t show_pmon(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf);

static ssize_t read_ice_mmu_pmon(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf);

static ssize_t read_ice_delphi_pmon(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf);

static ssize_t get_dump_pmon_status(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf);

static ssize_t store_pmon(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count);

static ssize_t set_dump_pmon_status(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count);

static ssize_t store_trace_node_cnt(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count);

static ssize_t store_trace_update_status(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count);

static ssize_t show_trace_node_cnt(struct kobject *kobj,
			struct kobj_attribute *attr, char *buf);

static ssize_t show_trace_update_status(struct kobject *kobj,
			struct kobj_attribute *attr, char *buf);

static ssize_t show_ctx_id(struct kobject *kobj,
			struct kobj_attribute *attr, char *buf);

static ssize_t show_ntw_id(struct kobject *kobj,
			struct kobj_attribute *attr, char *buf);

static ssize_t show_infer_num(struct kobject *kobj,
			struct kobj_attribute *attr, char *buf);

static ssize_t store_jobs(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count);

static ssize_t show_jobs(struct kobject *kobj,
			struct kobj_attribute *attr, char *buf);

static ssize_t store_ctx_id(struct kobject *kobj,
			struct kobj_attribute *attr,
			const char *buf, size_t count);

static ssize_t store_ntw_id(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count);

static ssize_t store_infer_num(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count);

static struct kobj_attribute pmoninfo_attr =
__ATTR(pmoninfo, 0444, show_pmoninfo, NULL);

static struct kobj_attribute pmon_attr =
__ATTR(pmon, 0664, show_pmon, store_pmon);

static struct kobj_attribute mmu_pmon_attr =
__ATTR(mmu_pmon, 0444, read_ice_mmu_pmon, NULL);

static struct kobj_attribute delphi_pmon_attr =
__ATTR(delphi_pmon, 0444, read_ice_delphi_pmon, NULL);

static struct kobj_attribute enable_mmu_pmon_attr =
__ATTR(enable_mmu_pmon, 0664, get_dump_pmon_status, set_dump_pmon_status);

static struct kobj_attribute enable_delphi_pmon_attr =
__ATTR(enable_delphi_pmon, 0664, get_dump_pmon_status, set_dump_pmon_status);

static struct kobj_attribute enable_nodes_attr =
__ATTR(node_count, 0664, show_trace_node_cnt, store_trace_node_cnt);

static struct kobj_attribute trace_update_status_attr =
__ATTR(update_status, 0664, show_trace_update_status,
		store_trace_update_status);

static struct kobj_attribute enable_job_attr =
__ATTR(jobs, 0664, show_jobs, store_jobs);

static struct kobj_attribute ctx_id_attr =
__ATTR(ctx_id, 0664, show_ctx_id, store_ctx_id);

static struct kobj_attribute ntw_id_attr =
__ATTR(ntw_id, 0664, show_ntw_id, store_ntw_id);

static struct kobj_attribute infer_num_attr =
__ATTR(infer_num, 0664, show_infer_num, store_infer_num);

static struct attribute *read_ice_pmon_attrs[] = {
	&mmu_pmon_attr.attr,
	&delphi_pmon_attr.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static struct attribute *pmon_attrs[] = {
	&pmoninfo_attr.attr,
	&pmon_attr.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static struct attribute *enable_pmon_attrs[] = {
	&enable_mmu_pmon_attr.attr,
	&enable_delphi_pmon_attr.attr,
	NULL,
};

static struct attribute *enable_nodes_attrs[] = {
	&enable_nodes_attr.attr,
	&trace_update_status_attr.attr,
	&pmoninfo_attr.attr,
	NULL,
};

static struct attribute *enable_job_attrs[] = {
	&enable_job_attr.attr,
	&ctx_id_attr.attr,
	&ntw_id_attr.attr,
	&infer_num_attr.attr,
	&pmon_attr.attr,
	NULL,
};

static struct attribute_group enable_pmon_attr_group = {
		.attrs = enable_pmon_attrs,
};

static struct attribute_group enable_nodes_attr_group = {
		.attrs = enable_nodes_attrs,
};

static struct attribute_group enable_job_attr_group = {
		.attrs = enable_job_attrs,
};

static struct attribute_group read_ice_pmon_attr_group = {
		.name = "pmon_dump",
		.attrs = read_ice_pmon_attrs,
};

static struct attribute_group pmon_attr_group = {
		.attrs = pmon_attrs,
};

struct kobject *icedrv_kobj;
static struct kobject *hwtrace_kobj;
static struct kobject *physical_ice_kobj;
static struct kobject *jobs_kobj;
static int ice_trace_set_ice_observer_sysfs(u8 dso_reg_index, u32 dso_reg_val,
							u32 dev_index);
static int ice_trace_set_job_observer_sysfs(u8 dso_reg_index, u32 dso_reg_val,
							u32 dev_index);
static int ice_trace_pmon_config_sysfs_node(u32 daemonfreq, u32 pmonindex,
						u32 node_index);

static int ice_trace_pmon_config_sysfs(u32 daemonfreq, u32 pmonindex,
						struct cve_device *ice_dev);
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

int ice_trace_dso_register_uncore_callbacks(struct ice_dso_regs_data *dso)
{
	int ret = 0;

	FUNC_ENTER()

	intel_icedrv_uncore_regbar_cb(&dso->regbar_cbs);
	if (!dso->regbar_cbs) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Error in getting regbar callback functions\n");
		ret = -ENODEV;
		goto out;
	}
	cve_os_log(CVE_LOGLEVEL_DEBUG,
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

int ice_trace_dso_register_uncore_callbacks(struct ice_dso_regs_data *dso)
{
	cve_os_log(CVE_LOGLEVEL_DEBUG,
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
	for (i = 0; i < MAX_DSO_CONFIG_REG; i++) {
		if (tmpCroffset == __get_dso_regoffset(i)
			|| (tmpCroffset == (uint64_t)(__get_dso_regoffset(i) |
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
		memcpy(ice_dev->dso.reg_readback_vals, default_dso_reg_vals,
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
				cfg_default.bar0_mem_icepe_offset);

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
	if (perf_ctr) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Ice perf counter is NULL\n");
		ret = -EINVAL;
		goto out;
	}
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
				cfg_default.bar0_mem_icepe_offset);

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
				cfg_default.bar0_mem_icepe_offset);

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
		goto out;
	}

	for (i = 0; i < ice_dev->dso.reg_num; i++) {
		port = ice_dev->dso.reg_offsets[i].port;
		croffset = ice_dev->dso.reg_offsets[i].croffset;

		ret = regbar_port_croffset_sanity(ice_dev, port, croffset);

		if (ret) {
			cve_os_dev_log(CVE_LOGLEVEL_ERROR,
				ice_dev->dev_index,
				"regbar_port_croffset_sanity() failed\n");
			goto out;
		}
		dso_reg_addr = (port << 16 | croffset) & 0xffffff;

		/* for DSO_CFG_DTF_SRC_CONFIG_REG shouldn't write to 30,31 bit*/
		if (croffset == __get_dso_regoffset(1)
			|| croffset == (uint16_t)(__get_dso_regoffset(1) |
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

		ice_dev->dso.reg_readback_vals[i] = value;
		/* for DSO_CFG_DTF_SRC_CONFIG_REG ignore
		 *30,31 bits value while reading
		 */
		if (croffset == __get_dso_regoffset(1)
			|| croffset == (uint16_t)(__get_dso_regoffset(1) |
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
		ice_dev->dso.reg_readback_vals[i] = value;

		/* for DSO_CFG_DTF_SRC_CONFIG_REG ignore
		 *30,31 bits value while reading
		 */
		if (croffset == __get_dso_regoffset(1)
			|| croffset == (uint16_t) (__get_dso_regoffset(1) |
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
	reg_offset = cfg_default.ice_sem_base +
			cfg_default.ice_sem_mmio_demon_control_offset;
	cve_os_write_mmio_32(ice_dev,
				reg_offset,
				ice_dev->daemon.conf.daemon_control);

	reg_offset_table = cfg_default.ice_sem_base +
			cfg_default.ice_sem_mmio_demon_table_offset;
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

	reg_offset = cfg_default.ice_sem_base +
			cfg_default.ice_sem_mmio_demon_enable_offset;
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
			cfg_default.bar0_mem_idcspare_offset);
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
	if (icebo_num >= NUM_ICE_BO) {
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
					0x4000 | __get_dso_regoffset(i);
		else
			ice_dev->dso.reg_offsets[i].croffset =
						__get_dso_regoffset(i);
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

static int get_ice_pmon_index(struct kobj_attribute *attr)
{
	int index;

	if (strcmp(attr->attr.name, "enable_mmu_pmon") == 0) {
		index = ICE_MMU_PMON_INDEX;
	} else if (strcmp(attr->attr.name, "enable_delphi_pmon") == 0) {
		index = ICE_DELPHI_PMON_INDEX;
	} else {
		index = -1;
		cve_os_log(CVE_LOGLEVEL_ERROR, "bad ice pmon param\n");
	}
	return index;

}
static u8 get_dso_filter(struct kobj_attribute *attr)
{
	u8 reg_index;

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
	return reg_index;
}
/* sysfs related functions.*/
static ssize_t show_dso_filter(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	int ret = 0;
	u32 dev_index;
	u32 node_idx;
	u8 reg_index = MAX_DSO_CONFIG_REG;
	struct cve_device *ice_dev;
	u32 value;
	u32 cached_value;
	u16 croffset;
	struct trace_node_sysfs *node_ptr;
	struct cve_device_group *dg;

	ret = sscanf(kobj->name, "ice%u", &dev_index);
	/* This section is for physical ice (legacy) sysfs */
	if (ret == 1) {
		if (dev_index >= NUM_ICE_UNIT) {
			cve_os_log(CVE_LOGLEVEL_ERROR, "wrong ice id %d\n",
						dev_index);
			return -EFAULT;
		}

		cve_os_log(CVE_LOGLEVEL_DEBUG, "ICE number %d\n", dev_index);
		cve_os_log(CVE_LOGLEVEL_DEBUG, "attr: %s\n", attr->attr.name);

		reg_index = get_dso_filter(attr);

		if (reg_index >= MAX_DSO_CONFIG_REG) {
			cve_os_log(CVE_LOGLEVEL_ERROR, "bad dso reg index\n");
			return -EINVAL;
		}

		ret = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
		if (ret != 0)
			return -ERESTARTSYS;

		ice_dev = cve_device_get(dev_index);
		if (!ice_dev) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"NULL ice_dev pointer\n");
			ret = -ENODEV;
			return ret;
		}

		croffset = ice_dev->dso.reg_offsets[reg_index].croffset;
		value = ice_dev->dso.reg_readback_vals[reg_index];
		cached_value = ice_dev->dso.reg_vals[reg_index];

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"DSO readback value 0x%x, DSO cached vale 0x%x\n",
			value, cached_value);

		ret += sprintf((buf + ret),
			"Cached value:0x%x,",
			cached_value);
		ret += sprintf((buf + ret),
			" Last update:0x%x\n",
			value);
		cve_os_unlock(&g_cve_driver_biglock);

		return ret;
	}

	dg = cve_dg_get();
	ret = sscanf(kobj->name, "node%u", &node_idx);
	/* This section is for  logical ice node sysfs */
	if (ret == 1) {
		if (node_idx >= dg->trace_node_cnt) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"Node index sysfs is INVALID\n");
			return -EFAULT;
		}
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Node id in show_dso is %u\n", node_idx);

		cve_os_log(CVE_LOGLEVEL_DEBUG, "attr: %s\n", attr->attr.name);

		node_ptr = &dg->node_group_sysfs[node_idx];
		reg_index = get_dso_filter(attr);

		if (reg_index >= MAX_DSO_CONFIG_REG) {
			cve_os_log(CVE_LOGLEVEL_ERROR, "bad dso reg index\n");
			return -EINVAL;
		}
		ret = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
		if (ret != 0)
			return -ERESTARTSYS;

		value = node_ptr->job.dso.reg_vals[reg_index];
		ret += sprintf((buf + ret),
			"value:0x%x\n", value);
		cve_os_unlock(&g_cve_driver_biglock);
		return ret;
	}

	cve_os_log(CVE_LOGLEVEL_ERROR,
			"FALIED to get valid ice/node id from %s\n",
			kobj->name);
	return -EFAULT;

}

static ssize_t store_ntw_id(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{

	int value;
	int ret;
	char *nw_id;
	u32 index;
	struct cve_device_group *dg;

	dg = cve_dg_get();
	ret = sscanf(kobj->name, "node%u", &index);
	if (ret < 1 || index >= dg->trace_node_cnt) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Failed to get valid node id from %s\n", kobj->name);
		return -EFAULT;
	}
	nw_id = (char *)buf;
	nw_id = strim(nw_id);

	ret = kstrtoint(nw_id, 10, &value);
	if (ret < 0)
		return -EFAULT;

	dg->node_group_sysfs[index].ntw_id = value;
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"ntw ID in node is %d\n", value);
	return count;
}

static ssize_t store_infer_num(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{

	int value;
	int ret;
	char *infer_num;
	u32 index;
	struct cve_device_group *dg;

	dg = cve_dg_get();
	ret = sscanf(kobj->name, "node%u", &index);
	if (ret < 1 || index >= dg->trace_node_cnt) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Failed to get valid node id from %s\n", kobj->name);
		return -EFAULT;
	}
	infer_num = (char *)buf;
	infer_num = strim(infer_num);

	ret = kstrtoint(infer_num, 10, &value);
	if (ret < 0)
		return -EFAULT;

	dg->node_group_sysfs[index].infer_num = value;
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Infer num in node is %d\n", value);
	return count;
}
static ssize_t store_ctx_id(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int value;
	int ret;
	char *ctx_id;
	u32 index;
	struct cve_device_group *dg;

	dg = cve_dg_get();
	ret = sscanf(kobj->name, "node%u", &index);
	if (ret < 1 || index >= dg->trace_node_cnt) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Failed to get valid node id from %s\n", kobj->name);
		return -EFAULT;
	}
	ctx_id = (char *)buf;
	ctx_id = strim(ctx_id);

	ret = kstrtoint(ctx_id, 10, &value);
	if (ret < 0)
		return -EFAULT;

	dg->node_group_sysfs[index].ctx_id = value;
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"ctx id in node is %d\n", value);
	return count;
}

static ssize_t store_dso_filter(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	u32 val;
	int ret;
	u32 dev_index;
	u32 node_idx;
	u8 reg_index = MAX_DSO_CONFIG_REG;

	ret = kstrtouint(buf, 16, &val);
	if (ret < 0)
		return ret;

	ret = sscanf(kobj->name, "ice%u", &dev_index);
	/* This section of code deals with Physical ice (legacy) sysfs */
	if (ret == 1) {
		if (dev_index >= NUM_ICE_UNIT) {
			cve_os_log(CVE_LOGLEVEL_ERROR, "wrong ice id %d\n",
							dev_index);
			return -EFAULT;
		}

		cve_os_log(CVE_LOGLEVEL_DEBUG, "user given value 0x%x\n", val);
		cve_os_log(CVE_LOGLEVEL_DEBUG, "ICE number %d\n", dev_index);
		cve_os_log(CVE_LOGLEVEL_DEBUG, "attr: %s\n", attr->attr.name);

		reg_index = get_dso_filter(attr);

		if (reg_index >= MAX_DSO_CONFIG_REG) {
			cve_os_log(CVE_LOGLEVEL_ERROR, "bad dso reg index\n");
			return -EINVAL;
		}

		ret = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
		if (ret != 0)
			return -ERESTARTSYS;

		ret = ice_trace_set_ice_observer_sysfs(reg_index,
						val, dev_index);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR, "set dso reg failed\n");
			cve_os_unlock(&g_cve_driver_biglock);
			return ret;
		}

		cve_os_unlock(&g_cve_driver_biglock);
		return count;
	}
	ret = sscanf(kobj->name, "node%u", &node_idx);
	/* This section of code deals with Logical ice sysfs */
	if (ret == 1) {

		cve_os_log(CVE_LOGLEVEL_DEBUG, "user given value 0x%x\n", val);
		cve_os_log(CVE_LOGLEVEL_DEBUG, "node number %d\n", node_idx);
		cve_os_log(CVE_LOGLEVEL_DEBUG, "attr: %s\n", attr->attr.name);

		reg_index = get_dso_filter(attr);

		if (reg_index >= MAX_DSO_CONFIG_REG) {
			cve_os_log(CVE_LOGLEVEL_ERROR, "bad dso reg index\n");
			return -EINVAL;
		}

		ret = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
		if (ret != 0)
			return -ERESTARTSYS;

		ret = ice_trace_set_job_observer_sysfs(reg_index,
						val, node_idx);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR, "set dso reg failed\n");
			cve_os_unlock(&g_cve_driver_biglock);
			return ret;
		}

		cve_os_unlock(&g_cve_driver_biglock);

		return count;
	}
	cve_os_log(CVE_LOGLEVEL_ERROR,
			"failed to get valid ice/node id from %s\n",
			kobj->name);
	return -EFAULT;

}

static ssize_t show_pmoninfo(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	int ret = 0;
	u32 i;
	u32 size;
	struct pmoninfo_details pmon_arr[] = {
	__PMONINFO(0, (cfg_default.mmu_base +
		cfg_default.mmu_atu_misses_offset),
		ICE_PMON_MMU_ATU0_MISSES, MMU, "ATU0 Misses"),
	__PMONINFO(1, (cfg_default.mmu_base +
		cfg_default.mmu_atu_misses_offset + 4),
		ICE_PMON_MMU_ATU1_MISSES, MMU, "ATU1 Misses"),
	__PMONINFO(2, (cfg_default.mmu_base +
		cfg_default.mmu_atu_misses_offset + 8),
		ICE_PMON_MMU_ATU2_MISSES, MMU, "ATU2 Misses"),
	__PMONINFO(3, (cfg_default.mmu_base +
		cfg_default.mmu_atu_misses_offset + 12),
		ICE_PMON_MMU_ATU3_MISSES, MMU, "ATU3 Misses"),
	__PMONINFO(4, (cfg_default.mmu_base +
		cfg_default.mmu_atu_transactions_offset),
		ICE_PMON_MMU_ATU0_TRANSACTIONS, MMU, "ATU0 transactions"),
	__PMONINFO(5, (cfg_default.mmu_base +
		cfg_default.mmu_atu_transactions_offset + 4),
		ICE_PMON_MMU_ATU1_TRANSACTIONS, MMU, "ATU1 transactions"),
	__PMONINFO(6, (cfg_default.mmu_base +
		cfg_default.mmu_atu_transactions_offset + 8),
		ICE_PMON_MMU_ATU2_TRANSACTIONS, MMU, "ATU2 transactions"),
	__PMONINFO(7, (cfg_default.mmu_base +
		cfg_default.mmu_atu_transactions_offset + 12),
		ICE_PMON_MMU_ATU3_TRANSACTIONS, MMU, "ATU3 transactions"),
	__PMONINFO(8, (cfg_default.mmu_base +
		cfg_default.mmu_read_issued_offset),
		ICE_PMON_MMU_READ_ISSUED, MMU, "Read issued"),
	__PMONINFO(9, (cfg_default.mmu_base +
		cfg_default.mmu_write_issued_offset),
		ICE_PMON_WRITE_READ_ISSUED, MMU, "Write issued"),
	__PMONINFO(10, (cfg_default.cbbid_gecoe_offset +
			cfg_default.ice_gecoe_dec_partial_access_count_offset),
		ICE_PMON_DEC_PARTIAL_ACCESS_COUNT, GECOE,
						"Decoder Partial access"),
	__PMONINFO(11, (cfg_default.cbbid_gecoe_offset +
			cfg_default.ice_gecoe_enc_partial_access_count_offset),
		ICE_PMON_ENC_PARTIAL_ACCESS_COUNT, GECOE,
						"Encoder Partial access"),
	__PMONINFO(12, (cfg_default.cbbid_gecoe_offset +
			cfg_default.ice_gecoe_dec_meta_miss_count_offset),
		ICE_PMON_DEC_META_MISS_COUNT, GECOE,
						"Decoder Meta Miss"),
	__PMONINFO(13, (cfg_default.cbbid_gecoe_offset +
			cfg_default.ice_gecoe_enc_uncom_mode_count_offset),
			ICE_PMON_ENC_UNCOM_MODE_COUNT, GECOE,
						"Encoder Uncompressed Mode"),
	__PMONINFO(14, (cfg_default.cbbid_gecoe_offset +
			cfg_default.ice_gecoe_enc_null_mode_count_offset),
			ICE_PMON_ENC_NULL_MODE_COUNT, GECOE,
							"Encoder Null Mode"),
	__PMONINFO(15, (cfg_default.cbbid_gecoe_offset +
			cfg_default.ice_gecoe_enc_sm_mode_count_offset),
			ICE_PMON_ENC_SM_MODE_COUNT, GECOE,
						"Encoder Significance Map"),
	__PMONINFO(16, (cfg_default.ice_delphi_base +
			cfg_default.ice_delphi_dbg_perf_cnt_1_reg_offset),
			ICE_PMON_DELPHI_DBG_PERF_CNT_1_REG, DELPHI,
						"Per Layer Cycle Counter"),
	__PMONINFO(17, (cfg_default.ice_delphi_base +
			cfg_default.ice_delphi_dbg_perf_cnt_2_reg_offset),
			ICE_PMON_DELPHI_DBG_PERF_CNT_2_REG, DELPHI,
						"Total Cycle Counter"),
};

	struct pmoninfo_details pmon_arr_p2[] = {
	__PMONINFO(18, (cfg_default.ice_delphi_base +
			cfg_default.ice_delphi_dbg_perf_status_reg_offset),
			ICE_PMON_DELPHI_DBG_PERF_STATUS_REG, DELPHI,
					"Inication of Per layer/Total Cycle Counter Staturation"
	),

	__PMONINFO(19, (cfg_default.ice_delphi_base +
			cfg_default.ice_delphi_gemm_cnn_startup_counter_offset),
			ICE_PMON_DELPHI_GEMM_CNN_START_UP_COUNT, DELPHI,
					"Gemm & CNN Mode - Startup Counter"
	),

	__PMONINFO(20, (cfg_default.ice_delphi_base +
			cfg_default.ice_delphi_gemm_compute_cycle_offset),
			ICE_PMON_DELPHI_GEMM_COMPUTE_COUNT, DELPHI,
					"Gemm Mode - Compute Cycles Counter"
	),

	__PMONINFO(21, (cfg_default.ice_delphi_base +
			cfg_default.ice_delphi_gemm_output_write_cycle_offset),
			ICE_PMON_DELPHI_GEMM_TEARDOWN_COUNT, DELPHI,
					"Gemm Mode - Output Write Cycles Counter"
	),

	__PMONINFO(22, (cfg_default.ice_delphi_base +
			cfg_default.ice_delphi_cnn_compute_cycles_offset),
			ICE_PMON_DELPHI_CNN_COMPUTE_COUNT, DELPHI,
					"Cnn Mode - Compute Cycles Counter"
	),

	__PMONINFO(23, (cfg_default.ice_delphi_base +
			cfg_default.ice_delphi_cnn_output_write_cycles_offset),
			ICE_PMON_DELPHI_CNN_TEARDOWN_COUNT, DELPHI,
					"Cnn Mode - Output Write Cycles Counter"
	),

	__PMONINFO(24, (cfg_default.ice_delphi_base +
			cfg_default.ice_delphi_credit_cfg_latency_offset),
			ICE_PMON_DELPHI_CONFIG_CREDIT_LATENCY_COUNT, DELPHI,
					"Delphi Config and Credit Latency Counter"
	),

	__PMONINFO(25, (cfg_default.ice_delphi_base +
		cfg_default.ice_delphi_perf_cnt_ovr_flw_indication_offset),
			ICE_PMON_DELPHI_OVERFLOW_PERF_COUNTER, DELPHI,
					"Overflow Indication For Perf Counter"
	)
};

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

	if (!ice_get_a_step_enable_flag()) {
		size = sizeof(pmon_arr_p2) /
				sizeof(struct pmoninfo_details);
		for (i = 0; i < size; i++) {
			ret += sprintf((buf + ret),
				"%d, 0x%x, %s, %s, \"%s\"\n",
				pmon_arr_p2[i].index,
				pmon_arr_p2[i].reg_offset,
				pmon_arr_p2[i].group_name,
				pmon_arr_p2[i].name,
				pmon_arr_p2[i].desc);
		}
	}
	return ret;
}

void get_ice_delphi_pmon_regs(struct cve_device *dev)
{
	u32 pmon_index, offset;
	int i = 0;

	for (i = 0; i < ICE_MAX_DELPHI_PMON; i++) {
		if (ice_get_a_step_enable_flag())
			if (i >= ICE_MAX_A_STEP_DELPHI_PMON)
				break;

		pmon_index = ICE_DELPHI_PMON_START_INDEX + i;
		offset = __get_pmon_config_regoffset(pmon_index);

		dev->delphi_pmon[i].pmon_value =
				cve_os_read_mmio_32(dev, offset);

	}
}

void get_ice_mmu_pmon_regs(struct cve_device *dev)
{
	u32 pmon_index, offset;
	int i = 0;

	for (i = 0; i < ICE_MAX_MMU_PMON; i++) {
		pmon_index = ICE_MMU_PMON_START_INDEX + i;
		offset = __get_pmon_config_regoffset(pmon_index);

		dev->mmu_pmon[i].pmon_value = cve_os_read_mmio_32(dev, offset);

	}
}

static ssize_t get_dump_pmon_status(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	int ret = 0;
	struct cve_device_group *device_group = cve_dg_get();
	int index;

	index = get_ice_pmon_index(attr);

	if (index == ICE_MMU_PMON_INDEX)
		ret += sprintf((buf + ret), "%d\n",
			(device_group->dump_ice_mmu_pmon)?1:0);
	else if (index == ICE_DELPHI_PMON_INDEX)
		ret += sprintf((buf + ret), "%d\n",
			(device_group->dump_ice_delphi_pmon)?1:0);
	else
		ret += sprintf((buf + ret), "bad ice PMON param\n");

	return ret;
}

static ssize_t show_trace_node_cnt(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct cve_device_group *dg;

	dg = cve_dg_get();

	return sprintf(buf, "%d\n", dg->trace_node_cnt);
}

static ssize_t show_trace_update_status(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct cve_device_group *dg;

	dg = cve_dg_get();

	return sprintf(buf, "%d\n", dg->trace_update_status);
}

static ssize_t show_ctx_id(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{

	struct cve_device_group *dg;
	u32 index;
	int ret;

	dg = cve_dg_get();
	ret = sscanf(kobj->name, "node%u", &index);
	if (ret < 1 || index >= dg->trace_node_cnt) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"FAILED to get valid node id from %s\n", kobj->name);
		return -EFAULT;
	}
	return sprintf(buf, "%lld\n", dg->node_group_sysfs[index].ctx_id);
}

static ssize_t show_ntw_id(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	u32 index;
	struct cve_device_group *dg;
	int ret;

	dg = cve_dg_get();
	ret = sscanf(kobj->name, "node%u", &index);
	if (ret < 1 || index >= dg->trace_node_cnt) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"FAILED to get valid node id from %s\n", kobj->name);
		return -EFAULT;
	}

	return sprintf(buf, "%lld\n", dg->node_group_sysfs[index].ntw_id);
}

static ssize_t show_infer_num(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	u32 index;
	int ret;
	struct cve_device_group *dg;

	dg = cve_dg_get();
	ret = sscanf(kobj->name, "node%u", &index);
	if (ret < 1 || index >= dg->trace_node_cnt) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"FAILED to get valid node id from %s\n", kobj->name);
		return -EFAULT;
	}

	return sprintf(buf, "%lld\n", dg->node_group_sysfs[index].infer_num);
}

static ssize_t show_jobs(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	int ret = 0;
	int i;
	struct trace_node_sysfs *node;
	u32 index;
	struct cve_device_group *dg;

	dg = cve_dg_get();
	ret = sscanf(kobj->name, "node%u", &index);
	if (ret < 1 || index >= dg->trace_node_cnt) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"FAILED to get valid node id from %s\n", kobj->name);
		return -EFAULT;
	}
	node = &dg->node_group_sysfs[index];

	for (i = 0; i < node->job_count; i++)
		ret += sprintf(buf + ret, "%u,", node->job_list[i]);

	buf[ret-1] = '\n';
	return ret;
}

void init_dso_default_nodes(struct trace_node_sysfs *trace_node)
{
	int i;
	struct ice_dso_regs_data *local_dso;
	struct ice_read_daemon_config *local_daemon;
	struct ice_perf_counter_config *local_perf_counter;

	local_dso = &trace_node->job.dso;
	local_daemon = &trace_node->job.daemon;
	local_perf_counter = &trace_node->job.perf_counter;

	for (i = 0; i < MAX_DSO_CONFIG_REG; i++) {
		local_dso->reg_offsets[i].croffset =
			__get_dso_regoffset(i);
	}
	memcpy(local_dso->reg_vals, default_dso_reg_vals,
						sizeof(default_dso_reg_vals));
	memcpy(local_dso->reg_readback_vals, default_dso_reg_vals,
			sizeof(default_dso_reg_vals));
	local_dso->reg_num = MAX_DSO_CONFIG_REG;
	local_dso->dso_config_status = TRACE_STATUS_DEFAULT;
	ice_trace_dso_register_uncore_callbacks(local_dso);

	/* Set registers reader daemon  configuration status to default */
	local_daemon->daemon_config_status = TRACE_STATUS_DEFAULT;
	local_daemon->conf.daemon_table_len = 0;
	local_daemon->reset_conf.daemon_table_len = 0;
	local_daemon->restore_needed_from_suspend = false;

	/*Initalize perf Counter config length to 0 */
	local_perf_counter->perf_counter_config_len = 0;
}

int create_kobj_nodes(void)
{
	int i;
	char name[30];
	int ret = 0;
	struct cve_device_group *dg;

	dg = cve_dg_get();

	ret = OS_ALLOC_ZERO(sizeof(struct trace_node_sysfs) *
			dg->trace_node_cnt, (void **)&dg->node_group_sysfs);

	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Failed to allocate memory %d\n", ret);
		return -ENOMEM;
	}

	for (i = 0; i < dg->trace_node_cnt; i++) {
		snprintf(name, sizeof(name), "node%d", i);
		dg->node_group_sysfs[i].node_kobj = kobject_create_and_add(name,
							jobs_kobj);
		if (!dg->node_group_sysfs[i].node_kobj) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"FAILED to create node kobj\n");
			ret = -ENOMEM;
			goto clear_out;
		}
		ret = sysfs_create_group(dg->node_group_sysfs[i].node_kobj,
						&filter_attr_group);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"Failed to create filter inside node\n");
			ret = -EFAULT;
			goto clear_node;
		}
		ret = sysfs_create_group(dg->node_group_sysfs[i].node_kobj,
						&enable_job_attr_group);

		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"Failed to create job inside node\n");
			ret = -EFAULT;
			goto clear_filters;
		}
		dg->node_group_sysfs[i].ctx_id = DEFAULT_ID;
		dg->node_group_sysfs[i].ntw_id = DEFAULT_ID;
		dg->node_group_sysfs[i].infer_num = DEFAULT_ID;

		init_dso_default_nodes(&dg->node_group_sysfs[i]);

	}
	return i;
clear_filters:
	sysfs_remove_group(dg->node_group_sysfs[i].node_kobj,
			&filter_attr_group);
clear_node:
	if (dg->node_group_sysfs[i].node_kobj) {
		kobject_put(dg->node_group_sysfs[i].node_kobj);
		dg->node_group_sysfs[i].node_kobj = NULL;
	}
clear_out:
	i--;
	for ( ; i >= 0; i--) {
		if (dg->node_group_sysfs[i].node_kobj) {
			sysfs_remove_group(dg->node_group_sysfs[i].node_kobj,
				&filter_attr_group);
			sysfs_remove_group(dg->node_group_sysfs[i].node_kobj,
				&enable_job_attr_group);
			kobject_put(dg->node_group_sysfs[i].node_kobj);
			dg->node_group_sysfs[i].node_kobj = NULL;
		}
	}
	ret = OS_FREE(dg->node_group_sysfs,
		sizeof(struct trace_node_sysfs) * dg->trace_node_cnt);
	dg->node_group_sysfs = NULL;
	dg->trace_node_cnt = 0;
	return ret;
}

ssize_t store_trace_update_status(struct kobject *kobj,
			struct kobj_attribute *attr,
			const char *buf, size_t count)
{
	char *update_status;
	int ret = 0;
	int status;
	struct cve_device_group *dg;

	dg = cve_dg_get();

	update_status = (char *)buf;
	update_status = strim(update_status);

	if (update_status == NULL)
		return -EFAULT;

	ret = kstrtoint(update_status, 10, &status);
	if (ret < 0)
		return ret;

	dg->trace_update_status = status;
	return count;
}

static void  __reset_icedrv_trace(struct cve_device *ice_dev)
{

	FUNC_ENTER()
	/* Set dso configuration status to default*/
	ice_dev->dso.dso_config_status = TRACE_STATUS_DEFAULT;
	ice_dev->logical_dso = false;

	/* Set registers reader daemon  configuration status to default */
	ice_dev->daemon.daemon_config_status = TRACE_STATUS_DEFAULT;
	ice_dev->daemon.conf.daemon_table_len = 0;
	ice_dev->daemon.reset_conf.daemon_table_len = 0;
	ice_dev->daemon.restore_needed_from_suspend = false;

	/*Initalize perf Counter config length to 0 */
	ice_dev->perf_counter.perf_counter_config_len = 0;


	FUNC_LEAVE();
}

void free_old_nodes(void)
{
	int i;
	struct cve_device_group *dg;
	struct cve_device *dev;
	int ret;
	u32 active_ice;

	dg = cve_dg_get();

	active_ice = (~g_icemask) & VALID_ICE_MASK;
	while (active_ice) {
		i = __builtin_ctz(active_ice);
		CVE_CLEAR_BIT(active_ice, i);
		dev = cve_device_get(i);
		if (!dev) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"CVE Dev is NULL\n");
			continue;
		}
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Reset ice trace related fields for dev %d\n",
				dev->dev_index);
		/* Reset the ice trace related fields */
		__reset_icedrv_trace(dev);
	}
	for (i = 0; i < dg->trace_node_cnt; i++) {
		if (dg->node_group_sysfs[i].node_kobj) {
			kobject_put(dg->node_group_sysfs[i].node_kobj);
			dg->node_group_sysfs[i].node_kobj = NULL;
		}
	}
	ret = OS_FREE(dg->node_group_sysfs,
		sizeof(struct trace_node_sysfs) * dg->trace_node_cnt);
	dg->node_group_sysfs = NULL;
	dg->trace_node_cnt = 0;

}

ssize_t store_trace_node_cnt(struct kobject *kobj,
			struct kobj_attribute *attr,
			const char *buf, size_t count)
{
	char *node_cnt;
	int ret = 0;
	int dump;
	struct cve_device_group *dg;

	dg = cve_dg_get();

	node_cnt = (char *)buf;
	node_cnt = strim(node_cnt);

	if (node_cnt == NULL)
		return -EFAULT;

	ret = kstrtoint(node_cnt, 10, &dump);
	if (ret < 0)
		return ret;

	cve_os_log(CVE_LOGLEVEL_DEBUG, "store_trace_node_cnt %d\n", dump);
	if (dg->trace_node_cnt)
		free_old_nodes();

	dg->trace_node_cnt = dump;
	ret = create_kobj_nodes();
	if (ret != dump) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"node count is %d but created kobj return  %d\n",
				dump, ret);
	}
	return count;
}

ssize_t store_jobs(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	char *dump_s;
	int i = 0;
	struct trace_node_sysfs *node;
	int dump;
	int ret;
	u32 index;
	struct cve_device_group *dg;

	dg = cve_dg_get();

	ret = sscanf(kobj->name, "node%u", &index);
	if (ret < 1 || index >= dg->trace_node_cnt) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"falied to get valid node id from %s\n", kobj->name);
		return -EFAULT;
	}
	node = &dg->node_group_sysfs[index];
	while ((dump_s = strsep((char **)&buf, ",")) != NULL) {
		dump_s = strim(dump_s);
		ret = kstrtoint(dump_s, 10, &dump);
		if (ret < 0)
			return -EFAULT;
		node->job_list[i] = dump;
		i++;

	}
	node->job_count = i;
	for (i = 0; i < node->job_count; i++)
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"job_# is: %d\n", node->job_list[i]);
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Job_count is %d", node->job_count);
	return count;
}

static ssize_t set_dump_pmon_status(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	int ret = 0;
	char *enable_dump;
	int dump;
	struct cve_device_group *device_group = cve_dg_get();
	int index;
	bool status_to_set;

	index = get_ice_pmon_index(attr);

	if (index < 0)
		return -EFAULT;

	enable_dump = (char *)buf;
	enable_dump = strim(enable_dump);

	if (enable_dump == NULL)
		return -EFAULT;

	ret = kstrtoint(enable_dump, 10, &dump);
	if (ret < 0)
		return ret;

	status_to_set = (dump <= 0)?false:true;

	if (index == ICE_MMU_PMON_INDEX)
		device_group->dump_ice_mmu_pmon = status_to_set;
	else if (index == ICE_DELPHI_PMON_INDEX)
		device_group->dump_ice_delphi_pmon = status_to_set;

	return count;
}
static int get_ice_id_from_kobj(const char *name, u32 *dev_index)
{
	int ret = 0;

	ret = sscanf(name, "ice%u", dev_index);
	if (ret < 1) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "failed getting ice id %s\n",
						name);
		return -EFAULT;
	}
	if (*dev_index >= NUM_ICE_UNIT) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "wrong ice id %d\n", *dev_index);
		return -EFAULT;
	}

	return ret;
}

static ssize_t read_ice_mmu_pmon(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	int ret = 0;
	int i = 0;
	u32 dev_index;
	struct cve_device *dev;
	struct cve_device_group *device_group = cve_dg_get();

	ret = get_ice_id_from_kobj(kobj->name, &dev_index);
	if (ret < 0)
		return ret;

	dev = cve_device_get(dev_index);
	if (!dev) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "NULL dev pointer\n");
		return -ENODEV;
	}

	if (!dev->dg->dump_ice_mmu_pmon) {
		ret += sprintf((buf + ret),
			"Error:%d Trying to read PMONs without enabling.\n",
			-EPERM);
		return ret;
	}

	ret = cve_os_lock(&device_group->poweroff_dev_list_lock,
			CVE_INTERRUPTIBLE);
	if (ret != 0) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"poweroff_dev_list_lock error\n");

		return ret;
	}
	cve_os_log(CVE_LOGLEVEL_DEBUG, "ICE number %d\n",
						dev_index);
	cve_os_log(CVE_LOGLEVEL_DEBUG, "attr: %s\n",
						attr->attr.name);

	if ((dev->power_state == ICE_POWER_ON) ||
		(dev->power_state == ICE_POWER_OFF_INITIATED)) {

		get_ice_mmu_pmon_regs(dev);
	}
	for (i = 0; i < ICE_MAX_MMU_PMON; i++) {
		ret += sprintf((buf + ret),
			"%s\t:%u\n",
			dev->mmu_pmon[i].pmon_name,
			dev->mmu_pmon[i].pmon_value);
	}

	cve_os_unlock(&device_group->poweroff_dev_list_lock);
	return ret;
}

static ssize_t read_ice_delphi_pmon(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	int ret = 0;
	int i = 0;
	u32 dev_index;
	struct cve_device *dev;
	struct cve_device_group *device_group = cve_dg_get();
	ICE_PMON_DELPHI_GEMM_CNN_STARTUP_COUNTER startup_cnt_reg;
	ICE_PMON_DELPHI_CFG_CREDIT_LATENCY latency_cnt_reg;
	ICE_PMON_DELPHI_OVERFLOW_INDICATION ovr_flow_reg;
	ICE_PMON_DELPHI_DBG_PERF_STATUS_REG_T perf_status_reg;

	ret = get_ice_id_from_kobj(kobj->name, &dev_index);
	if (ret < 0)
		return ret;

	dev = cve_device_get(dev_index);
	if (!dev) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "NULL dev pointer\n");
		return -ENODEV;
	}

	if (!dev->dg->dump_ice_delphi_pmon) {
		ret += sprintf((buf + ret),
			"Error:%d Trying to read PMONs without enabling.\n",
			-EPERM);
		return ret;
	}

	ret = cve_os_lock(&device_group->poweroff_dev_list_lock,
			CVE_INTERRUPTIBLE);
	if (ret != 0) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"poweroff_dev_list_lock error\n");

		return ret;
	}
	cve_os_log(CVE_LOGLEVEL_DEBUG, "ICE number %d\n",
						dev_index);
	cve_os_log(CVE_LOGLEVEL_DEBUG, "attr: %s\n",
						attr->attr.name);

	if ((dev->power_state == ICE_POWER_ON) ||
		(dev->power_state == ICE_POWER_OFF_INITIATED)) {

		get_ice_delphi_pmon_regs(dev);
	}
	for (i = 0; i < ICE_MAX_DELPHI_PMON; i++) {
		if (ice_get_a_step_enable_flag()) {
			if (i >= ICE_MAX_A_STEP_DELPHI_PMON)
				break;
		}
		switch (i) {

		case ICE_DELPHI_PMON_PER_LAYER_CYCLES:
		case ICE_DELPHI_PMON_TOTAL_CYCLES:
		case ICE_DELPHI_PMON_GEMM_COMPUTE_CYCLES:
		case ICE_DELPHI_PMON_GEMM_OUTPUT_WRITE_CYCLES:
		case ICE_DELPHI_PMON_CNN_COMPUTE_CYCLES:
		case ICE_DELPHI_PMON_CNN_OUTPUT_WRITE_CYCLES:

			ret += sprintf((buf + ret),
				"%s\t:%u\n",
				dev->delphi_pmon[i].pmon_name,
				dev->delphi_pmon[i].pmon_value);
		break;

		case ICE_DELPHI_PMON_CYCLES_COUNT_OVERFLOW:
			perf_status_reg.val = dev->delphi_pmon[i].pmon_value;

			ret += sprintf((buf + ret),
				"Per_Layer_Cycles_Overflow\t:%u\nTotal_Cycles_Overflow\t:%u\n",
				perf_status_reg.field.per_lyr_cyc_cnt_saturated,
				perf_status_reg.field.total_cyc_cnt_saturated);
		break;

		case ICE_DELPHI_PMON_GEMM_CNN_STARTUP:
			startup_cnt_reg.val = dev->delphi_pmon[i].pmon_value;
			ret += sprintf((buf + ret),
				"CNN_Startup_Count\t:%u\nGemm_Startup_Count\t:%u\n",
				startup_cnt_reg.field.pe_startup_perf_cnt,
				startup_cnt_reg.field.gemm_startup_perf_cnt);

		break;

		case ICE_DELPHI_PMON_CONFIG_CREDIT_LATENCY:
			latency_cnt_reg.val = dev->delphi_pmon[i].pmon_value;
			ret += sprintf((buf + ret),
				"Credit_Reset_Latency_Count\t:%u\nCfg_Latency_Count\t:%u\n",
				latency_cnt_reg.field.
						credit_reset_latency_perf_cnt,
				latency_cnt_reg.field.cfg_latency_perf_cnt);
		break;

		case ICE_DELPHI_PMON_PERF_COUNTERS_OVR_FLW:
			ovr_flow_reg.val = dev->delphi_pmon[i].pmon_value;
			ret += sprintf((buf + ret),
				"CNN_Startup_Overflow\t:%u\nGemm_Startup_Overflow\t:%u\nGemm_Compute_Overflow\t:%u\nGemm_Teardown_Overflow\t:%u\nCNN_Compute_Overflow\t:%u\nCNN_Teardown_Overflow\t:%u\nCredit_Reset_latency_Overflow\t:%u\nCfg_Latency_Overflow\t:%u\n",
			ovr_flow_reg.field.pe_startup_perf_cnt_ovr_flow,
			ovr_flow_reg.field.gemm_startup_perf_cnt_ovr_flow,
			ovr_flow_reg.field.gemm_compute_perf_cnt_ovr_flow,
			ovr_flow_reg.field.gemm_teardown_perf_cnt_ovr_flow,
			ovr_flow_reg.field.pe_compute_perf_cnt_ovr_flow,
			ovr_flow_reg.field.pe_teardown_perf_cnt_ovr_flow,
			ovr_flow_reg.field.
				credit_reset_latency_perf_cnt_ovr_flow,
			ovr_flow_reg.field.cfg_latency_perf_cnt_ovr_flow);
		break;

		default:
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"read_ice_delphi_pmon index error\n");
		}
	}

	cve_os_unlock(&device_group->poweroff_dev_list_lock);
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
	u32 node_index;
	int ret = 0;
	struct cve_device *ice_dev;
	struct cve_device_group *dg;
	struct trace_node_sysfs *node;

	dg = cve_dg_get();

	ret = sscanf(kobj->name, "ice%u", &dev_index);
	if (ret < 1) {
		ret = sscanf(kobj->name, "node%u", &node_index);
		if (ret < 1 || node_index >= dg->trace_node_cnt) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"failed to get valid ice/node id form %s\n",
					kobj->name);
			return -EFAULT;
		}
		goto node_pmon;
	}
	if (dev_index >= NUM_ICE_UNIT) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "wrong ice id %d\n", dev_index);
		return -EFAULT;
	}

	ice_dev = cve_device_get(dev_index);
	if (!ice_dev) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "NULL ice_dev pointer\n");
		return -ENODEV;
	}

	ice_dev->daemon.conf.daemon_table_len = 0; /* a new deamon table */
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
								ice_dev);
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

node_pmon:
	node = &dg->node_group_sysfs[node_index];
	node->job.daemon.conf.daemon_table_len = 0; /* a new deamon table */
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
		ret = ice_trace_pmon_config_sysfs_node(daemonfreq, pmonindex,
								node_index);
		cve_os_unlock(&g_cve_driver_biglock);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR, "pmon config failed\n");
			return ret;
		}
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
				cfg_default.bar0_mem_icepe_offset);

	/* If Device is ON */
	if ((value & pe_mask) != pe_mask) {
		if (ice_dev->daemon.is_default_config) {
			ice_dev->daemon.daemon_config_status =
				TRACE_STATUS_DEFAULT;
			cve_os_log(CVE_LOGLEVEL_INFO,
				"Ice is already powered off, no need of expilict Reg write for reset\n");
		} else {
			cve_os_log(CVE_LOGLEVEL_INFO,
				"ICE-%d not Powered ON, Reg write not done\n",
					ice_dev->dev_index);
		}
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
	reg_offset = cfg_default.ice_sem_base +
			cfg_default.ice_sem_mmio_demon_control_offset;
	cve_os_write_mmio_32(ice_dev,
				reg_offset,
				ice_dev->daemon.conf.daemon_control);

	reg_offset_table = cfg_default.ice_sem_base +
			cfg_default.ice_sem_mmio_demon_table_offset;
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

	reg_offset = cfg_default.ice_sem_base +
			cfg_default.ice_sem_mmio_demon_enable_offset;
	cve_os_write_mmio_32(ice_dev,
				reg_offset,
				ice_dev->daemon.conf.daemon_enable);
	if (ice_dev->daemon.is_default_config)
		ice_dev->daemon.daemon_config_status =
			TRACE_STATUS_DEFAULT;
	else
		ice_dev->daemon.daemon_config_status =
			TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_DONE;

out:
	FUNC_LEAVE();

	return ret;
}

static int  ice_trace_configure_reset_daemon_regs(u32 dev_index)
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
				cfg_default.bar0_mem_icepe_offset);

	/* If Device is ON */
	if ((value & pe_mask) != pe_mask) {
		cve_os_log(CVE_LOGLEVEL_INFO,
				"ICE-%d not Powered ON, Reg write not done\n",
				ice_dev->dev_index);
		goto out;
	}

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
				"daemon control = 0x%x\n",
				ice_dev->daemon.reset_conf.daemon_control);
	reg_offset = cfg_default.ice_sem_base +
			cfg_default.ice_sem_mmio_demon_control_offset;
	cve_os_write_mmio_32(ice_dev,
				reg_offset,
				ice_dev->daemon.reset_conf.daemon_control);

	reg_offset_table = cfg_default.ice_sem_base +
			cfg_default.ice_sem_mmio_demon_table_offset;
	for (i = 0; i < ice_dev->daemon.reset_conf.daemon_table_len; i++) {
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
					"daemon table[%d] = 0x%x\n", i,
				    ice_dev->daemon.reset_conf.daemon_table[i]);
		cve_os_write_mmio_32(ice_dev,
					(reg_offset_table + i * 4),
				    ice_dev->daemon.reset_conf.daemon_table[i]);
	}

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
					"daemon enable = 0x%x\n",
				      ice_dev->daemon.reset_conf.daemon_enable);

	reg_offset = cfg_default.ice_sem_base +
			cfg_default.ice_sem_mmio_demon_enable_offset;
	cve_os_write_mmio_32(ice_dev,
				reg_offset,
				ice_dev->daemon.reset_conf.daemon_enable);
	ice_dev->daemon.daemon_config_status =
				TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_DONE;
out:
	FUNC_LEAVE();

	return ret;
}

static int ice_trace_pmon_config_sysfs_node(u32 daemonfreq, u32 pmonindex,
						u32 node_index)
{
	int ret = 0;
	struct ice_register_reader_daemon *daemon_conf;
	u8 consecutive = 0;
	u32 curr_cfg;
	u8 freqexp = 0;
	u32 daemon_reg_offset;
	struct ice_perf_counter_setup *pmon_config_conf;
	u32 pmon_config_reg_offset = 0;
	u32 pmon_config_value;
	u32 pmon_config_mask = 0;
	bool configure_pmon = true;
	bool perform_reset = false;
	struct cve_device_group *dg;
	struct trace_node_sysfs *node;

	dg = cve_dg_get();
	if (node_index >= dg->trace_node_cnt) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Invalid node id %d", node_index);
		return -EFAULT;
	}
	node = &dg->node_group_sysfs[node_index];

	FUNC_ENTER();
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
			union ice_mmu_inner_mem_mmu_config_t reg;

			pmon_config_reg_offset = cfg_default.mmu_base +
						cfg_default.mmu_cfg_offset;


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

	case 19 ... 26:
		if (!ice_get_a_step_enable_flag()) {
			consecutive = 0;
			configure_pmon = false;
			break;
		}
		break;

	default:
		cve_os_log(CVE_LOGLEVEL_ERROR, "unsupported ipmon index\n");
		ret = -EINVAL;
		goto out;
	}

	daemon_reg_offset = __get_pmon_config_regoffset(pmonindex) &
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
	case 16384:
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
		cve_os_log(CVE_LOGLEVEL_WARNING,
				"Invalid Daemon freq.Default freq 1024 will be set\n");
		break;
	}
	if (perform_reset) {
		int i;

		perform_daemon_reset_node(&node->job);

		/*Perf Counters to default values*/
		/*reset perf counter reg values that are set */
		for (i = 0; i < node->job.perf_counter.perf_counter_config_len;
							i++) {
			node->job.perf_counter.conf[i].counter_value = 0x0;
		}
		node->job.perf_counter.is_default_config = true;

	} else {
		freqexp = 0xf & freqexp;/*only 4 bit b'23:20*/
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"freq exponent %d\n", freqexp);

		daemon_conf = &node->job.daemon.conf;
		/*TODO: check if only certain bit needs to be programmed */
		/*Enable bit 0:0*/
		daemon_conf->daemon_enable = 0x1;
		/*Immediate read disabled bit 2:2 */

		if (daemon_conf->daemon_table_len >= ICE_MAX_DAEMON_TABLE_LEN) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"Daemon table index exceeded max limit\n");
			goto out;

		}
		/* Driver currently doesn't support immediate read */
		daemon_conf->daemon_control = 0x0;
		daemon_conf->daemon_table[daemon_conf->daemon_table_len] =
			(0x80000000 | (consecutive << 24) | freqexp << 20 |
							daemon_reg_offset);
		daemon_conf->daemon_table_len++;
		node->job.daemon.daemon_config_status =
				TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_PENDING;
		node->job.daemon.is_default_config = false;
		/* PMON CONFIG*/
		if (configure_pmon) {
			curr_cfg =
				node->job.perf_counter.perf_counter_config_len;
			if (curr_cfg >= ICE_MAX_PMON_CONFIG) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
					"PMON config len is beyond limit\n");
				ret = -EINVAL;
				goto out;
			}
			pmon_config_conf =
				&node->job.perf_counter.conf[curr_cfg];
			node->job.perf_counter.perf_counter_config_len++;

			pmon_config_conf->register_offset =
						pmon_config_reg_offset;
			pmon_config_conf->counter_value = pmon_config_value;
			pmon_config_conf->counter_config_mask =
							pmon_config_mask;
			node->job.perf_counter.perf_counter_config_status =
				TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_PENDING;
			node->job.perf_counter.is_default_config = false;
		}
	}
out:
	FUNC_LEAVE();
	return ret;
}
static int ice_trace_pmon_config_sysfs(u32 daemonfreq, u32 pmonindex,
						struct cve_device *ice_dev)
{
	int ret = 0;
	struct ice_register_reader_daemon *daemon_conf;
	u8 consecutive = 0;
	u32 curr_cfg;
	u8 freqexp = 0;
	u32 daemon_reg_offset;
	struct ice_perf_counter_setup *pmon_config_conf;
	u32 pmon_config_reg_offset = 0;
	u32 pmon_config_value;
	u32 pmon_config_mask = 0;
	bool configure_pmon = true;
	bool perform_reset = false;

	FUNC_ENTER();
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
			union ice_mmu_inner_mem_mmu_config_t reg;

			pmon_config_reg_offset = cfg_default.mmu_base +
						cfg_default.mmu_cfg_offset;


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

	case 19 ... 26:
		if (!ice_get_a_step_enable_flag()) {
			consecutive = 0;
			configure_pmon = false;
			break;
		}
		break;

	default:
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
						"unsupported ipmon index\n");
		ret = -EINVAL;
		goto out;
	}

	daemon_reg_offset = __get_pmon_config_regoffset(pmonindex) &
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

		perform_daemon_reset(ice_dev);

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

		if (daemon_conf->daemon_table_len >= ICE_MAX_DAEMON_TABLE_LEN) {
			cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"Daemon table index exceeded max limit\n");
			goto out;

		}
		/* Driver currently doesn't support immediate read */
		daemon_conf->daemon_control = 0x0;
		daemon_conf->daemon_table[daemon_conf->daemon_table_len] =
			(0x80000000 | (consecutive << 24) | freqexp << 20 |
							daemon_reg_offset);
		daemon_conf->daemon_table_len++;
		ice_dev->daemon.daemon_config_status =
				TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_PENDING;
		ice_dev->daemon.is_default_config = false;
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
			ice_dev->perf_counter.is_default_config = false;
		}
	}
out:
	FUNC_LEAVE();
	return ret;
}

void perform_daemon_reset(struct cve_device *ice_dev)
{
	/*Daemon reset to default values */
	ice_dev->daemon.conf.daemon_enable = 0; /* Disable */
	ice_dev->daemon.conf.daemon_control = 0;
	ice_dev->daemon.conf.daemon_table_len =
				ICE_MAX_DAEMON_TABLE_LEN;

	memset(ice_dev->daemon.conf.daemon_table, 0,
			 ICE_MAX_DAEMON_TABLE_LEN * sizeof(u32));
	ice_dev->daemon.daemon_config_status =
			TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_PENDING;
	ice_dev->daemon.restore_needed_from_suspend = false;
	ice_dev->daemon.is_default_config = true;
	cve_os_dev_log(CVE_LOGLEVEL_INFO,
				ice_dev->dev_index,
				"Daemon reset configuration\n");
}

void perform_daemon_reset_node(struct hwtrace_job *job)
{
	/*Daemon reset to default values */
	job->daemon.conf.daemon_enable = 0; /* Disable */
	job->daemon.conf.daemon_control = 0;
	job->daemon.conf.daemon_table_len =
				ICE_MAX_DAEMON_TABLE_LEN;

	memset(job->daemon.conf.daemon_table, 0,
			 ICE_MAX_DAEMON_TABLE_LEN * sizeof(u32));
	job->daemon.daemon_config_status =
			TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_PENDING;
	job->daemon.restore_needed_from_suspend = false;
	job->daemon.is_default_config = true;
	cve_os_log(CVE_LOGLEVEL_INFO,
			"Daemon reset configuration(logical ice flow)\n");
}
void perform_daemon_suspend(struct cve_device *ice_dev)
{
	/*Daemon reset to default values */

	ice_dev->daemon.reset_conf.daemon_enable = 0; /* Disable */
	ice_dev->daemon.reset_conf.daemon_control = 0;
	ice_dev->daemon.reset_conf.daemon_table_len =
				ICE_MAX_DAEMON_TABLE_LEN;

	memset(ice_dev->daemon.reset_conf.daemon_table, 0,
			 ICE_MAX_DAEMON_TABLE_LEN * sizeof(u32));
	ice_dev->daemon.daemon_config_status =
			TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_PENDING;
	cve_os_dev_log(CVE_LOGLEVEL_INFO,
				ice_dev->dev_index,
				"Daemon reset configuration\n");
	ice_trace_configure_reset_daemon_regs(ice_dev->dev_index);

	ice_dev->daemon.restore_needed_from_suspend = true;
}

static int ice_trace_dso_sysfs_init(struct cve_device *ice_dev)
{
	int ret;
	/* Create the filter files associated with ice<n> kobject */
	ret = sysfs_create_group(ice_dev->ice_kobj, &filter_attr_group);
	if (ret) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"dso filter sysfs group creation failed\n");
	} else {
		memcpy(ice_dev->dso.reg_readback_vals, default_dso_reg_vals,
					sizeof(default_dso_reg_vals));
	}
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
static int ice_trace_enable_pmon_sysfs_init(void)
{
	int ret;

	/*Create the enable pmon file associated with hwtrace kobject*/
	ret = sysfs_create_group(physical_ice_kobj, &enable_pmon_attr_group);

	if (ret)
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"enable pmon sysfs group creation failed\n");

	return ret;
}

static int ice_trace_read_ice_pmon_sysfs_init(struct cve_device *ice_dev)
{
	int ret;

	/* Create the read pmon files associated with ice<n> kobject */
	ret = sysfs_create_group(ice_dev->ice_kobj, &read_ice_pmon_attr_group);
	if (ret)
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"read pmon sysfs group creation failed\n");

	return ret;
}

static void ice_trace_enable_pmon_sysfs_term(void)
{
	/*Create the enable pmon file associated with hwtrace kobject*/
	sysfs_remove_group(physical_ice_kobj, &enable_pmon_attr_group);
}

static int ice_trace_enable_trace_node_sysfs_init(void)
{
	int ret;

	ret = sysfs_create_group(jobs_kobj, &enable_nodes_attr_group);

	return ret;
}

static void ice_trace_enable_trace_node_sysfs_term(void)
{
	sysfs_remove_group(jobs_kobj, &enable_nodes_attr_group);
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
	if (!icedrv_kobj) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
					"icedrv kobj doesn't exist\n");
		ret = -ENOMEM;
		goto out;
	}

	if (hwtrace_kobj)
		goto ice_sysfs_jobs;

	hwtrace_kobj = kobject_create_and_add("hwtrace", icedrv_kobj);
	if (!hwtrace_kobj) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
					"hwtrace kobj creation failed\n");
		ret = -ENOMEM;
		goto out;
	}
/* TODO: Conditional check for jobs and physical */
ice_sysfs_jobs:
	if (jobs_kobj)
		goto ice_sysfs_physical;

	jobs_kobj = kobject_create_and_add("jobs", hwtrace_kobj);
	if (!jobs_kobj) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"jobs kobj creation failed\n");
		ret = -ENOMEM;
		goto hwtrace_kobj_free;
	}
	ret = ice_trace_enable_trace_node_sysfs_init();
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ice_trace_enable_trace_node_sysfs_init failed\n");
		goto jobs_kobj_free;
	}


ice_sysfs_physical:
	if (physical_ice_kobj)
		goto ice_sysfs;

	physical_ice_kobj = kobject_create_and_add("physical", hwtrace_kobj);
	if (!physical_ice_kobj) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"physical ice kobj creation failed\n");
		ret = -ENOMEM;
		goto enable_trace_node_sysfs_free;
	}
	ret = ice_trace_enable_pmon_sysfs_init();
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ice_trace_enable_pmon_sysfs_init failed\n");

		goto physical_ice_kobj_free;
	}

ice_sysfs:
	ice_dev->ice_kobj = NULL;
	snprintf(name, sizeof(name), "ice%d", ice_dev->dev_index);
	ice_dev->ice_kobj = kobject_create_and_add(name, physical_ice_kobj);
	if (!ice_dev->ice_kobj) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"ice%d kobj creation failed\n",
				ice_dev->dev_index);
		ret = -ENOMEM;
		goto enable_pmon_sysfs_free;
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
	}

	ret = ice_trace_read_ice_pmon_sysfs_init(ice_dev);
	if (ret) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"ice_trace_read_ice_pmon_sysfs_init failed\n");
	}

	goto out;

dso_filter_sysfs_free:
	ice_trace_dso_sysfs_term(ice_dev);
ice_kobj_free:
	kobject_put(ice_dev->ice_kobj);
	ice_dev->ice_kobj = NULL;
enable_pmon_sysfs_free:
	ice_trace_enable_pmon_sysfs_term();
physical_ice_kobj_free:
	kobject_put(physical_ice_kobj);
	physical_ice_kobj = NULL;
enable_trace_node_sysfs_free:
	ice_trace_enable_trace_node_sysfs_term();
jobs_kobj_free:
	kobject_put(jobs_kobj);
	jobs_kobj = NULL;
hwtrace_kobj_free:
	kobject_put(hwtrace_kobj);
	hwtrace_kobj = NULL;
out:
	FUNC_LEAVE();
	return ret;
}

void ice_trace_sysfs_term(struct cve_device *ice_dev)
{
	int i;
	int ret;
	struct cve_device_group *dg;

	dg = cve_dg_get();

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

	if (physical_ice_kobj) {
		kobject_put(physical_ice_kobj);
		physical_ice_kobj = NULL;
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
				"physical kobj deleted\n");
	}

	if (jobs_kobj) {
		kobject_put(jobs_kobj);
		jobs_kobj = NULL;
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
				"jobs kobj deleted\n");
	}
	if (dg->node_group_sysfs)
		for (i = 0; i < dg->trace_node_cnt; i++) {

			if (dg->node_group_sysfs[i].node_kobj) {
				kobject_put(dg->node_group_sysfs[i].node_kobj);
				dg->node_group_sysfs[i].node_kobj = NULL;
			}

	}
	if (dg->node_group_sysfs) {
		ret = OS_FREE(dg->node_group_sysfs,
			sizeof(struct trace_node_sysfs) * dg->trace_node_cnt);
		dg->node_group_sysfs = NULL;
		dg->trace_node_cnt = 0;
	}

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
		goto out;
	}

	port = ice_dev->dso.reg_offsets[dso_reg_index].port;
	croffset = ice_dev->dso.reg_offsets[dso_reg_index].croffset;

	ret = regbar_port_croffset_sanity(ice_dev, port, croffset);

	if (ret) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR,
				ice_dev->dev_index,
				"regbar_port_croffset_sanity() failed\n");
		goto out;
	}
	dso_reg_addr = (port << 16 | croffset) & 0xffffff;

	/* for DSO_CFG_DTF_SRC_CONFIG_REG shouldn't write to 30,31 bits*/
	if (croffset == __get_dso_regoffset(1)
		|| croffset == (__get_dso_regoffset(1) | 0x4000)) {
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
	ice_dev->dso.reg_readback_vals[dso_reg_index] = value;
	/* for DSO_CFG_DTF_SRC_CONFIG_REG ignore
	 *30,31 bits value while reading
	 */
	if (croffset == __get_dso_regoffset(1)
		|| croffset == (__get_dso_regoffset(1) | 0x4000)) {
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

static int ice_trace_set_job_observer_sysfs(u8 dso_reg_index, u32 dso_reg_val,
							u32 node_index)
{
	int ret = 0;
	struct trace_node_sysfs *node_ptr;
	struct cve_device_group *dg;

	dg = cve_dg_get();

	FUNC_ENTER();
	if (node_index >= dg->trace_node_cnt) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Invalid node %d\n", node_index);
		return -EFAULT;
	}
	node_ptr = &dg->node_group_sysfs[node_index];

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"node_index is %d\n", node_index);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"offset:%u USER VALUE %x\n",
			__get_dso_regoffset(dso_reg_index), dso_reg_val);

	node_ptr->job.dso.reg_offsets[dso_reg_index].croffset =
					__get_dso_regoffset(dso_reg_index);

	node_ptr->job.dso.reg_vals[dso_reg_index] = dso_reg_val;
	node_ptr->job.dso.dso_config_status =
				TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_PENDING;

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
	struct cve_device_group *device_group = cve_dg_get();

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
	if (icebo_num >= NUM_ICE_BO) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR,
			ice_dev->dev_index,
				"Invalid ICEBO number\n");
		ret = -EINVAL;
		goto out;
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
				0x4000 | __get_dso_regoffset(dso_reg_index);
	else
		ice_dev->dso.reg_offsets[dso_reg_index].croffset =
					__get_dso_regoffset(dso_reg_index);

	ice_dev->dso.reg_vals[dso_reg_index] = dso_reg_val;
	ice_dev->dso.dso_config_status =
				TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_PENDING;

	ret = cve_os_lock(&device_group->poweroff_dev_list_lock,
			CVE_INTERRUPTIBLE);
	if (ret != 0) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"poweroff_dev_list_lock error\n");

		goto out;
	}

	if (!((ice_dev->power_state == ICE_POWER_ON) ||
		(ice_dev->power_state == ICE_POWER_OFF_INITIATED))) {
		cve_os_log(CVE_LOGLEVEL_INFO,
				"ICE-%d not Powered ON, Reg write not done\n",
				ice_dev->dev_index);
		goto unlock;
	}
	ret = ice_trace_write_dso_reg_sysfs(ice_dev, dso_reg_index);
	if (ret)
		cve_os_dev_log(CVE_LOGLEVEL_ERROR,
					ice_dev->dev_index,
					"ice_trace_write_dso_regs_sysfs() failed\n");

unlock:
	cve_os_unlock(&device_group->poweroff_dev_list_lock);
out:
	FUNC_LEAVE();

	return ret;
}
#endif /* !RING3_VALIDATION*/
void ice_trace_set_default_dso(struct cve_device *ice_dev)
{
	memcpy(ice_dev->dso.reg_vals, default_dso_reg_vals,
						sizeof(default_dso_reg_vals));
	memcpy(ice_dev->dso.reg_readback_vals, default_dso_reg_vals,
						sizeof(default_dso_reg_vals));
}

int ice_trace_init_dso(struct cve_device *ice_dev)
{
	u8 icebo_num;
	u8 i;
	int ret = 0;
	u8 port;

	FUNC_ENTER();
	icebo_num = ice_dev->dev_index / 2;
	if (icebo_num >= NUM_ICE_BO) {
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
					0x4000 | __get_dso_regoffset(i);
		else
			ice_dev->dso.reg_offsets[i].croffset =
						__get_dso_regoffset(i);
	}
	memcpy(ice_dev->dso.reg_vals, default_dso_reg_vals,
						sizeof(default_dso_reg_vals));
	memcpy(ice_dev->dso.reg_readback_vals, default_dso_reg_vals,
						sizeof(default_dso_reg_vals));
out:
	FUNC_LEAVE();
	return ret;
}

int __ice_trace_dso_config_port_regsoffset(struct cve_device *ice_dev)
{
	u8 icebo_num;
	u8 i;
	int ret = 0;
	u8 port;

	FUNC_ENTER();
	icebo_num = ice_dev->dev_index / 2;
	if (icebo_num >= MAX_NUM_ICEBO) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
			"Invalid ICEBO number\n");
		ret = -EINVAL;
		goto out;
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

	for (i = 0; i < MAX_DSO_CONFIG_REG; i++)
		ice_dev->dso.reg_offsets[i].port = port;

	if (ice_dev->dev_index % 2) {
		for (i = 0; i < MAX_DSO_CONFIG_REG; i++) {
			if (ice_dev->dso.reg_offsets[i].croffset) {
				ice_dev->dso.reg_offsets[i].croffset |=
								0x4000;

				cve_os_log(CVE_LOGLEVEL_DEBUG,
				"offset:0x%x,value:0x%x\n",
				ice_dev->dso.reg_offsets[i].croffset,
				ice_dev->dso.reg_vals[i]);
			}
		}
	}

out:
	FUNC_LEAVE();
	return ret;
}
void configure_pmon_names(struct cve_device *dev)
{
	int i = 0;

	for (i = 0; i < ICE_MAX_MMU_PMON; i++)
		dev->mmu_pmon[i].pmon_name =
			ice_pmon_strings[ICE_MMU_PMON_START_INDEX + i - 1];
	for (i = 0; i < ICE_MAX_DELPHI_PMON; i++)
		dev->delphi_pmon[i].pmon_name =
			ice_pmon_strings[ICE_DELPHI_PMON_START_INDEX + i - 1];
}

