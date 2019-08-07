/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include <linux/uaccess.h>
#include <asm/msr.h>
#include "sph_log.h"
#include "sphcs_power.h"

#ifndef TEMPERATURE_TARGET_MSR
#define TEMPERATURE_TARGET_MSR 0x1A2
#endif

unsigned int s_time_units = 10;
unsigned int s_power_units = 10;
int s_tcc = -1;
int s_interrupt_thresh = -1;

static uint64_t compute_msr_time_window(uint64_t value)
{
	uint64_t x, y;

	//protect do_div
	if (s_time_units == 0) {
		sph_log_err(MAINTENANCE_LOG, "%s: Invalid time units: %u\n", __func__, s_time_units);
		value = 0;
		goto out;
	}

	do_div(value, s_time_units);

	//protect ilog2
	if (value == 0)
		goto out;

	y = ilog2(value);
	x = div64_u64(4 * (value - (1 << y)), 1 << y);

	value = (y & 0x1f) | ((x & 0x3) << 5);

out:
	sph_log_info(MAINTENANCE_LOG, "%s: time units: %d, value: %llu:\n", __func__, s_time_units, value);
	return value;
}

static uint64_t compute_readable_time_window(uint64_t value)
{
	uint64_t x, y;

	x = (value & 0x60) >> 5;
	y = value & 0x1f;
	value = (1ULL << y) * (4 + x) * s_time_units / 4;

	sph_log_info(MAINTENANCE_LOG, "%s: %llu:\n", __func__, value);

	return value;
}

static inline int power_hw_set_ratl(uint32_t time_window_ms, uint32_t max_temp_c)
{
	struct TEMPERATURE_TARGET tt_msr_wr;

	tt_msr_wr.value = 0;

	tt_msr_wr.TCC_OFFSET_CLAMPING_BIT = 1;
	tt_msr_wr.TCC_OFFSET_TIME_WINDOW = time_window_ms;
	tt_msr_wr.TJ_MAX_TCC_OFFSET = s_tcc - max_temp_c;

	sph_log_info(MAINTENANCE_LOG, "Writing TEMPERATURE_TARGET_MSR:\n");
	sph_log_info(MAINTENANCE_LOG, "    CLAMPING_BIT           = %u\n", tt_msr_wr.TCC_OFFSET_CLAMPING_BIT);
	sph_log_info(MAINTENANCE_LOG, "    TCC_OFFSET_TIME_WINDOW = %u\n", tt_msr_wr.TCC_OFFSET_TIME_WINDOW);
	sph_log_info(MAINTENANCE_LOG, "    TJ_MAX_TCC_OFFSET      = %u\n", tt_msr_wr.TJ_MAX_TCC_OFFSET);

	wrmsrl(TEMPERATURE_TARGET_MSR, tt_msr_wr.value);

	return 0;
}

static inline int is_temperature_in_range(uint32_t temperature)
{
	if (s_tcc < 0) {
		sph_log_err(MAINTENANCE_LOG, "sphcs power db is not initialized\n");
		return -EFAULT;
	}

	if (temperature > s_tcc) {
		sph_log_err(MAINTENANCE_LOG, "Throttle average temperature (%u) should not be larger than tcc (%d)\n", temperature, s_tcc);
		return -EINVAL;
	}

	if (temperature < s_tcc - TJ_MAX_TCC_OFFSET_MAX) {
		sph_log_err(MAINTENANCE_LOG, "Throttle average temperature (%u) should be large than (%d)\n", temperature, s_tcc - TJ_MAX_TCC_OFFSET_MAX);
		return -EINVAL;
	}

	return 0;
}

void power_hw_get_ratl(uint32_t *max_avg_temp,
		       uint32_t *time_window_ms,
		       uint8_t  *is_enabled,
		       bool      should_log)
{
	struct TEMPERATURE_TARGET msr;

	rdmsrl(TEMPERATURE_TARGET_MSR, msr.value);

	if (max_avg_temp)
		*max_avg_temp = msr.REF_TEMP - msr.TJ_MAX_TCC_OFFSET;

	if (time_window_ms)
		*time_window_ms = compute_readable_time_window(msr.TCC_OFFSET_TIME_WINDOW);

	if (is_enabled)
		*is_enabled = msr.TCC_OFFSET_CLAMPING_BIT;

	if (should_log) {
		sph_log_debug(MAINTENANCE_LOG, "Read TEMPERATURE_TARGET_MSR:\n");
		sph_log_debug(MAINTENANCE_LOG, "    CLAMPING_BIT           = %d\n", msr.TCC_OFFSET_CLAMPING_BIT);
		sph_log_debug(MAINTENANCE_LOG, "    TCC_OFFSET_TIME_WINDOW = %d (%llu ms)\n", msr.TCC_OFFSET_TIME_WINDOW,
			      compute_readable_time_window(msr.TCC_OFFSET_TIME_WINDOW));
		sph_log_debug(MAINTENANCE_LOG, "    TJ_MAX_TCC_OFFSET      = %d\n", msr.TJ_MAX_TCC_OFFSET);
		sph_log_debug(MAINTENANCE_LOG, "    REF_TEMP               = %d\n", msr.REF_TEMP);
	}
}

int power_handle_get_ratl(void __user *arg)
{
	int ret = 0;
	struct maint_ioctl_ratl req;

	power_hw_get_ratl(&req.max_avg_temp,
			  &req.time_window_ms,
			  &req.is_enabled,
			  true);

	if (copy_to_user(arg, &req, sizeof(req)))
		return -EIO;

	return ret;
}

int power_handle_set_ratl(void __user *arg)
{
	int ret = 0;
	struct maint_ioctl_ratl req;
	struct TEMPERATURE_TARGET msr_TEMPERATURE_TARGET;

	ret = copy_from_user(&req, arg, sizeof(req));
	if (unlikely(ret != 0))
		return -EIO;

	sph_log_debug(MAINTENANCE_LOG, "%s (time=%u ms, temperature=%u)\n", __func__, req.time_window_ms, req.max_avg_temp);

	ret = is_temperature_in_range(req.max_avg_temp);
	if (ret) {
		sph_log_err(MAINTENANCE_LOG, "Failed to set RATL\n");
		req.o_errno = ret;
		goto exit;
	}
	req.time_window_ms = compute_msr_time_window(req.time_window_ms);

	ret = power_hw_set_ratl(req.time_window_ms, req.max_avg_temp);
	if (ret) {
		sph_log_err(MAINTENANCE_LOG, "Failed to set RATL\n");
		req.o_errno = ret;
		goto exit;
	}

	rdmsrl(TEMPERATURE_TARGET_MSR, msr_TEMPERATURE_TARGET.value);

	sph_log_info(MAINTENANCE_LOG, "Reading TEMPERATURE_TARGET_MSR:\n");
	sph_log_info(MAINTENANCE_LOG, "    CLAMPING_BIT           = %u\n", msr_TEMPERATURE_TARGET.TCC_OFFSET_CLAMPING_BIT);
	sph_log_info(MAINTENANCE_LOG, "    TCC_OFFSET_TIME_WINDOW = %u\n", msr_TEMPERATURE_TARGET.TCC_OFFSET_TIME_WINDOW);
	sph_log_info(MAINTENANCE_LOG, "    TJ_MAX_TCC_OFFSET      = %u\n", msr_TEMPERATURE_TARGET.TJ_MAX_TCC_OFFSET);


	req.max_avg_temp = msr_TEMPERATURE_TARGET.REF_TEMP - msr_TEMPERATURE_TARGET.TJ_MAX_TCC_OFFSET;
	req.time_window_ms = compute_readable_time_window(msr_TEMPERATURE_TARGET.TCC_OFFSET_TIME_WINDOW);
	req.is_enabled = msr_TEMPERATURE_TARGET.TCC_OFFSET_CLAMPING_BIT;

exit:
	if (copy_to_user(arg, &req, sizeof(req)))
		return -EIO;

	return ret;
}

int power_handle_get_tcc(void __user *arg)
{
	uint32_t out_tcc;

	if (s_tcc < 0) {
		sph_log_err(MAINTENANCE_LOG, "sphcs power db is not initialized\n");
		return -EFAULT;
	}

	out_tcc = s_tcc;

	if (copy_to_user(arg, &out_tcc, sizeof(out_tcc)))
		return -EIO;

	return 0;
}

int power_handle_get_power_info(void __user *arg)
{
	struct PKG_POWER_INFO pkginf;
	struct maint_ioctl_power_info power_info;

	rdmsrl(MSR_PKG_POWER_INFO, pkginf.value);

	power_info.minimum_power = pkginf.MINIMUM_POWER * s_power_units;
	power_info.maximum_power = pkginf.MAXIMUM_POWER * s_power_units;
	power_info.maximum_time_window = compute_readable_time_window(pkginf.MAXIMUM_TIME_WINDOW);

	sph_log_info(GENERAL_LOG, "read PKG_POWER_INFO: value = %llu minimum_power = %u maximum_power = %u maximum_time_window = %u\n",
			pkginf.value, pkginf.MINIMUM_POWER, pkginf.MAXIMUM_POWER, pkginf.MAXIMUM_TIME_WINDOW);
	sph_log_info(MAINTENANCE_LOG, "calculated power info: max %u min %u max window %u\n",
			power_info.maximum_power, power_info.minimum_power, power_info.maximum_time_window);

	if (copy_to_user(arg, &power_info, sizeof(power_info)))
		return -EIO;

	return 0;
}

uint32_t sph_power_get_tdp(void)
{
	struct PKG_POWER_INFO pkginf;
	uint32_t tdp;

	rdmsrl(MSR_PKG_POWER_INFO, pkginf.value);
	tdp = pkginf.THERMAL_SPEC_POWER * s_power_units;

	return tdp;
}

int sph_power_init(void)
{
	struct TEMPERATURE_TARGET msr_T_TARGET;
	struct RAPL_POWER_UNIT    msr_RAPL_PU;

	rdmsrl(TEMPERATURE_TARGET_MSR, msr_T_TARGET.value);
	sph_log_info(MAINTENANCE_LOG, "read MSR TEMPERATURE_TARGET_MSR: %llu REF_TEMP = %u TCC_OFFSET_CLAMPING_BIT = %u\n",
			msr_T_TARGET.value, msr_T_TARGET.REF_TEMP, msr_T_TARGET.TCC_OFFSET_CLAMPING_BIT);
	s_tcc = msr_T_TARGET.REF_TEMP;

	rdmsrl(MSR_RAPL_POWER_UNIT, msr_RAPL_PU.value);
	sph_log_info(MAINTENANCE_LOG, "read MSR_RAPL_POWER_UNIT: %llu TIME_UNITS = %u POWER_UNITS = %u\n",
			msr_RAPL_PU.value,  msr_RAPL_PU.TIME_UNITS, msr_RAPL_PU.POWER_UNITS);
	s_time_units = 1000000 / (1 << msr_RAPL_PU.TIME_UNITS);

	s_power_units = 1000000 / (1 << msr_RAPL_PU.POWER_UNITS);

	sph_log_info(MAINTENANCE_LOG, "time units = %u,  power units = %u\n", s_time_units, s_power_units);

	return 0;
}
