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

#include <linux/init.h>
#include <linux/kernel.h>

#include  "cve_device.h"
#include "os_interface.h"
#include "cve_device_group.h"
#include "cve_linux_internal.h"
#include "sph_dvfs.h"


static int sphpb_set_icebo_ring_ratio(struct ice_sphmbox *sphmb, uint16_t value)
{
	union PCODE_MAILBOX_INTERFACE iface;

	iface.InterfaceData = 0;
	iface.BitField.Command = ICEDRV_PCU_MAILBOX_ICE2RING_RATIO_WRITE;

	return write_icedriver_mailbox(sphmb, iface,
				       (uint32_t)value, 0x0,
				       NULL, NULL);
}

static int sphpb_get_icebo_ring_ratio(struct ice_sphmbox *sphmb,
							uint16_t *value)
{
	union PCODE_MAILBOX_INTERFACE iface;
	uint32_t ratio_value;
	int ret;

	iface.InterfaceData = 0;
	iface.BitField.Command = ICEDRV_PCU_MAILBOX_ICE2RING_RATIO_READ;

	ret =  write_icedriver_mailbox(sphmb, iface,
				       0x0, 0x0,
				       &ratio_value, NULL);
	*value = ratio_value;
	return ret;
}

int icedrv_set_icebo_to_ring_ratio(uint16_t value)
{
	int ret;
	struct cve_device_group *dg;
	struct ice_sphmbox *sphmb = NULL;

	dg = cve_dg_get();
	if (!dg) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null dg pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}
	sphmb = &dg->sphmb;
	ret = sphpb_set_icebo_ring_ratio(sphmb, value);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"failure in sphpb_set_icebo_ring_ratio() - %d\n", ret);
	}

	return ret;
}

int icedrv_get_icebo_to_ring_ratio(uint16_t *value)
{
	int ret;
	struct cve_device_group *dg;
	struct ice_sphmbox *sphmb = NULL;

	if (!value) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null ratio value pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}
	dg = cve_dg_get();
	if (!dg) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null dg pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}
	sphmb = &dg->sphmb;
	ret = sphpb_get_icebo_ring_ratio(sphmb, value);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"failure in sphpb_get_icebo_ring_ratio() - %d\n", ret);
	}

	return ret;
}
int icedrv_set_ice_to_ice_ratio(uint32_t icebo, uint32_t value)
{
	cve_os_log(CVE_LOGLEVEL_ERROR, "feature not supported\n");

	return -EINVAL;
}

int icedrv_get_ice_to_ice_ratio(uint32_t icebo, uint32_t *value)
{
	cve_os_log(CVE_LOGLEVEL_ERROR, "feature not supported\n");

	return -EINVAL;
}

static int sphpb_get_icebo_frequency(struct ice_sphmbox *sphmb,
					uint32_t icebo_num, uint32_t *value)
{
	union PCODE_MAILBOX_INTERFACE iface;
	int ret = 0;

	iface.InterfaceData = 0;
	iface.BitField.Command = ICEDRV_PCU_MAILBOX_ICEBO_FREQ_READ;
	/* 0 and 1 indicate 2 IA cores */
	iface.BitField.Param1 = (uint8_t) (icebo_num + ICEBO0_CORE_INDEX);

	ret = write_icedriver_mailbox(sphmb, iface, 0x0, 0x0, value, NULL);

	return ret;
}

int icedrv_get_icebo_frequency(uint32_t icebo_num, uint32_t *freq)
{
	int ret;
	struct cve_device_group *dg;
	struct ice_sphmbox *sphmb = NULL;
	union icedrv_pcu_mailbox_icebo_frequency_read freq_vol;

	if (!freq) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null freq pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}
	dg = cve_dg_get();
	if (!dg) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null dg pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}
	sphmb = &dg->sphmb;
	freq_vol.value = 0;
	ret = sphpb_get_icebo_frequency(sphmb, icebo_num, &freq_vol.value);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"failure in sphpb_get_icebo_frequency() - %d\n", ret);
	}

	*freq = freq_vol.BitField.frequency * ICEBO_FREQ_FACTOR;
	return ret;
}

static int sphpb_set_clock_squash(struct ice_sphmbox *sphmb,
					uint32_t icebo_mask, uint32_t value)
{
	union PCODE_MAILBOX_INTERFACE iface;
	int ret = 0;

	iface.InterfaceData = 0;
	iface.BitField.Command = ICEDRV_PCU_MAILBOX_T_STATE_REQUEST;
	/* bits[1:0] indicate 2 IA cores */
	iface.BitField.Param1 = (uint8_t)icebo_mask << ICEBO0_CORE_INDEX;
	ret = write_icedriver_mailbox(sphmb, iface, value, 0x0, NULL, NULL);

	return ret;
}
#define MAX_TREQ_VAL 15

int icedrv_set_clock_squash(uint32_t icebo_mask, uint8_t t_state_req,
								bool enable)
{
	int ret;
	struct cve_device_group *dg;
	struct ice_sphmbox *sphmb = NULL;
	union icedrv_pcu_mailbox_treq_value treq;

	dg = cve_dg_get();
	if (!dg) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null dg pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}
	sphmb = &dg->sphmb;
	if (t_state_req > MAX_TREQ_VAL) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			" Invalid t_state_req value %d\n", t_state_req);
		return -EINVAL;
	}
	treq.value = 0;
	treq.BitField.tstate_req = t_state_req;
	treq.BitField.throttle_active = (enable == true) ? 1 : 0;
	ret = sphpb_set_clock_squash(sphmb, icebo_mask, treq.value);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"failure in sphpb_set_clock_squash() - %d\n", ret);
	}

	return ret;
}
