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

#include "icedrv_internal_sw_counter_funcs.h"


/* Create software counter nodes for all the ICEs allocated to the given NTW */
void ice_swc_create_infer_device_node(struct ice_network *ntw)
{
#ifndef RING3_VALIDATION
	struct cve_device *dev_head, *dev_next;
	int ret = 0;

	dev_head = ntw->ice_list;
	dev_next = dev_head;
	do {
		ret = ice_swc_create_node(ICEDRV_SWC_CLASS_INFER_DEVICE,
				dev_next->dev_index,
				ntw->network_id,
				&dev_next->hswc_infer);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"NtwID:0x%llx Unable to create SW Counter's Infer Device node:%d\n",
					ntw->network_id, dev_next->dev_index);
		}
		dev_next = cve_dle_next(dev_next, owner_list);
	} while (dev_head != dev_next);
#endif
}

/* Destroy software counter nodes for all the ICEs allocated to the given NTW */
void ice_swc_destroy_infer_device_node(struct ice_network *ntw)
{
#ifndef RING3_VALIDATION
	struct cve_device *dev_head, *dev_next;
	int ret = 0;

	dev_head = ntw->ice_list;
	dev_next = dev_head;
	do {
		if (dev_next->hswc_infer) {
			ret = ice_swc_destroy_node(
					ICEDRV_SWC_CLASS_INFER_DEVICE,
					dev_next->dev_index);
			if (ret < 0) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
				"NtwID:0x%llx Unable to destroy SW Counter's Infer Device node:%d\n",
				ntw->network_id, dev_next->dev_index);
			}
		}
		dev_next->hswc_infer = NULL;
		dev_next = cve_dle_next(dev_next, owner_list);
	} while (dev_head != dev_next);
#endif
}
