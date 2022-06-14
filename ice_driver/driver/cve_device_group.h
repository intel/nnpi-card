/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/


#ifndef CVE_DEVICE_GROUP_H_
#define CVE_DEVICE_GROUP_H_

#include "cve_device.h"

/* Parameters used to convert the timespec values: */
#define NSEC_PER_USEC	1000L
#define USEC_PER_SEC	1000000L
#define NSEC_PER_SEC	1000000000L

#define __local_builtin_popcount(y, ctr) \
do { \
	u32 pos = 0, x = y; \
	ctr = 0; \
	while (x) {\
		pos = __builtin_ctz(x); \
		x = (x >> (pos + 1)); \
		ctr++; \
	}; \
} while (0)

extern struct cve_device_group *g_cve_dev_group_list;

struct ice_drv_config {
	u8 enable_llc_config_via_axi_reg;
	u8 sph_soc;
	int ice_power_off_delay_ms;
	bool enable_sph_b_step;
	bool enable_sph_c_step;
	u8 ice_sch_preemption;
	u8 iccp_throttling;
	u32 initial_iccp_config[3];
};

/*
 * Get a CVE device based on device id.
 * inputs :
 * outputs:
 * returns: device group or NULL if there is no device group with such id
 */
struct cve_device *cve_device_get(u32 dev_index);

/*
 * Get a device group based on dg id.
 * inputs :
 * outputs:
 * returns: device group or NULL if there is no device group with such id
 */
struct cve_device_group *cve_dg_get(void);

/*
 * Create the global list of ICE devices.
 * inputs :
 * outputs:
 * returns: 0 on success, a negative error code on failure
 */
int ice_kmd_create_dg(void);

/*
 * Assign a device to a device group.
 * inputs :
 * cve_os_device *linux_device - the given device
 * outputs:
 * returns: 0 on success, a negative error code on failure
 */
int cve_dg_add_device(struct cve_device *linux_device);

/*
 * Remove a device from device group.
 * inputs :
 * cve_os_device *linux_device - the given device
 * outputs:
 * returns: 0 on success, a negative error code on failure
 */
int cve_dg_remove_device(struct cve_device *linux_device);

/*
 * Destroy all the allocated device groups.
 * inputs :
 * outputs:
 * returns: 0 on success, a negative error code on failure
 */
int ice_kmd_destroy_dg(void);

/*
 * Print device group attributes.
 * inputs :
 * outputs:
 * returns: 0 on success, a negative error code on failure
 */
void cve_dg_print(struct cve_device_group *group);

/*
 * Indicate whether this wq contain any jobs.
 * inputs :
 * context - the given context
 * outputs:
 * returns: 1 iff a workqueue contain submitted jobs.
 */

static inline int
is_workqueue_contain_network(struct cve_workqueue *wq)
{
	return (wq->pntw_list != NULL);
}

/*
 * Starts a separate Kernel thread that powers off ICEs after 1sec.
 * returns: 0 iff success
 */
int cve_dg_start_poweroff_thread(void);

/*
 * Terminates power off thread.
 */
void cve_dg_stop_poweroff_thread(void);

/*
 * Override default driver features
 */
void ice_set_driver_config_param(struct ice_drv_config *param);

/*
 * retrieve default driver configuration parameters
 */
struct ice_drv_config *ice_get_driver_config_param(void);

/* retrieve reference to first ICE in the list */
struct cve_device *ice_get_first_dev(void);

/* retrieve status of driver's axi config parameter */
u8 ice_enable_llc_config_via_axi_reg(void);

/* Check if code is running on real SOC */
u8 ice_is_soc(void);

/* set driver's ice power off delay config parameter */
void ice_set_power_off_delay_param(int time_ms);

/* retrieve status of driver's ice power off delay config parameter */
int ice_get_power_off_delay_param(void);

/* retrieve  a step enable flag */
int ice_get_a_step_enable_flag(void);

/* retrieve  b step enable flag */
int ice_get_b_step_enable_flag(void);

/* retrieve  c step enable flag */
int ice_get_c_step_enable_flag(void);

/* check if b or c step flag set */
int ice_check_b_or_c_step_enable_flag(void);

/* check if user has requested to disable preemption*/
u8 ice_sch_allow_preemption(void);

/*check if user has requested to do non throttling for B step*/
int ice_get_iccp_throttling_flag(void);

/*retrive initial cdyn requested value */
u32 ice_get_initial_cdyn_val(void);

/*retrive reset cdyn requested value */
u32 ice_get_reset_cdyn_val(void);

/*retrive blocked cdyn requested value */
u32 ice_get_blocked_cdyn_val(void);

enum resource_status ice_dg_check_resource_availability(
		struct ice_pnetwork *pntw);
bool ice_dg_can_lazy_capture_ice(struct ice_pnetwork *pntw);
void ice_dg_borrow_this_ice(struct ice_pnetwork *ntw,
		struct cve_device *dev, bool lazy);
void ice_dg_borrow_next_pbo(struct ice_pnetwork *pntw,
		struct cve_device **ice0,
		struct cve_device **ice1);
void ice_dg_borrow_next_dice(struct ice_pnetwork *pntw,
		struct cve_device **ice0);
void ice_dg_reserve_this_ice(struct cve_device *dev);
void ice_dg_release_this_ice(struct cve_device *dev);
void ice_dg_return_this_ice(struct ice_pnetwork *ntw,
		struct cve_device *dev);

int ice_dg_free_fw_mem_cache_nodes(struct ice_fw_mem_cache *fw_mem_cache);
int ice_dg_alloc_fw_mem_cache_nodes(struct ice_fw_mem_cache *fw_mem_cache);

int __ice_dg_check_free_cached_mem(u32 size);
int __ice_dg_get_cached_mem(u32 size, struct cve_dma_handle *dma_handle);
int __ice_dg_put_cached_mem(struct cve_dma_handle *dma_handle);
int __ice_dg_return_cached_mem(struct ice_pnetwork *pntw);
int __ice_dg_find_matching_fw(struct ice_pnetwork *pntw, u8 *md5,
		struct cve_fw_loaded_sections **out_node);

#ifndef RING3_VALIDATION


#define ice_dg_check_free_cached_mem(size) ({ \
	int ret = __ice_dg_check_free_cached_mem(size); \
	ret; \
})

#define ice_dg_get_cached_mem(size, dma_handle) ({ \
	int ret = __ice_dg_get_cached_mem(size, dma_handle); \
	ret; \
})

#define ice_dg_put_cached_mem(dma_handle) ({ \
	int ret = __ice_dg_put_cached_mem(dma_handle); \
	ret; \
})

#define ice_dg_return_cached_mem(pntw) ({ \
	int ret = __ice_dg_return_cached_mem(pntw); \
	ret; \
})

#define ice_dg_find_matching_fw(pntw, md5, out_node) ({ \
	int ret = __ice_dg_find_matching_fw(pntw, md5, out_node); \
	ret; \
})

#else

#define ice_dg_check_free_cached_mem(size) ({ \
	int ret = -1; \
	ret; \
})

#define ice_dg_get_cached_mem(size, dma_handle) ({ \
	int ret = -1; \
	ret; \
})

#define ice_dg_put_cached_mem(dma_handle) ({ \
	int ret = 0; \
	ret; \
})

#define ice_dg_return_cached_mem(pntw) ({ \
	int ret = 0; \
	ret; \
})

#define ice_dg_find_matching_fw(pntw, md5, out_node) ({ \
	int ret = -1; \
	ret; \
})

#endif





#endif /* CVE_DEVICE_GROUP_H_ */
