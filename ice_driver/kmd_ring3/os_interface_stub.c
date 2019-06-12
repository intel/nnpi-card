/*
 * NNP-I Linux Driver
 * Copyright (c) 2017-2019, Intel Corporation.
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


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include "doubly_linked_list.h"
#include "os_interface.h"
#include "device_interface.h"
#include "dispatcher.h"
#include "memory_manager.h"
#include "linux_kernel_mock.h"
#include "driver_interface.h"
#include "cve_linux_internal.h"
#include "cve_driver_utils.h"
#include "coral.h"
#include "coral_memory.h"
#include "cve_context_process.h"
#include "project_settings.h"
#include "ice_debug.h"

#ifdef NULL_DEVICE_RING3
#include "dummy_coral.h"
#endif

#include "ice_trace.h"
#include "ice_debug_event.h"
/* GLOBAL VARIABLES */
#define DEBUG_STR "DEBUG"
#define WARNING_STR "WARNING"
#define INFO_STR "INFO"
#define ERROR_STR "ERROR"

#ifdef IDC_ENABLE

struct cve_os_device *idc_os_device = NULL;
#endif

#ifdef ENABLE_SPH_STEP_B
#define HW_FOLDER "ice_2.9_hw_m0"
#else
#define HW_FOLDER "ice_2.9_hw"
#endif

u32 g_icemask;
u32 disable_embcb;
u32 core_mask;
bool print_debug;
static u32 icemask;

/* log file */
static FILE* pLogStream = NULL;
static uint32_t is_stdout = 0;

/* dynamic debug global */
struct cve_debug_st {
	const char *str;	/* debug env variable name*/
	u32 val;		/* debug configuration value*/
	u32 def_val;		/* debug configuration default value*/
};

/* This variable contains the debug-fs value of debug_wd_en */
u32 enable_wdt_debugfs;
int mem_detect_en;
int enable_llc = 0;

/* cve_debug doesn't contain the default value, but the real value that
 * was read from the env. variable
 */
static struct cve_debug_st cve_debug[] = {
		{"CVE_DRIVER_DEBUG_TENS_EN", 0, 0},
		/*{"CVE_DRIVER_DEBUG_WDT_EN", 0, 1},*/
		{"CVE_DRIVER_DEBUG_WDT_EN", 0, 0},
		{"CVE_DRIVER_DEBUG_DTF_SRC_EN", 0, 0},
		{"CVE_DRIVER_DEBUG_DTF_DST_EN", 0, 0},
		{"CVE_DRIVER_DEBUG_RECOVERY_ENABLE", 0, 1}
};

static pthread_mutex_t m_mutex;

struct task current_task = {NULL};
struct task *current = &current_task;

void * kzalloc(uint32_t size_bytes, int flags) {
	uint32_t * p;
	int retval = OS_ALLOC_ZERO(size_bytes + sizeof(uint32_t), (void**) &p);
	if (retval != 0)
		return NULL;
	*p = size_bytes;
	return p + 1;
}

void kfree(void * p) {
	uint32_t * _p = (uint32_t*) p - 1;
	uint32_t size_bytes = (*_p) + sizeof(uint32_t);
	OS_FREE(_p, size_bytes);
}

void * __get_free_page(int flags) {
	void * p;
	int retval = OS_ALLOC_ZERO(OS_PAGE_SIZE, &p);
	if (retval != 0)
		return NULL;
	return p;
}

void free_page(unsigned long p) {
	OS_FREE((void*) p, OS_PAGE_SIZE);
}


struct timer_desc {
	cve_os_timer_function handler;
	cve_timer_param_t param;
};
static struct timer_desc *m_timer_desc = NULL;

int request_firmware(const struct firmware **fw,
		const char *filename,
		struct device *device){

	struct firmware *_fw;
	struct stat st;
	int retval = 0;
	int fd;
	uint8_t *buf;

	/* allocate fw struct */
	retval = OS_ALLOC_ZERO(sizeof(struct firmware), (void **)&_fw);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "OS_ALLOC_ZERO failed %d\n", retval);
		goto failed_to_alloc_fw;
	}

	/* f]Get file size*/
	stat(filename, &st);
	_fw->size = st.st_size;

	/* allocate data buffer */
	retval = OS_ALLOC_ZERO(_fw->size, (void **)&buf);

	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "OS_ALLOC_ZERO failed %d\n", retval);
		goto failed_to_alloc_data;
	}

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "failed to open file %s\n", filename);
		retval = -errno;
		goto failed_to_open;
	}

	retval = read(fd, buf, _fw->size);
	if (fd == -1) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "failed to read file %s\n", filename);
		retval = -errno;
		goto failed_to_read;
	}
	close(fd);

	_fw->data = buf;
	*fw = _fw;
	return 0;

failed_to_read:
	close(fd);
failed_to_open:
	OS_FREE(buf, _fw->size);
failed_to_alloc_data:
	OS_FREE(_fw, sizeof(struct firmware));
failed_to_alloc_fw:
	*fw = NULL;
	return retval;
}

void release_firmware(const struct firmware *fw) {

	void *p;

	/* The line above is to cast out const qualifier:
	 * kernel kfree receives const void* while user space free, munmap
	 * receives  void*
	 */
	p = (void*)(uintptr_t)fw->data;
	OS_FREE(p, fw->size);

	/* The line above is to cast out const qualifier:
	 * kernel kfree receives const void* while user space free, munmap
	 * receives  void*
	 */
	p = (void*)(uintptr_t)fw;
	OS_FREE(p, sizeof(struct firmware));

}

#ifdef IDC_ENABLE

/*
 * Coral should provide new kind of interrupt handler
 * where dev_id is not present in the argument.
*/
static int cve_interrupt_handler(int irq)
{
	//u32 id = *((u32*)dev_id);
	int do_call_dpc;
	//struct cve_device *dev = cve_device_get(id);

	//cve_os_log(CVE_LOGLEVEL_ERROR, "Got interrupt from cve_id: %d\n", id);
	cve_os_lock(&g_cve_driver_biglock, CVE_NON_INTERRUPTIBLE);
	do_call_dpc = cve_di_interrupt_handler(&idc_os_device->idc_dev);
	cve_os_unlock(&g_cve_driver_biglock);

	if (do_call_dpc) {
		cve_di_interrupt_handler_deferred_proc(&idc_os_device->idc_dev);
	}
	return 0;
}

int ice_os_mutex_init(void)
{
	int retval = pthread_mutex_init(&m_mutex, NULL);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "pthread_mutex_init failed %d\n", retval);
	}

#ifdef _DEBUG
	if(getenv("CVE_DRIVER_PRINT_DEBUG") != NULL) {
		print_debug = true;
	} else {
		print_debug = false;
	}
#else
	print_debug = false;
#endif

	return retval;
}

int cve_os_interface_init(void)
{
	int retval;
	u32 i,j, dev_count = 0;
	u32 devices_nr = g_driver_settings.config->devices_nr;
	u32 icemask_user, icemask_reg, active_ice;
	u32 enable_llc_config_via_axi_reg = 0;
	char *icemask_user_str = NULL;
	char *coral_config = NULL;
	char *coral_mode = NULL;
	char *workspace = getenv("WORKSPACE");
	char *env_llc_config_via_axi_reg;
	struct ice_drv_config param;

	coral_mode = getenv("CORAL_PERF_MODE");
	coral_config = getenv("CORAL_CONFIG");

	if(coral_config == NULL) {
		char coral_default_config[MAX_FILE_NAME_LEN];

		if(workspace == NULL) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"WORKSPACE env variable is not set");
			ASSERT(workspace == NULL);
		}
		snprintf(coral_default_config, sizeof(coral_default_config), "%s%s%s%s", workspace, "/release_artifacts/", HW_FOLDER, "/config");

		if(coral_mode == NULL) {
					strcat(coral_default_config, "/coral.cfg");
			coral_config = coral_default_config;
		} else if (strcmp(coral_mode, xstr(PERF_MODE)) == 0) {
					strcat(coral_default_config, "/coral_perf.cfg");
			coral_config = coral_default_config;
		} else {
					strcat(coral_default_config, "/coral.cfg");
			coral_config = coral_default_config;
		}
	 }

	icemask_user_str = getenv("ICEMASK_USER");
	if (icemask_user_str)
		sscanf(icemask_user_str, "%x", &icemask_user);
	else
		icemask_user = 0x0;

	env_llc_config_via_axi_reg = getenv("enable_llc_config_via_axi_reg");
	if (env_llc_config_via_axi_reg)
		sscanf(env_llc_config_via_axi_reg, "%x", &enable_llc_config_via_axi_reg);

	param.enable_llc_config_via_axi_reg = enable_llc_config_via_axi_reg;
	/* For RING3, space is always set to 0*/
	param.sph_soc = 0;
	/* For RING3, ice_power_off_delay is 1000 ms */
	param.ice_power_off_delay_ms = 1000;
	ice_set_driver_config_param(&param);

	/* Coral does not support random MASK value. It can
	 * only enable N ICEs starting from ICE-0. If ICEMASK_USER
	 * is aligned with this then we initialize Coral with
	 * the exact number of ICEs, else all 12 are initialized
	 */
	devices_nr = __builtin_ctz(icemask_user);
	if (icemask_user != (((u32)0xFFF >> devices_nr) << devices_nr))
		devices_nr = 12;

	cve_os_log(CVE_LOGLEVEL_DEBUG, "Coral config %s\n", coral_config);
	cve_os_log(CVE_LOGLEVEL_DEBUG, "Initializing Coral with %u ICE\n", devices_nr);

	retval = coral_init_multi(coral_config, (ftype_interrupt_handler)&cve_interrupt_handler, devices_nr);
	if(retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "coral_init failed");
		goto out;
	}

	retval = OS_ALLOC_ZERO(sizeof(struct cve_os_device), (void**)&idc_os_device);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "OS_ALLOC_ZERO failed %d\n", retval);
		goto cve_os_device_alloc_failed;
	}
	idc_os_device->dev = NULL;

#ifdef IDC_ENABLE
	u64 *bar1_ptr = NULL;

	bar1_ptr = (u64 *)coral_get_bar1_base();
	if (!bar1_ptr) {
		retval = -1;
		goto out;
	}
	idc_os_device->idc_dev.bar1_base_address = (u64)bar1_ptr;
	cve_os_log(CVE_LOGLEVEL_DEBUG, "coral - bar1 address PA=0x%lx IAVA=0x%x\n",
			idc_os_device->idc_dev.bar1_base_address,
			(uintptr_t)bar1_ptr);
#endif

	icemask_reg = ice_di_get_icemask(&idc_os_device->idc_dev);
	g_icemask = icemask_user | icemask_reg;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"ICEMASK_USER: 0x%x, ICEMASK_REG: 0x%x\n",
		icemask_user, icemask_reg);

	active_ice = (~g_icemask) & VALID_ICE_MASK;
	if (!active_ice) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "No Active ICE\n");
		goto out;
	}

	/* Still not initializing all 12 ICE */
	while (active_ice) {
		i = __builtin_ctz(active_ice);
		CVE_CLEAR_BIT(active_ice, i);

		retval = cve_device_init(&idc_os_device->idc_dev.cve_dev[i], i);
		if (retval != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR, "cve_device_init failed %d\n", retval);
			goto cve_device_init_failed;
		}

		dev_count++;
	}

	//ice_debug_wake_up_event();
	ice_di_activate_driver();

	/* success */
	return 0;

	/*TODO: Cleanup order is wrong */
cve_device_init_failed:
	OS_FREE(idc_os_device, sizeof(struct cve_os_device));
cve_os_device_alloc_failed:
	for(j = 0; j < dev_count; j++) {
		cve_device_clean(&idc_os_device->idc_dev.cve_dev[j]);
	}
	pthread_mutex_destroy(&m_mutex);
out:
	return retval;
}

void ice_os_mutex_cleanup(void)
{
	int ret = pthread_mutex_destroy(&m_mutex);
	if (ret)
		cve_os_log(CVE_LOGLEVEL_ERROR, "Something wrong happened in os_interface_cleanup"
				" - could not destroy mutex ret=%d\n", ret);
}

void cve_os_interface_cleanup(void)
{
	u32 i, active_ice;

	ice_di_deactivate_driver();

	cve_dg_stop_poweroff_thread();

	active_ice = (~icemask) & VALID_ICE_MASK;
	while (active_ice) {
		i = __builtin_ctz(active_ice);
		CVE_CLEAR_BIT(active_ice, i);

		struct cve_device *dev = &idc_os_device->idc_dev.cve_dev[i];
		cve_device_clean(dev);
	}

	OS_FREE(idc_os_device, sizeof(struct cve_os_device));

	cve_os_timer_remove(m_timer_desc);
}

void getnstimeofday(struct timespec *ts) {

	timespec_get(ts, TIME_UTC);
}

#else

static int cve_interrupt_handler(int irq, void *dev_id)
{
	/* We should identify id by reading IDC register */
	u32 id = *((u32*)dev_id);
	int do_call_dpc;
	struct cve_device *dev = cve_device_get(id);

	cve_os_log(CVE_LOGLEVEL_ERROR, "Got interrupt from cve_id: %d\n", id);
	/* TBD
	 * need to remember to get the context from coral
	 * in order to identify which device raised the
	 * interrupt
	 */
	cve_os_lock(&g_cve_driver_biglock, CVE_NON_INTERRUPTIBLE);
	do_call_dpc = cve_di_interrupt_handler(dev);
	cve_os_unlock(&g_cve_driver_biglock);

	if (do_call_dpc) {
		cve_di_interrupt_handler_deferred_proc(dev);
	}
	return 0;
}

int cve_os_interface_init(void)
{
	u32 i,j;
	struct cve_os_device *cve_os_device = NULL;
	u32 devices_nr = g_driver_settings.config->devices_nr;
	char *workspace = getenv("WORKSPACE");
	char coral_default_config[MAX_FILE_NAME_LEN];

	int retval = pthread_mutex_init(&m_mutex, NULL);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "pthread_mutex_init failed %d\n", retval);
		goto out;
	}

	if(workspace == NULL) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"WORKSPACE env variable is not set");
		ASSERT(workspace == NULL);
	}
	strncpy(coral_default_config, workspace, sizeof(coral_default_config));
	strcat(coral_default_config, "/coral.cfg");
	char *coral_config		  = NULL;
	coral_config				= getenv("CORAL_CONFIG");
	if(coral_config == NULL) {
		coral_config = coral_default_config;
	}
	cve_os_log(CVE_LOGLEVEL_DEBUG, "Coral config %s\n", coral_config);

	retval = coral_init_multi(coral_config, (ftype_interrupt_handler)&cve_interrupt_handler, devices_nr);
	if(retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "coral_init failed");
		goto out;
	}

	for(i=0; i<devices_nr; i++) {

		retval = OS_ALLOC_ZERO(sizeof(struct cve_os_device), (void**)&cve_os_device);
		if (retval != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR, "OS_ALLOC_ZERO failed %d\n", retval);
			goto cve_os_device_alloc_failed;
		}

		cve_os_device->dev = NULL;
		retval = cve_device_init(&cve_os_device->cve_dev, i);
		if (retval != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR, "cve_device_init failed %d\n", retval);
			goto cve_device_init_failed;
		}
	}

	/* success */
	return 0;

cve_device_init_failed:
	OS_FREE(cve_os_device, sizeof(struct cve_os_device));
cve_os_device_alloc_failed:
	for(j=0; j<i; j++) {
		struct cve_device *dev = cve_device_get(j);
		if (dev) {
			struct cve_os_device *os_dev = to_cve_os_device(dev);
			cve_device_clean(&os_dev->cve_dev);
			OS_FREE(os_dev, sizeof(struct cve_os_device));
		}
	}
	pthread_mutex_destroy(&m_mutex);
out:
	return retval;
}

void cve_os_interface_cleanup(void)
{
	u32 i;
	u32 devices_nr = g_driver_settings.config->devices_nr;

	for(i=0; i<devices_nr; i++) {
		struct cve_device *dev = cve_device_get(i);
		if (dev) {
			struct cve_os_device *os_dev = to_cve_os_device(dev);
			cve_device_clean(&os_dev->cve_dev);
			OS_FREE(os_dev, sizeof(struct cve_os_device));
		}
	}

	int ret = pthread_mutex_destroy(&m_mutex);
	if (ret)
		cve_os_log(CVE_LOGLEVEL_ERROR, "Something wrong happened in os_interface_cleanup"
				" - could not destroy mutex ret=%d\n", ret);

	cve_os_timer_remove(m_timer_desc);
}

#endif


int cve_os_lock_init(cve_os_lock_t *lock)
{
	pthread_mutex_t *l = (pthread_mutex_t*)lock;
	return pthread_mutex_init(l, NULL);
}

int cve_os_lock(cve_os_lock_t *lock, int is_interruptible)
{
	pthread_mutex_t *l = (pthread_mutex_t*)lock;
	int pthread_mutex_lock_retval = pthread_mutex_lock(l);
	if (pthread_mutex_lock_retval)
		cve_os_log(CVE_LOGLEVEL_ERROR, "Could not obtain lock retval=%d\n", pthread_mutex_lock_retval);
	return pthread_mutex_lock_retval;
}


void cve_os_unlock(cve_os_lock_t *lock)
{
	pthread_mutex_t *l = (pthread_mutex_t*)lock;
	ASSERT(pthread_mutex_unlock(l) == 0);
}

int cve_os_read_user_memory(void *base_address, uint32_t size_bytes, void *kernel_copy)
{
	memcpy(kernel_copy, base_address, size_bytes);
	return 0;
}

int cve_os_write_user_memory(void *base_address, uint32_t size_bytes, void *kernel_copy)
{
	memcpy(base_address, kernel_copy, size_bytes);
	return 0;
}

int __cve_os_malloc_zero(uint32_t size_bytes, void ** out_ptr)
{
	uint32_t sb = round_up_os_pagesize(size_bytes);

	/* the MAP_32BIT is needed for ring3 validation with 64-bits. in ring3 validation the host
	 * virtual addresses are used as the physical addresses in the device page table. since
	 * there are only 36 bits for physical addresses in the page table, it cannot accomodate
	 * for 64-bits virtual addresses */
	void *p = mmap(0, sb, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	if (p == MAP_FAILED) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "mmap failed\n");
		return -ENOMEM;
	}
	memset(p, 0, sb);
	*out_ptr = p;

	return 0;
}

int __cve_os_free(void *base_address, uint32_t size_bytes)
{
	if (base_address) {
		int retval = munmap(base_address, round_up_os_pagesize(size_bytes));
		if (retval != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR, "munmap failed %d base_address=%p size_bytes=%u\n",
					errno, base_address, size_bytes);
			return retval;
		}
	}

	return 0;
}

int atomic_xchg(atomic_t *v, int n)
{
	int r = *v;
	*v = n;
	return r;
}

int atomic_read(const atomic_t *v)
{
	return (int)*v;
}

void atomic_set(atomic_t *v, int i)
{
	*v = i;
}

int atomic_add_return(int i, atomic_t *v)
{
	return __sync_add_and_fetch(v, i);
}

u64 atomic64_xchg(atomic64_t *v, u64 n)
{
	u64 r = *v;
	*v = n;
	return r;
}

u64 atomic64_read(const atomic64_t *v)
{
	return (unsigned long long)*v;
}

void atomic64_set(atomic64_t *v, u64 i)
{
	*v = i;
}

u64 atomic64_add_return(u64 i, atomic64_t *v)
{
	return __sync_add_and_fetch(v, i);
}

int atomic_sub_return(int i, atomic_t *v)
{
	return __sync_sub_and_fetch(v, i);
}

uint64_t cve_os_atomic_increment_64(atomic64_t *n)
{
	return __sync_add_and_fetch(n, 1);
}

/* return the current time stamp */
uint64_t cve_os_get_time_stamp(void)
{
	struct timeval tp;
	int retval = gettimeofday(&tp, NULL);
	assert(retval == 0);

	uint64_t t = tp.tv_usec + 1000000 * tp.tv_sec;
	return t;
}

uint32_t cve_os_get_msec_time_stamp(void)
{
	uint64_t t;

	/* convert from usec to msec */
	t = ((cve_os_get_time_stamp() + 500) / 1000);

	return (uint32_t) t;
}

int cve_open_misc(void)
{
	static uint64_t context_id = 0;

	union
	{
		cve_context_process_id_t context_pid;
		uint64_t handle;
	}u_context_id;
	u_context_id.handle = __sync_add_and_fetch(&context_id, 1);

	/* allocate process context */
	int retval = cve_context_process_create(
			u_context_id.context_pid);
	if (retval == 0) {
		retval = (int)u_context_id.handle;
	}

	return retval;
}

int cve_close_misc(int fd)
{
	cve_context_process_id_t context_pid =
			(cve_context_process_id_t)(uintptr_t)fd;

	int retval = cve_context_process_destroy(context_pid);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_context_process_destroy failed %d\n",
				retval);
	}
#ifdef NULL_DEVICE_RING3
	null_device_fini();
#endif
	if (pLogStream) {
		if(!is_stdout) {
			fclose(pLogStream);
		}
		is_stdout = 0;
		pLogStream = NULL;
	}

	return retval;
}

int cve_ioctl_misc(int fd, int request, struct cve_ioctl_param *param)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	cve_context_process_id_t context_pid =
			(cve_context_process_id_t)(uintptr_t)fd;

	switch(request) {
	case CVE_IOCTL_CREATE_CONTEXT:
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Simulation mode - CVE_IOCTL_CREATE_CONTEXT\n");
		retval = cve_ds_open_context(context_pid,
				(uint64_t *)&param->create_context.out_contextid);
		break;
	case CVE_IOCTL_DESTROY_CONTEXT:
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Simulation mode - CVE_IOCTL_DESTROY_CONTEXT\n");
		retval = cve_ds_close_context(
				context_pid,
				param->destroy_context.contextid);
		break;
	case CVE_IOCTL_CREATE_NETWORK:
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Simulation mode - CVE_IOCTL_CREATE_NETWORK\n");
		retval = cve_ds_handle_create_network(context_pid,
				param->create_network.contextid,
				&param->create_network.network,
				(uint64_t *)&param->create_network.network.network_id);
		break;
	case CVE_IOCTL_DESTROY_NETWORK:
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Simulation mode - CVE_IOCTL_DESTROY_NETWORK\n");
		retval = cve_ds_handle_destroy_network(context_pid,
				param->destroy_network.contextid,
				param->destroy_network.networkid);
		break;
	case CVE_IOCTL_CREATE_INFER:
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Simulation mode - CVE_IOCTL_CREATE_INFER\n");
		retval = cve_ds_handle_create_infer(context_pid,
				param->create_infer.contextid,
				param->create_infer.networkid,
				&param->create_infer.infer,
				(uint64_t *)&param->create_infer.infer.infer_id);
		break;
	case CVE_IOCTL_EXECUTE_INFER:
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Simulation mode - CVE_IOCTL_EXECUTE_INFER\n");
		retval = cve_ds_handle_execute_infer(context_pid,
				param->execute_infer.contextid,
				param->execute_infer.networkid,
				param->execute_infer.inferid,
				param->execute_infer.reserve_resource);
		break;
	case CVE_IOCTL_DESTROY_INFER:
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Simulation mode - CVE_IOCTL_DESTROY_INFER\n");
		retval = cve_ds_handle_destroy_infer(context_pid,
				param->destroy_infer.contextid,
				param->destroy_infer.networkid,
				param->destroy_infer.inferid);
		break;
	case CVE_IOCTL_LOAD_FIRMWARE:
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Simulation mode - CVE_IOCTL_LOAD_FIRMWARE: FW_IAVA=0x%llx, FW_Size=0x%x MAP_IAVA=0x %llx MAP_Size=0x%x \n",
				(uintptr_t)param->load_firmware.fw_image,
				param->load_firmware.fw_image_size_bytes,
				(uintptr_t)param->load_firmware.fw_binmap,
				param->load_firmware.fw_binmap_size_bytes);
		retval = cve_ds_handle_fw_loading(context_pid,
				param->load_firmware.contextid,
				param->load_firmware.fw_image,
				param->load_firmware.fw_binmap,
				param->load_firmware.fw_binmap_size_bytes);
		break;
	case CVE_IOCTL_WAIT_FOR_EVENT:
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Simulation mode - CVE_IOCTL_WAIT_FOR_EVENT\n");
		retval = cve_ds_wait_for_event(
				context_pid,
				&param->get_event);
		break;
	case CVE_IOCTL_GET_VERSION:
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Simulation mode - CVE_IOCTL_GET_VERSION\n");
		retval = cve_ds_get_version(context_pid,
				param->get_version.contextid,
				&param->get_version.out_versions);
		break;
	case ICE_IOCTL_HW_TRACE_CONFIG:
		{
			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"Simulation mode ICE_IOCTL_HW_TRACE_CONFIG\n");
			retval = ice_trace_config(&param->trace_cfg);
		}
		break;
	case CVE_IOCTL_GET_METADATA:
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Simulation mode - CVE_IOCTL_GET_METADATA\n");
		retval = cve_ds_get_metadata(
				&param->get_metadata.icemask);
		break;
	case ICE_IOCTL_WAIT_FOR_DEBUG_EVENT:
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Simulation mode - ICE_IOCTL_WAIT_FOR_DEBUG_EVENT\n");
		retval = ice_debug_wait_for_event(
				&param->get_debug_event);
		break;
	case ICE_IOCTL_DEBUG_CONTROL:
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Simulation mode - ICE_IOCTL_DEBUG_CONTROL\n");
		retval = ice_ds_debug_control(&param->debug_control);
		break;
	default:
		cve_os_log(CVE_LOGLEVEL_ERROR, "Unknown ioctl request (%d) was used\n", request);
		retval = -EINVAL;
		break;
	}
	return retval;
}

int cve_os_init_wait_que(cve_os_wait_que_t *que)
{
	int retval = pthread_cond_init(&que->cond, NULL);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "pthread_cond_init failed %d\n", retval);
		goto out;
	}
	que->mutex = &m_mutex;

	/* success */
	retval = 0;
out:
	return retval;
}


void cve_os_wakeup(cve_os_wait_que_t *que)
{
	int retval = pthread_mutex_lock(que->mutex);
	ASSERT(retval == 0);
	retval = pthread_cond_broadcast(&que->cond);
	ASSERT(retval == 0);
	retval = pthread_mutex_unlock(que->mutex);
	ASSERT(retval == 0);
}

void cve_os_memory_barrier(void)
{
	 __sync_synchronize();
}

int __cve_os_alloc_dma_sg(struct cve_device *cve_dev,
		u32 size_of_elem,
		u32 num_of_elem,
		struct cve_dma_handle *out_dma_handle)
{
	int ret;
	void *tmp;

	/* in ring3 we are not modeling the sgt allocations */
	ret =__cve_os_alloc_dma_contig(cve_dev,
			size_of_elem,
			num_of_elem,
			&tmp,
			out_dma_handle, 1);

	return ret;
}

void *cve_os_vmap_dma_handle(struct cve_dma_handle *dma_handle)
{
	return coral_pa_mem_get_direct_ptr(dma_handle->mem_handle.dma_address,
									0);
}

void cve_os_vunmap_dma_handle(void *vaddr)
{

}

/* Currently not supported */
u32 cve_os_cve_devices_nr(void)
{
	return 0;
}

void __cve_os_free_dma_sg(struct cve_device *cve_dev,
		u32 size,
		struct cve_dma_handle *dma_handle)
{
	/* in ring3 we are not modeling the sgt allocations */
	__cve_os_free_dma_contig(cve_dev,
			size,
			NULL,
			dma_handle, 1);
}

/*
 * This function allocates memory using coral memory allocation apis.
 * */
int __cve_os_alloc_dma_contig(struct cve_device *cve_dev, uint32_t size_of_elem, uint32_t num_of_elem, void **out_vaddr, struct cve_dma_handle * out_dma_handle, int aligned)
{
	uint64_t phy_addr;
	void *ptr;
	size_t  sb;

	/*Check that the size is cache line aligned.*/
	if (num_of_elem > 1 && !IS_ALIGNED(size_of_elem, L1_CACHE_BYTES)) {
		return -EINVAL;
	}
	sb = size_of_elem * num_of_elem;
	phy_addr = coral_pa_mem_allocate_memory(sb, ICE_DEFAULT_PAGE_SZ);
	ptr = coral_pa_mem_get_direct_ptr(phy_addr, sb);
	if (ptr == NULL) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "coral_memory_allocate failed\n");
		return -ENOMEM;
	}
	memset(ptr, 0, sb);
	*out_vaddr = ptr;

	out_dma_handle->mem_type = CVE_MEMORY_TYPE_KERNEL_CONTIG;
	out_dma_handle->mem_handle.dma_address =
			coral_pa_mem_get_phy_addr_for_ptr((void*) *out_vaddr);
	
	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"DMA_CONTIG was allocated. PA=0x%llx\n",
			out_dma_handle->mem_handle.dma_address);

	return 0;
}

void __cve_os_free_dma_contig(struct cve_device *cve_dev, uint32_t size, void *vaddr, struct cve_dma_handle *dma_handle, int aligned)
{
	/*Coral does the free during termination*/
}

int cve_os_dma_copy_from_buffer(struct cve_dma_handle *dma_handle,
		void *buffer,
		u32 size_bytes)
{
	void *host_vaddr = coral_pa_mem_get_direct_ptr(
			      (uint64_t)dma_handle->mem_handle.dma_address, 0);

	memcpy(host_vaddr, buffer, size_bytes);

	return 0;
}

static void timer_handler(int signum)
{
	m_timer_desc->handler(m_timer_desc->param);
}

int cve_os_timer_create(cve_os_timer_function handler, cve_os_timer_t *out_timer)
{
	if (m_timer_desc != NULL) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "timer already initializaed - add support to more timers\n");
		return -EBUSY;
	}

	struct timer_desc *td;
   	int retval = OS_ALLOC_ZERO(sizeof(*td), (void **)&td);
	if (retval != 0) {
		return retval;
	}


	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = timer_handler;
	retval = sigaction(SIGALRM, &sa, NULL);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "sigaction failed %s\n", strerror(errno));
		return -errno;
	}


	td->handler = handler;
	*out_timer = td;
	m_timer_desc = td;
	return 0;
}

int cve_os_timer_set(cve_os_timer_t timer, cve_timer_period_t period, cve_timer_param_t param)
{
	if (timer == NULL || timer != m_timer_desc) {
		return -EINVAL;
	}
	struct itimerval t;
	memset(&t, 0, sizeof(t));
	t.it_value.tv_usec = period;
	m_timer_desc->param = param;

	int retval = setitimer(ITIMER_REAL, &t, NULL);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "setitimer failed <%s>\n", strerror(errno));
		return -errno;
	}
	return 0;
}

void cve_os_timer_remove(cve_os_timer_t timer)
{
	if (timer == NULL || timer != m_timer_desc) {
		return;
	}

	int retval = cve_os_timer_set(timer, 0, 0);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "cve_os_timer_set failed %d\n", retval);
	}
	OS_FREE(m_timer_desc, sizeof(struct timer_desc));
	m_timer_desc = NULL;
	return;
}

static inline uintptr_t PTR_DISTANCE(void *a, void *b)
{
	uintptr_t ua = (uintptr_t)a;
	uintptr_t ub = (uintptr_t)b;
	if (a > b) return ua - ub;
	else return ub - ua;
}

uint32_t cve_os_read_icemask_bar0(struct idc_device *idc_dev, bool force_print)
{
	u32 offset_bytes;
	uint64_t value;

	offset_bytes = IDC_REGS_IDC_MMIO_BAR0_MEM_ICEMASKSTS_MMOFFSET;

	coral_mmio_read_multi_offset(offset_bytes, &value, 0, 0);
	cve_os_log(force_print ? CVE_LOGLEVEL_ERROR : CVE_LOGLEVEL_DEBUG,
		"[MMIO] ICEMASK reg:%s offset:0x%x value:0x%x\n",
		get_idc_regs_str(offset_bytes),
		offset_bytes,
		value);
	return value;
}

uint32_t cve_os_read_idc_mmio_bar_nr(struct cve_device *cve_dev, uint32_t bar_nr, uint32_t offset_bytes, bool force_print)
{
	ASSERT((offset_bytes & ~0x3UL) == offset_bytes );
	uint64_t value;

	coral_mmio_read_multi_offset(offset_bytes, &value, bar_nr, 0);
	cve_os_log(force_print ? CVE_LOGLEVEL_ERROR : CVE_LOGLEVEL_DEBUG,
		"[MMIO] reading reg:%s offset:0x%x value:0x%x\n",
		get_idc_regs_str(offset_bytes),
		offset_bytes,
		value);
	return value;
}

uint32_t cve_os_read_mmio_32_bar_nr(struct cve_device *cve_dev, uint32_t bar_nr, uint32_t offset_bytes, bool force_print)
{
	ASSERT((offset_bytes & ~0x3UL) == offset_bytes );
	uint64_t value;

#ifdef SPH
	coral_mmio_read_multi_offset(offset_bytes, &value, bar_nr, (uint32_t)cve_dev->dev_index);
#else
#ifdef IDC_ENABLE
	coral_mmio_read_multi_offset(ICE_OFFSET(cve_dev->dev_index) + offset_bytes, &value, bar_nr, 0);
#else
	coral_mmio_read_multi_offset(offset_bytes, &value, bar_nr, cve_dev->dev_index);
#endif
#endif
	cve_os_dev_log(force_print ? CVE_LOGLEVEL_ERROR : CVE_LOGLEVEL_DEBUG,
			cve_dev->dev_index,
		"[MMIO] reading reg:%s offset:0x%x value:0x%x\n",
		get_regs_str(offset_bytes),
		offset_bytes,
		value);
	/* This function will always return lower 32 bit values */
	return (uint32_t)value;
}

void cve_os_write_idc_mmio_bar_nr(struct cve_device *cve_dev, uint32_t bar_nr, uint32_t offset_bytes, uint64_t value)
{
	ASSERT((offset_bytes & ~0x3UL) == offset_bytes );

	char status = coral_mmio_write_multi_offset(offset_bytes, value, bar_nr, 0);
	ASSERT(status == 0);
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"[MMIO] writing reg:%s offset:0x%x value:%x\n",
		get_idc_regs_str(offset_bytes),
		offset_bytes,
		value);
}

void cve_os_write_mmio_32_bar_nr(struct cve_device *cve_dev, uint32_t bar_nr, uint32_t offset_bytes, uint32_t value)
{
	/* This function will always write lower 32 bit values */
	ASSERT((offset_bytes & ~0x3UL) == offset_bytes );

#ifdef SPH
	char status = coral_mmio_write_multi_offset(offset_bytes, value, bar_nr, uint32_t)cve_dev->dev_index);
#else
#ifdef IDC_ENABLE
	char status = coral_mmio_write_multi_offset(ICE_OFFSET(cve_dev->dev_index) + offset_bytes, value, bar_nr, 0);
#else
	char status = coral_mmio_write_multi_offset(offset_bytes, value, bar_nr, cve_dev->dev_index);
#endif
#endif
	ASSERT(status == 0);
	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			cve_dev->dev_index,
		"[MMIO] writing reg:%s offset:0x%x value:0x%x\n",
		get_regs_str(offset_bytes),
		offset_bytes,
		value);
}

int cve_os_write_user_memory_64(uint64_t *user_addr, uint64_t val)
{
	*user_addr = val;
	return 0;
}

int cve_os_write_user_memory_32(uint32_t *user_addr, uint32_t val)
{
	*user_addr = val;
	return 0;
}

int cve_os_read_user_memory_64(u64 *user_addr, u64 *val)
{
	*val = *user_addr;
	return 0;
}
void cve_os_pause(void)
{
	asm volatile("rep; nop" ::: "memory");
}

int cve_os_is_kernel_memory(uintptr_t vaddr)
{
	return 1;
}

void cve_os_sync_sg_memory_to_device(struct cve_device *cve_dev,
		struct sg_table *sgt)
{

}

void cve_os_sync_sg_memory_to_host(struct cve_device *cve_dev,
		struct sg_table *sgt)
{
}

void complete(struct completion *c)
{
}

int wait_for_completion_timeout(struct completion *c, int timeout)
{
	return 1;
}

void cve_debug_init (void)
{
	const char* mem_detect_env_val = getenv("CVE_DRIVER_MEMORY_DETECT_ENABLE");
	if (mem_detect_env_val == NULL) {
		mem_detect_en = 0;
	}
	else {
		mem_detect_en = atoi(mem_detect_env_val);
	}
}

u32 cve_debug_get(enum cve_debug_config d_config)
{
	switch (d_config) {
		case DEBUG_TENS_EN:
		case DEBUG_WD_EN:
		case DEBUG_DTF_SRC_EN:
		case DEBUG_DTF_DST_EN:
		case DEBUG_RECOVERY_EN:
		case DEBUG_CONF_NUM:
		{
			const char* cur_debug_val = getenv(cve_debug[d_config].str);
			if (cur_debug_val == NULL){
				cve_debug[d_config].val =
						cve_debug[d_config].def_val;
			}
			else{
				cve_debug[d_config].val = atoi(cur_debug_val);
			}
		}
		break;
		default:
			break;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"debug configuration %s = %d\n"
			,cve_debug[d_config].str,cve_debug[d_config].val);

	return cve_debug[d_config].val;
}

void cve_debug_set(enum cve_debug_config d_config , u32 val)
{
	cve_debug[d_config].val= val;
}

void cve_debug_destroy (void)
{

}

void cve_os_print_user_buffer(void **pages,
		u32 pages_nr,
		void *buffer_addr,
		u32 size_bytes,
		const char *buf_name)
{

	cve_utils_print_buffer(buffer_addr, size_bytes,
			buf_name, buffer_addr);
}

void cve_os_print_kernel_buffer(
		void *buffer_addr,
		u32 size_bytes,
		const char *buf_name)
{

	cve_utils_print_buffer(buffer_addr, size_bytes,
			buf_name, buffer_addr);
}

void cve_os_print_shared_buffer(
		void *buffer_addr,
		u32 size_bytes,
		const char *buf_name)
{

	cve_utils_print_buffer(buffer_addr, size_bytes,
			buf_name, buffer_addr);
}

int cve_sync_sgt_to_llc(struct sg_table *sgt)
{
	return 0;
}

uint32_t get_process_pid(void)
{
	return getpid();
}
