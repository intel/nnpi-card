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


#ifndef OS_INTERFACE_STUB_H_
#define OS_INTERFACE_STUB_H_

#include <pthread.h>
#include <stdbool.h>
#include <sys/time.h>
#include <stdio.h> /* for snprintf */
#include <stdarg.h>
#include <stdlib.h>

#include "cve_driver_internal_macros.h"
#include "cve_driver.h"

extern bool print_debug;

#define MAX_FILE_NAME_LEN 1024
typedef uint64_t cve_dma_addr_t;

typedef struct {
	pthread_mutex_t * mutex;
	pthread_cond_t cond;
	bool triggered;
} cve_os_wait_que_t;

typedef struct {
	char placeholder[CACHE_LINE_SIZE];
} __attribute__((aligned(CACHE_LINE_SIZE))) cve_os_lock_t;

#define ERESTARTSYS 512
typedef int cve_isr_retval_t;

typedef uint64_t atomic64_t;
typedef int atomic_t;

struct sg_table {
	struct scatterlist *sgl; /* the list */
	unsigned int nents; /* number of mapped entries */
	unsigned int orig_nents; /* original size of list */
};

static inline void udelay(unsigned long usecs)
{
	;
}

#define terminate_thread(device_group) \
	device_group->terminate_thread

#define cve_os_block_interruptible_infinite(que, predicate) \
({ \
	int _r = pthread_mutex_lock((que)->mutex); \
	if (_r == 0) { \
		for(;;) {\
			if (predicate)\
				break;\
			_r = pthread_cond_wait(&(que)->cond, (que)->mutex); \
		}\
	} \
	pthread_mutex_unlock((que)->mutex); \
	-_r;\
})

#define cve_os_printf(level, fmt, ...) _cve_os_printf(level, fmt, ##__VA_ARGS__);

#define cve_os_block_timeout(que, predicate, timeout_msec) \
({ \
        int _r = pthread_mutex_lock((que)->mutex); \
        if (_r == 0) { \
                if (!predicate) { \
                        struct timespec abstime; \
                        struct timeval now; \
                        gettimeofday(&now, NULL); \
                        abstime.tv_sec = now.tv_sec;\
                        long usec = (timeout_msec % 1000) * 1000; \
                        if (now.tv_usec + usec >= 1000000) { \
                                abstime.tv_sec += timeout_msec / 1000 + 1; \
                                abstime.tv_nsec = (now.tv_usec + usec - 1000000)*1000; \
                        } \
                        else {\
                                abstime.tv_sec += timeout_msec / 1000 + 1; \
                                abstime.tv_nsec = (now.tv_usec + usec)*1000; \
                        }; \
                        _r = (timeout_msec > 0) ? pthread_cond_timedwait(&(que)->cond, (que)->mutex, &abstime) : pthread_cond_wait(&(que)->cond, (que)->mutex); \
                } \
        } \
        pthread_mutex_unlock((que)->mutex); \
        /* Adjust return code to this of the Kernel*/ \
        switch (_r) {\
        case 0:\
		_r = 1;\
        	break;\
        case (ETIMEDOUT):\
		_r = 0;\
		break;\
        default:\
        /* This is ugly, but I prefer to be aligned to the Kernel */\
		_r = -ERESTARTSYS;\
        };\
	_r;\
})

#define cve_os_block_interruptible_timeout cve_os_block_timeout
\

#define cve_os_stringify(x) #x

struct bus_type {
	const char *name;
	const char *dev_name;
	struct device *dev_root;
	int (*probe)(struct device *dev);
	int (*remove)(struct device *dev);
	void (*shutdown)(struct device *dev);
	struct iommu_ops *iommu_ops;
};

struct device_private {
	void * driver_data;
};

struct device {
	struct device *parent;
	struct bus_type *bus; /* type of bus device is on */
	struct device_private * p;
};

struct completion {
};

#define DECLARE_COMPLETION(c) struct completion c

void complete(struct completion *c);

int wait_for_completion_timeout(struct completion *c, int timeout);

int ice_os_mutex_init(void);

void ice_os_mutex_cleanup(void);

void getnstimeofday(struct timespec *ts);
uint64_t trace_clock_local(void);
unsigned int jiffies_to_msecs(unsigned long jiffy);

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

struct debugfs_reg32 {
	const char *name;
	unsigned long offset;
};

static inline void pr_debug(const char *fmt, ...)
{
	va_list args;

	if (!print_debug)
		return;

	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);
}

static inline void pr_err(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);
}
static inline void pr_info(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);
}
static inline void pr_warn(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);
}

#endif /* OS_INTERFACE_STUB_H_ */
