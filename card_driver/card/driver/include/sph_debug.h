/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _SPH_KERNEL_DEBUG_H
#define _SPH_KERNEL_DEBUG_H

#define SPH_STATIC_ASSERT(x, s) _Static_assert((x), s)

#ifdef _DEBUG
#define SPH_ASSERT(x)						\
	do {							\
		if (likely(x))					\
			break;					\
		pr_err("SPH ASSERTION FAILED %s: %s: %u: %s\n", \
			__FILE__, __func__, __LINE__, #x);      \
		BUG();                                          \
	} while (0)

#else
#define SPH_ASSERT(x)

#endif //_DEBUG

/* Uncomment to have BUG() on spinlock held for more than 1 sec */
/* #define DEBUG_SPINLOCKS */

#ifdef DEBUG_SPINLOCKS

#define SPH_SPIN_LOCK(x) {                            \
	unsigned long max_jiffies = jiffies + 1*HZ;   \
	while (!spin_trylock(x)) {                    \
		if (time_after(jiffies, max_jiffies)) { \
			BUG();                        \
			max_jiffies = jiffies + 1*HZ; \
		}                                     \
	}                                             \
}

#define SPH_SPIN_LOCK_BH(x) {                         \
	unsigned long max_jiffies = jiffies + 1*HZ;   \
	while (!spin_trylock_bh(x)) {                 \
		if (time_after(jiffies, max_jiffies)) {\
			BUG();                        \
			max_jiffies = jiffies + 1*HZ; \
		}                                     \
	}                                             \
}

#define SPH_SPIN_LOCK_IRQSAVE(x, f) {                 \
	unsigned long max_jiffies = jiffies + 1*HZ;   \
	while (!spin_trylock_irqsave(x, f)) {         \
		if (time_after(jiffies, max_jiffies)) {\
			BUG();                        \
			max_jiffies = jiffies + 1*HZ; \
		}                                     \
	}                                             \
}

#else
#define SPH_SPIN_LOCK(x)            spin_lock(x)
#define SPH_SPIN_LOCK_BH(x)         spin_lock_bh(x)
#define SPH_SPIN_LOCK_IRQSAVE(x, f) spin_lock_irqsave(x, f)
#endif

#define SPH_SPIN_UNLOCK(x)               spin_unlock(x)
#define SPH_SPIN_UNLOCK_BH(x)            spin_unlock_bh(x)
#define SPH_SPIN_UNLOCK_IRQRESTORE(x, f) spin_unlock_irqrestore(x, f)

#endif
