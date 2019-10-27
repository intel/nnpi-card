/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#define DEFINE_INT_STAT(name,nb)   \
	struct int_stat_ ## name { \
		u32 len;           \
		struct per_mask {  \
			u32 mask;  \
			u32 count; \
		} elem[1 << (nb)]; \
	} name = {.len = (1 << (nb))}

#define INT_STAT_CLEAR(name)             \
{                                        \
	u32 i;                           \
	for (i = 0; i < name.len; i++) { \
		name.elem[i].mask = 0;   \
		name.elem[i].count = 0;  \
	}                                \
}

#define INT_STAT_INC(name, imask)                        \
{                                                        \
	u32 i;                                           \
	for (i = 0; i < name.len; i++) {                 \
		if (!name.elem[i].count) {               \
			name.elem[i].mask = imask;       \
			name.elem[i].count = 1;          \
			break;                           \
		} else if (name.elem[i].mask == imask) { \
			name.elem[i].count++;            \
			break;                           \
		}                                        \
	}                                                \
}

#define DEFINE_INT_STAT_DEBUGFS(name)                           \
static int int_stats_show_ ## name(struct seq_file *m, void *v) \
{                                                               \
	u32 i;                                                  \
	for (i = 0; i < name.len && name.elem[i].count; i++) {  \
		seq_printf(m, "mask=0x%x count=%d\n",           \
			   name.elem[i].mask,                   \
			   name.elem[i].count);                 \
	}                                                       \
	return 0;                                               \
}                                                               \
static ssize_t int_stats_write_ ## name(struct file *f,         \
					const char __user *buf, \
					size_t             size,\
					loff_t            *off) \
{                                                               \
	if (size < 3 && size > 0) {                             \
		char in;                                        \
		if (!copy_from_user(&in, buf, 1)) {             \
			if (in == '0') {                        \
				INT_STAT_CLEAR(name);           \
			}                                       \
		}                                               \
	}                                                       \
	return size;                                            \
}                                                               \
static int int_stats_open_ ## name(struct inode *inode, struct file *filp)   \
{                                                                            \
	return single_open(filp, int_stats_show_ ## name, inode->i_private); \
}                                                                            \
static const struct file_operations int_stats_fops_ ## name = {              \
	.open		= int_stats_open_ ## name,                           \
	.read		= seq_read,                                          \
	.write          = int_stats_write_ ##name,                           \
	.llseek		= seq_lseek,                                         \
	.release	= single_release,                                    \
}

#define INT_STAT_DEBUGFS_CREATE(name, dir)                                   \
	debugfs_create_file(#name, 0444, dir, NULL, &int_stats_fops_ ## name)

