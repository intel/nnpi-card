/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#include <linux/pci.h>
#include <linux/delay.h>
#include "sph_log.h"
#include "sphpb_bios_mailbox.h"


#define MCHBAR_EN BIT_ULL(0)
#define MCHBAR_MASK GENMASK_ULL(38, 16)
#define MCHBAR_SIZE BIT_ULL(16)
#define MCHBAR_LO_OFF 0x48
#ifdef CONFIG_PHYS_ADDR_T_64BIT
#define MCHBAR_HI_OFF (MCHBAR_LO_OFF + 0x4)
#endif

int sphpb_map_bios_mailbox(struct sphpb_pb *sphpb)
{
	return 0;
}

void sphpb_unmap_bios_mailbox(struct sphpb_pb *sphpb)
{
}

int set_sagv_freq(enum BIOS_SAGV_CONFIG_POLICIES qclk,
		  enum BIOS_SAGV_CONFIG_POLICIES psf0)
{
	return 0;
}

int get_imon_sa_calib_config(uint16_t *imon_offset, //fixed point S7.8
			     uint16_t *imon_slope_factor)  //fixed point U1.15
{
	return 0;
}

int set_imon_sa_calib_config(uint16_t imon_offset, //fixed point S7.8
			     uint16_t imon_slope_factor)  //fixed point U1.15
{
	return 0;
}

int get_imon_vccin_calib_config(uint16_t *imon_offset, //fixed point S7.8
				uint16_t *imon_slope)  //fixed point U1.15
{
	return 0;
}

int set_imon_vccin_calib_config(uint16_t imon_offset, //fixed point S7.8
				uint16_t imon_slope)  //fixed point U1.15
{
	return 0;
}
