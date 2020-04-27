/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifndef DRIVER_CVE_FW_MAP_INTERFACE_H_
#define DRIVER_CVE_FW_MAP_INTERFACE_H_


/*
 * WARNING: BE CAREFUL WHEN CHANGING THIS STRUCT LAYOUT
 *
 * This struct used for deserializing the binary FW map section.
 * Changes to this struct requires synchronization with the script
 * which generates the binary FW map file.
 *
 * DESCRIPTION - describe a section in a firmware binary
 *
 */
#pragma pack(1)
struct ICVE_FIRMWARE_SECTION_DESCRIPTOR {
	/* FW version
	 * 3*u32 = component version
	 * 3*u32 = product version
	 */
	u32 version[6];
	/* offset in fw binary image file */
	u32 offset_in_file;
	/* the address where the working copy starts
	 * in device virtual address space
	 */
	u32 cve_addr;
	/* size of section in bytes*/
	u32 size_bytes;
	/* permission attributes */
	u32 permissions;
	/* reserved */
	u32 reserved;
};

#pragma pack()


#endif /* DRIVER_CVE_FW_MAP_INTERFACE_H_ */
