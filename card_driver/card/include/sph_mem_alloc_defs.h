/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#define ECC_PROTECTED_HEAP_NAME "ecc_protected_heap"
#define ECC_NON_PROTECTED_HEAP_NAME "ecc_non_protected_heap"
#define P2P_HEAP_NAME "p2p_heap"

#pragma pack(push, 1)

union sph_mem_protected_buff_attr {
	struct {
		unsigned long long context_id_valid :  1;
		unsigned long long context_id       :  8;   // context id
		unsigned long long uc_ecc_severity  :  2;   // 0==Non-fatal 1==Context-fatal 2==Card-fatal
		unsigned long long reserved         : 53;
	};

	unsigned long long value;
};
#pragma pack(pop)

