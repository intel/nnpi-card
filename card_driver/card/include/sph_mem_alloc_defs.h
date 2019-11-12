



/*******************************************************************************
 * INTEL CORPORATION CONFIDENTIAL Copyright(c) 2017-2019 Intel Corporation. All Rights Reserved.
 *
 * The source code contained or described herein and all documents related to the
 * source code ("Material") are owned by Intel Corporation or its suppliers or
 * licensors. Title to the Material remains with Intel Corporation or its suppliers
 * and licensors. The Material contains trade secrets and proprietary and
 * confidential information of Intel or its suppliers and licensors. The Material
 * is protected by worldwide copyright and trade secret laws and treaty provisions.
 * No part of the Material may be used, copied, reproduced, modified, published,
 * uploaded, posted, transmitted, distributed, or disclosed in any way without
 * Intel's prior express written permission.
 *
 * No license under any patent, copyright, trade secret or other intellectual
 * property right is granted to or conferred upon you by disclosure or delivery of
 * the Materials, either expressly, by implication, inducement, estoppel or
 * otherwise. Any license under such intellectual property rights must be express
 * and approved by Intel in writing.
 ********************************************************************************/
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

