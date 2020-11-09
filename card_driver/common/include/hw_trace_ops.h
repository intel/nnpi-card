/*******************************************************************************
 * INTEL CORPORATION CONFIDENTIAL Copyright(c) 2017-2020 Intel Corporation. All Rights Reserved.
 *
 * The source code contained or described herein and all documents related to the
 * source code ("Material") are owned by Intel Corporation or its suppliers or
 * licensors. Title to the Material remains with Intel Corporation or its suppliers
 * and licensors. The Material contains trade secrets and proprietary and
 * confidential information of Intel or its suppliers and licensors. The Material
 * is protected by worldwide copyright and trade secret laws and treaty provisions .
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

#include "hwtrace_proto.h"

#define  HWTRACE_OPS_RT_XML_DUMP_FILE "/tmp/runtime_xml_data.bin"

class hw_trace_ops {
public:
	static void init(void);
	static void deinit(void);

	static int init_npk_from_driver(size_t resource_size, size_t resources_count);
	static int deinit_npk_to_driver(void);
	static int set_node_count(uint32_t node_count);
	static int set_node(ice_mask mask, ice_cnc_filter filter, int ctx_id, int infer_num, int net_id);
	static int set_job_mask(ice_mask mask);
	static int set_filter(ice_mask mask, ice_cnc_filter filter);
	static int set_trace_state(bool bEnable);
	static int get_status(sphHwTraceStatus *status); /* SPH_IGNORE_STYLE_CHECK */
	static int get_pmons(pmon_info **pmons, size_t *count); /* SPH_IGNORE_STYLE_CHECK */
	static int set_pmons(ice_mask mask, pmon_enable *pmons, size_t count, bool bWrite); /* SPH_IGNORE_STYLE_CHECK */
	static bool is_npk_driver_valid(void);
	static void reset_ice_setting(void);
	static void create_sw_channel(void);

	static int set_hw_ports(bool bEnable);
	static int set_ice_observers(bool bEnable);
#ifdef ULT
	static int ult_software_trace(size_t start, size_t count);
#endif //ULT
public:
	static int		s_node_index;
private:
	static int pmon_id_in_range(uint32_t id, uint32_t frequency);
	static bool		s_ice_driver_valid;
	static bool		s_npk_driver_valid;
	static int		s_full_stop_val;
	static int		s_node_count;

	static sphHwTraceStatus	s_status;

	static pmon_info	*s_pmons_array;

	static size_t		s_pmon_array_count;
};

void hwTraceOpsDumpCncData(const void *data, size_t size);
void hwTraceOpsDumpCncDataToSwTrace(const void *data, size_t size);
