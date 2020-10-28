/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#include "icedrv_internal_sw_counter_funcs.h"

#if (DISBALE_SWC == 0)

static int __create_sub_ntw_node(struct ice_network *ntw);
static int __destroy_sub_ntw_node(struct ice_network *ntw);

static int __get_swc(enum ICEDRV_SWC_CLASS class,
		struct ice_swc_node *swc_node, void **swc)
{
	int ret = 0;

	*swc = NULL;
	ret = ice_swc_check_node(class, swc_node->sw_id,
			swc_node->parent, swc);
	if (ret == 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"SW:%llu Counter not present\n",
				swc_node->sw_id);
		ret = -1;
		goto exit;
	}
exit:
	return ret;
}


static int __get_ctx_swc(enum ICEDRV_SWC_CLASS class,
		struct ds_context *ctx, void **swc)
{
	int ret = 0;
	struct ice_swc_node *swc_node = &ctx->swc_node;
	void *cur_node;

	*swc = NULL;
	ret = ice_swc_check_node(class, swc_node->sw_id, NULL, &cur_node);
	if (ret == 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"CTX:%p SW Counter for SWID:%llu not present\n",
				ctx, swc_node->sw_id);
		ret = -1;
		goto exit;
	}

	*swc = cur_node;
exit:
	return ret;
}

static int __get_sub_ntw_swc(struct ice_network *ntw, void **swc)
{
	return __get_swc(ICEDRV_SWC_CLASS_SUB_NETWORK, &ntw->swc_node, swc);
}

static int __get_full_ntw_swc(struct ice_network *ntw, void **swc)
{
	struct ice_user_full_ntw *user_full_ntw = ntw->pntw->user_full_ntw;
	struct ice_swc_node swc_node;

	swc_node.sw_id = user_full_ntw->sw_id;
	swc_node.parent = user_full_ntw->parent;

	return __get_swc(ICEDRV_SWC_CLASS_NETWORK, &swc_node, swc);
}

int _create_dev_node(struct cve_device *dev)
{
	int ret = 0;
	struct ice_swc_node swc_node;
	void *cur_node, *parent;

	swc_node.sw_id = dev->dev_index;

	ret = ice_swc_check_node(ICEDRV_SWC_CLASS_DEVICE,
			swc_node.sw_id, NULL, &cur_node);
	if (ret > 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ICE:%d SW Counter already present\n",
				dev->dev_index);
		goto exit;
	}
	parent = cur_node;

	if (!parent) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ICE:%d No parent found\n",
				dev->dev_index);
		ret = -1;
		goto exit;
	}

	ret = ice_swc_create_node(ICEDRV_SWC_CLASS_DEVICE,
					dev->dev_index, parent, &dev->hswc);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Unable to create SW Counter's Device node\n");
		goto exit;
	}

	dev->parent = parent;

exit:
	return ret;
}


int _destroy_dev_node(struct cve_device *dev)
{
	int ret = 0;

	ret = ice_swc_destroy_node(ICEDRV_SWC_CLASS_DEVICE,
			dev->parent, dev->dev_index);
	if (ret < 0)
		cve_os_log(CVE_LOGLEVEL_ERROR,
		"FAILED to delete the ICEDRV_SWC_CLASS_DEVICE SW Counter\n");

	return ret;
}


int _create_context_node(struct ds_context *ctx)
{
	int ret = 0;
	struct ice_swc_node *swc_node = &ctx->swc_node;
	void *cur_node, *parent;

	swc_node->parent = NULL;

	ret = ice_swc_check_node(ICEDRV_SWC_CLASS_CONTEXT,
			swc_node->sw_id, NULL, &cur_node);
	if (ret > 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"CTX:%p SW Counter for CTX:%llu already present\n",
				ctx, swc_node->sw_id);
		goto out;
	}
	parent = cur_node;

	if (!parent) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"CTX:%p No parent found\n", ctx);
		goto out;
	}

	ret = ice_swc_create_node(ICEDRV_SWC_CLASS_CONTEXT, swc_node->sw_id,
			parent, &ctx->hswc);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Error:%d CTX:%p Unable to create SW Counter's Context node\n",
				ret, ctx);
		goto out;
	}

	swc_node->parent = parent;

out:
	ice_swc_counter_inc(g_sph_swc_global,
			ICEDRV_SWC_GLOBAL_COUNTER_CTX_TOTAL);
	ice_swc_counter_inc(g_sph_swc_global,
			ICEDRV_SWC_GLOBAL_COUNTER_CTX_CURR);

	return ret;
}


int _destroy_context_node(struct ds_context *ctx)
{
	int ret = 0;
	struct ice_swc_node *swc_node = &ctx->swc_node;

	if (swc_node->parent) {
		ret = ice_swc_destroy_node(ICEDRV_SWC_CLASS_CONTEXT,
				swc_node->parent, swc_node->sw_id);
		if (ret < 0)
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"Error:%d CTX:%p Failed to delete the ICEDRV_SWC_CLASS_CONTEXT SW Counter\n",
					ret, ctx);
	}

	ice_swc_counter_dec(g_sph_swc_global,
			ICEDRV_SWC_GLOBAL_COUNTER_CTX_CURR);
	ice_swc_counter_inc(g_sph_swc_global,
			ICEDRV_SWC_GLOBAL_COUNTER_CTX_DEST);

	return ret;
}

static void __update_full_ntw_info(struct ice_network *ntw,
		struct ice_user_full_ntw *user_full_ntw)
{
		user_full_ntw->total_ice_ntw++;

		ice_swc_counter_inc(user_full_ntw->hswc,
				ICEDRV_SWC_NETWORK_COUNTER_SUB_NTW_CREATED);
		ice_swc_counter_inc(user_full_ntw->hswc,
				ICEDRV_SWC_NETWORK_COUNTER_SUB_NTW_ACTIVE);

}

static int __get_full_ntw_swc_node(struct ice_network *ntw)
{
	int ret = 0;
	struct ice_swc_node *swc_node = &ntw->pntw->swc_node;
	struct ds_context *ctx = ntw->pntw->wq->context;
	struct ice_user_full_ntw *user_full_ntw;

	if (!ctx->hswc) {
		ret = -1;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"NtwID:0x%llx No sw entry for context\n",
				ntw->network_id);
		goto exit;
	}

	if (!ntw->pntw->hswc) {
		ret = -1;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"NtwID:0x%llx No sw entry for parent network\n",
				ntw->network_id);
		goto exit;
	}

	/* lookup if this parent ntw node exsist*/
	user_full_ntw = cve_dle_lookup(ctx->user_full_ntw, list,
			sw_id, swc_node->sw_id);

	if (user_full_ntw)
		__update_full_ntw_info(ntw, user_full_ntw);
	else
		ret = -1;

exit:
	return ret;
}

int _create_pntw_node(struct ice_pnetwork *pntw)
{
	int ret = 0;
	struct ice_swc_node *swc_node = &pntw->swc_node;
	struct ds_context *ctx = pntw->wq->context;
	struct ice_user_full_ntw *user_full_ntw;
	void *parent;

	if (!ctx->hswc) {
		ret = -1;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"PNtwID:0x%llx No sw entry for context\n",
				pntw->pntw_id);
		goto exit;
	}

	ret = __get_ctx_swc(ICEDRV_SWC_CLASS_CONTEXT, ctx, &parent);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"PNtwID:0x%llx No sw entry for context\n",
				pntw->pntw_id);
		goto exit;
	}

	/*If this node doesnt exsit , allocate it*/
	ret = OS_ALLOC_ZERO(sizeof(*user_full_ntw), (void **)&user_full_ntw);
	if (ret < 0)
		goto exit;

	user_full_ntw->sw_id = swc_node->sw_id;

	ret = ice_swc_create_node(ICEDRV_SWC_CLASS_NETWORK,
			user_full_ntw->sw_id, parent, &user_full_ntw->hswc);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Error:%d PNtwID:0x%llx Unable to create SW Counter's Context node\n",
				ret, pntw->pntw_id);
		goto error_create_node;
	}

	pntw->hswc = user_full_ntw->hswc;
	pntw->user_full_ntw = user_full_ntw;
	user_full_ntw->parent = parent;
	ice_swc_counter_inc(ctx->hswc, ICEDRV_SWC_CONTEXT_COUNTER_NTW_TOTAL);
	ice_swc_counter_inc(ctx->hswc, ICEDRV_SWC_CONTEXT_COUNTER_NTW_CURR);

	cve_dle_add_to_list_before(ctx->user_full_ntw, list, user_full_ntw);

	return ret;

error_create_node:
	OS_FREE(user_full_ntw, sizeof(*user_full_ntw));
exit:
	return ret;
}


static int __put_full_ntw_swc_node(struct ice_network *ntw)
{
	struct ice_user_full_ntw *user_full_ntw = ntw->pntw->user_full_ntw;

	if (!user_full_ntw)
		return -1;

	user_full_ntw->total_ice_ntw--;
	ice_swc_counter_inc(user_full_ntw->hswc,
			ICEDRV_SWC_NETWORK_COUNTER_SUB_NTW_DESTROYED);
	ice_swc_counter_dec(user_full_ntw->hswc,
			ICEDRV_SWC_NETWORK_COUNTER_SUB_NTW_ACTIVE);

	return 0;
}

int _destroy_pntw_node(struct ice_pnetwork *pntw)
{
	int ret = 0;
	struct ice_swc_node *swc_node = &pntw->swc_node;
	struct ds_context *ctx = pntw->wq->context;
	struct ice_user_full_ntw *user_full_ntw = pntw->user_full_ntw;

	if (!user_full_ntw)
		goto exit;

	if (user_full_ntw->total_ice_ntw)
		goto exit;

	/* If user count is zero, then delete this node */
	cve_dle_remove_from_list(ctx->user_full_ntw, list,
			pntw->user_full_ntw);

	ice_swc_counter_dec(ctx->hswc, ICEDRV_SWC_CONTEXT_COUNTER_NTW_CURR);
	ice_swc_counter_inc(ctx->hswc, ICEDRV_SWC_CONTEXT_COUNTER_NTW_DEST);
	ret = ice_swc_destroy_node(ICEDRV_SWC_CLASS_NETWORK,
			user_full_ntw->parent,
			swc_node->sw_id);
	if (ret < 0)
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Error:%d CTX:%p Failed to delete the ICEDRV_SWC_CLASS_CONTEXT SW Counter\n",
				ret, ctx);

	OS_FREE(user_full_ntw, sizeof(*user_full_ntw));

exit:
	pntw->user_full_ntw = NULL;
	return ret;
}



static int __create_sub_ntw_node(struct ice_network *ntw)
{
	int ret = 0;
	struct ice_swc_node *swc_node = &ntw->swc_node;
	struct ice_user_full_ntw *user_full_ntw = ntw->pntw->user_full_ntw;
	void *parent;

	if (user_full_ntw) {
		ret = __get_full_ntw_swc(ntw, &parent);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"NtwID:0x%llx No sw entry for network\n",
					ntw->network_id);
			goto out;
		}

		ret = ice_swc_create_node(ICEDRV_SWC_CLASS_SUB_NETWORK,
				swc_node->sw_id, parent, &ntw->hswc);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"Error:%d NtwID:0x%llx Unable to create SW Counter's sub Network node\n",
					ret, ntw->network_id);
			goto out;
		}
		ice_swc_counter_set(ntw->hswc,
				ICEDRV_SWC_SUB_NETWORK_HANDLE,
				ntw->network_id);
		swc_node->parent = parent;

		_create_infer_device_node(ntw);
	}
out:
	return ret;
}

static int __destroy_sub_ntw_node(struct ice_network *ntw)
{
	int ret = 0;
	struct ice_swc_node *swc_node = &ntw->swc_node;

	if (ntw->hswc) {
		_destroy_infer_device_node(ntw);

		ret = ice_swc_destroy_node(ICEDRV_SWC_CLASS_SUB_NETWORK,
				swc_node->parent, swc_node->sw_id);
		if (ret < 0)
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"Error:%d NtwID:0x%llx SWID:%llu Failed to delete the ICEDRV_SWC_CLASS_SUB_NETWORK SW Counter\n",
					ret, ntw->network_id, swc_node->sw_id);
	}

	return ret;
}


int _create_ntw_node(struct ice_network *ntw)
{
	int ret = 0;

	ntw->hswc = NULL;
	ret = __get_full_ntw_swc_node(ntw);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Error:%d NtwID:0x%llx Unable to create SW Counter network  node\n",
				ret, ntw->network_id);
		goto exit;
	}

	ret = __create_sub_ntw_node(ntw);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Error:%d NtwID:0x%llx Unable to create SW Counter network  node\n",
				ret, ntw->network_id);
		goto error_sub_ntw_node;
	}

	return ret;

error_sub_ntw_node:
	__put_full_ntw_swc_node(ntw);
exit:
	return ret;
}

int _destroy_ntw_node(struct ice_network *ntw)
{
	int ret = 0;

	if (ntw->hswc) {
		ret = __destroy_sub_ntw_node(ntw);
		if (ret < 0)
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"Error:%d NtwID:0x%llx Failed in destroy_sub_ntw_node()\n",
					ret, ntw->network_id);

		__put_full_ntw_swc_node(ntw);
	}
	return ret;
}


int _create_infer_node(struct ice_infer *infer)
{
	int ret = 0;
	struct ice_network *ntw = infer->ntw;
	struct ice_swc_node *swc_node = &infer->swc_node;
	void *parent;

	infer->hswc = NULL;

	if (ntw->hswc) {
		ret = __get_sub_ntw_swc(ntw, &parent);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"NtwID:0x%llx No sw entry for context\n",
					ntw->network_id);
			goto out;
		}

		ret = ice_swc_create_node(ICEDRV_SWC_CLASS_INFER,
				swc_node->sw_id, parent, &infer->hswc);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"Error:%d NtwID:0x%llx Infer:%p SWID:%llu Unable to create SW Counter for Inference\n",
					ret, ntw->network_id,
					infer, swc_node->sw_id);
			goto out;
		}

		ice_swc_counter_set(infer->hswc,
				ICEDRV_SWC_INFER_HANDLE, infer->infer_id);

		ice_swc_counter_inc(ntw->hswc,
				ICEDRV_SWC_SUB_NETWORK_COUNTER_INF_CREATED);
		swc_node->parent = parent;
	}
out:
	return ret;
}


int _destroy_infer_node(struct ice_infer *infer)
{
	int ret = 0;
	struct ice_network *ntw = infer->ntw;
	struct ice_swc_node *swc_node = &infer->swc_node;

	if (infer->hswc) {
		ret = ice_swc_destroy_node(ICEDRV_SWC_CLASS_INFER,
				swc_node->parent, swc_node->sw_id);
		if (ret < 0)
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"Error:%d NtwID:0x%llx Infer:%p SWID:%llu Unable to delete SW Counter for Inference\n",
					ret, ntw->network_id, infer,
					swc_node->sw_id);

		ice_swc_counter_inc(ntw->hswc,
				ICEDRV_SWC_SUB_NETWORK_COUNTER_INF_DESTROYED);
	}

	return ret;
}


/* Create software counter nodes for all the ICEs allocated to the given NTW */
void _create_infer_device_node(struct ice_network *ntw)
{
	void *parent;
	int ret = 0;
	u8 count = 0;

	ret = __get_sub_ntw_swc(ntw, &parent);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"NtwID:0x%llx No sw entry for context\n",
				ntw->network_id);
		return;
	}

	ntw->dev_hswc_parent = parent;

	do {
		ret = ice_swc_create_node(ICEDRV_SWC_CLASS_INFER_DEVICE,
				count, parent, &ntw->dev_hswc[count]);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"NtwID:0x%llx Unable to create SW Counter's Infer Device node:%d\n",
					ntw->network_id, count);
		}

		ice_swc_counter_set(ntw->dev_hswc[count],
				ICEDRV_SWC_INFER_DEVICE_COUNTER_ID,
				0xFFFF);
		count++;
	} while (count < ntw->num_ice);
}

/* Destroy software counter nodes for all the ICEs allocated to the given NTW */
void _destroy_infer_device_node(struct ice_network *ntw)
{
	int ret = 0;
	u8 count = 0;

	do {
		if (ntw->dev_hswc[count]) {
			ret = ice_swc_destroy_node(
					ICEDRV_SWC_CLASS_INFER_DEVICE,
					ntw->dev_hswc_parent, count);
			if (ret < 0) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
						"NtwID:0x%llx Unable to destroy SW Counter's Infer Device node:%d\n",
						ntw->network_id, count);
			}
		}
		ntw->dev_hswc[count] = NULL;
		count++;
	} while (count < ntw->num_ice);
}

#endif /* DISBALE_SWC */
