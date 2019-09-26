/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "sphcs_net.h"
#include "dma_page_pool.h"

#include "sphcs_cs.h"
#include "sphcs_response_page_pool.h"
#include "ipc_protocol.h"
#include "sph_debug.h"
#include "sph_log.h"
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/version.h>
#include <linux/kmod.h>

struct net_dma_command_data {
	void *vptr;
	struct sk_buff *skb;
	page_handle card_dma_page_hndl;
	page_handle host_dma_page_hndl;
	dma_addr_t card_dma_addr;
	dma_addr_t host_dma_addr;
	u32 xfer_size;
	int host_skb_handle;
};

/*************************************************************************/
/* Handling network over PCI						*/
/*************************************************************************/

static struct net_device *s_net_dev;
static int s_dev_id = -1;
static unsigned char s_mac_addr[ETH_ALEN];

static struct net_device_stats *sphcs_net_dev_get_stats(struct net_device *dev)
{
	return &dev->stats;
}

static int sphcs_net_dev_config(struct net_device *dev, struct ifmap *map)
{
	if (dev->flags & IFF_UP)
		return -EBUSY;
	return 0;
}

static int sphcs_net_dev_change_mtu(struct net_device *dev, int new_mtu)
{
	sph_log_debug(ETH_LOG, "SPH_NET - sphcs_net_dev_change_mtu(%s). new_mtu: %d\n", dev->name, new_mtu);

	if ((new_mtu < 68) || (new_mtu > SPH_PAGE_SIZE - 14))
		return -EINVAL;

	dev->mtu = new_mtu;

	return 0;
}

static int sphcs_net_dev_open(struct net_device *dev)
{
	sph_log_debug(ETH_LOG, "SPH_NET - sphcs_net_dev_open(%s)\n", dev->name);

	netif_start_queue(dev); //start up the transmission queue
	return 0;
}

static int sphcs_net_dev_close(struct net_device *dev)
{
	sph_log_debug(ETH_LOG, "SPH_NET - sphcs_net_dev_close(%s)\n", dev->name);
	netif_stop_queue(dev); //shutdown the transmission queue
	return 0;
}

static int sphcs_net_dev_do_ioctl(struct net_device *dev, struct ifreq *ifr,
		int cmd)
{
	sph_log_debug(ETH_LOG, "SPH_NET - sphcs_net_dev_do_ioctl(%s)\n", dev->name);
	return -1;
}

int sphcs_net_out_msg_dma_complete_callback(struct sphcs *sphcs, void *ctx,
		const void *user_data, int status, u32 xferTimeUS)
{
	void *skb_data;
	u32 skb_size_aligned;
	u32 skb_data_offset;
	struct net_dma_command_data *dma_data = (struct net_dma_command_data *)user_data;
	union c2h_EthernetMsgDscr msg;

	msg.value[0] = 0;
	msg.value[1] = 0;
	msg.opcode = SPH_IPC_C2H_OP_ETH_MSG_DSCR;
	msg.size = dma_data->xfer_size - 1;
	msg.page_handle = dma_data->host_dma_page_hndl;
	msg.dma_addr = dma_data->host_dma_addr;

	sphcs_msg_scheduler_queue_add_msg(g_the_sphcs->net_respq,
					(u64 *)msg.value,
					sizeof(msg) / sizeof(u64));

	skb_data = dma_data->skb;
	skb_data_offset = (uintptr_t)skb_data & 0x7F;
	skb_size_aligned = ALIGN(dma_data->xfer_size+skb_data_offset, 0x80);
	dma_unmap_single(g_the_sphcs->hw_device, dma_data->card_dma_addr, skb_size_aligned, DMA_TO_DEVICE);

	s_net_dev->stats.tx_packets++;
	s_net_dev->stats.tx_bytes += dma_data->xfer_size;

	dev_kfree_skb_any(dma_data->skb);

	return 0;
}

static int sphcs_net_dev_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct net_dma_command_data dma_data;
	dma_addr_t dma_addr;
	dma_addr_t dma_addr_plus_offset;
	void *skb_data = skb->data;
	void *skb_data_aligned;
	u32 skb_size = skb->len;
	u32 skb_size_aligned;
	u32 skb_data_offset;
	int ret = 0;
	page_handle write_host_page_hndl;
	dma_addr_t write_host_page_addr;

	if (skb->len < 1 || skb->len > SPH_PAGE_SIZE) {
		s_net_dev->stats.tx_errors++;
		kfree_skb(skb);
		return 0;
	}

	if (g_the_sphcs == NULL) {
		sph_log_err(ETH_LOG, "SPH_NET - g_the_sphcs is NULL\n");
		s_net_dev->stats.tx_dropped++;
		kfree_skb(skb);
		return 0;
	}

	if (!g_the_sphcs->host_connected) {
		sph_log_err(ETH_LOG, "SPH_NET - host not connected\n");
		s_net_dev->stats.tx_dropped++;
		kfree_skb(skb);
		return 0;
	}


	ret = sphcs_response_pool_get_response_page(SPH_NET_RESPONSE_POOL_INDEX,
					   &write_host_page_addr,
					   &write_host_page_hndl);
	if (ret) {
		s_net_dev->stats.tx_dropped++;
		kfree_skb(skb);
		return 0;
	}

	/* align to cacheline (128 bytes) */
	skb_data_offset = (uintptr_t)skb_data & 0x7F;
	skb_data_aligned = (void *)((uintptr_t)skb_data & ~((uintptr_t)0x7F));
	skb_size_aligned = ALIGN(skb_size+skb_data_offset, 0x80);
	dma_addr = dma_map_single(g_the_sphcs->hw_device, skb_data_aligned, skb_size_aligned, DMA_TO_DEVICE);
	if (dma_mapping_error(g_the_sphcs->hw_device, dma_addr)) {
		sph_log_debug(ETH_LOG, "SPH_NET - Failed to map skb for dma xfer\n");
		s_net_dev->stats.tx_dropped++;
		kfree_skb(skb);
		return 0;
	}

	dma_addr_plus_offset = dma_addr + (dma_addr_t)skb_data_offset;

	dma_data.xfer_size = skb_size;
	dma_data.host_dma_page_hndl = write_host_page_hndl;
	dma_data.host_dma_addr = write_host_page_addr;
	dma_data.card_dma_addr = dma_addr;
	dma_data.skb = skb;

	/* start DMA for transferring the copied packet to host */
	sphcs_dma_sched_start_xfer_single(g_the_sphcs->dmaSched,
					  &g_dma_desc_c2h_normal,
					  dma_addr_plus_offset,
					  write_host_page_addr,
					  dma_data.xfer_size,
					  sphcs_net_out_msg_dma_complete_callback,
					  NULL,
					  &dma_data,
					  sizeof(dma_data));

	return 0;
}

static const struct net_device_ops ndo = {
	.ndo_open = sphcs_net_dev_open,
	.ndo_stop = sphcs_net_dev_close,
	.ndo_start_xmit = sphcs_net_dev_start_xmit,
	.ndo_do_ioctl = sphcs_net_dev_do_ioctl,
	.ndo_get_stats = sphcs_net_dev_get_stats,
	.ndo_set_config = sphcs_net_dev_config,
	.ndo_change_mtu = sphcs_net_dev_change_mtu};

static void sphcs_net_dev_setup(struct net_device *netdev)
{
	sph_log_debug(ETH_LOG, "SPH_NET - sphcs_net_dev_setup(%s)\n", netdev->name);

	memcpy(netdev->dev_addr, s_mac_addr, ETH_ALEN);

	ether_setup(netdev);
	netdev->netdev_ops = &ndo;
}

int sphcs_net_dev_init(void)
{
	sph_log_info(ETH_LOG, "SPH_NET - Loading sph network module:....");

	if (s_net_dev != NULL)
		return -1;

#if KERNEL_VERSION(3, 17, 0) > LINUX_VERSION_CODE  /* SPH_IGNORE_STYLE_CHECK */
	s_net_dev = alloc_netdev(0, "sphcs%d",
					sphcs_net_dev_setup);
#else
	s_net_dev = alloc_netdev(0, "sphcs%d", NET_NAME_UNKNOWN,
					sphcs_net_dev_setup);
#endif

	if (!s_net_dev) {
		sph_log_err(ETH_LOG, "alloc_netdev failed!\n");
		return -1;
	}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)) /* SPH_IGNORE_STYLE_CHECK */
	s_net_dev->max_mtu = SPH_PAGE_SIZE - 14;
#endif
	s_net_dev->mtu = SPH_PAGE_SIZE - 14;

	if (register_netdev(s_net_dev)) {
		sph_log_err(ETH_LOG, "SPH_NET - Failed to register sph net device\n");
		free_netdev(s_net_dev);
		return -1;
	}
	sph_log_info(ETH_LOG, "SPH_NET - Succeeded loading sph network module %s!\n\n",
			dev_name(&s_net_dev->dev));
	return 0;
}

void sphcs_net_dev_exit(void)
{
	sph_log_info(ETH_LOG, "SPH_NET - Unloading sph network module\n\n");
	if (s_net_dev != NULL) {
		unregister_netdev(s_net_dev);
		free_netdev(s_net_dev);
		s_net_dev = NULL;
		memset(s_mac_addr, 0, ETH_ALEN);
		s_dev_id = -1;
	}
}

/*
 * The packet has been retrieved from the transmission
 * medium. Build an skb around it, so upper layers can handle it
 */
static void sphcs_net_dev_rx(struct net_device *netdev, int data_size,
		unsigned char *buf)
{
	struct sk_buff *skb;

	if (netdev == NULL)
		return;

	skb = dev_alloc_skb(data_size + 2);
	if (!skb) {
		netdev->stats.rx_dropped++;
		return;
	}

	memcpy(skb_put(skb, data_size), buf, data_size);

	skb->dev = netdev;
	skb->protocol = eth_type_trans(skb, netdev);

	netdev->stats.rx_packets++;
	netdev->stats.rx_bytes += data_size;

	netif_rx(skb); //pass to the receive level
}

static void sphcs_net_send_ack(struct sphcs *sphcs, const void *user_data)
{
	struct net_dma_command_data *dma_data =
			(struct net_dma_command_data *)user_data;

	// Send a ACK reply to host to free the xmited skb
	union c2h_EthernetMsgDscr msg;

	msg.value[0] = 0;
	msg.value[1] = 0;
	msg.opcode = SPH_IPC_C2H_OP_ETH_MSG_DSCR;
	msg.size = dma_data->xfer_size - 1;
	msg.dma_addr = dma_data->host_dma_addr;
	msg.page_handle = dma_data->host_dma_page_hndl;
	msg.skb_handle = dma_data->host_skb_handle;
	msg.is_ack = 1;

	sphcs_msg_scheduler_queue_add_msg(sphcs->net_respq, msg.value,
				    sizeof(msg) / sizeof(u64));
}

int sphcs_net_in_msg_dma_complete_callback(struct sphcs *sphcs, void *ctx,
		const void *user_data, int status, u32 xferTimeUS)
{
	struct net_dma_command_data *dma_data =
			(struct net_dma_command_data *)user_data;

	sphcs_net_send_ack(sphcs, user_data);

	sphcs_net_dev_rx(s_net_dev, dma_data->xfer_size, dma_data->vptr);

	dma_page_pool_set_page_free(sphcs->net_dma_page_pool,
					dma_data->card_dma_page_hndl);

	return 0;
}

/*
 * called to process a
 * SPH_IPC_H2C_OP_ETH_MSG_DSCR message received from host.
 */
int sphcs_net_process_command(struct sphcs              *sphcs,
			      union h2c_EthernetMsgDscr *req)
{
	struct net_dma_command_data dma_data;
	dma_addr_t dma_addr;
	int ret;

	if (!req->dma_addr) {
		/* This is a protocol error - should not happen! */
		sph_log_err(ETH_LOG, "SPH_NET - Got network packet from host with NULL host dma_addr\n");
		return -1;
	}

	ret = dma_page_pool_get_free_page(sphcs->net_dma_page_pool,
						&dma_data.card_dma_page_hndl,
						&dma_data.vptr, &dma_addr);

	if (ret) {
		sph_log_err(ETH_LOG, "SPH_NET - Failed to get free DMA page\n");
		return ret;
	}

	dma_data.xfer_size = req->size + 1;
	dma_data.host_skb_handle = req->skb_handle;
	dma_data.host_dma_addr = req->dma_addr;

	/* start DMA xfer to bring the packet */
	ret = sphcs_dma_sched_start_xfer_single(sphcs->dmaSched,
						&g_dma_desc_h2c_low,
						dma_data.host_dma_addr,
						dma_addr,
						dma_data.xfer_size,
						sphcs_net_in_msg_dma_complete_callback,
						NULL,
						&dma_data,
						sizeof(dma_data));

	if (ret) {
		sph_log_err(ETH_LOG, "SPH_NET - Failed to start DMA xfer!\n");
		dma_page_pool_set_page_free(sphcs->net_dma_page_pool,
						dma_data.card_dma_page_hndl);
		return ret;
	}

	return 0;
}

struct netmsg_op_work {
	struct work_struct work;
	struct sphcs *sphcs;
	union h2c_EthernetMsgDscr cmd;
};



static void netmsg_op_work_handler(struct work_struct *work)
{
	struct netmsg_op_work
	*op = container_of(work,
			struct netmsg_op_work,
			work);

	if (sphcs_net_process_command(op->sphcs, &(op->cmd)))
		sph_log_info(ETH_LOG, "SPH_NET - Failed process net command\n");

	kfree(op);
}

/*
 * called to handle a
 * SPH_IPC_H2C_OP_ETH_MSG_DSCR message receviced from host.
 */
void IPC_OPCODE_HANDLER(ETH_MSG_DSCR)(struct sphcs              *sphcs,
				      union h2c_EthernetMsgDscr *cmd)
{
	struct netmsg_op_work *work;

	work = kzalloc(sizeof(*work), GFP_NOWAIT);
	if (!work)
		return;

	memcpy(work->cmd.value, cmd->value, sizeof(work->cmd.value));
	work->sphcs = sphcs;
	INIT_WORK(&work->work, netmsg_op_work_handler);
	queue_work(sphcs->wq, &work->work);
}

struct eth_set_ip_op_work {
	struct work_struct work;
	struct sphcs *sphcs;
	union h2c_EthernetConfig cmd;
};

static char *convertIp(char *o_ip_str, uint32_t ip_uint)
{
	uint8_t tmp0 = (ip_uint & 0xFF000000) >> 24;
	uint8_t tmp1 = (ip_uint & 0x00FF0000) >> 16;
	uint8_t tmp2 = (ip_uint & 0x0000FF00) >> 8;
	uint8_t tmp3 = (ip_uint & 0x000000FF);

	sprintf(o_ip_str, "%u.%u.%u.%u", tmp3, tmp2, tmp1, tmp0);

	s_dev_id = tmp0;
	return o_ip_str;
}

static void config_card_eth(struct work_struct *work)
{
	int ret = 0;
	char ip_str[16];
	union c2h_EthernetConfig msg;
	struct eth_set_ip_op_work *op = container_of(work,
						     struct eth_set_ip_op_work,
						     work);

	char *argv[] = {           /* SPH_IGNORE_STYLE_CHECK */
		"/sbin/ifconfig",
		"sphcs0",
		convertIp(ip_str, op->cmd.card_ip),
		NULL
	};

	static char *envp[] = {    /* SPH_IGNORE_STYLE_CHECK */
		"HOME=/",
		"PATH=/bin:/sbin:/usr/bin:/usr/sbin",
		NULL
	};

	if (op->cmd.card_ip == 0) {
		sphcs_net_dev_exit();
		sphcs_response_pool_clean_page_pool(SPH_NET_RESPONSE_POOL_INDEX);
	} else {
		memcpy(s_mac_addr, &op->cmd.value[10], ETH_ALEN);
		ret = sphcs_net_dev_init();
		if (ret == 0) {
			/* start user mode app to send ifconfig command*/
			ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
			if (ret)
				sph_log_err(ETH_LOG, "call_usermodehelper ifconfig failed. ip: %s, ret: %d\n", ip_str, ret);
		}
	}

	msg.value = 0;
	msg.opcode = SPH_IPC_C2H_OP_ETH_CONFIG;
	if (op->cmd.card_ip && ret == 0)
		msg.card_ip = op->cmd.card_ip;

	sphcs_msg_scheduler_queue_add_msg(g_the_sphcs->net_respq,
					  &msg.value,
					  sizeof(msg) / sizeof(u64));

	kfree(op);
}

/*
 * called to handle a
 * SPH_IPC_H2C_OP_ETH_CONFIG message receviced from host.
 */
void IPC_OPCODE_HANDLER(ETH_CONFIG)(struct sphcs              *sphcs,
				      union h2c_EthernetConfig *cmd)
{
	struct eth_set_ip_op_work *work;

	work = kzalloc(sizeof(*work), GFP_NOWAIT);
	if (!work)
		return;

	memcpy(work->cmd.value, cmd->value, sizeof(work->cmd.value));
	work->sphcs = sphcs;
	INIT_WORK(&work->work, config_card_eth);
	queue_work(sphcs->wq, &work->work);
}
