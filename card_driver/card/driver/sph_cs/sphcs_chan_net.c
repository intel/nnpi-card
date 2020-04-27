/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "sphcs_chan_net.h"
#include "dma_page_pool.h"

#include "sphcs_cs.h"
#include "nnp_debug.h"
#include "sph_log.h"
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/version.h>
#include <linux/kmod.h>
#include "sphcs_cmd_chan.h"

struct net_dma_command_data {
	void *vptr;
	struct sk_buff *skb;
	struct sphcs_cmd_chan *chan;
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
static struct sphcs_cmd_chan *s_net_cmd_chan;
static int s_dev_id = -1;
static unsigned char s_mac_addr[ETH_ALEN];
static pool_handle   s_net_dma_page_pool;
static int           s_c2h_handles;
static uint8_t      *s_c2h_busy_handles;

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

	if ((new_mtu < 68) || (new_mtu > NNP_PAGE_SIZE - 14))
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

static int sphcs_net_out_msg_dma_complete_callback(struct sphcs *sphcs,
						   void *ctx,
						   const void *user_data,
						   int status,
						   u32 xferTimeUS)
{
	void *skb_data;
	u32 skb_size_aligned;
	u32 skb_data_offset;
	struct net_dma_command_data *dma_data = (struct net_dma_command_data *)user_data;
	union c2h_ChanEthernetMsgDscr msg;

	msg.value = 0;
	msg.opcode = NNP_IPC_C2H_OP_CHAN_ETH_MSG_DSCR;
	msg.chanID = dma_data->chan->protocolID;
	msg.size = dma_data->xfer_size - 1;
	msg.skb_handle = dma_data->host_skb_handle;

	sphcs_msg_scheduler_queue_add_msg(dma_data->chan->respq,
					(u64 *)&msg.value,
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
	int c2h_skb_handle;
	dma_addr_t write_host_dma_addr;
	uint32_t cont;

	if (skb->len < 1 || skb->len > NNP_PAGE_SIZE) {
		s_net_dev->stats.tx_errors++;
		kfree_skb(skb);
		return 0;
	}

	if (g_the_sphcs == NULL || !s_net_cmd_chan) {
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

	/* allocate page in the c2h ring buffer */
	NNP_SPIN_LOCK_BH(&s_net_cmd_chan->c2h_rb[0].lock_bh);
	for (c2h_skb_handle = 0; c2h_skb_handle < s_c2h_handles; c2h_skb_handle++)
		if (!s_c2h_busy_handles[c2h_skb_handle]) {
			s_c2h_busy_handles[c2h_skb_handle] = 1;
			break;
		}
	NNP_SPIN_UNLOCK_BH(&s_net_cmd_chan->c2h_rb[0].lock_bh);

	if (c2h_skb_handle >= s_c2h_handles) {
		sph_log_err(ETH_LOG, "SPH_NET - c2h ringbuffer full\n");
		s_net_dev->stats.tx_dropped++;
		kfree_skb(skb);
		return 0;
	}

	write_host_dma_addr = host_rb_get_addr(&s_net_cmd_chan->c2h_rb[0],
					       c2h_skb_handle * NNP_PAGE_SIZE,
					       &cont);
	if (!write_host_dma_addr || cont < skb_size) {
		s_net_dev->stats.tx_dropped++;
		kfree_skb(skb);
		s_c2h_busy_handles[c2h_skb_handle] = 0;
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
		s_c2h_busy_handles[c2h_skb_handle] = 0;
		return 0;
	}

	dma_addr_plus_offset = dma_addr + (dma_addr_t)skb_data_offset;

	dma_data.xfer_size = skb_size;
	dma_data.host_skb_handle = c2h_skb_handle;
	dma_data.host_dma_addr = write_host_dma_addr;
	dma_data.card_dma_addr = dma_addr;
	dma_data.skb = skb;
	dma_data.chan = s_net_cmd_chan;

	/* start DMA for transferring the copied packet to host */
	sphcs_dma_sched_start_xfer_single(g_the_sphcs->dmaSched,
					  &g_dma_desc_c2h_normal,
					  dma_addr_plus_offset,
					  write_host_dma_addr,
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

static int sphcs_net_dev_init(uint32_t h2c_pages, uint32_t c2h_pages)
{
	int ret;

	sph_log_info(ETH_LOG, "SPH_NET - Loading sph network module:....");

	if (s_net_dev != NULL)
		return -1;

#if KERNEL_VERSION(3, 17, 0) > LINUX_VERSION_CODE  /* SPH_IGNORE_STYLE_CHECK */
	s_net_dev = alloc_netdev(0, "sphcschan%d",
					sphcs_net_dev_setup);
#else
	s_net_dev = alloc_netdev(0, "sphcschan%d", NET_NAME_UNKNOWN,
					sphcs_net_dev_setup);
#endif

	if (!s_net_dev) {
		sph_log_err(ETH_LOG, "alloc_netdev failed!\n");
		return -1;
	}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)) /* SPH_IGNORE_STYLE_CHECK */
	s_net_dev->max_mtu = NNP_PAGE_SIZE - 14;
#endif
	s_net_dev->mtu = NNP_PAGE_SIZE - 14;

	ret = dma_page_pool_create(g_the_sphcs->hw_device, h2c_pages, &s_net_dma_page_pool);
	if (ret < 0) {
		sph_log_err(START_UP_LOG, "Failed to create net dma page pool\n");
		free_netdev(s_net_dev);
		return -1;
	}

	s_c2h_handles = c2h_pages;
	s_c2h_busy_handles = kcalloc(c2h_pages, sizeof(uint8_t), GFP_KERNEL);
	if (!s_c2h_busy_handles) {
		sph_log_err(START_UP_LOG, "Failed to create net dma page pool\n");
		free_netdev(s_net_dev);
		dma_page_pool_destroy(s_net_dma_page_pool);
		return -1;
	}

	dma_page_pool_init_debugfs(s_net_dma_page_pool,
				   g_the_sphcs->debugfs_dir,
				   "chan_net_dma_page_pool");

	if (register_netdev(s_net_dev)) {
		sph_log_err(ETH_LOG, "SPH_NET - Failed to register sph net device\n");
		free_netdev(s_net_dev);
		return -1;
	}
	sph_log_info(ETH_LOG, "SPH_NET - Succeeded loading sph network module %s!\n\n",
			dev_name(&s_net_dev->dev));
	return 0;
}

static void sphcs_net_dev_exit(void)
{
	sph_log_info(ETH_LOG, "SPH_NET - Unloading sph network module\n\n");
	if (s_net_dev != NULL) {
		unregister_netdev(s_net_dev);
		free_netdev(s_net_dev);
		dma_page_pool_destroy(s_net_dma_page_pool);
		kfree(s_c2h_busy_handles);
		s_net_dev = NULL;
		s_net_cmd_chan = NULL;
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

static void sphcs_net_send_ack(struct sphcs_cmd_chan *cmd_chan, int skb_handle)
{
	// Send a ACK reply to host to free the xmited skb
	union c2h_ChanEthernetMsgDscr msg;

	msg.value = 0;
	msg.opcode = NNP_IPC_C2H_OP_CHAN_ETH_MSG_DSCR;
	msg.chanID = cmd_chan->protocolID;
	msg.skb_handle = skb_handle;
	msg.is_ack = 1;

	sphcs_msg_scheduler_queue_add_msg(cmd_chan->respq, &msg.value,
				    sizeof(msg) / sizeof(u64));
}

static int sphcs_net_in_msg_dma_complete_callback(struct sphcs *sphcs,
						  void *ctx,
						  const void *user_data,
						  int status,
						  u32 xferTimeUS)
{
	struct net_dma_command_data *dma_data =
			(struct net_dma_command_data *)user_data;

	sphcs_net_send_ack(dma_data->chan, dma_data->host_skb_handle);

	sphcs_net_dev_rx(s_net_dev, dma_data->xfer_size, dma_data->vptr);

	dma_page_pool_set_page_free(s_net_dma_page_pool, dma_data->card_dma_page_hndl);

	sphcs_cmd_chan_put(dma_data->chan);
	return 0;
}

/*
 * called to process a
 * NNP_IPC_H2C_OP_ETH_MSG_DSCR message received from host.
 */
static int sphcs_net_process_command(struct sphcs              *sphcs,
				     struct sphcs_cmd_chan     *cmd_chan,
				     union h2c_ChanEthernetMsgDscr *req)
{
	struct net_dma_command_data dma_data;
	dma_addr_t dma_addr;
	dma_addr_t host_dma_addr;
	int ret;
	uint32_t cont = 0;

	host_dma_addr = host_rb_get_addr(&cmd_chan->h2c_rb[0],
					 req->skb_handle * NNP_PAGE_SIZE,
					 &cont);
	NNP_ASSERT(cont >= req->size + 1);

	ret = dma_page_pool_get_free_page(s_net_dma_page_pool,
					  &dma_data.card_dma_page_hndl,
					  &dma_data.vptr, &dma_addr);

	if (ret) {
		sph_log_err(ETH_LOG, "SPH_NET - Failed to get free DMA page\n");
		sphcs_cmd_chan_put(cmd_chan);
		return ret;
	}

	dma_data.xfer_size = req->size + 1;
	dma_data.host_skb_handle = req->skb_handle;
	dma_data.host_dma_addr = host_dma_addr;
	dma_data.chan = cmd_chan;

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
		dma_page_pool_set_page_free(s_net_dma_page_pool, dma_data.card_dma_page_hndl);
		sphcs_cmd_chan_put(cmd_chan);
		return ret;
	}

	return 0;
}

struct netmsg_op_work {
	struct work_struct work;
	struct sphcs *sphcs;
	struct sphcs_cmd_chan *chan;
	union h2c_ChanEthernetMsgDscr cmd;
};



static void netmsg_op_work_handler(struct work_struct *work)
{
	struct netmsg_op_work *op = container_of(work,
						 struct netmsg_op_work,
						 work);

	if (op->cmd.is_ack) {
		s_c2h_busy_handles[op->cmd.skb_handle] = 0;
		sphcs_cmd_chan_put(op->chan);
		goto free_op;
	}

	if (sphcs_net_process_command(op->sphcs, op->chan, &(op->cmd)))
		sph_log_info(ETH_LOG, "SPH_NET - Failed process net command\n");
free_op:
	kfree(op);
}

/*
 * called to handle a
 * NNP_IPC_H2C_OP_ETH_MSG_DSCR message receviced from host.
 */
void IPC_OPCODE_HANDLER(CHAN_ETH_MSG_DSCR)(struct sphcs              *sphcs,
					   union h2c_ChanEthernetMsgDscr *cmd)
{
	struct netmsg_op_work *work;
	struct sphcs_cmd_chan *chan;

	chan = sphcs_find_channel(sphcs, cmd->chanID);
	if (!chan)
		return;

	if (!s_net_dev)
		goto fail;

	work = kzalloc(sizeof(*work), GFP_NOWAIT);
	if (!work)
		goto fail;

	work->cmd.value = cmd->value;
	work->sphcs = sphcs;
	work->chan = chan;
	INIT_WORK(&work->work, netmsg_op_work_handler);
	queue_work(sphcs->wq, &work->work);

	return;

fail:
	if (!cmd->is_ack)
		sphcs_net_send_ack(chan, cmd->skb_handle);
	sphcs_cmd_chan_put(chan);
}

struct eth_set_ip_op_work {
	struct work_struct work;
	struct sphcs *sphcs;
	struct sphcs_cmd_chan *chan;
	union h2c_ChanEthernetConfig cmd;
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

static void sphcs_net_chan_destroyed(struct sphcs_cmd_chan *cmd_chan, void *cb_ctx)
{
	if (s_net_dev != NULL)
		sphcs_net_dev_exit();
}

static void config_card_eth(struct work_struct *work)
{
	int ret = 0;
	char ip_str[16];
	union c2h_ChanEthernetConfig msg;
	struct eth_set_ip_op_work *op = container_of(work,
						     struct eth_set_ip_op_work,
						     work);

	char *argv[] = {           /* SPH_IGNORE_STYLE_CHECK */
		"/sbin/ifconfig",
		"sphcschan0",
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
		op->chan->destroy_cb = NULL;
	} else if (op->chan->h2c_rb[0].host_sgt.sgl && op->chan->h2c_rb[0].size > 0 &&
		   op->chan->c2h_rb[0].host_sgt.sgl && op->chan->c2h_rb[0].size > 0) {
		memcpy(s_mac_addr, &op->cmd.value[10], ETH_ALEN);
		ret = sphcs_net_dev_init(op->chan->h2c_rb[0].size / NNP_PAGE_SIZE,
					 op->chan->c2h_rb[0].size / NNP_PAGE_SIZE);
		if (ret == 0) {
			/* start user mode app to send ifconfig command*/
			ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
			if (ret)
				sph_log_err(ETH_LOG, "call_usermodehelper ifconfig failed. ip: %s, ret: %d\n", ip_str, ret);
			s_net_cmd_chan = op->chan;
			op->chan->destroy_cb = sphcs_net_chan_destroyed;
			op->chan->destroy_cb_ctx = NULL;
		}
	}

	msg.value = 0;
	msg.opcode = NNP_IPC_C2H_OP_CHAN_ETH_CONFIG;
	msg.chanID = op->chan->protocolID;
	if (op->cmd.card_ip && ret == 0)
		msg.card_ip = op->cmd.card_ip;

	sphcs_msg_scheduler_queue_add_msg(op->chan->respq,
					  &msg.value,
					  sizeof(msg) / sizeof(u64));

	sphcs_cmd_chan_put(op->chan);

	kfree(op);
}

/*
 * called to handle a
 * NNP_IPC_H2C_OP_ETH_CONFIG message receviced from host.
 */
void IPC_OPCODE_HANDLER(CHAN_ETH_CONFIG)(struct sphcs                 *sphcs,
					 union h2c_ChanEthernetConfig *cmd)
{
	struct eth_set_ip_op_work *work;
	struct sphcs_cmd_chan *chan;
	union c2h_ChanEthernetConfig msg;

	chan = sphcs_find_channel(sphcs, cmd->chanID);
	if (!chan)
		return;

	work = kzalloc(sizeof(*work), GFP_NOWAIT);
	if (!work)
		goto fail;

	memcpy(work->cmd.value, cmd->value, sizeof(cmd->value));
	work->sphcs = sphcs;
	work->chan = chan;
	INIT_WORK(&work->work, config_card_eth);
	queue_work(chan->wq, &work->work);

	return;

fail:
	msg.value = 0;
	msg.opcode = NNP_IPC_C2H_OP_CHAN_ETH_CONFIG;
	msg.chanID = chan->protocolID;
	sphcs_msg_scheduler_queue_add_msg(chan->respq,
					  &msg.value,
					  sizeof(msg) / sizeof(u64));
	sphcs_cmd_chan_put(chan);
}
