/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#include <linux/platform_device.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/of.h>

#include "cve_driver_internal.h"
#include "cve_linux_internal.h"
#include "cve_project_internal.h"

static int cve_platform_probe(struct platform_device *pdev);
static int cve_platform_remove(struct platform_device *pdev);
static const struct of_device_id m_cve_of_match_table[] = {
	{ .compatible = "intel,coh-cve", .data = NULL },
	{},
};
MODULE_DEVICE_TABLE(of, m_cve_of_match_table);

/* OS interface functions */
static struct platform_driver m_cve_platform_driver = {
		.driver = {
			.name = MODULE_NAME,
			.of_match_table = m_cve_of_match_table,
		},
		.probe = cve_platform_probe,
		.remove = cve_platform_remove,
};

static int cve_platform_probe(struct platform_device *pdev)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct resource *res;
	int irq;
	struct cve_os_device *linux_device;
	struct reset_control *rstc;
	struct clk *cve_clk;
	u32 dts_elem[2];

	FUNC_ENTER();

	/* store the generic device structure */
	linux_device = devm_kzalloc(&pdev->dev,
				sizeof(struct cve_os_device),
				GFP_KERNEL);

	if (linux_device == NULL) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Failed to allocate %d\n",
				retval);
		goto out;
	}
	linux_device->dev = &pdev->dev;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"platform_get_resource failed\n");
		goto out;
	}

	/* store the device memory region into appropriate struct */
	linux_device->cached_mmio_base.iobase[0] =
			devm_ioremap_resource(&pdev->dev, res);
	if (!linux_device->cached_mmio_base.iobase[0]) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"devm_ioremap_resource failed\n");
		goto out;
	}

	platform_set_drvdata(pdev, linux_device);

	/* store the size of the memory region into appropriate struct */
	linux_device->cached_mmio_base.len[0] = resource_size(res);

	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "missing IRQ resource\n");
		goto out;
	}

	retval = devm_request_threaded_irq(&pdev->dev,
			irq,
			cve_os_interrupt_handler,
			cve_os_interrupt_handler_bh,
			IRQF_SHARED,
			MODULE_NAME,
			linux_device);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "devm_request_irq failed %d\n",
				retval);
		goto out;
	}

	retval = dma_set_mask_and_coherent(&pdev->dev, CVE_DMA_BIT_MASK);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"dma_set_mask_and_coherent failed %d\n",
				retval);
		goto out;
	}

	rstc = devm_reset_control_get_optional(&pdev->dev, NULL);
	if (IS_ERR_OR_NULL(rstc)) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"devm_reset_control_get_optional failed %ld\n",
				PTR_ERR(rstc));
		goto out;
	}
	linux_device->rstc = rstc;

	/* get cve clock */
	cve_clk = devm_clk_get(&pdev->dev, NULL);
	if (IS_ERR(cve_clk)) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
		"failed to get clock rate %ld\n",
		PTR_ERR(cve_clk));
		goto out;
	}

	linux_device->cve_clk = cve_clk;

	/* enable cve clock */
	retval = clk_prepare_enable(linux_device->cve_clk);
	if (retval) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
		"failed to enabled cve clock %d\n",
		retval);
		goto out;
	}

	/* get cve index [0-7] */
	retval = of_property_read_u32_array(pdev->dev.of_node, "resource",
		dts_elem, ARRAY_SIZE(dts_elem));
	if (retval) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"failed to get cve index %d\n",
			retval);
		goto out;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"values read from dts: <%u, %u> (1st is a string read as u32, means \"&coh_resource\". 2nd is the device index)\n",
		dts_elem[0], dts_elem[1]);

	/* dts_elem[1] is the device index read from dts file.
	 * dts entry format is: "resource = <&coh_resource [index]>"
	 */
	retval = cve_probe_common(linux_device, dts_elem[1]);
	if (retval) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"cve_probe_common failed %d\n",
			retval);
		goto out;
	}

	/* success */
	retval = 0;
out:
	FUNC_LEAVE();
	return retval;
}

static int cve_platform_remove(struct platform_device *pdev)
{
	struct cve_os_device *linux_device;

	FUNC_ENTER();
	linux_device = platform_get_drvdata(pdev);
	/* disable cve clock */
	clk_disable(linux_device->cve_clk);
	clk_unprepare(linux_device->cve_clk);
	cve_remove_common(linux_device);
	FUNC_LEAVE();
	return 0;
}

/* init/cleanup */

int cve_register_driver(void)
{
	int retval;

	FUNC_ENTER();

	retval = platform_driver_register(&m_cve_platform_driver);
	if (retval) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"platform_driver_register failed %d\n",
				retval);
		goto out;
	}

	/* success */
	retval = 0;
out:
	FUNC_LEAVE();
	return retval;
}

void cve_unregister_driver(void)
{
	FUNC_ENTER();
	platform_driver_unregister(&m_cve_platform_driver);
	FUNC_LEAVE();
}

MODULE_AUTHOR("Vladimir Kondratiev <vladimir.kondratiev@intel.com>");

