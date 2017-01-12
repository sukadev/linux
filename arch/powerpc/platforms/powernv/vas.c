/*
 * Copyright 2016 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/of.h>

#include "vas.h"

static bool init_done;
LIST_HEAD(vas_instances);

static int init_vas_instance(struct platform_device *pdev)
{
	int rc, vasid;
	struct vas_instance *vinst;
	struct device_node *dn = pdev->dev.of_node;
	struct resource *res;

	rc = of_property_read_u32(dn, "ibm,vas-id", &vasid);
	if (rc) {
		pr_err("VAS: No ibm,vas-id property for %s?\n", pdev->name);
		return -ENODEV;
	}

	if (pdev->num_resources != 4) {
		pr_err("VAS: Unexpected DT configuration for [%s, %d]\n",
				pdev->name, vasid);
		return -ENODEV;
	}

	vinst = kcalloc(1, sizeof(*vinst), GFP_KERNEL);
	if (!vinst)
		return -ENOMEM;

	INIT_LIST_HEAD(&vinst->node);
	ida_init(&vinst->ida);
	mutex_init(&vinst->mutex);
	vinst->vas_id = vasid;
	vinst->pdev = pdev;

	res = &pdev->resource[0];
	vinst->hvwc_bar_start = res->start;
	vinst->hvwc_bar_len = res->end - res->start + 1;

	res = &pdev->resource[1];
	vinst->uwc_bar_start = res->start;
	vinst->uwc_bar_len = res->end - res->start + 1;

	res = &pdev->resource[2];
	vinst->paste_base_addr = res->start;

	res = &pdev->resource[3];
	vinst->paste_win_id_shift = 63 - res->end;

	pr_devel("VAS: Initialized instance [%s, %d], paste_base 0x%llx, "
			"paste_win_id_shift 0x%llx\n", pdev->name, vasid,
			vinst->paste_base_addr, vinst->paste_win_id_shift);

	vinst->ready = true;
	list_add(&vinst->node, &vas_instances);

	dev_set_drvdata(&pdev->dev, vinst);

	return 0;
}

/*
 * Although this is read/used multiple times, it is written to only
 * during initialization.
 */
struct vas_instance *find_vas_instance(int vasid)
{
	struct list_head *ent;
	struct vas_instance *vinst;

	list_for_each(ent, &vas_instances) {
		vinst = list_entry(ent, struct vas_instance, node);
		if (vinst->vas_id == vasid)
			return vinst;
	}

	pr_devel("VAS: Instance %d not found\n", vasid);
	return NULL;
}

bool vas_initialized(void)
{
	return init_done;
}

static int vas_probe(struct platform_device *pdev)
{
	if (!pdev || !pdev->dev.of_node)
		return -ENODEV;

	return init_vas_instance(pdev);
}

static void free_inst(struct vas_instance *vinst)
{
	list_del(&vinst->node);

	kfree(vinst);
}

static int vas_remove(struct platform_device *pdev)
{
	struct vas_instance *vinst;

	vinst = dev_get_drvdata(&pdev->dev);

	pr_devel("VAS: Removed instance [%s, %d]\n", pdev->name,
				vinst->vas_id);
	free_inst(vinst);

	return 0;
}
static const struct of_device_id powernv_vas_match[] = {
	{ .compatible = "ibm,vas",},
	{},
};

static struct platform_driver vas_driver = {
	.driver = {
		.name = "vas",
		.of_match_table = powernv_vas_match,
	},
	.probe = vas_probe,
	.remove = vas_remove,
};

module_platform_driver(vas_driver);

int vas_init(void)
{
	int found = 0;
	struct device_node *dn;

	for_each_compatible_node(dn, NULL, "ibm,vas") {
		of_platform_device_create(dn, NULL, NULL);
		found++;
	}

	if (!found)
		return -ENODEV;

	pr_devel("VAS: Found %d instances\n", found);
	init_done = true;

	return 0;
}

void vas_exit(void)
{
	struct list_head *ent;
	struct vas_instance *vinst;

	list_for_each(ent, &vas_instances) {
		vinst = list_entry(ent, struct vas_instance, node);
		of_platform_depopulate(&vinst->pdev->dev);
	}

	init_done = false;
}

module_init(vas_init);
module_exit(vas_exit);
MODULE_DESCRIPTION("Bare metal IBM Virtual Accelerator Switchboard");
MODULE_AUTHOR("Sukadev Bhattiprolu <sukadev@linux.vnet.ibm.com>");
MODULE_LICENSE("GPL");
