/*
 * Copyright 2016-17 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#define pr_fmt(fmt) "vas: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/of.h>
#include <asm/prom.h>

#include "vas.h"

/*
 * vas_mutex protects both vas_instances and chip_to_vas_id_map.
 */
static DEFINE_MUTEX(vas_mutex);
static LIST_HEAD(vas_instances);

/*
 * Create a mapping between a chip id and its VAS id(s). For POWER9, this
 * is a 1:1 to mapping. In the future, it may be a 1:N.
 */
struct chip_to_vas_id {
	int chip_id;
	int vas_id;
	struct list_head list;
};

static struct list_head chip_to_vas_id_map = LIST_HEAD_INIT(chip_to_vas_id_map);

static int map_chip_id(int chip_id, int vasid)
{
	struct chip_to_vas_id *c2v;

	c2v = kmalloc(sizeof(*c2v), GFP_KERNEL);
	if (!c2v)
		return -ENOMEM;

	INIT_LIST_HEAD(&c2v->list);
	c2v->chip_id = chip_id;
	c2v->vas_id = vasid;

	list_add(&c2v->list, &chip_to_vas_id_map);

	return 0;
}

static int cpu_to_vas_id(int cpu)
{
	int chip;
	struct chip_to_vas_id *c2v;
	struct list_head *l;

	chip = cpu_to_chip_id(cpu);

	list_for_each(l, &chip_to_vas_id_map) {
		c2v = list_entry(l, struct chip_to_vas_id, list);
		if (c2v->chip_id == chip)
			return c2v->vas_id;
	}

	WARN_ON_ONCE(1);
	return 0;
}


static int init_vas_instance(struct platform_device *pdev)
{
	int rc, vasid;
	struct resource *res;
	struct vas_instance *vinst;
	struct device_node *dn = pdev->dev.of_node;

	rc = of_property_read_u32(dn, "ibm,vas-id", &vasid);
	if (rc) {
		pr_err("No ibm,vas-id property for %s?\n", pdev->name);
		return -ENODEV;
	}

	if (pdev->num_resources != 4) {
		pr_err("Unexpected DT configuration for [%s, %d]\n",
				pdev->name, vasid);
		return -ENODEV;
	}

	vinst = kzalloc(sizeof(*vinst), GFP_KERNEL);
	if (!vinst)
		return -ENOMEM;

	INIT_LIST_HEAD(&vinst->node);
	ida_init(&vinst->ida);
	mutex_init(&vinst->mutex);
	vinst->vas_id = vasid;
	vinst->pdev = pdev;

	res = &pdev->resource[0];
	vinst->hvwc_bar_start = res->start;

	res = &pdev->resource[1];
	vinst->uwc_bar_start = res->start;

	res = &pdev->resource[2];
	vinst->paste_base_addr = res->start;

	res = &pdev->resource[3];
	if (res->end > 62) {
		pr_err("Bad 'paste_win_id_shift' in DT, %llx\n", res->end);
		goto free_vinst;
	}

	vinst->paste_win_id_shift = 63 - res->end;

	pr_devel("Initialized instance [%s, %d], paste_base 0x%llx, "
			"paste_win_id_shift 0x%llx\n", pdev->name, vasid,
			vinst->paste_base_addr, vinst->paste_win_id_shift);

	mutex_lock(&vas_mutex);
	rc = map_chip_id(of_get_ibm_chip_id(dn), vasid);
	if (rc) {
		mutex_unlock(&vas_mutex);
		goto free_vinst;
	}
	list_add(&vinst->node, &vas_instances);
	mutex_unlock(&vas_mutex);

	dev_set_drvdata(&pdev->dev, vinst);

	return 0;

free_vinst:
	kfree(vinst);
	return -ENODEV;

}

/*
 * Although this is read/used multiple times, it is written to only
 * during initialization.
 */
struct vas_instance *find_vas_instance(int vasid)
{
	struct list_head *ent;
	struct vas_instance *vinst;

	mutex_lock(&vas_mutex);

	if (vasid == -1)
		vasid = cpu_to_vas_id(smp_processor_id());

	list_for_each(ent, &vas_instances) {
		vinst = list_entry(ent, struct vas_instance, node);
		if (vinst->vas_id == vasid) {
			mutex_unlock(&vas_mutex);
			return vinst;
		}
	}
	mutex_unlock(&vas_mutex);

	pr_devel("Instance %d not found\n", vasid);
	return NULL;
}

static int vas_probe(struct platform_device *pdev)
{
	return init_vas_instance(pdev);
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
};

static int __init vas_init(void)
{
	int found = 0;
	struct device_node *dn;

	platform_driver_register(&vas_driver);

	for_each_compatible_node(dn, NULL, "ibm,vas") {
		of_platform_device_create(dn, NULL, NULL);
		found++;
	}

	if (!found)
		return -ENODEV;

	pr_devel("Found %d instances\n", found);

	return 0;
}
device_initcall(vas_init);
