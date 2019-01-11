/* main.c - Application main entry point */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sysinit/sysinit.h"

#include "modlog/modlog.h"
#include "host/ble_uuid.h"
#include "host/ble_hs.h"
#include "console/console.h"

#include "bttester.h"

static void on_reset(int reason)
{
	MODLOG_DFLT(ERROR, "Resetting state; reason=%d\n", reason);
}

static void on_sync(void)
{
	MODLOG_DFLT(INFO, "Bluetooth initialized\n");

	tester_init();
}

static void gatts_register_cb(struct ble_gatt_register_ctxt *ctxt, void *arg)
{
	char buf[BLE_UUID_STR_LEN];

	switch (ctxt->op) {
		case BLE_GATT_REGISTER_OP_SVC:
		MODLOG_DFLT(INFO, "registered service %s with handle=%d\n",
			    ble_uuid_to_str(ctxt->svc.svc_def->uuid, buf),
			    ctxt->svc.handle);
			break;

		case BLE_GATT_REGISTER_OP_CHR:
		MODLOG_DFLT(INFO, "registering characteristic %s with "
				   "def_handle=%d val_handle=%d\n",
			    ble_uuid_to_str(ctxt->chr.chr_def->uuid, buf),
			    ctxt->chr.def_handle,
			    ctxt->chr.val_handle);
			break;

		case BLE_GATT_REGISTER_OP_DSC:
		MODLOG_DFLT(INFO, "registering descriptor %s with handle=%d\n",
			    ble_uuid_to_str(ctxt->dsc.dsc_def->uuid, buf),
			    ctxt->dsc.handle);
			break;

		default:
			assert(0);
			break;
	}
}

int main(int argc, char **argv)
{
#ifdef ARCH_sim
	mcu_sim_parse_args(argc, argv);
#endif

	/* Initialize OS */
	sysinit();

	/* Initialize the NimBLE host configuration. */
	ble_hs_cfg.reset_cb = on_reset;
	ble_hs_cfg.sync_cb = on_sync;
	ble_hs_cfg.gatts_register_cb = gatts_register_cb,
	ble_hs_cfg.store_status_cb = ble_store_util_status_rr;

	while (1) {
		os_eventq_run(os_eventq_dflt_get());
	}
	return 0;
}
