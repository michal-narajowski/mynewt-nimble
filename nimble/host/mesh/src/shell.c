/** @file
 *  @brief Bluetooth Mesh shell
 *
 */

/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "syscfg/syscfg.h"

#if MYNEWT_VAL(BLE_MESH_SHELL)

#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include "shell/shell.h"
#include "console/console.h"
#include "mesh/mesh.h"
#include "mesh/main.h"
#include "mesh/glue.h"
#include "mesh/testing.h"
#include "hal/hal_gpio.h"
#include "bsp/bsp.h"

/* Private includes for raw Network & Transport layer access */
#include "net.h"
#include "access.h"
#include "adv.h"
#include "mesh_priv.h"
#include "lpn.h"
#include "transport.h"
#include "foundation.h"
#include "testing.h"
#include "cmd.h"

/* This should be higher priority (lower value) than main task priority */
#define BLE_MESH_SHELL_TASK_PRIO 126
#define BLE_MESH_SHELL_STACK_SIZE 768

OS_TASK_STACK_DEFINE(g_blemesh_shell_stack, BLE_MESH_SHELL_STACK_SIZE);

struct os_task mesh_shell_task;
static struct os_eventq mesh_shell_queue;

#define CID_NVAL   0xffff
#define CID_VENDOR  0x05C3

/* Vendor Model data */
#define VND_MODEL_ID_1 0x1234

/* Default net, app & dev key values, unless otherwise specified */
static const u8_t default_key[16] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
};

/* Model send data */
#define MODEL_BOUNDS_MAX 2

static struct model_data {
	struct bt_mesh_model *model;
	u16_t addr;
	u16_t appkey_idx;
} model_bound[MODEL_BOUNDS_MAX];

static struct {
	u16_t local;
	u16_t dst;
	u16_t net_idx;
	u16_t app_idx;
} net = {
	.local = BT_MESH_ADDR_UNASSIGNED,
	.dst = BT_MESH_ADDR_UNASSIGNED,
	.app_idx = BT_MESH_KEY_DEV,
};

static struct bt_mesh_cfg_srv cfg_srv = {
	.relay = BT_MESH_RELAY_DISABLED,
	.beacon = BT_MESH_BEACON_ENABLED,
#if MYNEWT_VAL(BLE_MESH_FRIEND)
	.frnd = BT_MESH_FRIEND_DISABLED,
#else
	.frnd = BT_MESH_FRIEND_NOT_SUPPORTED,
#endif
#if MYNEWT_VAL(BLE_MESH_GATT_PROXY)
	.gatt_proxy = BT_MESH_GATT_PROXY_DISABLED,
#else
	.gatt_proxy = BT_MESH_GATT_PROXY_NOT_SUPPORTED,
#endif

	.default_ttl = 7,

	/* 3 transmissions with 20ms interval */
	.net_transmit = BT_MESH_TRANSMIT(2, 20),
	.relay_retransmit = BT_MESH_TRANSMIT(2, 20),
};

#define CUR_FAULTS_MAX 4

static u8_t cur_faults[CUR_FAULTS_MAX];
static u8_t reg_faults[CUR_FAULTS_MAX * 2];

static void get_faults(u8_t *faults, u8_t faults_size, u8_t *dst, u8_t *count)
{
	u8_t i, limit = *count;

	for (i = 0, *count = 0; i < faults_size && *count < limit; i++) {
		if (faults[i]) {
			*dst++ = faults[i];
			(*count)++;
		}
	}
}

static int fault_get_cur(struct bt_mesh_model *model, u8_t *test_id,
			 u16_t *company_id, u8_t *faults, u8_t *fault_count)
{
	printk("Sending current faults\n");

	*test_id = 0x00;
	*company_id = CID_VENDOR;

	get_faults(cur_faults, sizeof(cur_faults), faults, fault_count);

	return 0;
}

static int fault_get_reg(struct bt_mesh_model *model, u16_t cid,
			 u8_t *test_id, u8_t *faults, u8_t *fault_count)
{
	if (cid != CID_VENDOR) {
		printk("Faults requested for unknown Company ID 0x%04x\n", cid);
		return -EINVAL;
	}

	printk("Sending registered faults\n");

	*test_id = 0x00;

	get_faults(reg_faults, sizeof(reg_faults), faults, fault_count);

	return 0;
}

static int fault_clear(struct bt_mesh_model *model, uint16_t cid)
{
	if (cid != CID_VENDOR) {
		return -EINVAL;
	}

	memset(reg_faults, 0, sizeof(reg_faults));

	return 0;
}

static int fault_test(struct bt_mesh_model *model, uint8_t test_id,
		      uint16_t cid)
{
	if (cid != CID_VENDOR) {
		return -EINVAL;
	}

	if (test_id != 0x00) {
		return -EINVAL;
	}

	return 0;
}

static const struct bt_mesh_health_srv_cb health_srv_cb = {
	.fault_get_cur = fault_get_cur,
	.fault_get_reg = fault_get_reg,
	.fault_clear = fault_clear,
	.fault_test = fault_test,
};

static struct bt_mesh_health_srv health_srv = {
	.cb = &health_srv_cb,
};

static struct bt_mesh_model_pub health_pub;

static void
health_pub_init(void)
{
    health_pub.msg  = BT_MESH_HEALTH_FAULT_MSG(CUR_FAULTS_MAX);
}


static struct bt_mesh_cfg_cli cfg_cli = {
};

static struct bt_mesh_model_pub gen_level_pub;
static struct bt_mesh_model_pub gen_onoff_pub;

static uint8_t gen_on_off_state;
static int16_t gen_level_state;

static void gen_onoff_status(struct bt_mesh_model *model,
                             struct bt_mesh_msg_ctx *ctx)
{
    struct os_mbuf *msg = NET_BUF_SIMPLE(3);
    uint8_t *status;

    console_printf("#mesh-onoff STATUS\n");

    bt_mesh_model_msg_init(msg, BT_MESH_MODEL_OP_2(0x82, 0x04));
    status = net_buf_simple_add(msg, 1);
    *status = gen_on_off_state;

    if (bt_mesh_model_send(model, ctx, msg, NULL, NULL)) {
        console_printf("#mesh-onoff STATUS: send status failed\n");
    }

    os_mbuf_free_chain(msg);
}

static void gen_onoff_get(struct bt_mesh_model *model,
              struct bt_mesh_msg_ctx *ctx,
              struct os_mbuf *buf)
{
    console_printf("#mesh-onoff GET\n");

    gen_onoff_status(model, ctx);
}

static void gen_onoff_set(struct bt_mesh_model *model,
              struct bt_mesh_msg_ctx *ctx,
              struct os_mbuf *buf)
{
    console_printf("#mesh-onoff SET\n");

    gen_on_off_state = buf->om_data[0];
    hal_gpio_write(LED_2, !gen_on_off_state);

    gen_onoff_status(model, ctx);
}

static void gen_onoff_set_unack(struct bt_mesh_model *model,
                struct bt_mesh_msg_ctx *ctx,
                struct os_mbuf *buf)
{
    console_printf("#mesh-onoff SET-UNACK\n");

    gen_on_off_state = buf->om_data[0];
    hal_gpio_write(LED_2, !gen_on_off_state);
}

static const struct bt_mesh_model_op gen_onoff_op[] = {
    { BT_MESH_MODEL_OP_2(0x82, 0x01), 0, gen_onoff_get },
    { BT_MESH_MODEL_OP_2(0x82, 0x02), 2, gen_onoff_set },
    { BT_MESH_MODEL_OP_2(0x82, 0x03), 2, gen_onoff_set_unack },
    BT_MESH_MODEL_OP_END,
};

static void gen_level_status(struct bt_mesh_model *model,
                             struct bt_mesh_msg_ctx *ctx)
{
    struct os_mbuf *msg = NET_BUF_SIMPLE(4);

    console_printf("#mesh-level STATUS\n");

    bt_mesh_model_msg_init(msg, BT_MESH_MODEL_OP_2(0x82, 0x08));
    net_buf_simple_add_le16(msg, gen_level_state);

    if (bt_mesh_model_send(model, ctx, msg, NULL, NULL)) {
        console_printf("#mesh-level STATUS: send status failed\n");
    }

    os_mbuf_free_chain(msg);
}

static void gen_level_get(struct bt_mesh_model *model,
              struct bt_mesh_msg_ctx *ctx,
              struct os_mbuf *buf)
{
    console_printf("#mesh-level GET\n");

    gen_level_status(model, ctx);
}

static void gen_level_set(struct bt_mesh_model *model,
              struct bt_mesh_msg_ctx *ctx,
              struct os_mbuf *buf)
{
    int16_t level;

    level = (int16_t) net_buf_simple_pull_le16(buf);
    console_printf("#mesh-level SET: level=%d\n", level);

    gen_level_status(model, ctx);

    gen_level_state = level;
    console_printf("#mesh-level: level=%d\n", gen_level_state);
}

static void gen_level_set_unack(struct bt_mesh_model *model,
                struct bt_mesh_msg_ctx *ctx,
                struct os_mbuf *buf)
{
    int16_t level;

    level = (int16_t) net_buf_simple_pull_le16(buf);
    console_printf("#mesh-level SET-UNACK: level=%d\n", level);

    gen_level_state = level;
    console_printf("#mesh-level: level=%d\n", gen_level_state);
}

static void gen_delta_set(struct bt_mesh_model *model,
              struct bt_mesh_msg_ctx *ctx,
              struct os_mbuf *buf)
{
    int16_t delta_level;

    delta_level = (int16_t) net_buf_simple_pull_le16(buf);
    console_printf("#mesh-level DELTA-SET: delta_level=%d\n", delta_level);

    gen_level_status(model, ctx);

    gen_level_state += delta_level;
    console_printf("#mesh-level: level=%d\n", gen_level_state);
}

static void gen_delta_set_unack(struct bt_mesh_model *model,
                struct bt_mesh_msg_ctx *ctx,
                struct os_mbuf *buf)
{
    int16_t delta_level;

    delta_level = (int16_t) net_buf_simple_pull_le16(buf);
    console_printf("#mesh-level DELTA-SET: delta_level=%d\n", delta_level);

    gen_level_state += delta_level;
    console_printf("#mesh-level: level=%d\n", gen_level_state);
}

static void gen_move_set(struct bt_mesh_model *model,
             struct bt_mesh_msg_ctx *ctx,
             struct os_mbuf *buf)
{
}

static void gen_move_set_unack(struct bt_mesh_model *model,
                   struct bt_mesh_msg_ctx *ctx,
                   struct os_mbuf *buf)
{
}

static const struct bt_mesh_model_op gen_level_op[] = {
    { BT_MESH_MODEL_OP_2(0x82, 0x05), 0, gen_level_get },
    { BT_MESH_MODEL_OP_2(0x82, 0x06), 3, gen_level_set },
    { BT_MESH_MODEL_OP_2(0x82, 0x07), 3, gen_level_set_unack },
    { BT_MESH_MODEL_OP_2(0x82, 0x09), 5, gen_delta_set },
    { BT_MESH_MODEL_OP_2(0x82, 0x0a), 5, gen_delta_set_unack },
    { BT_MESH_MODEL_OP_2(0x82, 0x0b), 3, gen_move_set },
    { BT_MESH_MODEL_OP_2(0x82, 0x0c), 3, gen_move_set_unack },
    BT_MESH_MODEL_OP_END,
};

static void model_bound_cb(u16_t addr, struct bt_mesh_model *model,
			   u16_t key_idx)
{
	int i;

	printk("remote addr 0x%04x key_idx 0x%04x model %p\n",
	       addr, key_idx, model);

	for (i = 0; i < ARRAY_SIZE(model_bound); i++) {
		if (!model_bound[i].model) {
			model_bound[i].model = model;
			model_bound[i].addr = addr;
			model_bound[i].appkey_idx = key_idx;

			return;
		}
	}

	printk("model_bound is full\n");
}

static void model_unbound_cb(u16_t addr, struct bt_mesh_model *model,
			     u16_t key_idx)
{
	int i;

	printk("remote addr 0x%04x key_idx 0x%04x model %p\n",
	       addr, key_idx, model);

	for (i = 0; i < ARRAY_SIZE(model_bound); i++) {
		if (model_bound[i].model == model) {
			model_bound[i].model = NULL;
			model_bound[i].addr = 0x0000;
			model_bound[i].appkey_idx = BT_MESH_KEY_UNUSED;

			return;
		}
	}

	printk("model not found\n");
}

static struct bt_test_cb bt_test_cb = {
	.mesh_model_bound = model_bound_cb,
	.mesh_model_unbound = model_unbound_cb,
};


void show_faults(u8_t test_id, u16_t cid, u8_t *faults, size_t fault_count)
{
	size_t i;

	if (!fault_count) {
		printk("Health Test ID 0x%02x Company ID 0x%04x: no faults\n",
		       test_id, cid);
		return;
	}

	printk("Health Test ID 0x%02x Company ID 0x%04x Fault Count %zu:\n",
	       test_id, cid, fault_count);

	for (i = 0; i < fault_count; i++) {
		printk("\t0x%02x\n", faults[i]);
	}
}

static void health_current_status(struct bt_mesh_health_cli *cli, u16_t addr,
				  u8_t test_id, u16_t cid, u8_t *faults,
				  size_t fault_count)
{
	printk("Health Current Status from 0x%04x\n", addr);
	show_faults(test_id, cid, faults, fault_count);
}

static struct bt_mesh_health_cli health_cli = {
	.current_status = health_current_status,
};

static u8_t dev_uuid[16] = MYNEWT_VAL(BLE_MESH_DEV_UUID);

static struct bt_mesh_model root_models[] = {
	BT_MESH_MODEL_CFG_SRV(&cfg_srv),
	BT_MESH_MODEL_CFG_CLI(&cfg_cli),
	BT_MESH_MODEL_HEALTH_SRV(&health_srv, &health_pub),
	BT_MESH_MODEL_HEALTH_CLI(&health_cli),
    BT_MESH_MODEL(BT_MESH_MODEL_ID_GEN_ONOFF_SRV, gen_onoff_op,
              &gen_onoff_pub, NULL),
    BT_MESH_MODEL(BT_MESH_MODEL_ID_GEN_LEVEL_SRV, gen_level_op,
              &gen_level_pub, NULL),
};

static struct bt_mesh_model vnd_models[] = {
	BT_MESH_MODEL_VND(CID_VENDOR, VND_MODEL_ID_1, BT_MESH_MODEL_NO_OPS, NULL,
			  NULL),
};

static struct bt_mesh_elem elements[] = {
	BT_MESH_ELEM(0, root_models, vnd_models),
};

static const struct bt_mesh_comp comp = {
	.cid = CID_VENDOR,
	.elem = elements,
	.elem_count = ARRAY_SIZE(elements),
};

static u8_t hex2val(char c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	} else if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	} else if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	} else {
		return 0;
	}
}

static size_t hex2bin(const char *hex, u8_t *bin, size_t bin_len)
{
	size_t len = 0;

	while (*hex && len < bin_len) {
		bin[len] = hex2val(*hex++) << 4;

		if (!*hex) {
			len++;
			break;
		}

		bin[len++] |= hex2val(*hex++);
	}

	return len;
}

static void prov_complete(u16_t net_idx, u16_t addr)
{
	printk("Local node provisioned, net_idx 0x%04x address 0x%04x\n",
	       net_idx, addr);
	net.net_idx = net_idx,
	net.local = addr;
	net.dst = addr;
}

static void prov_reset(void)
{
	printk("The local node has been reset and needs reprovisioning\n");
}

static int output_number(bt_mesh_output_action_t action, uint32_t number)
{
	printk("OOB Number: %lu\n", number);
	return 0;
}

static int output_string(const char *str)
{
	printk("OOB String: %s\n", str);
	return 0;
}

static bt_mesh_input_action_t input_act;
static u8_t input_size;

static int cmd_input_num(int argc, char *argv[])
{
	int err;

	if (argc < 2) {
		return -EINVAL;
	}

	if (input_act != BT_MESH_ENTER_NUMBER) {
		printk("A number hasn't been requested!\n");
		return 0;
	}

	if (strlen(argv[1]) < input_size) {
		printk("Too short input (%u digits required)\n",
		       input_size);
		return 0;
	}

	err = bt_mesh_input_number(strtoul(argv[1], NULL, 10));
	if (err) {
		printk("Numeric input failed (err %d)\n", err);
		return 0;
	}

	input_act = BT_MESH_NO_INPUT;
	return 0;
}

struct shell_cmd_help cmd_input_num_help = {
	NULL, "<number>", NULL
};

static int cmd_input_str(int argc, char *argv[])
{
	int err;

	if (argc < 2) {
		return -EINVAL;
	}

	if (input_act != BT_MESH_ENTER_STRING) {
		printk("A string hasn't been requested!\n");
		return 0;
	}

	if (strlen(argv[1]) < input_size) {
		printk("Too short input (%u characters required)\n",
		       input_size);
		return 0;
	}

	err = bt_mesh_input_string(argv[1]);
	if (err) {
		printk("String input failed (err %d)\n", err);
		return 0;
	}

	input_act = BT_MESH_NO_INPUT;
	return 0;
}

struct shell_cmd_help cmd_input_str_help = {
	NULL, "<string>", NULL
};

static int input(bt_mesh_input_action_t act, u8_t size)
{
	switch (act) {
	case BT_MESH_ENTER_NUMBER:
		printk("Enter a number (max %u digits) with: input-num <num>\n",
		       size);
		break;
	case BT_MESH_ENTER_STRING:
		printk("Enter a string (max %u chars) with: input-str <str>\n",
		       size);
		break;
	default:
		printk("Unknown input action %u (size %u) requested!\n",
		       act, size);
		return -EINVAL;
	}

	input_act = act;
	input_size = size;
	return 0;
}

static const char *bearer2str(bt_mesh_prov_bearer_t bearer)
{
	switch (bearer) {
	case BT_MESH_PROV_ADV:
		return "PB-ADV";
	case BT_MESH_PROV_GATT:
		return "PB-GATT";
	default:
		return "unknown";
	}
}

static void link_open(bt_mesh_prov_bearer_t bearer)
{
	printk("Provisioning link opened on %s\n", bearer2str(bearer));
}

static void link_close(bt_mesh_prov_bearer_t bearer)
{
	printk("Provisioning link closed on %s\n", bearer2str(bearer));
}

static u8_t static_val[16];

static struct bt_mesh_prov prov = {
	.uuid = dev_uuid,
	.link_open = link_open,
	.link_close = link_close,
	.complete = prov_complete,
	.reset = prov_reset,
	.static_val = NULL,
	.static_val_len = 0,
	.output_size = 4,
	.output_actions = (BT_MESH_BLINK | BT_MESH_BEEP | BT_MESH_DISPLAY_NUMBER | BT_MESH_DISPLAY_STRING),
	.output_number = output_number,
	.output_string = output_string,
	.input_size = 4,
	.input_actions = (BT_MESH_ENTER_NUMBER | BT_MESH_ENTER_STRING),
	.input = input,
};

static int cmd_static_oob(int argc, char *argv[])
{
	if (argc < 2) {
		prov.static_val = NULL;
		prov.static_val_len = 0;
	} else {
		prov.static_val_len = hex2bin(argv[1], static_val, 16);
		if (prov.static_val_len) {
			prov.static_val = static_val;
		} else {
			prov.static_val = NULL;
		}
	}

	if (prov.static_val) {
		printk("Static OOB value set (length %u)\n",
		       prov.static_val_len);
	} else {
		printk("Static OOB value cleared\n");
	}

	return 0;
}

struct shell_cmd_help cmd_static_oob_help = {
	NULL, "[val: 1-16 hex values]", NULL
};

static int cmd_uuid(int argc, char *argv[])
{
	u8_t uuid[16];
	size_t len;

	if (argc < 2) {
		return -EINVAL;
	}

	len = hex2bin(argv[1], uuid, sizeof(uuid));
	if (len < 1) {
		return -EINVAL;
	}

	memcpy(dev_uuid, uuid, len);
	memset(dev_uuid + len, 0, sizeof(dev_uuid) - len);

	printk("Device UUID set\n");

	return 0;
}

struct shell_cmd_help cmd_uuid_help = {
	NULL, "<UUID: 1-16 hex values>", NULL
};

static int cmd_reset(int argc, char *argv[])
{
	bt_mesh_reset();
	printk("Local node reset complete\n");
	return 0;
}

static u8_t str2u8(const char *str)
{
	if (isdigit(str[0])) {
		return strtoul(str, NULL, 0);
	}

	return (!strcmp(str, "on") || !strcmp(str, "enable"));
}

static bool str2bool(const char *str)
{
	return str2u8(str);
}

#if MYNEWT_VAL(BLE_MESH_LOW_POWER)
static int cmd_lpn(int argc, char *argv[])
{
	static bool enabled;
	int err;

	if (argc < 2) {
		printk("%s\n", enabled ? "enabled" : "disabled");
		return 0;
	}

	if (str2bool(argv[1])) {
		if (enabled) {
			printk("LPN already enabled\n");
			return 0;
		}

		err = bt_mesh_lpn_set(true);
		if (err) {
			printk("Enabling LPN failed (err %d)\n", err);
		} else {
			enabled = true;
		}
	} else {
		if (!enabled) {
			printk("LPN already disabled\n");
			return 0;
		}

		err = bt_mesh_lpn_set(false);
		if (err) {
			printk("Enabling LPN failed (err %d)\n", err);
		} else {
			enabled = false;
		}
	}

	return 0;
}

static int cmd_poll(int argc, char *argv[])
{
	int err;

	err = bt_mesh_lpn_poll();
	if (err) {
		printk("Friend Poll failed (err %d)\n", err);
	}

	return 0;
}

static void lpn_cb(u16_t friend_addr, bool established)
{
	if (established) {
		printk("Friendship (as LPN) established to Friend 0x%04x\n",
		       friend_addr);
	} else {
		printk("Friendship (as LPN) lost with Friend 0x%04x\n",
		       friend_addr);
	}
}

struct shell_cmd_help cmd_lpn_help = {
	NULL, "<value: off, on>", NULL
};

#endif /* MESH_LOW_POWER */

static int check_addr_unassigned(uint8_t addr[BLE_DEV_ADDR_LEN])
{
	return memcmp(addr, (uint8_t[BLE_DEV_ADDR_LEN]){0, 0, 0, 0, 0, 0},
			BLE_DEV_ADDR_LEN) == 0;
}

static int cmd_init(int argc, char *argv[])
{
	int err;
	ble_addr_t addr;

	if (check_addr_unassigned(MYNEWT_VAL(BLE_PUBLIC_DEV_ADDR))) {
		/* Use NRPA */
		err = ble_hs_id_gen_rnd(1, &addr);
		assert(err == 0);
		err = ble_hs_id_set_rnd(addr.val);
		assert(err == 0);

		err = bt_mesh_init(addr.type, &prov, &comp);
	}
	else {
		err = bt_mesh_init(0, &prov, &comp);
	}

	if (err) {
		printk("Mesh initialization failed (err %d)\n", err);
	}

	printk("Mesh initialized\n");
	printk("Use \"pb-adv on\" or \"pb-gatt on\" to enable advertising\n");

	/* Set device key for vendor model */
	vnd_models[0].keys[0] = BT_MESH_KEY_DEV;

	if (IS_ENABLED(CONFIG_BT_TESTING)) {
		bt_test_cb_register(&bt_test_cb);
	}

#if MYNEWT_VAL(BLE_MESH_LOW_POWER)
	bt_mesh_lpn_set_cb(lpn_cb);
#endif

	return 0;
}

#if MYNEWT_VAL(BLE_MESH_GATT_PROXY)
static int cmd_ident(int argc, char *argv[])
{
	int err;

	err = bt_mesh_proxy_identity_enable();
	if (err) {
		printk("Failed advertise using Node Identity (err %d)\n", err);
	}

	return 0;
}
#endif /* MESH_GATT_PROXY */

static int cmd_get_comp(int argc, char *argv[])
{
	struct os_mbuf*comp = NET_BUF_SIMPLE(32);
	u8_t status, page = 0x00;
	int err;

	if (argc > 1) {
		page = strtol(argv[1], NULL, 0);
	}

	net_buf_simple_init(comp, 0);
	err = bt_mesh_cfg_comp_data_get(net.net_idx, net.dst, page,
					&status, comp);
	if (err) {
		printk("Getting composition failed (err %d)\n", err);
		return 0;
	}

	if (status != 0x00) {
		printk("Got non-success status 0x%02x\n", status);
		return 0;
	}

	printk("Got Composition Data for 0x%04x:\n", net.dst);
	printk("\tCID      0x%04x\n", net_buf_simple_pull_le16(comp));
	printk("\tPID      0x%04x\n", net_buf_simple_pull_le16(comp));
	printk("\tVID      0x%04x\n", net_buf_simple_pull_le16(comp));
	printk("\tCRPL     0x%04x\n", net_buf_simple_pull_le16(comp));
	printk("\tFeatures 0x%04x\n", net_buf_simple_pull_le16(comp));

	while (comp->om_len > 4) {
		u8_t sig, vnd;
		u16_t loc;
		int i;

		loc = net_buf_simple_pull_le16(comp);
		sig = net_buf_simple_pull_u8(comp);
		vnd = net_buf_simple_pull_u8(comp);

		printk("\n\tElement @ 0x%04x:\n", loc);

		if (comp->om_len < ((sig * 2) + (vnd * 4))) {
			printk("\t\t...truncated data!\n");
			break;
		}

		if (sig) {
			printk("\t\tSIG Models:\n");
		} else {
			printk("\t\tNo SIG Models\n");
		}

		for (i = 0; i < sig; i++) {
			u16_t mod_id = net_buf_simple_pull_le16(comp);

			printk("\t\t\t0x%04x\n", mod_id);
		}

		if (vnd) {
			printk("\t\tVendor Models:\n");
		} else {
			printk("\t\tNo Vendor Models\n");
		}

		for (i = 0; i < vnd; i++) {
			u16_t cid = net_buf_simple_pull_le16(comp);
			u16_t mod_id = net_buf_simple_pull_le16(comp);

			printk("\t\t\tCompany 0x%04x: 0x%04x\n", cid, mod_id);
		}
	}

	return 0;
}

struct shell_cmd_help cmd_get_comp_help = {
	NULL, "[page]", NULL
};

static int cmd_dst(int argc, char *argv[])
{
	if (argc < 2) {
		printk("Destination address: 0x%04x%s\n", net.dst,
		       net.dst == net.local ? " (local)" : "");
		return 0;
	}

	if (!strcmp(argv[1], "local")) {
		net.dst = net.local;
	} else {
		net.dst = strtoul(argv[1], NULL, 0);
	}

	printk("Destination address set to 0x%04x%s\n", net.dst,
	       net.dst == net.local ? " (local)" : "");
	return 0;
}

struct shell_cmd_help cmd_dst_help = {
	NULL, "[destination address]", NULL
};

static int cmd_netidx(int argc, char *argv[])
{
	if (argc < 2) {
		printk("NetIdx: 0x%04x\n", net.net_idx);
		return 0;
	}

	net.net_idx = strtoul(argv[1], NULL, 0);
	printk("NetIdx set to 0x%04x\n", net.net_idx);
	return 0;
}

struct shell_cmd_help cmd_netidx_help = {
	NULL, "[NetIdx]", NULL
};

static int cmd_appidx(int argc, char *argv[])
{
	if (argc < 2) {
		printk("AppIdx: 0x%04x\n", net.app_idx);
		return 0;
	}

	net.app_idx = strtoul(argv[1], NULL, 0);
	printk("AppIdx set to 0x%04x\n", net.app_idx);
	return 0;
}

struct shell_cmd_help cmd_appidx_help = {
	NULL, "[AppIdx]", NULL
};

static int cmd_net_send_random_bytes(int argc, char *argv[])
{
	struct os_mbuf *msg = NET_BUF_SIMPLE(UINT16_MAX);
	struct bt_mesh_msg_ctx ctx = {
		.addr = net.dst,
		.net_idx = net.net_idx,
		.app_idx = net.app_idx,
		.send_ttl = bt_mesh_default_ttl_get()
	};
	struct bt_mesh_net_tx tx = {
		.ctx = &ctx,
		.src = net.local,
		.xmit = bt_mesh_net_transmit_get(),
	};
	u16_t len;
	u8_t byte;
	int err;
	int i;

	if (argc < 2) {
		err = -EINVAL;
		goto done;
	}

	len = strtoul(argv[1], NULL, 0);

	printk("Sending %d bytes", len);

	net_buf_simple_init(msg, 0);

	for (i = 0, byte = 0; i < len ; ++i) {
		net_buf_simple_add_u8(msg, byte++);
	}

	err = bt_mesh_trans_send(&tx, msg, NULL, NULL);
	if (err) {
		printk("Failed to send (err %d)\n", err);
	}

done:
	os_mbuf_free(msg);
	return err;
}

struct shell_cmd_help cmd_net_send_random_bytes_help = {
	NULL, "<number of bytes>", NULL
};

static int cmd_net_send(int argc, char *argv[])
{
	struct os_mbuf *msg = NET_BUF_SIMPLE(UINT8_MAX);
	struct bt_mesh_msg_ctx ctx = {
		.net_idx = net.net_idx,
		.app_idx = BT_MESH_KEY_DEV,
	};
	size_t len;
	u8_t ttl;
	u16_t dst;
	int err;

	if (argc < 4) {
		err = -EINVAL;
		goto done;
	}

	ttl = strtoul(argv[1], NULL, 0);
	dst = strtoul(argv[2], NULL, 0);

	net_buf_simple_init(msg, 0);
	len = hex2bin(argv[3], msg->om_data, net_buf_simple_tailroom(msg) - 4);
	net_buf_simple_add_mem(msg, msg->om_data, len);

	ctx.send_ttl = ttl;
	ctx.addr = dst;

	printk("ttl 0x%02x dst 0x%04x payload_len %d\n", ttl,
	       dst, len);

	err = bt_mesh_model_send(&vnd_models[0], &ctx, msg, NULL, NULL);
	if (err) {
		printk("Failed to send (err %d)\n", err);
	}

done:
	os_mbuf_free(msg);
	return err;
}

struct shell_cmd_help cmd_net_send_help = {
	NULL, "<ttl> <dst> <hex string>", NULL
};

static int cmd_model_send(int argc, char *argv[])
{
	struct bt_mesh_model *model = NULL;
	struct os_mbuf *msg = NET_BUF_SIMPLE(UINT8_MAX);
	struct bt_mesh_msg_ctx ctx = {
		.net_idx = net.net_idx,
		.app_idx = BT_MESH_KEY_DEV,
		.send_ttl = BT_MESH_TTL_DEFAULT,
	};
	size_t len;
	u16_t src, dst;
	int err, i;

	if (argc < 4) {
		err = -EINVAL;
		goto done;
	}

	src = strtoul(argv[1], NULL, 0);
	dst = strtoul(argv[2], NULL, 0);

	/* Lookup source address */
	for (i = 0; i < ARRAY_SIZE(model_bound); i++) {
		if (model_bound[i].model->elem->addr == src) {
			model = model_bound[i].model;
			ctx.app_idx = model_bound[i].appkey_idx;

			break;
		}
	}

	if (!model) {
		printk("Model not found\n");
		err = -EINVAL;

		goto done;
	}

	net_buf_simple_init(msg, 0);
	len = hex2bin(argv[3], msg->om_data, net_buf_simple_tailroom(msg) - 4);
	net_buf_simple_add_mem(msg, msg->om_data, len);

	ctx.addr = dst;

	printk("src 0x%04x dst 0x%04x payload_len %d\n", src,
	       dst, len);

	err = bt_mesh_model_send(model, &ctx, msg, NULL, NULL);
	if (err) {
		printk("Failed to send (err %d)\n", err);
	}


done:
	os_mbuf_free(msg);
	return err;
}

struct shell_cmd_help cmd_model_send_help = {
	NULL, "<src> <dst> <hex string>", NULL
};

static int cmd_iv_update(int argc, char *argv[])
{
	if (bt_mesh_iv_update()) {
		printk("Transitioned to IV Update In Progress state\n");
	} else {
		printk("Transitioned to IV Update Normal state\n");
	}

	printk("IV Index is 0x%08lx\n", bt_mesh.iv_index);

	return 0;
}

static int cmd_rpl_clear(int argc, char *argv[])
{
	bt_mesh_rpl_clear();
	return 0;
}

#if MYNEWT_VAL(BLE_MESH_LOW_POWER)
static int cmd_lpn_subscribe(int argc, char *argv[])
{
	u16_t address;

	if (argc < 2) {
		return -EINVAL;
	}

	address = strtoul(argv[1], NULL, 0);

	printk("address 0x%04x", address);

	bt_mesh_lpn_group_add(address);

	return 0;
}

struct shell_cmd_help cmd_lpn_subscribe_help = {
	NULL, "<addr>", NULL
};

static int cmd_lpn_unsubscribe(int argc, char *argv[])
{
	u16_t address;

	if (argc < 2) {
		return -EINVAL;
	}

	address = strtoul(argv[1], NULL, 0);

	printk("address 0x%04x", address);

	bt_mesh_lpn_group_del(&address, 1);

	return 0;
}

struct shell_cmd_help cmd_lpn_unsubscribe_help = {
	NULL, "<addr>", NULL
};
#endif

static int cmd_iv_update_test(int argc, char *argv[])
{
	bool enable;

	if (argc < 2) {
		return -EINVAL;
	}

	enable = str2bool(argv[1]);
	if (enable) {
		printk("Enabling IV Update test mode\n");
	} else {
		printk("Disabling IV Update test mode\n");
	}

	bt_mesh_iv_update_test(enable);

	return 0;
}

struct shell_cmd_help cmd_iv_update_test_help = {
	NULL, "<value: off, on>", NULL
};

static int cmd_beacon(int argc, char *argv[])
{
	u8_t status;
	int err;

	if (argc < 2) {
		err = bt_mesh_cfg_beacon_get(net.net_idx, net.dst, &status);
	} else {
		u8_t val = str2u8(argv[1]);

		err = bt_mesh_cfg_beacon_set(net.net_idx, net.dst, val,
					     &status);
	}

	if (err) {
		printk("Unable to send Beacon Get/Set message (err %d)\n", err);
		return 0;
	}

	printk("Beacon state is 0x%02x\n", status);

	return 0;
}

struct shell_cmd_help cmd_beacon_help = {
	NULL, "[val: off, on]", NULL
};

static int cmd_ttl(int argc, char *argv[])
{
	u8_t ttl;
	int err;

	if (argc < 2) {
		err = bt_mesh_cfg_ttl_get(net.net_idx, net.dst, &ttl);
	} else {
		u8_t val = strtoul(argv[1], NULL, 0);

		err = bt_mesh_cfg_ttl_set(net.net_idx, net.dst, val, &ttl);
	}

	if (err) {
		printk("Unable to send Default TTL Get/Set (err %d)\n", err);
		return 0;
	}

	printk("Default TTL is 0x%02x\n", ttl);

	return 0;
}

struct shell_cmd_help cmd_ttl_help = {
	NULL, "[ttl: 0x00, 0x02-0x7f]", NULL
};

static int cmd_friend(int argc, char *argv[])
{
	u8_t frnd;
	int err;

	if (argc < 2) {
		err = bt_mesh_cfg_friend_get(net.net_idx, net.dst, &frnd);
	} else {
		u8_t val = str2u8(argv[1]);

		err = bt_mesh_cfg_friend_set(net.net_idx, net.dst, val, &frnd);
	}

	if (err) {
		printk("Unable to send Friend Get/Set (err %d)\n", err);
		return 0;
	}

	printk("Friend is set to 0x%02x\n", frnd);

	return 0;
}

struct shell_cmd_help cmd_friend_help = {
	NULL, "[val: off, on]", NULL
};

static int cmd_gatt_proxy(int argc, char *argv[])
{
	u8_t proxy;
	int err;

	if (argc < 2) {
		err = bt_mesh_cfg_gatt_proxy_get(net.net_idx, net.dst, &proxy);
	} else {
		u8_t val = str2u8(argv[1]);

		err = bt_mesh_cfg_gatt_proxy_set(net.net_idx, net.dst, val,
						 &proxy);
	}

	if (err) {
		printk("Unable to send GATT Proxy Get/Set (err %d)\n", err);
		return 0;
	}

	printk("GATT Proxy is set to 0x%02x\n", proxy);

	return 0;
}

struct shell_cmd_help cmd_gatt_proxy_help = {
	NULL, "[val: off, on]", NULL
};

static int cmd_relay(int argc, char *argv[])
{
	u8_t relay, transmit;
	int err;

	if (argc < 2) {
		err = bt_mesh_cfg_relay_get(net.net_idx, net.dst, &relay,
					    &transmit);
	} else {
		u8_t val = str2u8(argv[1]);
		u8_t count, interval, new_transmit;

		if (val) {
			if (argc > 2) {
				count = strtoul(argv[2], NULL, 0);
			} else {
				count = 2;
			}

			if (argc > 3) {
				interval = strtoul(argv[3], NULL, 0);
			} else {
				interval = 20;
			}

			new_transmit = BT_MESH_TRANSMIT(count, interval);
		} else {
			new_transmit = 0;
		}

		err = bt_mesh_cfg_relay_set(net.net_idx, net.dst, val,
					    new_transmit, &relay, &transmit);
	}

	if (err) {
		printk("Unable to send Relay Get/Set (err %d)\n", err);
		return 0;
	}

	printk("Relay is 0x%02x, Transmit 0x%02x (count %u interval %ums)\n",
	       relay, transmit, BT_MESH_TRANSMIT_COUNT(transmit),
	       BT_MESH_TRANSMIT_INT(transmit));

	return 0;
}

struct shell_cmd_help cmd_relay_help = {
	NULL, "[val: off, on] [count: 0-7] [interval: 0-32]", NULL
};

static int cmd_net_key_add(int argc, char *argv[])
{
	u8_t key_val[16];
	u16_t key_net_idx;
	u8_t status;
	int err;

	if (argc < 2) {
		return -EINVAL;
	}

	key_net_idx = strtoul(argv[1], NULL, 0);

	if (argc > 2) {
		size_t len;

		len = hex2bin(argv[3], key_val, sizeof(key_val));
		memset(key_val, 0, sizeof(key_val) - len);
	} else {
		memcpy(key_val, default_key, sizeof(key_val));
	}

	err = bt_mesh_cfg_net_key_add(net.net_idx, net.dst, key_net_idx,
				      key_val, &status);
	if (err) {
		printk("Unable to send NetKey Add (err %d)\n", err);
		return 0;
	}

	if (status) {
		printk("NetKeyAdd failed with status 0x%02x\n", status);
	} else {
		printk("NetKey added with NetKey Index 0x%03x\n", key_net_idx);
	}

	return 0;
}

struct shell_cmd_help cmd_net_key_add_help = {
	NULL, "<NetKeyIndex> [val]", NULL
};

static int cmd_app_key_add(int argc, char *argv[])
{
	u8_t key_val[16];
	u16_t key_net_idx, key_app_idx;
	u8_t status;
	int err;

	if (argc < 3) {
		return -EINVAL;
	}

	key_net_idx = strtoul(argv[1], NULL, 0);
	key_app_idx = strtoul(argv[2], NULL, 0);

	if (argc > 3) {
		size_t len;

		len = hex2bin(argv[3], key_val, sizeof(key_val));
		memset(key_val, 0, sizeof(key_val) - len);
	} else {
		memcpy(key_val, default_key, sizeof(key_val));
	}

	err = bt_mesh_cfg_app_key_add(net.net_idx, net.dst, key_net_idx,
				      key_app_idx, key_val, &status);
	if (err) {
		printk("Unable to send App Key Add (err %d)\n", err);
		return 0;
	}

	if (status) {
		printk("AppKeyAdd failed with status 0x%02x\n", status);
	} else {
		printk("AppKey added, NetKeyIndex 0x%04x AppKeyIndex 0x%04x\n",
		       key_net_idx, key_app_idx);
	}

	return 0;
}

struct shell_cmd_help cmd_app_key_add_help = {
	NULL, "<NetKeyIndex> <AppKeyIndex> [val]", NULL
};

static int cmd_mod_app_bind(int argc, char *argv[])
{
	u16_t elem_addr, mod_app_idx, mod_id, cid;
	u8_t status;
	int err;

	if (argc < 4) {
		return -EINVAL;
	}

	elem_addr = strtoul(argv[1], NULL, 0);
	mod_app_idx = strtoul(argv[2], NULL, 0);
	mod_id = strtoul(argv[3], NULL, 0);

	if (argc > 4) {
		cid = strtoul(argv[4], NULL, 0);
		err = bt_mesh_cfg_mod_app_bind_vnd(net.net_idx, net.dst,
						   elem_addr, mod_app_idx,
						   mod_id, cid, &status);
	} else {
		err = bt_mesh_cfg_mod_app_bind(net.net_idx, net.dst, elem_addr,
					       mod_app_idx, mod_id, &status);
	}

	if (err) {
		printk("Unable to send Model App Bind (err %d)\n", err);
		return 0;
	}

	if (status) {
		printk("Model App Bind failed with status 0x%02x\n", status);
	} else {
		printk("AppKey successfully bound\n");
	}

	return 0;
}

struct shell_cmd_help cmd_mod_app_bind_help = {
	NULL, "<addr> <AppIndex> <Model ID> [Company ID]", NULL
};

static int cmd_mod_sub_add(int argc, char *argv[])
{
	u16_t elem_addr, sub_addr, mod_id, cid;
	u8_t status;
	int err;

	if (argc < 4) {
		return -EINVAL;
	}

	elem_addr = strtoul(argv[1], NULL, 0);
	sub_addr = strtoul(argv[2], NULL, 0);
	mod_id = strtoul(argv[3], NULL, 0);

	if (argc > 4) {
		cid = strtoul(argv[4], NULL, 0);
		err = bt_mesh_cfg_mod_sub_add_vnd(net.net_idx, net.dst,
						  elem_addr, sub_addr, mod_id,
						  cid, &status);
	} else {
		err = bt_mesh_cfg_mod_sub_add(net.net_idx, net.dst, elem_addr,
					      sub_addr, mod_id, &status);
	}

	if (err) {
		printk("Unable to send Model Subscription Add (err %d)\n", err);
		return 0;
	}

	if (status) {
		printk("Model Subscription Add failed with status 0x%02x\n",
		       status);
	} else {
		printk("Model subscription was successful\n");
	}

	return 0;
}

struct shell_cmd_help cmd_mod_sub_add_help = {
	NULL, "<elem addr> <sub addr> <Model ID> [Company ID]", NULL
};

static int cmd_mod_sub_del(int argc, char *argv[])
{
	u16_t elem_addr, sub_addr, mod_id, cid;
	u8_t status;
	int err;

	if (argc < 4) {
		return -EINVAL;
	}

	elem_addr = strtoul(argv[1], NULL, 0);
	sub_addr = strtoul(argv[2], NULL, 0);
	mod_id = strtoul(argv[3], NULL, 0);

	if (argc > 4) {
		cid = strtoul(argv[4], NULL, 0);
		err = bt_mesh_cfg_mod_sub_del_vnd(net.net_idx, net.dst,
						  elem_addr, sub_addr, mod_id,
						  cid, &status);
	} else {
		err = bt_mesh_cfg_mod_sub_del(net.net_idx, net.dst, elem_addr,
					      sub_addr, mod_id, &status);
	}

	if (err) {
		printk("Unable to send Model Subscription Delete (err %d)\n",
		       err);
		return 0;
	}

	if (status) {
		printk("Model Subscription Delete failed with status 0x%02x\n",
		       status);
	} else {
		printk("Model subscription deltion was successful\n");
	}

	return 0;
}

struct shell_cmd_help cmd_mod_sub_del_help = {
	NULL, "<elem addr> <sub addr> <Model ID> [Company ID]", NULL
};

static int cmd_mod_sub_add_va(int argc, char *argv[])
{
	u16_t elem_addr, sub_addr, mod_id, cid;
	u8_t label[16];
	u8_t status;
	size_t len;
	int err;

	if (argc < 4) {
		return -EINVAL;
	}

	elem_addr = strtoul(argv[1], NULL, 0);

	len = hex2bin(argv[2], label, sizeof(label));
	memset(label + len, 0, sizeof(label) - len);

	mod_id = strtoul(argv[3], NULL, 0);

	if (argc > 4) {
		cid = strtoul(argv[4], NULL, 0);
		err = bt_mesh_cfg_mod_sub_va_add_vnd(net.net_idx, net.dst,
						     elem_addr, label, mod_id,
						     cid, &sub_addr, &status);
	} else {
		err = bt_mesh_cfg_mod_sub_va_add(net.net_idx, net.dst,
						 elem_addr, label, mod_id,
						 &sub_addr, &status);
	}

	if (err) {
		printk("Unable to send Mod Sub VA Add (err %d)\n", err);
		return 0;
	}

	if (status) {
		printk("Mod Sub VA Add failed with status 0x%02x\n",
		       status);
	} else {
		printk("0x%04x subscribed to Label UUID %s (va 0x%04x)\n",
		       elem_addr, argv[2], sub_addr);
	}

	return 0;
}

struct shell_cmd_help cmd_mod_sub_add_va_help = {
	NULL, "<elem addr> <Label UUID> <Model ID> [Company ID]", NULL
};

static int cmd_mod_sub_del_va(int argc, char *argv[])
{
	u16_t elem_addr, sub_addr, mod_id, cid;
	u8_t label[16];
	u8_t status;
	size_t len;
	int err;

	if (argc < 4) {
		return -EINVAL;
	}

	elem_addr = strtoul(argv[1], NULL, 0);

	len = hex2bin(argv[2], label, sizeof(label));
	memset(label + len, 0, sizeof(label) - len);

	mod_id = strtoul(argv[3], NULL, 0);

	if (argc > 4) {
		cid = strtoul(argv[4], NULL, 0);
		err = bt_mesh_cfg_mod_sub_va_del_vnd(net.net_idx, net.dst,
						     elem_addr, label, mod_id,
						     cid, &sub_addr, &status);
	} else {
		err = bt_mesh_cfg_mod_sub_va_del(net.net_idx, net.dst,
						 elem_addr, label, mod_id,
						 &sub_addr, &status);
	}

	if (err) {
		printk("Unable to send Model Subscription Delete (err %d)\n",
		       err);
		return 0;
	}

	if (status) {
		printk("Model Subscription Delete failed with status 0x%02x\n",
		       status);
	} else {
		printk("0x%04x unsubscribed from Label UUID %s (va 0x%04x)\n",
		       elem_addr, argv[2], sub_addr);
	}

	return 0;
}

struct shell_cmd_help cmd_mod_sub_del_va_help = {
	NULL, "<elem addr> <Label UUID> <Model ID> [Company ID]", NULL
};

static int mod_pub_get(u16_t addr, u16_t mod_id, u16_t cid)
{
	struct bt_mesh_cfg_mod_pub pub;
	u8_t status;
	int err;

	if (cid == CID_NVAL) {
		err = bt_mesh_cfg_mod_pub_get(net.net_idx, net.dst, addr,
					      mod_id, &pub, &status);
	} else {
		err = bt_mesh_cfg_mod_pub_get_vnd(net.net_idx, net.dst, addr,
						  mod_id, cid, &pub, &status);
	}

	if (err) {
		printk("Model Publication Get failed (err %d)\n", err);
		return 0;
	}

	if (status) {
		printk("Model Publication Get failed (status 0x%02x)\n",
		       status);
		return 0;
	}

	printk("Model Publication for Element 0x%04x, Model 0x%04x:\n"
	       "\tPublish Address:                0x%04x\n"
	       "\tAppKeyIndex:                    0x%04x\n"
	       "\tCredential Flag:                %u\n"
	       "\tPublishTTL:                     %u\n"
	       "\tPublishPeriod:                  0x%02x\n"
	       "\tPublishRetransmitCount:         %u\n"
	       "\tPublishRetransmitInterval:      %ums\n",
	       addr, mod_id, pub.addr, pub.app_idx, pub.cred_flag, pub.ttl,
	       pub.period, BT_MESH_PUB_TRANSMIT_COUNT(pub.transmit),
	       BT_MESH_PUB_TRANSMIT_INT(pub.transmit));

	return 0;
}

static int mod_pub_set(u16_t addr, u16_t mod_id, u16_t cid, char *argv[])
{
	struct bt_mesh_cfg_mod_pub pub;
	u8_t status, count;
	u16_t interval;
	int err;

	pub.addr = strtoul(argv[0], NULL, 0);
	pub.app_idx = strtoul(argv[1], NULL, 0);
	pub.cred_flag = str2bool(argv[2]);
	pub.ttl = strtoul(argv[3], NULL, 0);
	pub.period = strtoul(argv[4], NULL, 0);

	count = strtoul(argv[5], NULL, 0);
	if (count > 7) {
		printk("Invalid retransmit count\n");
		return -EINVAL;
	}

	interval = strtoul(argv[6], NULL, 0);
	if (interval > (31 * 50) || (interval % 50)) {
		printk("Invalid retransmit interval %u\n", interval);
		return -EINVAL;
	}

	pub.transmit = BT_MESH_PUB_TRANSMIT(count, interval);

	if (cid == CID_NVAL) {
		err = bt_mesh_cfg_mod_pub_set(net.net_idx, net.dst, addr,
					      mod_id, &pub, &status);
	} else {
		err = bt_mesh_cfg_mod_pub_set_vnd(net.net_idx, net.dst, addr,
						  mod_id, cid, &pub, &status);
	}

	if (err) {
		printk("Model Publication Set failed (err %d)\n", err);
		return 0;
	}

	if (status) {
		printk("Model Publication Set failed (status 0x%02x)\n",
		       status);
	} else {
		printk("Model Publication successfully set\n");
	}

	return 0;
}

static int cmd_mod_pub(int argc, char *argv[])
{
	u16_t addr, mod_id, cid;

	if (argc < 3) {
		return -EINVAL;
	}

	addr = strtoul(argv[1], NULL, 0);
	mod_id = strtoul(argv[2], NULL, 0);

	argc -= 3;
	argv += 3;

	if (argc == 1 || argc == 8) {
		cid = strtoul(argv[0], NULL, 0);
		argc--;
		argv++;
	} else {
		cid = CID_NVAL;
	}

	if (argc > 0) {
		if (argc < 7) {
			return -EINVAL;
		}

		return mod_pub_set(addr, mod_id, cid, argv);
	} else {
		return mod_pub_get(addr, mod_id, cid);
	}
}

struct shell_cmd_help cmd_mod_pub_help = {
	NULL, "<addr> <mod id> [cid] [<PubAddr> "
	"<AppKeyIndex> <cred> <ttl> <period> <count> <interval>]" , NULL
};

static void hb_sub_print(struct bt_mesh_cfg_hb_sub *sub)
{
	printk("Heartbeat Subscription:\n"
	       "\tSource:      0x%04x\n"
	       "\tDestination: 0x%04x\n"
	       "\tPeriodLog:   0x%02x\n"
	       "\tCountLog:    0x%02x\n"
	       "\tMinHops:     %u\n"
	       "\tMaxHops:     %u\n",
	       sub->src, sub->dst, sub->period, sub->count,
	       sub->min, sub->max);
}

static int hb_sub_get(int argc, char *argv[])
{
	struct bt_mesh_cfg_hb_sub sub;
	u8_t status;
	int err;

	err = bt_mesh_cfg_hb_sub_get(net.net_idx, net.dst, &sub, &status);
	if (err) {
		printk("Heartbeat Subscription Get failed (err %d)\n", err);
		return 0;
	}

	if (status) {
		printk("Heartbeat Subscription Get failed (status 0x%02x)\n",
		       status);
	} else {
		hb_sub_print(&sub);
	}

	return 0;
}

static int hb_sub_set(int argc, char *argv[])
{
	struct bt_mesh_cfg_hb_sub sub;
	u8_t status;
	int err;

	sub.src = strtoul(argv[1], NULL, 0);
	sub.dst = strtoul(argv[2], NULL, 0);
	sub.period = strtoul(argv[3], NULL, 0);

	err = bt_mesh_cfg_hb_sub_set(net.net_idx, net.dst, &sub, &status);
	if (err) {
		printk("Heartbeat Subscription Set failed (err %d)\n", err);
		return 0;
	}

	if (status) {
		printk("Heartbeat Subscription Set failed (status 0x%02x)\n",
		       status);
	} else {
		hb_sub_print(&sub);
	}

	return 0;
}

static int cmd_hb_sub(int argc, char *argv[])
{
	if (argc > 1) {
		if (argc < 4) {
			return -EINVAL;
		}

		return hb_sub_set(argc, argv);
	} else {
		return hb_sub_get(argc, argv);
	}
}

struct shell_cmd_help cmd_hb_sub_help = {
	NULL, "<src> <dst> <period>", NULL
};

static int hb_pub_get(int argc, char *argv[])
{
	struct bt_mesh_cfg_hb_pub pub;
	u8_t status;
	int err;

	err = bt_mesh_cfg_hb_pub_get(net.net_idx, net.dst, &pub, &status);
	if (err) {
		printk("Heartbeat Publication Get failed (err %d)\n", err);
		return 0;
	}

	if (status) {
		printk("Heartbeat Publication Get failed (status 0x%02x)\n",
		       status);
		return 0;
	}

	printk("Heartbeat publication:\n");
	printk("\tdst 0x%04x count 0x%02x period 0x%02x\n",
	       pub.dst, pub.count, pub.period);
	printk("\tttl 0x%02x feat 0x%04x net_idx 0x%04x\n",
	       pub.ttl, pub.feat, pub.net_idx);

	return 0;
}

static int hb_pub_set(int argc, char *argv[])
{
	struct bt_mesh_cfg_hb_pub pub;
	u8_t status;
	int err;

	pub.dst = strtoul(argv[1], NULL, 0);
	pub.count = strtoul(argv[2], NULL, 0);
	pub.period = strtoul(argv[3], NULL, 0);
	pub.ttl = strtoul(argv[4], NULL, 0);
	pub.feat = strtoul(argv[5], NULL, 0);
	pub.net_idx = strtoul(argv[5], NULL, 0);

	err = bt_mesh_cfg_hb_pub_set(net.net_idx, net.dst, &pub, &status);
	if (err) {
		printk("Heartbeat Publication Set failed (err %d)\n", err);
		return 0;
	}

	if (status) {
		printk("Heartbeat Publication Set failed (status 0x%02x)\n",
		       status);
	} else {
		printk("Heartbeat publication successfully set\n");
	}

	return 0;
}

static int cmd_hb_pub(int argc, char *argv[])
{
	if (argc > 1) {
		if (argc < 7) {
			return -EINVAL;
		}

		return hb_pub_set(argc, argv);
	} else {
		return hb_pub_get(argc, argv);
	}
}

struct shell_cmd_help cmd_hb_pub_help = {
	NULL, "<dst> <count> <period> <ttl> <features> <NetKeyIndex>" , NULL
};

#if MYNEWT_VAL(BLE_MESH_PROV)
static int cmd_pb(bt_mesh_prov_bearer_t bearer, int argc, char *argv[])
{
	int err;

	if (argc < 2) {
		return -EINVAL;
	}

	if (str2bool(argv[1])) {
		err = bt_mesh_prov_enable(bearer);
		if (err) {
			printk("Failed to enable %s (err %d)\n",
			       bearer2str(bearer), err);
		} else {
			printk("%s enabled\n", bearer2str(bearer));
		}
	} else {
		err = bt_mesh_prov_disable(bearer);
		if (err) {
			printk("Failed to disable %s (err %d)\n",
			       bearer2str(bearer), err);
		} else {
			printk("%s disabled\n", bearer2str(bearer));
		}
	}

	return 0;

}

struct shell_cmd_help cmd_pb_help = {
	NULL, "<val: off, on>", NULL
};

#endif

#if MYNEWT_VAL(BLE_MESH_PB_ADV)
static int cmd_pb_adv(int argc, char *argv[])
{
	return cmd_pb(BT_MESH_PROV_ADV, argc, argv);
}
#endif /* CONFIG_BT_MESH_PB_ADV */

#if MYNEWT_VAL(BLE_MESH_PB_GATT)
static int cmd_pb_gatt(int argc, char *argv[])
{
	return cmd_pb(BT_MESH_PROV_GATT, argc, argv);
}
#endif /* CONFIG_BT_MESH_PB_GATT */

static int cmd_provision(int argc, char *argv[])
{
	u16_t net_idx, addr;
	u32_t iv_index;
	int err;

	if (argc < 3) {
		return -EINVAL;
	}

	net_idx = strtoul(argv[1], NULL, 0);
	addr = strtoul(argv[2], NULL, 0);

	if (argc > 3) {
		iv_index = strtoul(argv[3], NULL, 0);
	} else {
		iv_index = 0;
	}

	err = bt_mesh_provision(default_key, net_idx, 0, iv_index, 0, addr,
				default_key);
	if (err) {
		printk("Provisioning failed (err %d)\n", err);
	}

	return 0;
}

struct shell_cmd_help cmd_provision_help = {
	NULL, "<NetKeyIndex> <addr> [IVIndex]" , NULL
};

int cmd_timeout(int argc, char *argv[])
{
	s32_t timeout;

	if (argc < 2) {
		timeout = bt_mesh_cfg_cli_timeout_get();
		if (timeout == K_FOREVER) {
			printk("Message timeout: forever\n");
		} else {
			printk("Message timeout: %lu seconds\n",
			       timeout / 1000);
		}

		return 0;
	}

	timeout = strtol(argv[1], NULL, 0);
	if (timeout < 0 || timeout > (INT32_MAX / 1000)) {
		timeout = K_FOREVER;
	} else {
		timeout = timeout * 1000;
	}

	bt_mesh_cfg_cli_timeout_set(timeout);
	if (timeout == K_FOREVER) {
		printk("Message timeout: forever\n");
	} else {
		printk("Message timeout: %lu seconds\n",
		       timeout / 1000);
	}

	return 0;
}

struct shell_cmd_help cmd_timeout_help = {
	NULL, "[timeout in seconds]", NULL
};

static int cmd_fault_get(int argc, char *argv[])
{
	u8_t faults[32];
	size_t fault_count;
	u8_t test_id;
	u16_t cid;
	int err;

	if (argc < 2) {
		return -EINVAL;
	}

	cid = strtoul(argv[1], NULL, 0);
	fault_count = sizeof(faults);

	err = bt_mesh_health_fault_get(net.net_idx, net.dst, net.app_idx, cid,
				       &test_id, faults, &fault_count);
	if (err) {
		printk("Failed to send Health Fault Get (err %d)\n", err);
	} else {
		show_faults(test_id, cid, faults, fault_count);
	}

	return 0;
}

struct shell_cmd_help cmd_fault_get_help = {
	NULL, "<Company ID>", NULL
};

static int cmd_fault_clear(int argc, char *argv[])
{
	u8_t faults[32];
	size_t fault_count;
	u8_t test_id;
	u16_t cid;
	int err;

	if (argc < 2) {
		return -EINVAL;
	}

	cid = strtoul(argv[1], NULL, 0);
	fault_count = sizeof(faults);

	err = bt_mesh_health_fault_clear(net.net_idx, net.dst, net.app_idx,
					 cid, &test_id, faults, &fault_count);
	if (err) {
		printk("Failed to send Health Fault Clear (err %d)\n", err);
	} else {
		show_faults(test_id, cid, faults, fault_count);
	}

	return 0;
}

struct shell_cmd_help cmd_fault_clear_help = {
	NULL, "<Company ID>", NULL
};

static int cmd_fault_clear_unack(int argc, char *argv[])
{
	u16_t cid;
	int err;

	if (argc < 2) {
		return -EINVAL;
	}

	cid = strtoul(argv[1], NULL, 0);

	err = bt_mesh_health_fault_clear(net.net_idx, net.dst, net.app_idx,
					 cid, NULL, NULL, NULL);
	if (err) {
		printk("Health Fault Clear Unacknowledged failed (err %d)\n",
		       err);
	}

	return 0;
}

struct shell_cmd_help cmd_fault_clear_unack_help = {
	NULL, "<Company ID>", NULL
};

static int cmd_fault_test(int argc, char *argv[])
{
	u8_t faults[32];
	size_t fault_count;
	u8_t test_id;
	u16_t cid;
	int err;

	if (argc < 3) {
		return -EINVAL;
	}

	cid = strtoul(argv[1], NULL, 0);
	test_id = strtoul(argv[2], NULL, 0);
	fault_count = sizeof(faults);

	err = bt_mesh_health_fault_test(net.net_idx, net.dst, net.app_idx,
					cid, test_id, faults, &fault_count);
	if (err) {
		printk("Failed to send Health Fault Test (err %d)\n", err);
	} else {
		show_faults(test_id, cid, faults, fault_count);
	}

	return 0;
}

struct shell_cmd_help cmd_fault_test_help = {
	NULL, "<Company ID> <Test ID>", NULL
};

static int cmd_fault_test_unack(int argc, char *argv[])
{
	u16_t cid;
	u8_t test_id;
	int err;

	if (argc < 3) {
		return -EINVAL;
	}

	cid = strtoul(argv[1], NULL, 0);
	test_id = strtoul(argv[2], NULL, 0);

	err = bt_mesh_health_fault_test(net.net_idx, net.dst, net.app_idx,
					cid, test_id, NULL, NULL);
	if (err) {
		printk("Health Fault Test Unacknowledged failed (err %d)\n",
		       err);
	}

	return 0;
}

struct shell_cmd_help cmd_fault_test_unack_help = {
	NULL, "<Company ID> <Test ID>", NULL
};

static int cmd_period_get(int argc, char *argv[])
{
	u8_t divisor;
	int err;

	err = bt_mesh_health_period_get(net.net_idx, net.dst, net.app_idx,
					&divisor);
	if (err) {
		printk("Failed to send Health Period Get (err %d)\n", err);
	} else {
		printk("Health FastPeriodDivisor: %u\n", divisor);
	}

	return 0;
}

static int cmd_period_set(int argc, char *argv[])
{
	u8_t divisor, updated_divisor;
	int err;

	if (argc < 2) {
		return -EINVAL;
	}

	divisor = strtoul(argv[1], NULL, 0);

	err = bt_mesh_health_period_set(net.net_idx, net.dst, net.app_idx,
					divisor, &updated_divisor);
	if (err) {
		printk("Failed to send Health Period Set (err %d)\n", err);
	} else {
		printk("Health FastPeriodDivisor: %u\n", updated_divisor);
	}

	return 0;
}

struct shell_cmd_help cmd_period_set_help = {
	NULL, "<divisor>", NULL
};

static int cmd_period_set_unack(int argc, char *argv[])
{
	u8_t divisor;
	int err;

	if (argc < 2) {
		return -EINVAL;
	}

	divisor = strtoul(argv[1], NULL, 0);

	err = bt_mesh_health_period_set(net.net_idx, net.dst, net.app_idx,
					divisor, NULL);
	if (err) {
		printk("Failed to send Health Period Set (err %d)\n", err);
	}

	return 0;
}

struct shell_cmd_help cmd_period_set_unack_help = {
	NULL, "<divisor>", NULL
};

static int cmd_attention_get(int argc, char *argv[])
{
	u8_t attention;
	int err;

	err = bt_mesh_health_attention_get(net.net_idx, net.dst, net.app_idx,
					   &attention);
	if (err) {
		printk("Failed to send Health Attention Get (err %d)\n", err);
	} else {
		printk("Health Attention Timer: %u\n", attention);
	}

	return 0;
}

static int cmd_attention_set(int argc, char *argv[])
{
	u8_t attention, updated_attention;
	int err;

	if (argc < 2) {
		return -EINVAL;
	}

	attention = strtoul(argv[1], NULL, 0);

	err = bt_mesh_health_attention_set(net.net_idx, net.dst, net.app_idx,
					   attention, &updated_attention);
	if (err) {
		printk("Failed to send Health Attention Set (err %d)\n", err);
	} else {
		printk("Health Attention Timer: %u\n", updated_attention);
	}

	return 0;
}

struct shell_cmd_help cmd_attention_set_help = {
	NULL, "<timer>", NULL
};

static int cmd_attention_set_unack(int argc, char *argv[])
{
	u8_t attention;
	int err;

	if (argc < 2) {
		return -EINVAL;
	}

	attention = strtoul(argv[1], NULL, 0);

	err = bt_mesh_health_attention_set(net.net_idx, net.dst, net.app_idx,
					   attention, NULL);
	if (err) {
		printk("Failed to send Health Attention Set (err %d)\n", err);
	}

	return 0;
}

struct shell_cmd_help cmd_attention_set_unack_help = {
	NULL, "<timer>", NULL
};

static int cmd_add_fault(int argc, char *argv[])
{
	u8_t fault_id;
	u8_t i;

	if (argc < 2) {
		return -EINVAL;
	}

	fault_id = strtoul(argv[1], NULL, 0);
	if (!fault_id) {
		printk("The Fault ID must be non-zero!\n");
		return -EINVAL;
	}

	for (i = 0; i < sizeof(cur_faults); i++) {
		if (!cur_faults[i]) {
			cur_faults[i] = fault_id;
			break;
		}
	}

	if (i == sizeof(cur_faults)) {
		printk("Fault array is full. Use \"del-fault\" to clear it\n");
		return 0;
	}

	for (i = 0; i < sizeof(reg_faults); i++) {
		if (!reg_faults[i]) {
			reg_faults[i] = fault_id;
			break;
		}
	}

	if (i == sizeof(reg_faults)) {
		printk("No space to store more registered faults\n");
	}

	bt_mesh_fault_update(&elements[0]);

	return 0;
}

struct shell_cmd_help cmd_add_fault_help = {
	NULL, "<Fault ID>", NULL
};

static int cmd_del_fault(int argc, char *argv[])
{
	u8_t fault_id;
	u8_t i;

	if (argc < 2) {
		memset(cur_faults, 0, sizeof(cur_faults));
		printk("All current faults cleared\n");
		bt_mesh_fault_update(&elements[0]);
		return 0;
	}

	fault_id = strtoul(argv[1], NULL, 0);
	if (!fault_id) {
		printk("The Fault ID must be non-zero!\n");
		return -EINVAL;
	}

	for (i = 0; i < sizeof(cur_faults); i++) {
		if (cur_faults[i] == fault_id) {
			cur_faults[i] = 0;
			printk("Fault cleared\n");
		}
	}

	bt_mesh_fault_update(&elements[0]);

	return 0;
}

struct shell_cmd_help cmd_del_fault_help = {
	NULL, "[Fault ID]", NULL
};

static int cmd_print_credentials(int argc, char *argv[])
{
	bt_test_print_credentials();
	return 0;
}

static void print_comp_elem(struct bt_mesh_elem *elem,
			    bool primary)
{
	struct bt_mesh_model *mod;
	int i;

	printk("Loc: %u\n", elem->loc);
	printk("Model count: %u\n", elem->model_count);
	printk("Vnd model count: %u\n", elem->vnd_model_count);

	for (i = 0; i < elem->model_count; i++) {
		mod = &elem->models[i];
		printk("  Model: %u\n", i);
		printk("    ID: 0x%04x\n", mod->id);
		printk("    Opcode: 0x%08lx\n", mod->op->opcode);
	}

	for (i = 0; i < elem->vnd_model_count; i++) {
		mod = &elem->vnd_models[i];
		printk("  Vendor model: %u\n", i);
		printk("    Company: 0x%04x\n", mod->vnd.company);
		printk("    ID: 0x%04x\n", mod->vnd.id);
		printk("    Opcode: 0x%08lx\n", mod->op->opcode);
	}
}

static int cmd_print_composition_data(int argc, char *argv[])
{
	const struct bt_mesh_comp *comp;
	int i;

	comp = bt_mesh_comp_get();

	printk("CID: %u\n", comp->cid);
	printk("PID: %u\n", comp->pid);
	printk("VID: %u\n", comp->vid);

	for (i = 0; i < comp->elem_count; i++) {
		print_comp_elem(&comp->elem[i], i == 0);
	}

	return 0;
}

/*****************************************************************************
 * $white-list                                                               *
 *****************************************************************************/

#define CMD_WL_MAX_SZ   8

static struct kv_pair cmd_addr_type[] = {
    { "public",     BLE_ADDR_PUBLIC },
    { "random",     BLE_ADDR_RANDOM },
    { NULL }
};


static int
cmd_white_list(int argc, char **argv)
{
    static ble_addr_t addrs[CMD_WL_MAX_SZ];
    int addrs_cnt;
    int rc;

    rc = parse_arg_all(argc - 1, argv + 1);
    if (rc != 0) {
        return rc;
    }

    addrs_cnt = 0;
    while (1) {
        if (addrs_cnt >= CMD_WL_MAX_SZ) {
            return EINVAL;
        }

        rc = parse_arg_mac("addr", addrs[addrs_cnt].val);
        if (rc == ENOENT) {
            break;
        } else if (rc != 0) {
            console_printf("invalid 'addr' parameter\n");
            return rc;
        }

        addrs[addrs_cnt].type = parse_arg_kv("addr_type", cmd_addr_type, &rc);
        if (rc != 0) {
            console_printf("invalid 'addr' parameter\n");
            return rc;
        }

        addrs_cnt++;
    }

    if (addrs_cnt == 0) {
        return EINVAL;
    }

    rc = ble_gap_wl_set(addrs, addrs_cnt);
    bt_mesh_scan_filter_policy = 1;

    return rc;
}

static const struct shell_param white_list_params[] = {
    {"addr", "white-list device addresses, usage: =[XX:XX:XX:XX:XX:XX]"},
    {"addr_type", "white-list address types, usage: =[public|random]"},
    {NULL, NULL}
};

static const struct shell_cmd_help white_list_help = {
    .summary = "set white-list addresses",
    .usage = NULL,
    .params = white_list_params,
};

static const struct shell_cmd mesh_commands[] = {
	{ "init", cmd_init, NULL },
	{ "white-list", cmd_white_list, &white_list_help },
	{ "timeout", cmd_timeout, &cmd_timeout_help },
#if MYNEWT_VAL(BLE_MESH_PB_ADV)
	{ "pb-adv", cmd_pb_adv, &cmd_pb_help },
#endif
#if MYNEWT_VAL(BLE_MESH_PB_GATT)
	{ "pb-gatt", cmd_pb_gatt, &cmd_pb_help },
#endif
	{ "reset", cmd_reset, NULL },
	{ "uuid", cmd_uuid, &cmd_uuid_help },
	{ "input-num", cmd_input_num, &cmd_input_num_help },
	{ "input-str", cmd_input_str, &cmd_input_str_help },
	{ "static-oob", cmd_static_oob, &cmd_static_oob_help },
	{ "provision", cmd_provision, &cmd_provision_help },
#if MYNEWT_VAL(BLE_MESH_LOW_POWER)
	{ "lpn", cmd_lpn, &cmd_lpn_help },
	{ "poll", cmd_poll, NULL },
#endif
#if MYNEWT_VAL(BLE_MESH_GATT_PROXY)
	{ "ident", cmd_ident, NULL },
#endif
	{ "dst", cmd_dst, &cmd_dst_help },
	{ "netidx", cmd_netidx, &cmd_netidx_help },
	{ "appidx", cmd_appidx, &cmd_appidx_help },

	/* Commands which access internal APIs, for testing only */
	{ "net-send", cmd_net_send, &cmd_net_send_help },
	{ "net-send-random-bytes", cmd_net_send_random_bytes, &cmd_net_send_random_bytes_help },
	{ "model-send", cmd_model_send, &cmd_model_send_help },
	{ "iv-update", cmd_iv_update, NULL },
	{ "iv-update-test", cmd_iv_update_test, &cmd_iv_update_test_help },
	{ "rpl-clear", cmd_rpl_clear, NULL },
#if MYNEWT_VAL(BLE_MESH_LOW_POWER)
	{ "lpn-subscribe", cmd_lpn_subscribe, &cmd_lpn_subscribe_help },
	{ "lpn-unsubscribe", cmd_lpn_unsubscribe, &cmd_lpn_unsubscribe_help },
#endif
	{ "print-credentials", cmd_print_credentials, NULL },
	{ "print-composition-data", cmd_print_composition_data, NULL },

	/* Configuration Client Model operations */
	{ "get-comp", cmd_get_comp, &cmd_get_comp_help },
	{ "beacon", cmd_beacon, &cmd_beacon_help },
	{ "ttl", cmd_ttl, &cmd_ttl_help},
	{ "friend", cmd_friend, &cmd_friend_help },
	{ "gatt-proxy", cmd_gatt_proxy, &cmd_gatt_proxy_help },
	{ "relay", cmd_relay, &cmd_relay_help },
	{ "net-key-add", cmd_net_key_add, &cmd_net_key_add_help },
	{ "app-key-add", cmd_app_key_add, &cmd_app_key_add_help },
	{ "mod-app-bind", cmd_mod_app_bind, &cmd_mod_app_bind_help },
	{ "mod-pub", cmd_mod_pub, &cmd_mod_pub_help },
	{ "mod-sub-add", cmd_mod_sub_add, &cmd_mod_sub_add_help },
	{ "mod-sub-del", cmd_mod_sub_del, &cmd_mod_sub_del_help },
	{ "mod-sub-add-va", cmd_mod_sub_add_va, &cmd_mod_sub_add_va_help },
	{ "mod-sub-del-va", cmd_mod_sub_del_va, &cmd_mod_sub_del_va_help },
	{ "hb-sub", cmd_hb_sub, &cmd_hb_sub_help },
	{ "hb-pub", cmd_hb_pub, &cmd_hb_pub_help },

	/* Health Client Model Operations */
	{ "fault-get", cmd_fault_get, &cmd_fault_get_help },
	{ "fault-clear", cmd_fault_clear, &cmd_fault_clear_help },
	{ "fault-clear-unack", cmd_fault_clear_unack, &cmd_fault_clear_unack_help },
	{ "fault-test", cmd_fault_test, &cmd_fault_test_help },
	{ "fault-test-unack", cmd_fault_test_unack, &cmd_fault_test_unack_help },
	{ "period-get", cmd_period_get, NULL },
	{ "period-set", cmd_period_set, &cmd_period_set_help },
	{ "period-set-unack", cmd_period_set_unack, &cmd_period_set_unack_help },
	{ "attention-get", cmd_attention_get, NULL },
	{ "attention-set", cmd_attention_set, &cmd_attention_set_help },
	{ "attention-set-unack", cmd_attention_set_unack, &cmd_attention_set_unack_help },

	/* Health Server Model Operations */
	{ "add-fault", cmd_add_fault, &cmd_add_fault_help },
	{ "del-fault", cmd_del_fault, &cmd_del_fault_help },

	{ NULL, NULL, NULL}
};

static void mesh_shell_thread(void *args)
{
	while (1) {
		os_eventq_run(&mesh_shell_queue);
	}
}

static void bt_mesh_shell_task_init(void)
{
	os_eventq_init(&mesh_shell_queue);

	os_task_init(&mesh_shell_task, "mesh_sh", mesh_shell_thread, NULL,
		     BLE_MESH_SHELL_TASK_PRIO, OS_WAIT_FOREVER, g_blemesh_shell_stack,
		     BLE_MESH_SHELL_STACK_SIZE);
}
#endif

void ble_mesh_shell_init(void)
{
#if (MYNEWT_VAL(BLE_MESH_SHELL))

	/* Initialize health pub message */
	health_pub_init();

	/* Shell and other mesh clients should use separate task to
	   avoid deadlocks with mesh message processing queue */
	bt_mesh_shell_task_init();
	shell_evq_set(&mesh_shell_queue);
	shell_register("mesh", mesh_commands);
#endif
}
