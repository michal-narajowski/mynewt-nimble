/* gatt.c - Bluetooth GATT Server Tester */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <errno.h>
#include <assert.h>

#include "glue.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "console/console.h"

#include "bttester.h"
#include "../../../../apache-mynewt-nimble/nimble/host/src/ble_gatt_priv.h"

#define CONTROLLER_INDEX 0
#define MAX_BUFFER_SIZE 2048
#define MAX_UUID_LEN 16

#define GATT_PERM_READ_AUTHORIZATION	0x40
#define GATT_PERM_WRITE_AUTHORIZATION	0x80

static const ble_uuid16_t BT_UUID_GATT_CEP = BLE_UUID16_INIT(0x2900);
static const ble_uuid16_t BT_UUID_GATT_CCC = BLE_UUID16_INIT(0x2902);

static int gatt_chr_perm_map[] = {
	BLE_GATT_CHR_F_READ,
	BLE_GATT_CHR_F_WRITE,
	BLE_GATT_CHR_F_READ_ENC,
	BLE_GATT_CHR_F_WRITE_ENC,
	BLE_GATT_CHR_F_READ_AUTHEN,
	BLE_GATT_CHR_F_WRITE_AUTHEN,
	BLE_GATT_CHR_F_READ_AUTHOR,
	BLE_GATT_CHR_F_WRITE_AUTHOR,
};

static int gatt_dsc_perm_map[] = {
	BLE_ATT_F_READ,
	BLE_ATT_F_WRITE,
	BLE_ATT_F_READ_ENC,
	BLE_ATT_F_WRITE_ENC,
	BLE_ATT_F_READ_AUTHEN,
	BLE_ATT_F_WRITE_AUTHEN,
	BLE_ATT_F_READ_AUTHOR,
	BLE_ATT_F_WRITE_AUTHOR,
};

/* GATT server context */
#define SERVER_MAX_SVCS		10
#define SERVER_MAX_CHRS		25
#define SERVER_MAX_DSCS		25
#define SERVER_MAX_UUIDS	60

struct gatt_value {
    u16_t len;
    u8_t *data;
    u8_t enc_key_size;
    u8_t flags[1];
    u8_t type;
    void *ptr;
};

enum {
    GATT_VALUE_TYPE_CHR,
    GATT_VALUE_TYPE_DSC,
};

static struct ble_gatt_svc_def svcs[SERVER_MAX_SVCS];
static struct ble_gatt_chr_def chrs[SERVER_MAX_CHRS];
static struct ble_gatt_dsc_def dscs[SERVER_MAX_DSCS];
static struct ble_gatt_svc_def *inc_svcs[SERVER_MAX_SVCS];
static ble_uuid_any_t uuids[SERVER_MAX_UUIDS];
static struct gatt_value gatt_values[SERVER_MAX_UUIDS];
static u8_t data[MAX_BUFFER_SIZE];

static u8_t svc_count;
static u8_t chr_count;
static u8_t dsc_count;
static u8_t inc_svc_count;
static u8_t uuid_count;
static u8_t gatt_value_count;
static u32_t data_len;

/*
 * gatt_buf - cache used by a gatt client (to cache data read/discovered)
 * and gatt server (to store attribute user_data).
 * It is not intended to be used by client and server at the same time.
 */
static struct {
    u16_t len;
    u8_t buf[MAX_BUFFER_SIZE];
} gatt_buf;

static void *gatt_buf_add(const void *data, size_t len)
{
	void *ptr = gatt_buf.buf + gatt_buf.len;

	if ((len + gatt_buf.len) > MAX_BUFFER_SIZE) {
		return NULL;
	}

	if (data) {
		memcpy(ptr, data, len);
	} else {
		(void)memset(ptr, 0, len);
	}

	gatt_buf.len += len;

	SYS_LOG_DBG("%d/%d used", gatt_buf.len, MAX_BUFFER_SIZE);

	return ptr;
}

static void *gatt_buf_reserve(size_t len)
{
	return gatt_buf_add(NULL, len);
}

static void gatt_buf_clear(void)
{
	(void)memset(&gatt_buf, 0, sizeof(gatt_buf));
}

struct ble_gatt_svc_def *alloc_svc(void)
{
	assert(svc_count < (SERVER_MAX_SVCS - 1));
	return &svcs[svc_count++];
}

void free_last_svc(void)
{
	svc_count--;
	memset(&svcs[svc_count], 0, sizeof(struct ble_gatt_svc_def));
}

struct ble_gatt_svc_def *find_svc_by_id(u16_t id)
{
	if (id <= svc_count) {
		return &svcs[id-1];
	} else {
		return NULL;
	}
}

struct ble_gatt_svc_def *get_last_svc(void)
{
	if (svc_count > 0) {
		return &svcs[svc_count-1];
	} else {
		return NULL;
	}
}

struct ble_gatt_svc_def **alloc_inc_svc_arr(void)
{
	assert(inc_svc_count < (SERVER_MAX_SVCS - 1));
	return &inc_svcs[inc_svc_count++];
}

struct ble_gatt_svc_def **get_last_inc_svc_arr(void)
{
	if (inc_svc_count > 0) {
		return &inc_svcs[inc_svc_count-1];
	} else {
		return NULL;
	}
}

struct ble_gatt_chr_def *alloc_chr(void)
{
	assert(chr_count < (SERVER_MAX_CHRS - 1));
	return &chrs[chr_count++];
}

void free_last_chr(void)
{
	chr_count--;
	memset(&chrs[chr_count], 0, sizeof(struct ble_gatt_chr_def));
}

struct ble_gatt_chr_def *get_last_chr(void)
{
	if (chr_count > 0) {
		return &chrs[chr_count-1];
	} else {
		return NULL;
	}
}

struct ble_gatt_dsc_def *alloc_dsc(void)
{
	assert(dsc_count < (SERVER_MAX_DSCS - 1));
	return &dscs[dsc_count++];
}

void free_last_dsc(void)
{
	dsc_count--;
	memset(&dscs[dsc_count], 0, sizeof(struct ble_gatt_dsc_def));
}

ble_uuid_any_t *alloc_uuid(void)
{
	assert(uuid_count < (SERVER_MAX_UUIDS - 1));
	return &uuids[uuid_count++];
}

void free_last_uuid(void)
{
	uuid_count--;
	memset(&uuids[uuid_count], 0, sizeof(ble_uuid_any_t));
}

struct gatt_value *alloc_gatt_value(void)
{
	assert(gatt_value_count < (SERVER_MAX_UUIDS - 1));
	return &gatt_values[gatt_value_count++];
}

void free_last_gatt_value(void)
{
	gatt_value_count--;
	memset(&gatt_values[gatt_value_count], 0, sizeof(struct gatt_value));
}

struct gatt_value *get_last_gatt_value(void)
{
	if (gatt_value_count > 0) {
		return &gatt_values[gatt_value_count-1];
	} else {
		return NULL;
	}
}

u8_t *alloc_data(u16_t len)
{
	u8_t *buf;

	assert(data_len < (MAX_BUFFER_SIZE - 1 - len));
	buf = &data[data_len];
	data_len += len;

	return buf;
}

void free_data(u8_t len)
{
	data_len -= len;
	memset(&data[data_len - len], 0, len);
}

/* Convert UUID from BTP command to bt_uuid */
static u8_t btp2bt_uuid(const u8_t *uuid, u8_t len,
			   ble_uuid_any_t *bt_uuid)
{
	u16_t le16;

	switch (len) {
	case 0x02: /* UUID 16 */
		bt_uuid->u.type = BLE_UUID_TYPE_16;
		memcpy(&le16, uuid, sizeof(le16));
		BLE_UUID16(bt_uuid)->value = le16toh(le16);
		break;
	case 0x10: /* UUID 128*/
		bt_uuid->u.type = BLE_UUID_TYPE_128;
		memcpy(BLE_UUID128(bt_uuid)->value, uuid, 16);
		break;
	default:
		return BTP_STATUS_FAILED;
	}

	return BTP_STATUS_SUCCESS;
}

static void supported_commands(u8_t *data, u16_t len)
{
	u8_t cmds[4];
	struct gatt_read_supported_commands_rp *rp = (void *) cmds;

	SYS_LOG_DBG("");

	memset(cmds, 0, sizeof(cmds));

	tester_set_bit(cmds, GATT_READ_SUPPORTED_COMMANDS);
	tester_set_bit(cmds, GATT_ADD_SERVICE);
	tester_set_bit(cmds, GATT_ADD_CHARACTERISTIC);
	tester_set_bit(cmds, GATT_ADD_DESCRIPTOR);
	tester_set_bit(cmds, GATT_ADD_INCLUDED_SERVICE);
	tester_set_bit(cmds, GATT_SET_VALUE);
	tester_set_bit(cmds, GATT_START_SERVER);
	tester_set_bit(cmds, GATT_SET_ENC_KEY_SIZE);
	tester_set_bit(cmds, GATT_EXCHANGE_MTU);
	tester_set_bit(cmds, GATT_DISC_PRIM_UUID);
	tester_set_bit(cmds, GATT_FIND_INCLUDED);
	tester_set_bit(cmds, GATT_DISC_ALL_CHRC);
	tester_set_bit(cmds, GATT_DISC_CHRC_UUID);
	tester_set_bit(cmds, GATT_DISC_ALL_DESC);
	tester_set_bit(cmds, GATT_READ);
	tester_set_bit(cmds, GATT_READ_LONG);
	tester_set_bit(cmds, GATT_READ_MULTIPLE);
	tester_set_bit(cmds, GATT_WRITE_WITHOUT_RSP);
	tester_set_bit(cmds, GATT_SIGNED_WRITE_WITHOUT_RSP);
	tester_set_bit(cmds, GATT_WRITE);
	tester_set_bit(cmds, GATT_WRITE_LONG);
	tester_set_bit(cmds, GATT_CFG_NOTIFY);
	tester_set_bit(cmds, GATT_CFG_INDICATE);
	tester_set_bit(cmds, GATT_GET_ATTRIBUTES);
	tester_set_bit(cmds, GATT_GET_ATTRIBUTE_VALUE);

	tester_send(BTP_SERVICE_ID_GATT, GATT_READ_SUPPORTED_COMMANDS,
		    CONTROLLER_INDEX, (u8_t *) rp, sizeof(cmds));
}

static void add_service(u8_t *data, u16_t len)
{
	const struct gatt_add_service_cmd *cmd = (void *) data;
	struct gatt_add_service_rp rp;
	struct ble_gatt_svc_def *svc_def;
	ble_uuid_any_t *uuid = alloc_uuid();

	SYS_LOG_DBG("");

	if (svc_count >= SERVER_MAX_SVCS - 1) {
		goto fail;
	}

	if (btp2bt_uuid(cmd->uuid, cmd->uuid_length, uuid)) {
		goto fail;
	}

	if (svc_count > 0) {
		/* if there is a service already
		 * add an empty char and empty
		 * included service array to indicate
		 * end of list for the previous svc
		 */
		alloc_chr();
		alloc_inc_svc_arr();
	}

	svc_def = alloc_svc();

	switch (cmd->type) {
	case GATT_SERVICE_PRIMARY:
		svc_def->type = BLE_GATT_SVC_TYPE_PRIMARY;
		break;
	case GATT_SERVICE_SECONDARY:
		svc_def->type = BLE_GATT_SVC_TYPE_SECONDARY;
		break;
	}

	svc_def->uuid = &uuid->u;
	rp.svc_id = 0;

	tester_send(BTP_SERVICE_ID_GATT, GATT_ADD_SERVICE, CONTROLLER_INDEX,
		    (u8_t *) &rp, sizeof(rp));

	return;
fail:
	free_last_uuid();
	tester_rsp(BTP_SERVICE_ID_GATT, GATT_ADD_SERVICE, CONTROLLER_INDEX,
		   BTP_STATUS_FAILED);
}

static size_t read_value(uint16_t conn_handle, uint16_t attr_handle,
			 struct ble_gatt_access_ctxt *ctxt,
			 void *arg)
{
	const struct gatt_value *value = arg;
	char str[BLE_UUID_STR_LEN];
	int rc;

	memset(str, '\0', sizeof(str));

	if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
		ble_uuid_to_str(ctxt->chr->uuid, str);
	} else {
		ble_uuid_to_str(ctxt->dsc->uuid, str);
	}

	SYS_LOG_DBG("uuid=%s", str);

	SYS_LOG_DBG("handle=%d", attr_handle);
	SYS_LOG_DBG("value=0x%s", bt_hex(value->data, value->len));
	rc = os_mbuf_append(ctxt->om, value->data, value->len);
	SYS_LOG_DBG("len=%d", ctxt->om->om_len);
	return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
}

static void attr_value_changed_ev(u16_t handle, const u8_t *value, u16_t len)
{
	u8_t buf[len + sizeof(struct gatt_attr_value_changed_ev)];
	struct gatt_attr_value_changed_ev *ev = (void *) buf;

	SYS_LOG_DBG("");

	ev->handle = htole16(handle);
	ev->data_length = htole16(len);
	memcpy(ev->data, value, len);

	tester_send(BTP_SERVICE_ID_GATT, GATT_EV_ATTR_VALUE_CHANGED,
		    CONTROLLER_INDEX, buf, sizeof(buf));
}

static size_t write_value(uint16_t conn_handle, uint16_t attr_handle,
			  struct ble_gatt_access_ctxt *ctxt,
			  void *arg)
{
	struct gatt_value *value = arg;
	uint16_t om_len, len;
	int rc;

	SYS_LOG_DBG("");

	om_len = OS_MBUF_PKTLEN(ctxt->om);
	if (om_len > value->len) {
		return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
	}

	rc = ble_hs_mbuf_to_flat(ctxt->om, value->data, value->len, &len);
	if (rc != 0) {
		return BLE_ATT_ERR_UNLIKELY;
	}

	/* Maximum attribute value size is 512 bytes */
	assert(value->len < 512);

	attr_value_changed_ev(attr_handle, value->data, value->len);

	return 0;
}


static int gatt_svr_access_cb(uint16_t conn_handle, uint16_t attr_handle,
			      struct ble_gatt_access_ctxt *ctxt,
			      void *arg)
{
	switch (ctxt->op) {
		case BLE_GATT_ACCESS_OP_READ_CHR:
		case BLE_GATT_ACCESS_OP_READ_DSC:
			return read_value(conn_handle, attr_handle,
					  ctxt, arg);
		case BLE_GATT_ACCESS_OP_WRITE_CHR:
		case BLE_GATT_ACCESS_OP_WRITE_DSC:
			return write_value(conn_handle, attr_handle,
					   ctxt, arg);
		default:
			assert(0);
			return BLE_ATT_ERR_UNLIKELY;
	}

	/* Unknown characteristic; the nimble stack should not have called this
	 * function.
	 */
	assert(0);
	return BLE_ATT_ERR_UNLIKELY;
}

static void add_characteristic(u8_t *data, u16_t len)
{
	const struct gatt_add_characteristic_cmd *cmd = (void *) data;
	struct gatt_add_characteristic_rp rp;
	struct ble_gatt_svc_def *svc_def;
	struct ble_gatt_chr_def *chr_def;
	ble_uuid_any_t *uuid = alloc_uuid();
	struct gatt_value *value = alloc_gatt_value();
	int i;

	SYS_LOG_DBG("");

	if (chr_count >= SERVER_MAX_CHRS - 1) {
		goto fail;
	}

	if (btp2bt_uuid(cmd->uuid, cmd->uuid_length, uuid)) {
		goto fail;
	}

	/* characterisic must be added only sequential */
	if (cmd->svc_id) {
		goto fail;
	}

	/* there must be a service registered */
	if (svc_count <= 0) {
		goto fail;
	}

	svc_def = get_last_svc();
	assert(svc_def != NULL);

	chr_def = alloc_chr();
	chr_def->uuid = &uuid->u;
	chr_def->access_cb = gatt_svr_access_cb;
	chr_def->flags = cmd->properties;
	chr_def->arg = value;
	value->type = GATT_VALUE_TYPE_CHR;
	value->ptr = (void *) chr_def;

	for (i = 0; i < 8; ++i) {
		if (cmd->permissions & BIT(i)) {
			chr_def->flags |= gatt_chr_perm_map[i];
		}
	}

	if (svc_def->characteristics == NULL) {
		svc_def->characteristics = chr_def;
	}

	rp.char_id = 0;

    tester_send(BTP_SERVICE_ID_GATT, GATT_ADD_CHARACTERISTIC,
                CONTROLLER_INDEX, (u8_t *) &rp, sizeof(rp));
	return;

fail:
	free_last_uuid();
	free_last_gatt_value();
	tester_rsp(BTP_SERVICE_ID_GATT, GATT_ADD_CHARACTERISTIC,
		   CONTROLLER_INDEX, BTP_STATUS_FAILED);
}

static void add_descriptor(u8_t *data, u16_t len)
{
	const struct gatt_add_descriptor_cmd *cmd = (void *) data;
	struct gatt_add_descriptor_rp rp;
	struct ble_gatt_chr_def *chr_def;
	struct ble_gatt_dsc_def *dsc_def;
	ble_uuid_any_t *uuid = alloc_uuid();
	struct gatt_value *value;
	int i;

	SYS_LOG_DBG("");

	if (dsc_count >= SERVER_MAX_DSCS - 1) {
		goto fail;
	}

	/* Must be declared first svc or at least 3 attrs (svc+char+char val) */
	/* TODO: if (!svc_count || attr_count < 3) */
	if (!svc_count) {
		goto fail;
	}

	if (btp2bt_uuid(cmd->uuid, cmd->uuid_length, uuid)) {
		goto fail;
	}

	/* descriptor can be added only sequential */
	if (cmd->char_id) {
		goto fail;
	}

	/* Lookup preceding Characteristic Declaration here */
	chr_def = get_last_chr();
	assert(chr_def != NULL);

	dsc_def = alloc_dsc();
	dsc_def->att_flags = cmd->permissions;
	dsc_def->uuid = &uuid->u;
	if (chr_def->descriptors == NULL) {
		chr_def->descriptors = dsc_def;
	}

	value = alloc_gatt_value();
	dsc_def->access_cb = gatt_svr_access_cb;
	dsc_def->arg = value;
	value->type = GATT_VALUE_TYPE_DSC;
	value->ptr = (void *) dsc_def;

	if (!ble_uuid_cmp(&uuid->u, &BT_UUID_GATT_CEP.u)) {
		/* TODO: */
	} else if (!ble_uuid_cmp(&uuid->u, &BT_UUID_GATT_CCC.u)) {
		/* handled by host */
	} else {
		for (i = 0; i < 8; ++i) {
			if (cmd->permissions & BIT(i)) {
				dsc_def->att_flags |= gatt_dsc_perm_map[i];
			}
		}
	}

	rp.desc_id = 0;
	tester_send(BTP_SERVICE_ID_GATT, GATT_ADD_DESCRIPTOR, CONTROLLER_INDEX,
		    (u8_t *) &rp, sizeof(rp));
	return;

fail:
	tester_rsp(BTP_SERVICE_ID_GATT, GATT_ADD_DESCRIPTOR,
		   CONTROLLER_INDEX, BTP_STATUS_FAILED);
}

static void add_included(u8_t *data, u16_t len)
{
	const struct gatt_add_included_service_cmd *cmd = (void *) data;
	struct gatt_add_included_service_rp rp;
	struct ble_gatt_svc_def *last_svc, *svc;
	struct ble_gatt_svc_def **inc_svc;
	u16_t included_service_id = 0;

	last_svc = get_last_svc();
	assert(last_svc != NULL);

	svc = find_svc_by_id(cmd->svc_id);
	assert(svc != NULL);

	inc_svc = alloc_inc_svc_arr();
	if (last_svc->includes == NULL) {
		last_svc->includes = (const struct ble_gatt_svc_def **) inc_svc;
	}

	*inc_svc = svc;

	rp.included_service_id = sys_cpu_to_le16(included_service_id);
	tester_send(BTP_SERVICE_ID_GATT, GATT_ADD_INCLUDED_SERVICE,
		    CONTROLLER_INDEX, (u8_t *) &rp, sizeof(rp));
}

#if 0
static u8_t set_cep_value(struct bt_gatt_attr *attr, const void *value,
			     const u16_t len)
{
	struct bt_gatt_cep *cep_value = attr->user_data;
	u16_t properties;

	if (len != sizeof(properties)) {
		return BTP_STATUS_FAILED;
	}

	memcpy(&properties, value, len);
	cep_value->properties = sys_le16_to_cpu(properties);

	return BTP_STATUS_SUCCESS;
}
#endif

static void set_value(u8_t *data, u16_t len)
{
	const struct gatt_set_value_cmd *cmd = (void *) data;
	struct gatt_value *gatt_value;
	u16_t value_len;
	const u8_t *value;

	SYS_LOG_DBG("");

	if (cmd->attr_id) {
		goto fail;
	}

	gatt_value = get_last_gatt_value();
	assert(gatt_value != NULL);

	value_len = htole16(cmd->len);
	value = cmd->value;

#if 0
	/* Value has been already set while adding CCC to the gatt_db */
	if (!ble_uuid_cmp(attr->uuid, BT_UUID_GATT_CCC)) {
		return BTP_STATUS_SUCCESS;
	}

	/* Set CEP value */
	if (!bt_uuid_cmp(attr->uuid, BT_UUID_GATT_CEP)) {
		return set_cep_value(attr, data->value, data->len);
	}
#endif

	/* Check if attribute value has been already set */
	if (!gatt_value->len) {
		gatt_value->data = alloc_data(value_len);
		gatt_value->len = value_len;
	}

	/* Fail if value length doesn't match  */
	if (gatt_value->len != value_len) {
		goto fail;
	}

	memcpy(gatt_value->data, value, value_len);

#if 0
	if (tester_test_bit(value->flags, GATT_VALUE_CCC_FLAG) && ccc_value) {
		if (ccc_value == BT_GATT_CCC_NOTIFY) {
			bt_gatt_notify(NULL, attr, value->data, value->len);
		} else {
			indicate_params.attr = attr;
			indicate_params.data = value->data;
			indicate_params.len = value->len;
			indicate_params.func = indicate_cb;

			bt_gatt_indicate(NULL, &indicate_params);
		}
	}
#endif

	tester_rsp(BTP_SERVICE_ID_GATT, GATT_SET_VALUE, CONTROLLER_INDEX,
		   BTP_STATUS_SUCCESS);
	return;

fail:
	tester_rsp(BTP_SERVICE_ID_GATT, GATT_SET_VALUE, CONTROLLER_INDEX,
		   BTP_STATUS_FAILED);
}

static void start_server(u8_t *data, u16_t len)
{
	struct gatt_start_server_rp rp;
	int rc;

	SYS_LOG_DBG("");

	rc = ble_gatts_reset();
	if (rc) {
		SYS_LOG_DBG("reset");
		goto fail;
	}

	rc = ble_gatts_count_cfg(svcs);
	if (rc) {
		SYS_LOG_DBG("count_cfg");
		goto fail;
	}

	rc = ble_gatts_add_svcs(svcs);
	if (rc) {
		SYS_LOG_DBG("add");
		goto fail;
	}

	rc = ble_gatts_start();
	if (rc) {
		SYS_LOG_DBG("start, rc=%d", rc);
		goto fail;
	}

	ble_gatts_show_local();

	tester_send(BTP_SERVICE_ID_GATT, GATT_START_SERVER, CONTROLLER_INDEX,
		    (u8_t *) &rp, sizeof(rp));

	return;
fail:
	tester_rsp(BTP_SERVICE_ID_GATT, GATT_START_SERVER,
		   CONTROLLER_INDEX, BTP_STATUS_FAILED);
}

static void set_enc_key_size(u8_t *data, u16_t len)
{
	const struct gatt_set_enc_key_size_cmd *cmd = (void *) data;
	struct gatt_value *val;
	u8_t status = 0;

	/* Fail if requested key size is invalid */
	if (cmd->key_size < 0x07 || cmd->key_size > 0x0f) {
		status = BTP_STATUS_FAILED;
		goto fail;
	}

	val = get_last_gatt_value();
	assert(val != NULL);
	assert(val->ptr != NULL);

	switch(val->type) {
	case GATT_VALUE_TYPE_CHR:
		((struct ble_gatt_chr_def *) val->ptr)->min_key_size =
			cmd->key_size;
		break;
	case GATT_VALUE_TYPE_DSC:
		((struct ble_gatt_dsc_def *) val->ptr)->min_key_size =
			cmd->key_size;
		break;
	default:
		break;
	}

fail:
	tester_rsp(BTP_SERVICE_ID_GATT, GATT_SET_ENC_KEY_SIZE, CONTROLLER_INDEX,
		   status);
}

static int exchange_func(uint16_t conn_handle,
			 const struct ble_gatt_error *error,
			 uint16_t mtu, void *arg)
{
	SYS_LOG_DBG("");

	if (error->status) {
		tester_rsp(BTP_SERVICE_ID_GATT, GATT_EXCHANGE_MTU,
			   CONTROLLER_INDEX, BTP_STATUS_FAILED);

		return 0;
	}

	tester_rsp(BTP_SERVICE_ID_GATT, GATT_EXCHANGE_MTU, CONTROLLER_INDEX,
		   BTP_STATUS_SUCCESS);

	return 0;
}

static void exchange_mtu(u8_t *data, u16_t len)
{
	struct ble_gap_conn_desc conn;
	int rc;

	SYS_LOG_DBG("");

	rc = ble_gap_conn_find_by_addr((bt_addr_le_t *)data, &conn);
	if (rc) {
		goto fail;
	}

	if (ble_gattc_exchange_mtu(conn.conn_handle, exchange_func, NULL)) {
		goto fail;
	}

	return;
fail:
	tester_rsp(BTP_SERVICE_ID_GATT, GATT_EXCHANGE_MTU,
		   CONTROLLER_INDEX, BTP_STATUS_FAILED);
}


static void discover_destroy(void)
{
	gatt_buf_clear();
}

static int disc_prim_uuid_cb(uint16_t conn_handle,
			     const struct ble_gatt_error *error,
			     const struct ble_gatt_svc *gatt_svc, void *arg)
{
	struct gatt_disc_prim_uuid_rp *rp = (void *) gatt_buf.buf;
	struct gatt_service *service;
	const ble_uuid_any_t *uuid;
	u8_t uuid_length;

	SYS_LOG_DBG("");

	if (error->status != 0) {
		tester_send(BTP_SERVICE_ID_GATT, GATT_DISC_PRIM_UUID,
			    CONTROLLER_INDEX, gatt_buf.buf, gatt_buf.len);
		discover_destroy();
		return 0;
	}

	uuid = &gatt_svc->uuid;
	uuid_length = (uint8_t) (uuid->u.type == BLE_UUID_TYPE_16 ? 2 : 16);

	service = gatt_buf_reserve(sizeof(*service) + uuid_length);
	if (!service) {
		tester_rsp(BTP_SERVICE_ID_GATT, GATT_DISC_PRIM_UUID,
			   CONTROLLER_INDEX, BTP_STATUS_FAILED);
		discover_destroy();
		return BLE_HS_EDONE;
	}

	service->start_handle = htole16(gatt_svc->start_handle);
	service->end_handle = htole16(gatt_svc->start_handle);
	service->uuid_length = uuid_length;

	if (uuid->u.type == BLE_UUID_TYPE_16) {
		u16_t u16 = htole16(BLE_UUID16(uuid)->value);

		memcpy(service->uuid, &u16, uuid_length);
	} else {
		memcpy(service->uuid, BLE_UUID128(uuid)->value,
		       uuid_length);
	}

	rp->services_count++;

	return 0;
}

static void disc_prim_uuid(u8_t *data, u16_t len)
{
	const struct gatt_disc_prim_uuid_cmd *cmd = (void *) data;
	struct ble_gap_conn_desc conn;
	ble_uuid_any_t uuid;
	int rc;

	SYS_LOG_DBG("");

	rc = ble_gap_conn_find_by_addr((bt_addr_le_t *)data, &conn);
	if (rc) {
		goto fail;
	}

	if (btp2bt_uuid(cmd->uuid, cmd->uuid_length, &uuid)) {
		goto fail;
	}

	if (!gatt_buf_reserve(sizeof(struct gatt_disc_prim_uuid_rp))) {
		goto fail;
	}

	if (ble_gattc_disc_svc_by_uuid(conn.conn_handle, &uuid.u,
				       disc_prim_uuid_cb, NULL)) {
		discover_destroy();
		goto fail;
	}

	return;

fail:
	tester_rsp(BTP_SERVICE_ID_GATT, GATT_DISC_PRIM_UUID, CONTROLLER_INDEX,
		   BTP_STATUS_FAILED);
}

static int find_included_cb(uint16_t conn_handle,
			    const struct ble_gatt_error *error,
			    const struct ble_gatt_svc *gatt_svc, void *arg)
{
	struct gatt_find_included_rp *rp = (void *) gatt_buf.buf;
	struct gatt_included *included;
	const ble_uuid_any_t *uuid;
	u8_t uuid_length;

	SYS_LOG_DBG("");

	if (error->status != 0) {
		tester_send(BTP_SERVICE_ID_GATT, GATT_FIND_INCLUDED,
			    CONTROLLER_INDEX, gatt_buf.buf, gatt_buf.len);
		discover_destroy();
		return 0;
	}

	uuid = &gatt_svc->uuid;
	uuid_length = (uint8_t) (uuid->u.type == BLE_UUID_TYPE_16 ? 2 : 16);


	included = gatt_buf_reserve(sizeof(*included) + uuid_length);
	if (!included) {
		tester_rsp(BTP_SERVICE_ID_GATT, GATT_FIND_INCLUDED,
			   CONTROLLER_INDEX, BTP_STATUS_FAILED);
		discover_destroy();
		return BLE_HS_EDONE;
	}

	/* FIXME */
	included->included_handle = htole16(gatt_svc->start_handle);
	included->service.start_handle = htole16(gatt_svc->start_handle);
	included->service.end_handle = htole16(gatt_svc->start_handle);
	included->service.uuid_length = uuid_length;

	if (uuid->u.type == BLE_UUID_TYPE_16) {
		u16_t u16 = htole16(BLE_UUID16(uuid)->value);

		memcpy(included->service.uuid, &u16, uuid_length);
	} else {
		memcpy(included->service.uuid, BLE_UUID128(uuid)->value,
		       uuid_length);
	}

	rp->services_count++;

	return 0;
}

static void find_included(u8_t *data, u16_t len)
{
	const struct gatt_find_included_cmd *cmd = (void *) data;
	struct ble_gap_conn_desc conn;
	uint16_t start_handle, end_handle;
	int rc;

	SYS_LOG_DBG("");

	rc = ble_gap_conn_find_by_addr((bt_addr_le_t *)data, &conn);
	if (rc) {
		goto fail;
	}

	if (!gatt_buf_reserve(sizeof(struct gatt_find_included_rp))) {
		goto fail;
	}

	start_handle = htole16(cmd->start_handle);
	end_handle = htole16(cmd->end_handle);

	if (ble_gattc_find_inc_svcs(conn.conn_handle, start_handle, end_handle,
				    find_included_cb, NULL)) {
		discover_destroy();
		goto fail;
	}

	return;

fail:
	tester_rsp(BTP_SERVICE_ID_GATT, GATT_FIND_INCLUDED, CONTROLLER_INDEX,
		   BTP_STATUS_FAILED);
}

static int disc_chrc_cb(uint16_t conn_handle,
			const struct ble_gatt_error *error,
			const struct ble_gatt_chr *gatt_chr, void *arg)
{
	struct gatt_disc_chrc_rp *rp = (void *) gatt_buf.buf;
	struct gatt_characteristic *chrc;
	const ble_uuid_any_t *uuid;
	u8_t btp_opcode = (uint8_t) (int) arg;
	u8_t uuid_length;

	SYS_LOG_DBG("");

	if (error->status != 0) {
		tester_send(BTP_SERVICE_ID_GATT, btp_opcode,
			    CONTROLLER_INDEX, gatt_buf.buf, gatt_buf.len);
		discover_destroy();
		return 0;
	}

	uuid = &gatt_chr->uuid;
	uuid_length = (uint8_t) (uuid->u.type == BLE_UUID_TYPE_16 ? 2 : 16);

	chrc = gatt_buf_reserve(sizeof(*chrc) + uuid_length);
	if (!chrc) {
		tester_rsp(BTP_SERVICE_ID_GATT, btp_opcode,
			   CONTROLLER_INDEX, BTP_STATUS_FAILED);
		discover_destroy();
		return BLE_HS_EDONE;
	}

	chrc->characteristic_handle = htole16(gatt_chr->def_handle);
	chrc->properties = gatt_chr->properties;
	chrc->value_handle = htole16(gatt_chr->val_handle);
	chrc->uuid_length = uuid_length;

	if (uuid->u.type == BLE_UUID_TYPE_16) {
		u16_t u16 = htole16(BLE_UUID16(uuid)->value);

		memcpy(chrc->uuid, &u16, uuid_length);
	} else {
		memcpy(chrc->uuid, BLE_UUID128(uuid)->value,
		       uuid_length);
	}

	rp->characteristics_count++;

	return 0;
}

static void disc_all_chrc(u8_t *data, u16_t len)
{
	const struct gatt_disc_all_chrc_cmd *cmd = (void *) data;
	struct ble_gap_conn_desc conn;
	uint16_t start_handle, end_handle;
	int rc;

	SYS_LOG_DBG("");

	rc = ble_gap_conn_find_by_addr((bt_addr_le_t *)data, &conn);
	if (rc) {
		SYS_LOG_DBG("Conn find failed");
		goto fail;
	}

	if (!gatt_buf_reserve(sizeof(struct gatt_disc_chrc_rp))) {
		SYS_LOG_DBG("Buf reserve failed");
		goto fail;
	}

	start_handle = htole16(cmd->start_handle);
	end_handle = htole16(cmd->end_handle);

	rc = ble_gattc_disc_all_chrs(conn.conn_handle, start_handle, end_handle,
				    disc_chrc_cb, (void *)GATT_DISC_ALL_CHRC);

	SYS_LOG_DBG("\nrc=%d\n", rc);

	if (rc) {
		discover_destroy();
		goto fail;
	}

	return;

fail:
	tester_rsp(BTP_SERVICE_ID_GATT, GATT_DISC_ALL_CHRC, CONTROLLER_INDEX,
		   BTP_STATUS_FAILED);
}

static void disc_chrc_uuid(u8_t *data, u16_t len)
{
	const struct gatt_disc_chrc_uuid_cmd *cmd = (void *) data;
	struct ble_gap_conn_desc conn;
	uint16_t start_handle, end_handle;
	ble_uuid_any_t uuid;
	int rc;

	SYS_LOG_DBG("");

	rc = ble_gap_conn_find_by_addr((bt_addr_le_t *)data, &conn);
	if (rc) {
		goto fail;
	}

	if (btp2bt_uuid(cmd->uuid, cmd->uuid_length, &uuid)) {
		goto fail;
	}

	if (!gatt_buf_reserve(sizeof(struct gatt_disc_chrc_rp))) {
		goto fail;
	}

	start_handle = htole16(cmd->start_handle);
	end_handle = htole16(cmd->end_handle);

	if (ble_gattc_disc_chrs_by_uuid(conn.conn_handle, start_handle,
					end_handle, &uuid.u, disc_chrc_cb,
					(void *)GATT_DISC_CHRC_UUID)) {
		discover_destroy();
		goto fail;
	}

	return;

fail:
	tester_rsp(BTP_SERVICE_ID_GATT, GATT_DISC_CHRC_UUID, CONTROLLER_INDEX,
		   BTP_STATUS_FAILED);
}

static int disc_all_desc_cb(uint16_t conn_handle,
			    const struct ble_gatt_error *error,
			    uint16_t chr_def_handle,
			    const struct ble_gatt_dsc *gatt_dsc,
			    void *arg)
{
	struct gatt_disc_all_desc_rp *rp = (void *) gatt_buf.buf;
	struct gatt_descriptor *dsc;
	const ble_uuid_any_t *uuid;
	u8_t uuid_length;

	SYS_LOG_DBG("");

	if (error->status != 0) {
		tester_send(BTP_SERVICE_ID_GATT, GATT_DISC_ALL_DESC,
			    CONTROLLER_INDEX, gatt_buf.buf, gatt_buf.len);
		discover_destroy();
		return 0;
	}

	uuid = &gatt_dsc->uuid;
	uuid_length = (uint8_t) (uuid->u.type == BLE_UUID_TYPE_16 ? 2 : 16);

	dsc = gatt_buf_reserve(sizeof(*dsc) + uuid_length);
	if (!dsc) {
		tester_rsp(BTP_SERVICE_ID_GATT, GATT_DISC_ALL_DESC,
			   CONTROLLER_INDEX, BTP_STATUS_FAILED);
		discover_destroy();
		return BLE_HS_EDONE;
	}

	dsc->descriptor_handle = htole16(gatt_dsc->handle);
	dsc->uuid_length = uuid_length;

	if (uuid->u.type == BLE_UUID_TYPE_16) {
		u16_t u16 = htole16(BLE_UUID16(uuid)->value);

		memcpy(dsc->uuid, &u16, uuid_length);
	} else {
		memcpy(dsc->uuid, BLE_UUID128(uuid)->value,
		       uuid_length);
	}

	rp->descriptors_count++;

	return 0;
}

static void disc_all_desc(u8_t *data, u16_t len)
{
	const struct gatt_disc_all_desc_cmd *cmd = (void *) data;
	struct ble_gap_conn_desc conn;
	uint16_t start_handle, end_handle;
	int rc;

	SYS_LOG_DBG("");

	rc = ble_gap_conn_find_by_addr((bt_addr_le_t *)data, &conn);
	if (rc) {
		goto fail;
	}

	if (!gatt_buf_reserve(sizeof(struct gatt_disc_all_desc_rp))) {
		goto fail;
	}

	start_handle = htole16(cmd->start_handle) - 1;
	end_handle = htole16(cmd->end_handle);

	rc = ble_gattc_disc_all_dscs(conn.conn_handle, start_handle, end_handle,
				    disc_all_desc_cb, NULL);

	SYS_LOG_DBG("rc=%d", rc);

	if (rc) {
		discover_destroy();
		goto fail;
	}

	return;

fail:
	tester_rsp(BTP_SERVICE_ID_GATT, GATT_DISC_ALL_DESC, CONTROLLER_INDEX,
		   BTP_STATUS_FAILED);
}

static void read_destroy()
{
	gatt_buf_clear();
}

static int read_cb(uint16_t conn_handle,
		   const struct ble_gatt_error *error,
		   struct ble_gatt_attr *attr,
		   void *arg)
{
	struct gatt_read_rp *rp = (void *) gatt_buf.buf;
	u8_t btp_opcode = (uint8_t) (int) arg;

	SYS_LOG_DBG("status=%d", error->status);

	if (error->status != 0 && error->status != BLE_HS_EDONE) {
		rp->att_response = (uint8_t) BLE_HS_ATT_ERR(error->status);
		tester_send(BTP_SERVICE_ID_GATT, btp_opcode,
			    CONTROLLER_INDEX, gatt_buf.buf, gatt_buf.len);
		read_destroy();
		return 0;
	}

	if (!gatt_buf_add(attr->om->om_data, attr->om->om_len)) {
		tester_rsp(BTP_SERVICE_ID_GATT, btp_opcode,
			   CONTROLLER_INDEX, BTP_STATUS_FAILED);
		read_destroy();
		return 0;
	}

	rp->data_length += attr->om->om_len;

	tester_send(BTP_SERVICE_ID_GATT, btp_opcode,
		    CONTROLLER_INDEX, gatt_buf.buf, gatt_buf.len);
	read_destroy();

	return 0;
}

static void read(u8_t *data, u16_t len)
{
	const struct gatt_read_cmd *cmd = (void *) data;
	struct ble_gap_conn_desc conn;
	int rc;

	SYS_LOG_DBG("");

	rc = ble_gap_conn_find_by_addr((bt_addr_le_t *)data, &conn);
	if (rc) {
		goto fail;
	}

	if (!gatt_buf_reserve(sizeof(struct gatt_read_rp))) {
		goto fail;
	}

	if (ble_gattc_read(conn.conn_handle, htole16(cmd->handle),
			   read_cb, (void *)GATT_READ)) {
		discover_destroy();
		goto fail;
	}

	return;

fail:
	tester_rsp(BTP_SERVICE_ID_GATT, GATT_READ, CONTROLLER_INDEX,
		   BTP_STATUS_FAILED);
}

static void read_long(u8_t *data, u16_t len)
{
	const struct gatt_read_long_cmd *cmd = (void *) data;
	struct ble_gap_conn_desc conn;
	int rc;

	SYS_LOG_DBG("");

	rc = ble_gap_conn_find_by_addr((bt_addr_le_t *)data, &conn);
	if (rc) {
		goto fail;
	}

	if (!gatt_buf_reserve(sizeof(struct gatt_read_rp))) {
		goto fail;
	}

	if (ble_gattc_read_long(conn.conn_handle, htole16(cmd->handle),
			   htole16(cmd->offset), read_cb,
			   (void *)GATT_READ_LONG)) {
		discover_destroy();
		goto fail;
	}

	return;

fail:
	tester_rsp(BTP_SERVICE_ID_GATT, GATT_READ_LONG, CONTROLLER_INDEX,
		   BTP_STATUS_FAILED);
}

static void read_multiple(u8_t *data, u16_t len)
{
	const struct gatt_read_multiple_cmd *cmd = (void *) data;
	u16_t handles[cmd->handles_count];
	struct ble_gap_conn_desc conn;
	int rc, i;

	SYS_LOG_DBG("");

	for (i = 0; i < ARRAY_SIZE(handles); i++) {
		handles[i] = htole16(cmd->handles[i]);
	}

	rc = ble_gap_conn_find_by_addr((bt_addr_le_t *)data, &conn);
	if (rc) {
		goto fail;
	}

	if (!gatt_buf_reserve(sizeof(struct gatt_read_rp))) {
		goto fail;
	}

	if (ble_gattc_read_mult(conn.conn_handle, handles,
				cmd->handles_count, read_cb,
				(void *)GATT_READ_MULTIPLE)) {
		discover_destroy();
		goto fail;
	}

	return;

fail:
	tester_rsp(BTP_SERVICE_ID_GATT, GATT_READ_MULTIPLE, CONTROLLER_INDEX,
		   BTP_STATUS_FAILED);
}

static void write_without_rsp(u8_t *data, u16_t len, u8_t op,
			      bool sign)
{
	const struct gatt_write_without_rsp_cmd *cmd = (void *) data;
	struct ble_gap_conn_desc conn;
	u8_t status = BTP_STATUS_SUCCESS;
	int rc;

	SYS_LOG_DBG("");

	rc = ble_gap_conn_find_by_addr((bt_addr_le_t *)data, &conn);
	if (rc) {
		status = BTP_STATUS_FAILED;
		goto rsp;
	}

	if (ble_gattc_write_no_rsp_flat(conn.conn_handle, htole16(cmd->handle),
					cmd->data, htole16(cmd->data_length))) {
		status = BTP_STATUS_FAILED;
	}

rsp:
	tester_rsp(BTP_SERVICE_ID_GATT, op, CONTROLLER_INDEX, status);
}

static int write_rsp(uint16_t conn_handle,
		     const struct ble_gatt_error *error,
		     struct ble_gatt_attr *attr,
		     void *arg)
{
	uint8_t err = (uint8_t) error->status;
	u8_t btp_opcode = (uint8_t) (int) arg;

	SYS_LOG_DBG("");

	tester_send(BTP_SERVICE_ID_GATT, btp_opcode,
		    CONTROLLER_INDEX, &err,
		    sizeof(err));
	return 0;
}

static void write(u8_t *data, u16_t len)
{
	const struct gatt_write_cmd *cmd = (void *) data;
	struct ble_gap_conn_desc conn;
	int rc;

	SYS_LOG_DBG("");

	rc = ble_gap_conn_find_by_addr((bt_addr_le_t *)data, &conn);
	if (rc) {
		goto fail;
	}

	if (ble_gattc_write_flat(conn.conn_handle, htole16(cmd->handle),
				 cmd->data, htole16(cmd->data_length),
				 write_rsp, (void *) GATT_WRITE)) {
		goto fail;
	}

	return;

fail:
	tester_rsp(BTP_SERVICE_ID_GATT, GATT_WRITE, CONTROLLER_INDEX,
		   BTP_STATUS_FAILED);
}

static void write_long(u8_t *data, u16_t len)
{
	const struct gatt_write_long_cmd *cmd = (void *) data;
	struct ble_gap_conn_desc conn;
	struct os_mbuf *om;
	int rc;

	SYS_LOG_DBG("");

	rc = ble_gap_conn_find_by_addr((bt_addr_le_t *)data, &conn);
	if (rc) {
		goto fail;
	}

	om = ble_hs_mbuf_from_flat(cmd->data, htole16(cmd->data_length));

	if (ble_gattc_write_long(conn.conn_handle, htole16(cmd->handle),
				 htole16(cmd->offset), om, write_rsp,
				 (void *) GATT_WRITE_LONG)) {
		goto fail;
	}

	return;

fail:
	tester_rsp(BTP_SERVICE_ID_GATT, GATT_WRITE_LONG, CONTROLLER_INDEX,
		   BTP_STATUS_FAILED);
}

static struct bt_gatt_subscribe_params {
    u16_t ccc_handle;
    u16_t value;
    u16_t value_handle;
} subscribe_params;

/* ev header + default MTU_ATT-3 */
static u8_t ev_buf[33];

int tester_gatt_notify_rx_ev(u16_t conn_handle, u16_t attr_handle,
			     u8_t indication, struct os_mbuf *om)
{
	struct gatt_notification_ev *ev = (void *) ev_buf;
	struct ble_gap_conn_desc conn;
	const bt_addr_le_t *addr;
	int rc;

	SYS_LOG_DBG("");

	if (!subscribe_params.ccc_handle) {
		return 0;
	}

	rc = ble_gap_conn_find(conn_handle, &conn);
	if (rc) {
		return -1;
	}

	addr = &conn.peer_ota_addr;

	ev->type = (u8_t) (indication ? GATT_CFG_INDICATE : GATT_CFG_NOTIFY);
	ev->handle = htole16(attr_handle);
	ev->data_length = htole16(om->om_len);
	memcpy(ev->data, om->om_data, om->om_len);
	memcpy(ev->address, addr->val, sizeof(ev->address));
	ev->address_type = addr->type;

	tester_send(BTP_SERVICE_ID_GATT, GATT_EV_NOTIFICATION,
		    CONTROLLER_INDEX, ev_buf, sizeof(*ev) + om->om_len);

	return 0;

}

int tester_gatt_subscribe_ev(u16_t conn_handle, u16_t attr_handle, u8_t reason,
			     u8_t prev_notify, u8_t cur_notify,
			     u8_t prev_indicate, u8_t cur_indicate)
{
	SYS_LOG_DBG("");

	if (cur_notify == 0 && cur_indicate == 0) {
		SYS_LOG_INF("Unsubscribed");
		memset(&subscribe_params, 0, sizeof(subscribe_params));
		return 0;
	}

	if (cur_notify) {
		SYS_LOG_INF("Subscribed to notifications");
	}

	if (cur_indicate) {
		SYS_LOG_INF("Subscribed to indications");
	}

	return 0;
}

static int enable_subscription(u16_t conn_handle, u16_t ccc_handle,
			       u16_t value)
{
	u8_t op, status;
	SYS_LOG_DBG("");

//	/* Fail if there is another subscription enabled */
//	if (subscribe_params.ccc_handle) {
//		SYS_LOG_ERR("Another subscription already enabled");
//		return -EEXIST;
//	}

	op = (uint8_t) (value == 0x0002 ? GATT_CFG_NOTIFY :
			GATT_CFG_INDICATE);

	if (ble_gattc_write_no_rsp_flat(conn_handle,
					ccc_handle,
					&value,
					sizeof(value))) {
		status = BTP_STATUS_FAILED;
		goto rsp;
	}

	status = BTP_STATUS_SUCCESS;

	subscribe_params.ccc_handle = value;

rsp:
	tester_rsp(BTP_SERVICE_ID_GATT, op, CONTROLLER_INDEX, status);

//	subscribe_params.ccc_handle = ccc_handle;
//	subscribe_params.value = value;
//
//	return ble_gattc_disc_all_chrs(conn_handle, 0x0001,
//		ccc_handle, discover_func, NULL);
	return 0;
}

static int disable_subscription(u16_t conn_handle, u16_t ccc_handle)
{
	u16_t value = 0x00;

	SYS_LOG_DBG("");

	/* Fail if CCC handle doesn't match */
	if (ccc_handle != subscribe_params.ccc_handle) {
		SYS_LOG_ERR("CCC handle doesn't match");
		return -EINVAL;
	}

	if (ble_gattc_write_no_rsp_flat(conn_handle, ccc_handle,
					&value, sizeof(value))) {
		return -EINVAL;
	}

	subscribe_params.ccc_handle = 0;

	return 0;
}

static void config_subscription(u8_t *data, u16_t len, u8_t op)
{
	const struct gatt_cfg_notify_cmd *cmd = (void *) data;
	struct ble_gap_conn_desc conn;
	u16_t ccc_handle = sys_le16_to_cpu(cmd->ccc_handle);
	u8_t status;
	int rc;

	SYS_LOG_DBG("");

	rc = ble_gap_conn_find_by_addr((bt_addr_le_t *)data, &conn);
	if (rc) {
		tester_rsp(BTP_SERVICE_ID_GATT, op, CONTROLLER_INDEX,
			   BTP_STATUS_FAILED);
		return;
	}

	if (cmd->enable) {
		u16_t value;

		if (op == GATT_CFG_NOTIFY) {
			value = 0x0002;
		} else {
			value = 0x0001;
		}

		/* on success response will be sent from callback */
		if (enable_subscription(conn.conn_handle,
					ccc_handle, value) == 0) {
			return;
		}

		status = BTP_STATUS_FAILED;
	} else {
		if (disable_subscription(conn.conn_handle, ccc_handle) < 0) {
			status = BTP_STATUS_FAILED;
		} else {
			status = BTP_STATUS_SUCCESS;
		}
	}

	SYS_LOG_DBG("Config subscription (op %u) status %u", op, status);

	tester_rsp(BTP_SERVICE_ID_GATT, op, CONTROLLER_INDEX, status);
}

struct get_attrs_foreach_data {
	ble_uuid_any_t *uuid;
	u16_t start_handle, end_handle;
	struct os_mbuf *buf;
	u8_t count;
};

static u8_t foreach_get_attrs(u16_t handle,
			      u16_t flags,
			      bool chr,
			      const ble_uuid_t *uuid,
			      struct get_attrs_foreach_data *foreach)
{
	struct gatt_attr *gatt_attr;
	int *flag_arr;
	int flag_arr_len;
	int i;

	if (handle < foreach->start_handle && handle > foreach->end_handle) {
		return 0;
	}

	if (foreach->uuid && ble_uuid_cmp(&foreach->uuid->u, uuid)) {
		return 0;
	}

	SYS_LOG_DBG("");

	gatt_attr = net_buf_simple_add(foreach->buf, sizeof(*gatt_attr));
	gatt_attr->handle = htole16(handle);
	if (chr) {
		flag_arr = gatt_chr_perm_map;
		flag_arr_len = ARRAY_SIZE(gatt_chr_perm_map);

		/* FIXME: Handle WRITE_NO_RSP */
		if (flags & BLE_GATT_CHR_F_WRITE_NO_RSP) {
			gatt_attr->permission |= BIT(1);
		}
	} else {
		flag_arr = gatt_dsc_perm_map;
		flag_arr_len = ARRAY_SIZE(gatt_dsc_perm_map);
	}

	for (i = 0; i < flag_arr_len; ++i) {
		if (flags & flag_arr[i]) {
			gatt_attr->permission |= BIT(i);
		}
	}

	if (uuid->type == BLE_UUID_TYPE_16) {
		gatt_attr->type_length = 2;
		net_buf_simple_add_le16(foreach->buf,
					BLE_UUID16(uuid)->value);
	} else {
		gatt_attr->type_length = 16;
		net_buf_simple_add_mem(foreach->buf,
				       BLE_UUID128(uuid)->value,
				       gatt_attr->type_length);
	}

	foreach->count++;

	return 0;
}

static void get_attrs_cb(const struct ble_gatt_svc_def *svc,
			 uint16_t handle, uint16_t end_group_handle,
			 void *arg)
{
	struct get_attrs_foreach_data *foreach = arg;
	const struct ble_gatt_chr_def *chr;
	const struct ble_gatt_dsc_def *dsc;

	SYS_LOG_DBG("");

	handle += 1;

	for (chr = svc->characteristics; chr && chr->uuid; ++chr) {
		handle += 2;
		foreach_get_attrs(handle, chr->flags, true,
				  chr->uuid, foreach);
		for (dsc = chr->descriptors; dsc && dsc->uuid; ++dsc) {
			handle++;
			foreach_get_attrs(handle, dsc->att_flags,
					  false, dsc->uuid, foreach);
		}
	}
}

static void get_attrs(u8_t *data, u16_t len)
{
	const struct gatt_get_attributes_cmd *cmd = (void *) data;
	struct gatt_get_attributes_rp *rp;
	struct os_mbuf *buf = NET_BUF_SIMPLE(BTP_DATA_MAX_SIZE);
	struct get_attrs_foreach_data foreach;
	u16_t start_handle, end_handle;
        ble_uuid_any_t uuid;
        char str[BLE_UUID_STR_LEN];

	SYS_LOG_DBG("");

        memset(str, 0, sizeof(str));
	memset(&uuid, 0, sizeof(uuid));
	start_handle = htole16(cmd->start_handle);
	end_handle = htole16(cmd->end_handle);

	if (cmd->type_length) {
		if (btp2bt_uuid(cmd->type, cmd->type_length, &uuid)) {
			goto fail;
		}

		ble_uuid_to_str(&uuid.u, str);
		SYS_LOG_DBG("start 0x%04x end 0x%04x, uuid %s", start_handle,
			    end_handle, str);

		foreach.uuid = &uuid;
	} else {
		SYS_LOG_DBG("start 0x%04x end 0x%04x", start_handle, end_handle);
		foreach.uuid = NULL;
	}

	net_buf_simple_init(buf, sizeof(*rp));

	foreach.start_handle = start_handle;
	foreach.end_handle = end_handle;
	foreach.buf = buf;
	foreach.count = 0;

	ble_gatts_lcl_svc_foreach(get_attrs_cb, &foreach);

	rp = (void *) net_buf_simple_push(buf, sizeof(*rp));
	rp->attrs_count = foreach.count;

	tester_send(BTP_SERVICE_ID_GATT, GATT_GET_ATTRIBUTES, CONTROLLER_INDEX,
		    buf->om_data, buf->om_len);

	goto free;
fail:
	tester_rsp(BTP_SERVICE_ID_GATT, GATT_GET_ATTRIBUTES, CONTROLLER_INDEX,
		   BTP_STATUS_FAILED);
free:
	os_mbuf_free_chain(buf);
}

static int foreach_get_attr_val(u16_t handle,
				ble_gatt_access_fn access_cb,
				void *arg,
				struct ble_gatt_access_ctxt *ctxt,
				u16_t rx_handle)

{
	struct gatt_get_attribute_value_rp *rp;
	int rc;

	if (handle != rx_handle) {
		return 0;
	}

	SYS_LOG_DBG("handle=%d", handle);

	rp = net_buf_simple_add(ctxt->om, sizeof(*rp));

	SYS_LOG_DBG("len=%d", ctxt->om->om_len);

	rc = access_cb(0, handle, ctxt, arg);

	rp->att_response = (uint8_t) rc;
	SYS_LOG_DBG("len=%d", ctxt->om->om_len);
	rp->value_length += ctxt->om->om_len;

	return BLE_HS_EDONE;
}

static void get_attr_val_cb(const struct ble_gatt_svc_def *svc,
			    uint16_t handle, uint16_t end_group_handle,
			    void *arg)
{
	struct get_attrs_foreach_data *foreach = arg;
	struct os_mbuf *buf = foreach->buf;
	struct ble_gatt_access_ctxt ctxt;
	const struct ble_gatt_chr_def *chr;
	const struct ble_gatt_dsc_def *dsc;
	int rc;

	SYS_LOG_DBG("");

	ctxt.om = buf;

	for (chr = svc->characteristics; chr && chr->uuid; ++chr) {
		handle += 2;

		ctxt.op = BLE_GATT_ACCESS_OP_READ_CHR;
		ctxt.chr = chr;

		rc = foreach_get_attr_val(handle,
					  chr->access_cb, chr->arg,
					  &ctxt, foreach->start_handle);
		if (rc == BLE_HS_EDONE) {
			return;
		}

		for (dsc = chr->descriptors; dsc && dsc->uuid; ++dsc) {
			handle++;

			ctxt.op = BLE_GATT_ACCESS_OP_READ_DSC;
			ctxt.dsc = dsc;

			rc = foreach_get_attr_val(handle,
						  dsc->access_cb, dsc->arg,
						  &ctxt, foreach->start_handle);
			if (rc == BLE_HS_EDONE) {
				return;
			}
		}
	}
}

static void get_attr_val(u8_t *data, u16_t len)
{
	const struct gatt_get_attribute_value_cmd *cmd = (void *) data;
	struct os_mbuf *buf = NET_BUF_SIMPLE(BTP_DATA_MAX_SIZE);
	struct get_attrs_foreach_data foreach;
	u16_t handle = sys_cpu_to_le16(cmd->handle);

	SYS_LOG_DBG("handle=%d", handle);

	memset(&foreach, 0, sizeof(foreach));
	net_buf_simple_init(buf, 0);

	foreach.buf = buf;
	foreach.start_handle = handle;

	ble_gatts_lcl_svc_foreach(get_attr_val_cb, &foreach);

	if (buf->om_len) {
		tester_send(BTP_SERVICE_ID_GATT, GATT_GET_ATTRIBUTE_VALUE,
			    CONTROLLER_INDEX, buf->om_data, buf->om_len);
	} else {
		tester_rsp(BTP_SERVICE_ID_GATT, GATT_GET_ATTRIBUTE_VALUE,
			   CONTROLLER_INDEX, BTP_STATUS_FAILED);
	}

	os_mbuf_free_chain(buf);
}

void tester_handle_gatt(u8_t opcode, u8_t index, u8_t *data,
			 u16_t len)
{
	switch (opcode) {
	case GATT_READ_SUPPORTED_COMMANDS:
		supported_commands(data, len);
		return;
	case GATT_ADD_SERVICE:
		add_service(data, len);
		return;
	case GATT_ADD_CHARACTERISTIC:
		add_characteristic(data, len);
		return;
	case GATT_ADD_DESCRIPTOR:
		add_descriptor(data, len);
		return;
	case GATT_ADD_INCLUDED_SERVICE:
		add_included(data, len);
		return;
	case GATT_SET_VALUE:
		set_value(data, len);
		return;
	case GATT_START_SERVER:
		start_server(data, len);
		return;
	case GATT_SET_ENC_KEY_SIZE:
		set_enc_key_size(data, len);
		return;
	case GATT_EXCHANGE_MTU:
		exchange_mtu(data, len);
		return;
	case GATT_DISC_PRIM_UUID:
		disc_prim_uuid(data, len);
		return;
	case GATT_FIND_INCLUDED:
		find_included(data, len);
		return;
	case GATT_DISC_ALL_CHRC:
		disc_all_chrc(data, len);
		return;
	case GATT_DISC_CHRC_UUID:
		disc_chrc_uuid(data, len);
		return;
	case GATT_DISC_ALL_DESC:
		disc_all_desc(data, len);
		return;
	case GATT_READ:
		read(data, len);
		return;
	case GATT_READ_LONG:
		read_long(data, len);
		return;
	case GATT_READ_MULTIPLE:
		read_multiple(data, len);
		return;
	case GATT_WRITE_WITHOUT_RSP:
		write_without_rsp(data, len, opcode, false);
		return;
	case GATT_SIGNED_WRITE_WITHOUT_RSP:
		write_without_rsp(data, len, opcode, true);
		return;
	case GATT_WRITE:
		write(data, len);
		return;
	case GATT_WRITE_LONG:
		write_long(data, len);
		return;
	case GATT_CFG_NOTIFY:
	case GATT_CFG_INDICATE:
		config_subscription(data, len, opcode);
		return;
	case GATT_GET_ATTRIBUTES:
		get_attrs(data, len);
		return;
	case GATT_GET_ATTRIBUTE_VALUE:
		get_attr_val(data, len);
		return;
	default:
		tester_rsp(BTP_SERVICE_ID_GATT, opcode, index,
			   BTP_STATUS_UNKNOWN_CMD);
		return;
	}
}

u8_t tester_init_gatt(void)
{
	return BTP_STATUS_SUCCESS;
}

u8_t tester_unregister_gatt(void)
{
	return BTP_STATUS_SUCCESS;
}
