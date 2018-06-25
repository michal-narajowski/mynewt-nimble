/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __MODEL_SRV_H__
#define __MODEL_SRV_H__

struct bt_mesh_gen_onoff_srv_cb {
    int (*get)(struct bt_mesh_model *model, u8_t *state);
    int (*set)(struct bt_mesh_model *model, u8_t state);
};

extern const struct bt_mesh_model_op gen_onoff_srv_op[];

#define BT_MESH_MODEL_GEN_ONOFF_SRV(srv, pub)		\
	BT_MESH_MODEL(BT_MESH_MODEL_ID_GEN_ONOFF_SRV,	\
		      gen_onoff_srv_op, pub, srv)

struct bt_mesh_gen_level_srv_cb {
    int (*get)(struct bt_mesh_model *model, s16_t *level);
    int (*set)(struct bt_mesh_model *model, s16_t level);
};

extern const struct bt_mesh_model_op gen_level_srv_op[];

#define BT_MESH_MODEL_GEN_LEVEL_SRV(srv, pub)		\
	BT_MESH_MODEL(BT_MESH_MODEL_ID_GEN_LEVEL_SRV,	\
		      gen_level_srv_op, pub, srv)

struct bt_mesh_light_lightness_srv_cb {
    int (*get)(struct bt_mesh_model *model, s16_t *level);
    int (*set)(struct bt_mesh_model *model, s16_t level);
};

extern const struct bt_mesh_model_op light_lightness_srv_op[];

#define BT_MESH_MODEL_LIGHT_LIGHTNESS_SRV(srv, pub)		\
	BT_MESH_MODEL(BT_MESH_MODEL_ID_LIGHT_LIGHTNESS_SRV,	\
		      light_lightness_srv_op, pub, srv)

#define BT_MESH_SENSOR_DSC_LEN   8

struct bt_mesh_sensor_descriptor {
    u16_t pid;
    u16_t pos_tolerance:12;
    u16_t neg_tolerance:12;
    u8_t sampling;
    u8_t period;
    u8_t interval;
} __attribute__((__packed__));

struct bt_mesh_sensor_srv_cb {
    int (*dsc_get)(struct bt_mesh_model *model, u16_t pid, u8_t *data);
    int (*get)(struct bt_mesh_model *model, u16_t pid, u8_t *data);

    u8_t properties_count;
    u8_t sensor_data_size;
};

extern const struct bt_mesh_model_op sensor_srv_op[];

#define BT_MESH_MODEL_SENSOR_SRV(srv, pub)		\
	BT_MESH_MODEL(BT_MESH_MODEL_ID_SENSOR_SRV,	\
		      sensor_srv_op, pub, srv)

void bt_mesh_sensor_mpid(u8_t len, u16_t pid, u8_t *data, u8_t *mpid_len);

void bt_mesh_set_gen_onoff_srv_cb(struct bt_mesh_gen_onoff_srv_cb *gen_onoff_cb);
void bt_mesh_set_gen_level_srv_cb(struct bt_mesh_gen_level_srv_cb *gen_level_cb);
void bt_mesh_set_light_lightness_srv_cb(struct bt_mesh_light_lightness_srv_cb *light_lightness_cb);

#endif
