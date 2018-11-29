/* glue.h - Bluetooth tester headers */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "os/endian.h"

#define SYS_LOG_DBG(fmt, ...)   console_printf("[DBG] %s: " fmt "\n", __func__, ## __VA_ARGS__);
#define SYS_LOG_INF(fmt, ...)   console_printf("[INF] %s: " fmt "\n", __func__, ## __VA_ARGS__);
#define SYS_LOG_ERR(fmt, ...)   console_printf("[WRN] %s: " fmt "\n", __func__, ## __VA_ARGS__);

#define sys_cpu_to_le16 htole16
#define sys_cpu_to_le32 htole32
#define sys_le32_to_cpu le32toh
