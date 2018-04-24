/*
 * Software in this file is based heavily on code written in the FreeBSD source
 * code repostiory.  While the code is written from scratch, it contains
 * many of the ideas and logic flow in the original source, this is a
 * derivative work, and the following license applies as well:
 *
 * Copyright (c) 1982, 1986, 1988, 1991, 1993
 *  The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include "FreeRTOS.h"
#include "task.h"
#include "timers.h"
#include "bsp.h"
#include "nordic_common.h"
#include "nrf_drv_clock.h"
#include "sdk_errors.h"
#include "app_error.h"

#include "nimble/nimble_port.h"
#include "host/ble_hs.h"
#include "services/gap/ble_svc_gap.h"

static const char gap_name[] = "FreeRTOS NimBLE";

static TaskHandle_t nimble_host_task_h;

static void start_advertise(void);

static void
put_ad(uint8_t ad_type, uint8_t ad_len, const void *ad, uint8_t *buf,
       uint8_t *len)
{
    buf[(*len)++] = ad_len + 1;
    buf[(*len)++] = ad_type;

    memcpy(&buf[*len], ad, ad_len);

    *len += ad_len;
}

static void
update_ad(void)
{
    uint8_t ad[BLE_HS_ADV_MAX_SZ];
    uint8_t ad_len = 0;
    uint8_t ad_flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;

    put_ad(BLE_HS_ADV_TYPE_FLAGS, 1, &ad_flags, ad, &ad_len);
    put_ad(BLE_HS_ADV_TYPE_COMP_NAME, sizeof(gap_name), gap_name, ad, &ad_len);

    ble_gap_adv_set_data(ad, ad_len);
}

static int
gap_event_cb(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status) {
            start_advertise();
        }
        break;

    case BLE_GAP_EVENT_DISCONNECT:
        start_advertise();
        break;
    }

    return 0;
}

static void
start_advertise(void)
{
    struct ble_gap_adv_params advp;
    int rc;

    update_ad();

    memset(&advp, 0, sizeof advp);
    advp.conn_mode = BLE_GAP_CONN_MODE_UND;
    advp.disc_mode = BLE_GAP_DISC_MODE_GEN;
    rc = ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, NULL, BLE_HS_FOREVER,
                           &advp, gap_event_cb, NULL);
    assert(rc == 0);
}

static void
on_sync_cb(void)
{
    start_advertise();
}

static void
nimble_host_task(void *param)
{
    ble_hs_cfg.sync_cb = on_sync_cb;

    ble_svc_gap_device_name_set(gap_name);

    while (1) {
        os_eventq_run(os_eventq_dflt_get());
    }
}

int main(void)
{
    ret_code_t ret;

    ret = nrf_drv_clock_init();
    APP_ERROR_CHECK(ret);

    bsp_board_init(BSP_INIT_LEDS);

    /* Initialize NimBLE porting layer */
    nimble_port_init();

    /*
     * Create task where NimBLE host will run. It is not strictly necessary to
     * have separate task for NimBLE host, but since it needs to read default
     * event queue it is just easier to handle it like this.
     */
    xTaskCreate(nimble_host_task, "nh", configMINIMAL_STACK_SIZE + 400,
                NULL, 1, &nimble_host_task_h);

    vTaskStartScheduler();

    /* We should never reach this code */
    assert(0);

    while (true) {
    }
}
