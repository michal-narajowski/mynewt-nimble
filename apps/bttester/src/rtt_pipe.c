/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include "syscfg/syscfg.h"

#if MYNEWT_VAL(BTTESTER_PIPE_RTT)

#include "os/mynewt.h"
#include "rtt/SEGGER_RTT.h"

#include "bttester_pipe.h"

static struct hal_timer rtt_timer;

static bttester_pipe_recv_cb app_cb;

static u8_t *recv_buf;
static size_t recv_buf_len;
static size_t recv_off;

#define RTT_INPUT_POLL_INTERVAL_MIN     10 /* ms */
#define RTT_INPUT_POLL_INTERVAL_STEP    10 /* ms */
#define RTT_INPUT_POLL_INTERVAL_MAX     250 /* ms */

static void
rtt_pipe_poll_func(void *arg)
{
    static uint32_t itvl_ms = RTT_INPUT_POLL_INTERVAL_MIN;
    static int key = -1;
    int avail = recv_buf_len - recv_off;

    if (key < 0) {
        key = SEGGER_RTT_GetKey();
    }

    if (key < 0) {
        itvl_ms += RTT_INPUT_POLL_INTERVAL_STEP;
        itvl_ms = min(itvl_ms, RTT_INPUT_POLL_INTERVAL_MAX);
    } else {
        while (key >= 0 && avail > 0) {
            recv_buf[recv_off] = (u8_t) key;
            recv_off++;
            avail = recv_buf_len - recv_off;
            key = SEGGER_RTT_GetKey();
        }

        /*
	 * Call application callback with received data. Application
	 * may provide new buffer or alter data offset.
	 */
        recv_buf = app_cb(recv_buf, &recv_off);

        itvl_ms = RTT_INPUT_POLL_INTERVAL_MIN;
    }

    os_cputime_timer_relative(&rtt_timer, itvl_ms * 1000);
}

int
bttester_pipe_send(const u8_t *data, int len)
{
    SEGGER_RTT_Write(0, data, len);
    return 0;
}


void
bttester_pipe_register(u8_t *buf, size_t len, bttester_pipe_recv_cb cb)
{
    recv_buf = buf;
    recv_buf_len = len;
    app_cb = cb;
}

int
bttester_pipe_init(void)
{
    os_cputime_timer_init(&rtt_timer, rtt_pipe_poll_func, NULL);
    os_cputime_timer_relative(&rtt_timer, 200000);
    return 0;
}
#endif /* MYNEWT_VAL(BTTESTER_PIPE_RTT) */
