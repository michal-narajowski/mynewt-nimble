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

#ifndef _OSAL_H_
#define _OSAL_H_

#include "FreeRTOS.h"
#include "semphr.h"
#include "task.h"
#include "timers.h"

#ifdef __cplusplus
extern "C" {
#endif

struct os_event {
    uint8_t ev_queued;
    os_event_fn *ev_cb;
    void *ev_arg;
};

struct os_eventq {
    QueueHandle_t q;
};

struct os_callout {
    struct os_event c_ev;
    struct os_eventq *c_evq;
    uint32_t c_ticks;
    TimerHandle_t c_timer;
};

struct os_mutex
{
    SemaphoreHandle_t handle;
};

struct os_sem
{
    SemaphoreHandle_t handle;
};

#ifdef __cplusplus
}
#endif

#endif  /* _OSAL_H_ */
