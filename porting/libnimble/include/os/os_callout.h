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
#ifndef _OS_CALLOUT_H
#define _OS_CALLOUT_H

#include "os/os_eventq.h"
#include "os/os_time.h"

#ifdef __cplusplus
extern "C" {
#endif

struct os_callout {
    uint32_t c_ticks;
    int dummy;
};

void os_callout_init(struct os_callout *co, struct os_eventq *evq,
                     os_event_fn *ev_cb, void *ev_arg);

void os_callout_stop(struct os_callout *co);

int os_callout_reset(struct os_callout *co, int32_t ticks);

os_time_t os_callout_remaining_ticks(struct os_callout *co, os_time_t time);

int os_callout_queued(struct os_callout *c);

void os_callout_tick(void);

os_time_t os_callout_wakeup_ticks(os_time_t now);

#ifdef __cplusplus
}
#endif

#endif /* _OS_CALLOUT_H */
