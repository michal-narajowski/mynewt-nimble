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

#ifndef _OS_H
#define _OS_H

#include "osal/osal.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef min
#define min(a, b) ((a)<(b)?(a):(b))
#endif

#ifndef max
#define max(a, b) ((a)>(b)?(a):(b))
#endif

#define OS_ALIGN(__n, __a) (                             \
        (((__n) & ((__a) - 1)) == 0)                   ? \
            (__n)                                      : \
            ((__n) + ((__a) - ((__n) & ((__a) - 1))))    \
        )

int os_started(void);

#include "os/endian.h"
#include "os/os_arch.h"
#include "os/os_callout.h"
#include "os/os_error.h"
#include "os/os_eventq.h"
#include "os/os_mbuf.h"
#include "os/os_mempool.h"
#include "os/os_mutex.h"
#include "os/os_sched.h"
#include "os/os_sem.h"
#include "os/os_task.h"
#include "os/os_time.h"

#ifdef __cplusplus
}
#endif

#endif /* _OS_H */
