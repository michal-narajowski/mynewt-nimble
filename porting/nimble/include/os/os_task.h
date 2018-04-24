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

#ifndef _OS_TASK_H
#define _OS_TASK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct os_task {
    int dummy;
};

typedef void (*os_task_func_t)(void *);

int os_task_init(struct os_task *, const char *, os_task_func_t, void *,
                 uint8_t, os_time_t, os_stack_t *, uint16_t);

#ifdef __cplusplus
}
#endif

#endif /* _OS_TASK_H */
