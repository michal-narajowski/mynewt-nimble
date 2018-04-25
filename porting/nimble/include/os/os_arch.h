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

#ifndef _OS_ARCH_H
#define _OS_ARCH_H

#include "nimble_osal/osal.h"
#include "os/os_error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned int os_sr_t;
typedef unsigned int os_stack_t;

#define OS_STACK_ALIGN(__nmemb) \
    (OS_ALIGN(((__nmemb) * 16), OS_STACK_ALIGNMENT))

#define OS_ENTER_CRITICAL(__os_sr) (__os_sr = os_arch_save_sr())
#define OS_EXIT_CRITICAL(__os_sr) (os_arch_restore_sr(__os_sr))
#define OS_ASSERT_CRITICAL() (assert(os_arch_in_critical()))

os_sr_t os_arch_save_sr(void);

void os_arch_restore_sr(os_sr_t sr);

#ifdef __cplusplus
}
#endif

#endif /* _OS_ARCH_H */
