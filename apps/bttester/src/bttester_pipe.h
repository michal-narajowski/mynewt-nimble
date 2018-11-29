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

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define u8_t uint8_t

typedef u8_t *(*bttester_pipe_recv_cb)(u8_t *buf, size_t *off);
void bttester_pipe_register(u8_t *buf, size_t len, bttester_pipe_recv_cb cb);
int bttester_pipe_send(const u8_t *data, int len);
int bttester_pipe_init(void);

#ifdef __cplusplus
}
#endif

