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

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "os/os.h"

static struct os_eventq dflt_evq;
#define portVECTACTIVE_MASK					( 0xFFUL )
#define portNVIC_INT_CTRL_REG             ( * ( ( volatile uint32_t * ) 0xe000ed04 ) )

static inline bool in_isr()
{
	return (portNVIC_INT_CTRL_REG & portVECTACTIVE_MASK) != 0;
}

int
os_started(void)
{
    return xTaskGetSchedulerState() != taskSCHEDULER_NOT_STARTED;
}

struct os_task *
os_sched_get_current_task(void)
{
    return xTaskGetCurrentTaskHandle();
}

os_sr_t
os_arch_save_sr(void)
{
    /* TODO return value of status register (should map to architecture-specific call) */

    return 0;
}

void
os_arch_restore_sr(os_sr_t osr)
{
    /* TODO restore value of status register (should map to architecture-specific call) */
}

struct os_eventq *
os_eventq_dflt_get(void)
{
    if (!dflt_evq.q) {
        dflt_evq.q = xQueueCreate(32, sizeof(struct os_event *));
    }

    return &dflt_evq;
}

void
os_eventq_init(struct os_eventq *evq)
{
    evq->q = xQueueCreate(32, sizeof(struct os_event *));
}

struct os_event *
os_eventq_get_timo(struct os_eventq *evq, os_time_t timo)
{
    struct os_event *ev = NULL;
    BaseType_t ret;

    ret = xQueueReceive(evq->q, &ev, timo);
    assert(ret == pdPASS || ret == errQUEUE_EMPTY);

    if (ev) {
    	ev->ev_queued = 0;
    }

    return ev;

}

struct os_event *
os_eventq_get(struct os_eventq *evq)
{
	return os_eventq_get_timo(evq, portMAX_DELAY);
}

struct os_event *os_eventq_get_no_wait(struct os_eventq *evq)
{
	return os_eventq_get_timo(evq, 0);
}

void os_sched(struct os_task *t)
{

}

os_time_t os_callout_remaining_ticks(struct os_callout *co, os_time_t now)
{
	os_time_t rt;
	uint32_t exp = xTimerGetExpiryTime(co->c_timer);

	taskENTER_CRITICAL();

	if (exp > now) {
		rt = exp - now;
	} else {
		return 0;
	}

	taskEXIT_CRITICAL();

	return rt;
}

void
os_eventq_put(struct os_eventq *evq, struct os_event *ev)
{
    BaseType_t ret;

    if (OS_EVENT_QUEUED(ev)) {
        return;
    }

    ev->ev_queued = 1;

    ret = xQueueSendToBack(evq->q, &ev, 0);
    assert(ret == pdPASS);
}
struct os_event *
os_eventq_poll_0timo(struct os_eventq **evq, int nevqs)
{
	int i;
	struct os_event *ev = NULL;

	taskENTER_CRITICAL();

	for (i = 0; i < nevqs; ++i) {
		ev = os_eventq_get_no_wait(evq[i]);
		if (ev) {
			break;
		}
	}

	taskEXIT_CRITICAL();

	return ev;
}

#define QUEUE_LENGTH 32

struct os_event *
os_eventq_poll(struct os_eventq **evq, int nevqs, os_time_t timo)
{
	int i;
	QueueSetHandle_t xQueueSet;
	struct os_event *ev;

	if (timo == 0) {
		return os_eventq_poll_0timo(evq, nevqs);
	}

	taskENTER_CRITICAL();

	xQueueSet = xQueueCreateSet( nevqs * QUEUE_LENGTH );

	for (i = 0; i < nevqs; ++i) {
		if (!os_eventq_is_empty(evq[i])) {
			return os_eventq_get_no_wait(evq[i]);
		}

		xQueueAddToSet(evq[i]->q, xQueueSet);
	}

	ev = xQueueSelectFromSet(xQueueSet, timo);

	taskEXIT_CRITICAL();

	return ev;
}

int
os_eventq_is_empty(struct os_eventq *evq)
{
	return xQueueIsQueueEmptyFromISR(evq->q);
}

void
os_eventq_remove(struct os_eventq *evq, struct os_event *ev)
{
    struct os_event *tmp_ev;
    BaseType_t ret;
    int i;
    int count;

    if (!OS_EVENT_QUEUED(ev)) {
        return;
    }

    /*
     * XXX We cannot extract element from inside FreeRTOS queue so as a quick
     * workaround we'll just remove all elements and add them back except the
     * one we need to remove. This is silly, but works for now - we probably
     * better use counting semaphore with os_queue to handle this in future.
     */

    vPortEnterCritical();

    count = uxQueueMessagesWaiting(evq->q);
    for (i = 0; i < count; i++) {
        ret = xQueueReceive(evq->q, &tmp_ev, 0);
        assert(ret == pdPASS);

        if (tmp_ev == ev) {
            continue;
        }

        ret = xQueueSendToBack(evq->q, &tmp_ev, 0);
        assert(ret == pdPASS);
    }

    vPortExitCritical();

    ev->ev_queued = 0;
}

void
os_eventq_run(struct os_eventq *evq)
{
    struct os_event *ev;

    ev = os_eventq_get(evq);
    assert(ev->ev_cb != NULL);

    ev->ev_cb(ev);
}

os_error_t
os_mutex_init(struct os_mutex *mu)
{
    if (!mu) {
        return OS_INVALID_PARM;
    }

    mu->handle = xSemaphoreCreateRecursiveMutex();
    assert(mu->handle);

    return OS_OK;
}

os_error_t
os_mutex_pend(struct os_mutex *mu, uint32_t timeout)
{
    if (!mu) {
        return OS_INVALID_PARM;
    }

    assert(mu->handle);

    if (in_isr()) {
        assert(0);
    } else {
        if (xSemaphoreTakeRecursive(mu->handle, timeout) != pdPASS) {
            return OS_TIMEOUT;
        }
    }

    return OS_OK;
}

os_error_t
os_mutex_release(struct os_mutex *mu)
{
    if (!mu) {
        return OS_INVALID_PARM;
    }

    assert(mu->handle);

    if (in_isr()) {
        assert(0);
    } else {
        if (xSemaphoreGiveRecursive(mu->handle) != pdPASS) {
            return OS_BAD_MUTEX;
        }
    }

    return OS_OK;
}

os_error_t
os_sem_init(struct os_sem *sem, uint16_t tokens)
{
    if (!sem) {
        return OS_INVALID_PARM;
    }

    sem->handle = xSemaphoreCreateCounting(128, tokens);
    assert(sem->handle);

    return OS_OK;
}

os_error_t
os_sem_pend(struct os_sem *sem, uint32_t timeout)
{
    BaseType_t woken;

    if (!sem) {
        return OS_INVALID_PARM;
    }

    assert(sem->handle);

    if (in_isr()) {
        assert(timeout == 0);
        if (xSemaphoreTakeFromISR(sem->handle, &woken) != pdPASS) {
            portYIELD_FROM_ISR(woken);
            return OS_TIMEOUT;
        }
        portYIELD_FROM_ISR(woken);
    } else {
        if (xSemaphoreTake(sem->handle, timeout) != pdPASS) {
            return OS_TIMEOUT;
        }
    }

    return OS_OK;
}

os_error_t
os_sem_release(struct os_sem *sem)
{
    BaseType_t ret;
    BaseType_t woken;

    if (!sem) {
        return OS_INVALID_PARM;
    }

    assert(sem->handle);

    if (in_isr()) {
        ret = xSemaphoreGiveFromISR(sem->handle, &woken);
        assert(ret == pdPASS);

        portYIELD_FROM_ISR(woken);
    } else {
        ret = xSemaphoreGive(sem->handle);
        assert(ret == pdPASS);
    }

    return OS_OK;
}

uint16_t
os_sem_get_count(struct os_sem *sem)
{
    return uxSemaphoreGetCount(sem->handle);
}

static void
os_callout_timer_cb(TimerHandle_t timer)
{
    struct os_callout *c;

    c = pvTimerGetTimerID(timer);
    assert(c);

    if (c->c_evq) {
        os_eventq_put(c->c_evq, &c->c_ev);
    } else {
        c->c_ev.ev_cb(&c->c_ev);
    }
}

void
os_callout_init(struct os_callout *c, struct os_eventq *evq,
                os_event_fn *ev_cb, void *ev_arg)
{
    memset(c, 0, sizeof(*c));
    c->c_ev.ev_cb = ev_cb;
    c->c_ev.ev_arg = ev_arg;
    c->c_evq = evq;
    c->c_timer = xTimerCreate("co", 1, pdFALSE, c, os_callout_timer_cb);
}

int
os_callout_reset(struct os_callout *c, int32_t ticks)
{
    BaseType_t woken1, woken2, woken3;

    if (ticks < 0) {
        return OS_EINVAL;
    }

    if (ticks == 0) {
        ticks = 1;
    }

    c->c_ticks = os_time_get() + ticks;

    if (in_isr()) {
        xTimerStopFromISR(c->c_timer, &woken1);
        xTimerChangePeriodFromISR(c->c_timer, ticks, &woken2);
        xTimerResetFromISR(c->c_timer, &woken3);

        portYIELD_FROM_ISR(woken1 || woken2 || woken3);
    } else {
        xTimerStop(c->c_timer, portMAX_DELAY);
        xTimerChangePeriod(c->c_timer, ticks, portMAX_DELAY);
        xTimerReset(c->c_timer, portMAX_DELAY);
    }

    return OS_OK;
}

int
os_callout_queued(struct os_callout *c)
{
    return xTimerIsTimerActive(c->c_timer) == pdTRUE;
}

void
os_callout_stop(struct os_callout *c)
{
    xTimerStop(c->c_timer, portMAX_DELAY);
}

os_time_t
os_time_get(void)
{
    return xTaskGetTickCountFromISR();
}

int
os_time_ms_to_ticks(uint32_t ms, uint32_t *out_ticks)
{
    /* Assume 1000 ticks/sec */
    *out_ticks = ms;

    return OS_OK;
}

int
os_time_ticks_to_ms(uint32_t ticks, uint32_t *out_ms)
{
    /* Assume 1000 ticks/sec */
    *out_ms = ticks;

    return OS_OK;
}

uint32_t
os_time_ms_to_ticks32(uint32_t ms)
{
    /* Assume 1000 ticks/sec */
    return ms;
}

uint32_t
os_time_ticks_to_ms32(uint32_t ticks)
{
    /* Assume 1000 ticks/sec */
    return ticks;
}

int64_t os_get_uptime_usec(void)
{
	return 0;
}

void os_time_delay(int32_t ticks)
{
	vTaskDelay(ticks);
}
