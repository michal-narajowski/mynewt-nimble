#include <stddef.h>
#include <stdint.h>
#include "os/os"

int
os_started(void)
{
    /* TODO return non-zero value if OS scheduler is running */

    return 0;
}

struct os_task *
os_sched_get_current_task(void)
{
    /* TODO return current task */

    return NULL;
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

os_time_t
os_time_get(void)
{
    /* TODO get current */

    return 0;
}

int
os_time_ms_to_ticks(uint32_t ms, uint32_t *out_ticks)
{
    return 0;
}

struct os_eventq *
os_eventq_dflt_get(void)
{
    return NULL;
}

void
os_eventq_put(struct os_eventq *evq, struct os_event *ev)
{
    return;
}

os_error_t
os_mutex_init(struct os_mutex *mu)
{
    return OS_ENOENT;
}

os_error_t
os_mutex_pend(struct os_mutex *mu, uint32_t timeout)
{
    return OS_ENOENT;
}

os_error_t
os_mutex_release(struct os_mutex *mu)
{
    return OS_ENOENT;
}

os_error_t
os_sem_init(struct os_sem *sem, uint16_t tokens)
{
    return OS_ENOENT;
}

os_error_t
os_sem_release(struct os_sem *sem)
{
    return OS_ENOENT;
}

os_error_t
os_sem_pend(struct os_sem *sem, uint32_t timeout)
{
    return OS_ENOENT;
}

void
os_callout_init(struct os_callout *c, struct os_eventq *evq,
                os_event_fn *ev_cb, void *ev_arg)
{
}

int
os_callout_reset(struct os_callout *c, int32_t ticks)
{
    return OS_ENOENT;
}

int
os_task_init(struct os_task *t, const char *name, os_task_func_t func,
             void *arg, uint8_t prio, os_time_t sanity_itvl,
             os_stack_t *stack_bottom, uint16_t stack_size)
{
    return OS_ENOENT;
}
