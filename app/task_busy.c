
#include <immintrin.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>

#include <rte_spinlock.h>
#include <rte_malloc.h>

#include <eng_thread.h>
#include <eng_addon.h>

#include "app_modules.h"
#include "global_db.h"
#include "task_busy.h"
#include "app_mbuf.h"

/****************************************************************************
 * Busy task
 ****************************************************************************/
struct busy_work_s {

#define NB_VAL	3
    rte_atomic64_t val[NB_VAL];
    rte_spinlock_t lock;

} __attribute__((aligned(RTE_CACHE_LINE_SIZE * 2)));

static unsigned NB_WORKS = 8;

struct private_s {
    uint64_t cnt;
    uint64_t start;
    uint64_t nb_rtm;
    uint64_t rtm;
    struct busy_work_s *wk[64];
};

static struct busy_work_s *SharedWork;
static unsigned NB_BUSY_TASKS;


static int
BusyTaskInit(struct eng_conf_db_s *conf __rte_unused,
             struct eng_thread_s *th __rte_unused,
             struct eng_task_s *task)
{
    int ret;

    ENG_ERR(TASKBUSY, "lcore:%u", th->lcore_id);

    if (!SharedWork) {
        SharedWork = rte_zmalloc("work", sizeof(*SharedWork) * NB_WORKS,
                                 RTE_CACHE_LINE_SIZE);
        if (!SharedWork) {
            ret = -ENOMEM;
            goto end;
        }

        for (unsigned i = 0; i < NB_WORKS; i++)
            rte_spinlock_init(&SharedWork[i].lock);
    }

    struct private_s *pri = (struct private_s *) task->private_area;
    for (unsigned i = 0; i < NB_WORKS; i++)
        pri->wk[i] = &SharedWork[i];

    ret = app_global_db_add_task(task);
 end:
    if (!ret)
        task->task_id = NB_BUSY_TASKS++;

    ENG_ERR(TASKBUSY, "end. ret:%d", ret);
    return ret;
}

static inline void
CAS(rte_atomic64_t *v,
    uint64_t add)
{
    int retry;
    do {
        uint64_t src = rte_atomic64_read(v);
        retry = rte_atomic64_cmpset((volatile uint64_t *) &v->cnt,
                                    src, src + add);
    } while (!retry);
}

static inline int
spin_update(struct busy_work_s *wk)
{
    rte_spinlock_lock_tm(&wk->lock);

    for (unsigned i = 0; i < NB_VAL; i++) {
        wk->val[i].cnt += 1;
    }

    rte_spinlock_unlock_tm(&wk->lock);
    return -1;
}

static inline int
cas_update(struct busy_work_s *wk)
{
    for (unsigned i = 0; i < NB_VAL; i++) {
        CAS(&wk->val[i], 1);
    }
    return -1;
}

static inline int
atomic_update(struct busy_work_s *wk)
{
    for (unsigned i = 0; i < NB_VAL; i++) {
        rte_atomic64_inc(&wk->val[i]);
    }
    return -1;
}

static inline int
hle_update(struct busy_work_s *wk)
{
    for (unsigned i = 0; i < NB_VAL - 1; i++)
        __atomic_fetch_add(&wk->val[i].cnt, 1,
                           __ATOMIC_ACQUIRE|__ATOMIC_HLE_ACQUIRE);

    __atomic_fetch_add(&wk->val[NB_VAL - 1].cnt, 1,
                       __ATOMIC_RELEASE|__ATOMIC_HLE_RELEASE);
    return 0;
}

static inline int
rtm_update(struct busy_work_s *wk)
{
    unsigned retry = 3;

    while (retry--) {
        unsigned status;

        status = _xbegin();
        if (status == _XBEGIN_STARTED) {

            if (rte_spinlock_is_locked(&wk->lock))
                _xabort(_XABORT_CONFLICT);

            for (unsigned i = 0; i < NB_VAL; i++) {
                wk->val[i].cnt += 1;
            }
            _xend();
            return 0;
        }

        if (!(status & _XABORT_RETRY))
            break;
    }

    spin_update(wk);
    return -1;
}

static int (*update_fnc)(struct busy_work_s *) = spin_update;

int
app_task_busy_set_type(enum busy_type_e type)
{
    switch (type) {
    case TYPE_SPINLOCK:
        update_fnc = spin_update;
        break;
    case TYPE_CAS:
        update_fnc = cas_update;
        break;
    case TYPE_ATOMIC:
        update_fnc = atomic_update;
        break;
    case TYPE_HLE:
        update_fnc = hle_update;
        break;
    case TYPE_RTM:
        update_fnc = rtm_update;
        break;
    default:
        return -1;
    }
    return 0;
}

void
app_task_busy_set_nb(unsigned n)
{
    if (n > 64)
        n = 64;
    NB_WORKS = n;
}

static inline int
update_cnt(struct busy_work_s *wk)
{
    return update_fnc(wk);
}

static unsigned
BusyTaskEntry(struct eng_thread_s *th,
              struct eng_task_s *task,
              uint64_t now)
{
    struct private_s *pri = (struct private_s *) task->private_area;

#define NB_LOOPS	UINT64_C(10000000)

    if (pri->cnt < NB_LOOPS) {
        if (!pri->cnt)
             pri->start = now;

        if (!update_cnt(pri->wk[now & (NB_WORKS - 1)]))
            pri->rtm += 1;

    } else if (pri->cnt == NB_LOOPS) {
        uint64_t cnt = 0;

        for (unsigned i = 0; i < NB_WORKS; i++) {
            for (unsigned j = 0; j < NB_VAL; j++) {
                cnt += rte_atomic64_read(&pri->wk[i]->val[j]);
            }
        }

        ENG_ERR(TASKBUSY,
                "Fin core:%u RTM:%"PRIu64" cnt:%"PRIu64" %f",
                th->lcore_id,
                pri->rtm,
                cnt,
                (double) (now - pri->start) / (double) rte_get_tsc_hz());

        if (cnt == NB_LOOPS * 8 * NB_VAL)
            rte_exit(0, "end\n");
    }

    pri->cnt += 1;
    return 0;
}

static const struct eng_addon_s Addon = {
    .name       = "TkBusy",
    .task_init  = BusyTaskInit,
    .task_entry = BusyTaskEntry,
};

static struct eng_addon_constructor_s AddonConstructor = {
    .addon = &Addon,
};

void
app_task_busy_register(void)
{
    eng_addon_register(&AddonConstructor);
}
