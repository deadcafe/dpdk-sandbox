/*
 * Copyright (c) 2019 deadcafe.beef@gmail.com All Rights Reserved.
 *
 * Unauthorized inspection, duplication, utilization or modification
 * of this file is prohibited.  Other related documents, whether
 * explicitly marked or implied, may also fall under this copyright.
 * Distribution of information obtained from this file and other related
 * documents to a third party is not permitted under any circumstances.
 */

/**
 * @file        eng_thread.c
 * @brief       Engine thread
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>
#include <syslog.h>
#include <pthread.h>

#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_errno.h>

#include "papi.h"

#include "conf.h"
#include "eng_port.h"
#include "eng_mbuf.h"
#include "eng_log.h"
#include "eng_addon.h"
#include "eng_thread.h"
#include "eng_panic.h"
#include "eng_cli.h"

struct thread_mng_s {
    struct eng_thread_s *lcores[RTE_MAX_LCORE];
    struct eng_thread_s *threads[RTE_MAX_LCORE];
    const struct rte_memzone *mz;
    unsigned nb_threads;
    pid_t primary;

    volatile bool is_dead __rte_cache_aligned;

} __attribute__((aligned(RTE_CACHE_LINE_SIZE)));

#define ENG_THREAD_MANAGER "EngineThreadManager"
static struct thread_mng_s *Mng;

static inline struct thread_mng_s *
find_mng(void)
{
    struct thread_mng_s *mng = Mng;

    if (!mng) {
        const struct rte_memzone *mz;

        mz = rte_memzone_lookup(ENG_THREAD_MANAGER);
        if (mz) {
            mng = mz->addr;
            Mng = mng;
        }
    }
    return mng;
}

static int
mng_init(void)
{
    struct thread_mng_s *mng = find_mng();
    int ret = 0;

    if (!mng) {
        const struct rte_memzone *mz;

        mz = rte_memzone_reserve(ENG_THREAD_MANAGER,
                                 sizeof(*mng),
                                 rte_socket_id(),
                                 RTE_MEMZONE_2MB | RTE_MEMZONE_1GB |
                                 RTE_MEMZONE_SIZE_HINT_ONLY);
        if (!mz) {
            ret = -ENOMEM;
            goto end;
        }

        mng = mz->addr;
        memset(mng, 0, sizeof(*mng));
        mng->mz = mz;
        mng->primary = getpid();
        Mng = mng;
    }
 end:
    return ret;
}

/*
 *
 */
static inline enum eng_thread_state_e
read_thread_state(struct eng_thread_s *th)
{
    enum eng_thread_state_e state =
        (enum eng_thread_state_e) rte_atomic32_read(&th->state);
    rte_rmb();
    return state;
}

static inline enum eng_thread_state_e
set_thread_state(struct eng_thread_s *th,
                 enum eng_thread_state_e state)
{
    rte_atomic32_set(&th->state, state);
    rte_wmb();
    return state;
}

static inline enum eng_thread_state_e
read_thread_cmd(struct eng_thread_s *th)
{
    enum eng_thread_state_e cmd =
        (enum eng_thread_state_e) rte_atomic32_read(&th->cmd);
    rte_rmb();
    return cmd;
}

static inline enum eng_thread_state_e
set_thread_cmd(struct eng_thread_s *th,
               enum eng_thread_state_e cmd)
{
    rte_atomic32_set(&th->cmd, cmd);
    rte_wmb();
    return cmd;
}

void
eng_thread_cmd_set(struct eng_thread_s *self,
                   enum eng_thread_state_e cmd)
{
    struct thread_mng_s *mng = find_mng();

    for (unsigned i = 0; i < mng->nb_threads; i++) {
        if (mng->threads[i] == self)
            continue;
        set_thread_cmd(mng->threads[i], cmd);
    }
    for (unsigned i = 0; i < mng->nb_threads; i++) {
        if (mng->threads[i] == self)
            continue;

        uint64_t limit = rte_rdtsc() + rte_get_tsc_hz();
        while (read_thread_state(mng->threads[i]) != cmd) {
            if (limit < rte_rdtsc()) {
                ENG_ERR(CORE, "give up. ignored:%s",
                        mng->threads[i]->name);
                break;
            }
            rte_pause();
        }
    }
}

void
eng_thread_master_exit(void)
{
    struct thread_mng_s *mng = find_mng();

    if (mng) {
        set_thread_cmd(mng->threads[0], ENG_THREAD_STATE_EXIT);
    }
}

__attribute__((destructor)) static void
set_dead(void)
{
    struct thread_mng_s *mng = find_mng();

    if (mng && !mng->is_dead) {
        if (mng->primary == getpid() &&
            rte_lcore_id() == rte_get_master_lcore()) {
            mng->is_dead = true;
            rte_wmb();
            fprintf(stderr, "i'm dead.\n");
        } else {
            fprintf(stderr, "i'm not master.\n");
        }
    }
}

bool
eng_primary_is_dead(void)
{
    struct thread_mng_s *mng = find_mng();
    bool ret = false;

    if (mng) {
        ret = mng->is_dead;
        rte_rmb();
    } else {
        fprintf(stderr, "not found mng.\n");
    }
    return ret;
}

/*
 *
 */
static inline unsigned
task_sched(struct eng_thread_s *th)
{
    struct eng_task_s *task;
    uint64_t now = rte_rdtsc();
    uint64_t limits = rte_get_tsc_hz();
    limits >>= 10;	/* 1ms */
    uint64_t th_sub = 0;
    unsigned th_cnt = 0;

    STAILQ_FOREACH(task, &th->tasks, node) {
        unsigned nb;
        uint64_t last, sub;
#if 0
        ENG_ERR(CORE, "th:%s tsk:%s", th->name, task->name);
#endif
        nb = task->entry(th, task, now);

        last = now;
        now = rte_rdtsc();
        sub = now - last;

        if (nb) {
            task->usage.events += nb;
            task->usage.execs += 1;
            task->usage.tsc_sum += sub;

            if (sub > limits)
                task->usage.busies += 1;
        } else {
            task->usage.idles += 1;
            task->usage.idle_tsc += sub;

            if (sub > limits)
                task->usage.exceptions += 1;
        }
        task->usage.update = now;

        th_sub += sub;
        th_cnt += nb;
    }

    if (th_cnt) {
        th->usage.events += th_cnt;
        th->usage.execs += 1;
        th->usage.tsc_sum += th_sub;

        if (th_sub > limits)
            th->usage.busies += 1;
    } else {
        th->usage.idles += 1;
        th->usage.idle_tsc += th_sub;

        if (th_sub > limits)
            th->usage.exceptions += 1;
    }
    th->usage.update = now;

    return th_cnt;
}

static const char *StateName[] = {
    "Stop",
    "Run",
    "Exit",
};

/*
 *
 */
static void
thread_loop(struct eng_thread_s *th)
{
    th->start_tsc = rte_rdtsc();
    ENG_WARN(CORE, "thread start: %s %"PRIu64, th->name, th->start_tsc);

    bool is_master = (rte_lcore_id() == rte_get_master_lcore());
    if (is_master) {
        set_thread_cmd(th, ENG_THREAD_STATE_RUNNING);
        eng_thread_cmd_set(th, ENG_THREAD_STATE_RUNNING);
    }

    enum eng_thread_state_e state, cmd;
    state = read_thread_state(th);

    while (1) {
        cmd = read_thread_cmd(th);
#if 0
        ENG_DEBUG(CORE, "%s state:%s cmd:%s", th->name,
                  StateName[state], StateName[cmd]);
#endif

        if (unlikely(cmd != state)) {

            ENG_DEBUG(CORE, "%s %s -> %s %"PRIu64, th->name,
                      StateName[state], StateName[cmd],
                      th->start_tsc);

            switch (cmd) {
            case ENG_THREAD_STATE_STOP:
                /* flush all ports */
                eng_port_flush_ports(&th->ports);
                break;

            case ENG_THREAD_STATE_RUNNING:
                break;

            default:
                ENG_ERR(CORE, "unknown cmd:%d ignored\n", cmd);
                cmd = ENG_THREAD_STATE_EXIT;
                /* fall-through */
            case ENG_THREAD_STATE_EXIT:
                eng_port_flush_ports(&th->ports);
                break;
            }

            state = set_thread_state(th, cmd);
        }

        if (state == ENG_THREAD_STATE_RUNNING) {
            if (!task_sched(th)) {
                eng_port_flush_ports(&th->ports);
                rte_pause();
            }
        } else if (state == ENG_THREAD_STATE_EXIT) {
            break;
        } else {
            rte_pause();
        }
    }

    if (is_master) {
        ENG_WARN(CORE, "process going down. pid:%d", getpid());
        eng_thread_cmd_set(th, ENG_THREAD_STATE_EXIT);
        set_dead();
        rte_exit(0, "bye\n");
    }

    ENG_WARN(CORE, "Exit: %s", th->name);
}

struct eng_thread_s *
eng_thread_self_info(void)
{
    struct thread_mng_s *mng = find_mng();

    return mng->lcores[rte_lcore_id()];
}

unsigned
eng_thread_nb_threads(void)
{
    struct thread_mng_s *mng = find_mng();

    return mng->nb_threads;
}

struct eng_thread_s *
eng_thread_info_th(unsigned th_id)
{
    struct thread_mng_s *mng = find_mng();

    if (th_id > mng->nb_threads)
        return NULL;
    return mng->threads[th_id];
}

/*
 *
 */
static int
thread_entry(void *arg __rte_unused)
{
    thread_loop(eng_thread_self_info());
    return 0;
}

static struct eng_task_s *
create_task(struct eng_conf_db_s *db,
            struct eng_thread_s *th,
            const char *name)
{
    struct eng_task_s *task;

    ENG_DEBUG(CORE, "creating task: %s", name);

    task = rte_zmalloc_socket(name, sizeof(*task), RTE_CACHE_LINE_SIZE,
                              rte_lcore_to_socket_id(th->lcore_id));
    if (task) {
        const char *in_port;

        snprintf(task->name, sizeof(task->name), "%s", name);

        in_port = eng_conf_task_in_port(db, name);
        if (in_port) {
            task->in_port = eng_port_find(&th->ports, in_port,
                                         ENG_PORT_DIR_IN);
            if (!task->in_port) {
                task->in_port = eng_port_in_create(db, in_port);
                if (!task->in_port) {
                    rte_free(task);
                    task = NULL;
                    goto end;
                }
                STAILQ_INSERT_TAIL(&th->ports, task->in_port, node);
            }
            th->nb_ports++;
        }

        /* create out-ports */
        char buff[512];
        int nb_ports;
        const char *ports[ENG_MAX_NB_OUT_PORTS];

        nb_ports = eng_conf_task_out_port_list(db, name,
                                               ports, RTE_DIM(ports),
                                               buff, sizeof(buff));
        for (int i = 0; i < nb_ports; i++) {
            task->out_ports[i] = eng_port_find(&th->ports, ports[i],
                                                    ENG_PORT_DIR_OUT);
            if (!task->out_ports[i]) {
                task->out_ports[i] = eng_port_out_create(db, ports[i]);
                if (!task->out_ports[i]) {
                    rte_free(task);
                    task = NULL;
                    goto end;
                }
                STAILQ_INSERT_TAIL(&th->ports, task->out_ports[i],
                                   node);
            }
        }
        task->nb_out_ports = nb_ports;
        th->nb_ports += task->nb_out_ports;
        task->burst_size = ENG_TASK_BURST_SIZE_DEFAULT;
        task->th = th;
        ENG_DEBUG(CORE, "created task: %s", name);
    }
 end:
    return task;
}

static int
create_task_list(struct eng_conf_db_s *db,
                 struct eng_thread_s *th,
                 const char *th_name)
{
    char buff[256];
    const char *tasks[ENG_MAX_NB_TASKS];
    int nb_tasks;

    nb_tasks = eng_conf_thread_task_list(db, th_name,
                                         tasks, RTE_DIM(tasks),
                                         buff, sizeof(buff));
    if (nb_tasks <= 0)
        return -1;

    for (int i = 0; i < nb_tasks; i++) {
        struct eng_task_s *task;

        task = create_task(db, th, tasks[i]);
        if (task) {
            th->nb_tasks++;
            STAILQ_INSERT_TAIL(&th->tasks, task, node);
        } else {
            ENG_ERR(CORE, "failed to create task: %s", tasks[i]);
            return -1;
        }
    }
    return 0;
}

static int
setup_task(struct eng_conf_db_s *db,
           struct eng_thread_s *th,
           struct eng_task_s *task)
{
    const char *addon = eng_conf_task_addon(db, task->name);
    if (!addon) {
        return -1;
    }
    if (eng_addon_task_init(db, addon, th, task)) {
        ENG_ERR(CORE, "failed init addon: %s", addon);
        return -1;
    }
    return 0;
}

static struct rte_mempool *
thread_mbufpool(struct eng_conf_db_s *db,
                const char *name)
{
    return eng_mbufpool(db, eng_conf_thread_mbufpool(db, name));
}

static struct eng_thread_s *
create_thread(struct eng_conf_db_s *db,
              const char *name,
              unsigned lcore_id,
              unsigned thread_id)
{
    struct eng_thread_s *th;

    ENG_DEBUG(CORE, "creating thread: %s", name);

    th = rte_zmalloc_socket(NULL, sizeof(*th),
                            RTE_CACHE_LINE_SIZE * 2,
                            rte_socket_id());
    if (th) {
        th->mp = thread_mbufpool(db, name);
        if (th->mp == NULL) {
            rte_free(th);
            th = NULL;
            goto end;
        }

        snprintf(th->name, RTE_DIM(th->name), "%s", name);

        th->thread_id = thread_id;
        th->lcore_id = lcore_id;
        th->nb_slaves = 0;
        th->nb_ports = 0;
        th->nb_tasks = 0;

        set_thread_state(th, ENG_THREAD_STATE_STOP);
        set_thread_cmd(th, ENG_THREAD_STATE_STOP);

        STAILQ_INIT(&th->tasks);
        STAILQ_INIT(&th->ports);
        STAILQ_INIT(&th->slaves);

        if (create_task_list(db, th, name)) {
            rte_free(th);
            th = NULL;
            goto end;
        }
        ENG_DEBUG(CORE, "created thread: %s", name);
    } else {
        ENG_ERR(CORE, "not enough memory: %s", name);
    }
 end:
    return th;
}

static int
setup_thread(struct eng_conf_db_s *db,
             struct eng_thread_s *th)
{
    /* setup tasks in thread */
    struct eng_task_s *task;
    STAILQ_FOREACH(task, &th->tasks, node) {
        if (setup_task(db, th, task)) {
            return -1;
        }
    }
    return 0;
}

/*****************************************************************************
 *
 *****************************************************************************/
static void *
poll_primary(void *arg __rte_unused)
{
    while (!eng_primary_is_dead())
        sleep(1);

    rte_exit(0, "Primary is dead, bye.\n");
}

#define ARRAYOF(_a)	(sizeof(_a)/sizeof(_a[0]))

#define SET_ARG(_ac,_av,_v)                                     \
    do {                                                        \
        if (ARRAYOF(_av) - 1 > (unsigned) (_ac)) {              \
            (_av)[(_ac)] = (_v);                                \
            (_ac) += 1;                                         \
            (_av)[(_ac)] = NULL;                                \
        }                                                       \
    } while (0)

int
eng_thread_second(const char *prog,
                  unsigned lcore)
{
    char *args;
    int ac = 0;
    char *av[64];
    size_t size = 1024;
    int ret = -1;

    args = malloc(size);
    if (args) {
        char *p = args;
        size_t len;

        len = snprintf(p, size, "%s", prog);
        SET_ARG(ac, av, p);
        p += (len + 1);
        size -= (len + 1);

#if 0
        len = snprintf(p, size, "--lcores=%u", lcore);
        SET_ARG(ac, av, p);
        p += (len + 1);
        size -= (len + 1);
#else
        (void) lcore;
#endif

        len = snprintf(p, size, "--proc-type=secondary");
        SET_ARG(ac, av, p);
        p += (len + 1);
        size -= (len + 1);

        len = snprintf(p, size, "--no-pci");
        SET_ARG(ac, av, p);
        p += (len + 1);
        size -= (len + 1);

        optind = 0;	/* reset getopt */

        ret = rte_eal_init(ac, av);
        if (ret < 0) {
            fprintf(stderr, "init faile. ret:%d %s",
                    ret, rte_strerror(rte_errno));

            fprintf(stderr, "eal options:\n");
            for (int i = 0; i < ac; i++)
                fprintf(stderr, "\t%d %s\n", i, av[i]);
        } else {
            pthread_t th;
            if (pthread_create(&th, NULL, poll_primary, NULL))
                return -1;
        }

        free(args);
    }
    return (ret < 0) ? -1 : 0;
}

/*
 * signal catcher thread
 */
static void *
signal_handler(void *arg)
{
    struct eng_signal_s *eng_signal = arg;
    int sig_no;

    while ((sigwait(&eng_signal->sigset, &sig_no)) == 0) {
        if (eng_signal->handler)
            eng_signal->handler(sig_no);
    }
    return arg;
}

static int
create_signal_thread(struct eng_signal_s *eng_signal)
{
    ENG_ERR(CORE, "start\n");

    if (eng_signal) {
        if (!sigisemptyset(&eng_signal->sigset)) {
            pthread_t th;
            pthread_attr_t attr;

            pthread_attr_init(&attr);
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

#if 0 /* unnecessary */
            cpu_set_t cpuset;
            if (pthread_getaffinity_np(pthread_self(), sizeof(cpuset), &cpuset))
                return -1;
            if (pthread_attr_setaffinity_np(&attr, sizeof(cpuset), &cpuset))
                return -1;
#endif
            if (pthread_create(&th, &attr, signal_handler, eng_signal)) {
                ENG_ERR(CORE, "failed to create signal thread\n");
                return -1;
            }
        }
    }
    ENG_ERR(CORE, "end\n");
    return 0;
}

int
eng_thread_launch(struct eng_conf_db_s *db,
                  struct eng_signal_s *eng_signal)
{
    unsigned lcore_id;
    unsigned nb_slaves = 0;
    int ret = -1;

    ENG_ERR(CORE, "start\n");

    if (!db)
        return -EINVAL;

    if (create_signal_thread(eng_signal))
        goto end;

    if (mng_init())
        goto end;

    struct thread_mng_s *mng = find_mng();

    /* create slaves */
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        const char *name;
        struct eng_thread_s *th;
        unsigned thread_id;

        name = eng_conf_lcore_thread(db, lcore_id);
        if (!name)
            goto end;

        ENG_DEBUG(CORE, "creating lcore_id: %u", lcore_id);

        thread_id = ++nb_slaves;

        th = create_thread(db, name, lcore_id, thread_id);
        if (!th)
            goto end;

        mng->threads[thread_id] = th;
        mng->lcores[lcore_id] = th;

        ENG_DEBUG(CORE, "done lcore_id: %u", lcore_id);
    }

    /* create master */
    {
        lcore_id = rte_get_master_lcore();

        const char *name = eng_conf_lcore_thread(db, lcore_id);
        if (!name)
            goto end;

        ENG_DEBUG(CORE, "creating lcore_id: %u", lcore_id);

        struct eng_thread_s *th = create_thread(db, name, lcore_id, 0);
        if (!th)
            goto end;

        th->nb_slaves = nb_slaves;

        for (unsigned i = 1; i <= nb_slaves; i++) {
            mng->threads[i]->nb_slaves = nb_slaves;
            STAILQ_INSERT_TAIL(&th->slaves, mng->threads[i], node);
        }

        mng->threads[0] = th;
        mng->lcores[lcore_id] = th;
        mng->nb_threads = nb_slaves + 1;

        ENG_DEBUG(CORE, "done lcore_id: %u", lcore_id);
    }

    /*
     * must be after pmd port creation (done by create_thread())
     */
    if (eng_addon_global_init(db))
        goto end;

    /* setup threads */
    {
        unsigned thread_id;
        for (thread_id = 0; thread_id < mng->nb_threads; thread_id++) {
            if (setup_thread(db, mng->threads[thread_id]))
                goto end;
        }
        mng->threads[0]->conf_db = db;
    }

    ret = rte_eal_mp_remote_launch(thread_entry, NULL, CALL_MASTER);
    rte_eal_mp_wait_lcore();
 end:

    ENG_ERR(CORE, "end: %d\n", ret);
    return ret;
}

static unsigned
get_lcore_list(struct eng_conf_db_s *db,
               unsigned *lcore_ids,
               unsigned max_lcore)
{
    struct eng_conf_node_s *node = NULL;
    unsigned nb_lcores = 0;
    char name[128];

    while ((node = eng_conf_thread_name_next(db, node,
                                             name, sizeof(name))) != NULL &&
           (nb_lcores < max_lcore)) {
        int lcore_id = eng_conf_thread_lcore(db, name);

        if (lcore_id < 0) {
            ENG_ERR(CORE, "invalid lcore_id : %s", name);
            return 0;
        }

        if (eng_conf_add_lcore_thread(db, lcore_id, name))
            return 0;

        if (eng_conf_is_master_thread(db, name)) {
            if (eng_conf_add_master_lcore(db, lcore_id))
                return 0;
        }

        lcore_ids[nb_lcores] = lcore_id;
        nb_lcores++;
    }
    return nb_lcores;
}

/*
 * not yet, rte initialized
 */
unsigned
eng_thread_lcores(struct eng_conf_db_s *db,
                  char *buff,
                  size_t size)
{
    unsigned lcore_ids[64];
    unsigned nb_lcores;
    unsigned s = 0;

    nb_lcores = get_lcore_list(db, lcore_ids, RTE_DIM(lcore_ids));
    for (unsigned i = 0; i < nb_lcores; i++) {
        if (s)
            s += snprintf(&buff[s], size - s, ",%u", lcore_ids[i]);
        else
            s += snprintf(&buff[s], size - s, "%u", lcore_ids[i]);
    }

    ENG_DEBUG(CORE, "number of lcores:%u", nb_lcores);
    return nb_lcores;
}

/*****************************************************************************
 * cli usage
 *****************************************************************************/
static void
show_usage_raw(FILE *fp,
               const char *msg,
               const struct eng_usage_s *usage)
{
    fprintf(fp, "%s\n", msg);
    fprintf(fp,
            "  pkt:%"PRIu64" call:%"PRIu64" cycle:%"PRIu64" %.1f cycle/pkt %.1f cycle/call\n",
            usage->events, usage->execs, usage->tsc_sum,
            (double) usage->tsc_sum / (double) usage->events,
            (double) usage->tsc_sum / (double) usage->execs);

    fprintf(fp,
            "  idle:%"PRIu64" cycle:%"PRIu64" call rate:%.1f%% cycle rate:%.1f%% busy:%"PRIu64" except:%"PRIu64"\n",
            usage->idles, usage->idle_tsc,
            (double) (usage->execs * 100) / (double) (usage->execs + usage->idles),
            (double) (usage->tsc_sum * 100) / (double) (usage->tsc_sum + usage->idle_tsc),
            usage->busies, usage->exceptions);
}

static struct eng_usage_s *
show_usage_ext_thread(FILE *fp,
                      struct eng_thread_s *th,
                      struct eng_usage_s *usages)
{
    struct eng_task_s *task;
    unsigned seq = 0;
    char buff[80];

    snprintf(buff, sizeof(buff), "<< %s thread_id:%u lcore:%u >>",
             th->name, th->thread_id, th->lcore_id);
    show_usage_raw(fp, buff, usages++);

    STAILQ_FOREACH(task, &th->tasks, node) {
        snprintf(buff, sizeof(buff), "task:%s seq:%u", task->name, seq++);
        show_usage_raw(fp, buff, usages++);
    }
    fprintf(fp, "\n");
    return usages;
}

static unsigned
get_nb_usages(struct thread_mng_s *mng)
{
    unsigned nb = mng->nb_threads;

    for (unsigned i = 0; i < mng->nb_threads; i++) {
        nb += mng->threads[i]->nb_tasks;
    }
    return nb;
}

static unsigned
usage_ext_update(struct thread_mng_s *mng,
                 struct eng_usage_s *usages,
                 unsigned nb_usages)
{
    unsigned n = 0;
    for (unsigned i = 0; i < mng->nb_threads; i++) {
        if (n >= nb_usages)
            break;
        usages[n].tsc_sum  = mng->threads[i]->usage.tsc_sum  - usages[n].tsc_sum;
        usages[n].events   = mng->threads[i]->usage.events   - usages[n].events;
        usages[n].execs    = mng->threads[i]->usage.execs    - usages[n].execs;
        usages[n].update   = mng->threads[i]->usage.update   - usages[n].update;
        usages[n].idle_tsc = mng->threads[i]->usage.idle_tsc - usages[n].idle_tsc;
        usages[n].idles    = mng->threads[i]->usage.idles    - usages[n].idles;
        usages[n].busies   = mng->threads[i]->usage.busies   - usages[n].busies;
        usages[n].exceptions = mng->threads[i]->usage.exceptions - usages[n].exceptions;

        n += 1;

        struct eng_task_s *task;
        STAILQ_FOREACH(task, &mng->threads[i]->tasks, node) {
            if (n >= nb_usages)
                break;
            usages[n].tsc_sum  = task->usage.tsc_sum  - usages[n].tsc_sum;
            usages[n].events   = task->usage.events   - usages[n].events;
            usages[n].execs    = task->usage.execs    - usages[n].execs;
            usages[n].update   = task->usage.update   - usages[n].update;
            usages[n].idle_tsc = task->usage.idle_tsc - usages[n].idle_tsc;
            usages[n].idles    = task->usage.idles    - usages[n].idles;
            usages[n].busies   = task->usage.busies   - usages[n].busies;
            usages[n].exceptions = task->usage.exceptions - usages[n].exceptions;

            n += 1;
        }
    }
    return n;
}

static int
show_usage_ext(FILE *fp,
               struct thread_mng_s *mng,
               unsigned sleeps)
{
    unsigned nb_usages = get_nb_usages(mng);
    struct eng_usage_s *usages;

    usages = calloc(nb_usages, sizeof(*usages));
    if (usages) {
        usage_ext_update(mng, usages, nb_usages);

        if (sleeps) {
            fprintf(fp, "please wait %u seconds\n", sleeps);
            sleep(sleeps);
            usage_ext_update(mng, usages, nb_usages);
        }

        struct eng_usage_s *next = usages;
        for (unsigned i = 0; i < mng->nb_threads; i++)
            next = show_usage_ext_thread(fp, mng->threads[i], next);

        free(usages);
    }
    return 0;
}

enum eng_cli_cmd_type_e {
    CMD_INVALID = -1,

    CMD_DUMP_USAGE,

    NB_CMDs,
};

static const struct eng_cli_cmd_info_s CmdInfos[NB_CMDs] = {
    [CMD_DUMP_USAGE] = { "dump", "[--sleep SEC]", },
};

/* constructor */
ENG_GENERATE_CLI(TaskUsage, "usage", CmdInfos, cmd_usage);

static const struct option LongOptions[] = {
    { "cmd",      required_argument, NULL, 'c', },
    { "help",     no_argument,       NULL, 'h', },
    { "sleeps",   required_argument, NULL, 's', },
    { NULL,       0,                 NULL, 0,   },
};

static int
cmd_usage(int ac,
          char *av[])
{
    int opt, index;
    int err = 0;
    enum eng_cli_cmd_type_e cmd = CMD_INVALID;
    struct thread_mng_s *mng = find_mng();
    unsigned sleeps = 1;

    while ((opt = getopt_long(ac, av, "c:t:hs",
                              LongOptions, &index)) != EOF && !err) {
        switch (opt) {
        case 'c':       /* cmd */
            cmd = eng_cli_get_cmd_type(optarg);
            break;

        case 'h':       /* Help */
            CMD_USAGE(TaskUsage);
            return 0;

        case 's':
            sleeps = atoi(optarg);
            break;

        default:
            err = -EINVAL;
            break;
        }
    }

    if (!err) {
        switch (cmd) {
        case CMD_DUMP_USAGE:
            err = show_usage_ext(eng_stdout, mng, sleeps);
            break;

        case CMD_INVALID:
        default:
            err = -EINVAL;
            break;
        }
    }
    if (err) {
        char buff[80];

        fprintf(stderr, "%s\n", strerror_r(-(err), buff, sizeof(buff)));
        CMD_USAGE(TaskUsage);
    }
    return 0;
}

bool
eng_thread_is_valid(unsigned thread_id)
{
    struct thread_mng_s *mng = find_mng();

    return mng->nb_threads > thread_id;
}

int
eng_thread2lcore(unsigned thread_id)
{
    struct thread_mng_s *mng = find_mng();

    if (mng->nb_threads > thread_id)
        return mng->threads[thread_id]->lcore_id;
    return -1;
}

int
eng_lcore2thread(unsigned lcore_id)
{
    struct thread_mng_s *mng = find_mng();

    if (lcore_id < RTE_MAX_LCORE &&
        mng->lcores[lcore_id])
        return mng->lcores[lcore_id]->thread_id;
    return -1;
}


