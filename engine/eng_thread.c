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

#include "conf.h"
#include "eng_port.h"
#include "eng_mbuf.h"
#include "eng_log.h"
#include "eng_addon.h"
#include "eng_thread.h"
#include "eng_panic.h"

static struct eng_thread_s *LCoreInfo[RTE_MAX_LCORE];
static struct eng_master_ctroller_s *MasterCtrl;

#define ENG_MSTER_CONTROLLER	"ENG_MASTER_CONTROLLER"

static enum eng_thread_state_e
cmd_handler(struct eng_master_ctroller_s *ctrl,
            enum eng_thread_state_e state)
{
    ctrl->ret = -EINVAL;
    return state;
}

static eng_cmd_handler_t CmdHandlers[32] = {
    [0] = cmd_handler,
    [1] = cmd_handler,
    [2] = cmd_handler,
    [3] = cmd_handler,
    [4] = cmd_handler,
    [5] = cmd_handler,
    [6] = cmd_handler,
    [7] = cmd_handler,
    [8] = cmd_handler,
    [9] = cmd_handler,
    [10] = cmd_handler,
    [11] = cmd_handler,
    [12] = cmd_handler,
    [13] = cmd_handler,
    [14] = cmd_handler,
    [15] = cmd_handler,
    [16] = cmd_handler,
    [17] = cmd_handler,
    [18] = cmd_handler,
    [19] = cmd_handler,
    [20] = cmd_handler,
    [21] = cmd_handler,
    [22] = cmd_handler,
    [23] = cmd_handler,
    [24] = cmd_handler,
    [25] = cmd_handler,
    [26] = cmd_handler,
    [27] = cmd_handler,
    [28] = cmd_handler,
    [29] = cmd_handler,
    [30] = cmd_handler,
    [31] = cmd_handler,
};

int
fpe_register_cmd_handler(int cmd,
                         eng_cmd_handler_t handler)
{
    if (!handler || cmd < 0 || (int) RTE_DIM(CmdHandlers) <= cmd)
        return -EINVAL;

    if (CmdHandlers[cmd] != cmd_handler)
        return -EEXIST;

    CmdHandlers[cmd] = handler;
    return 0;
}

/*
 *
 */
static inline enum eng_thread_state_e
read_thread_state(struct eng_thread_s *th)
{
    return (enum eng_thread_state_e) rte_atomic32_read(&th->state);
}

static inline enum eng_thread_state_e
set_thread_state(struct eng_thread_s *th,
                 enum eng_thread_state_e state)
{
    rte_atomic32_set(&th->state, state);
    rte_mb();
    return state;
}

static inline enum eng_thread_state_e
read_thread_cmd(struct eng_thread_s *th)
{
    return (enum eng_thread_state_e) rte_atomic32_read(&th->cmd);
}

static inline void
set_thread_cmd(struct eng_thread_s *th,
               enum eng_thread_state_e cmd)
{
    rte_atomic32_set(&th->cmd, cmd);
    rte_mb();
}

/*
 *
 */
static inline struct eng_master_ctroller_s *
find_master_ctrl(void)
{
    struct eng_master_ctroller_s *ctrl = MasterCtrl;

    if (!ctrl) {
        const struct rte_memzone *mz;

        mz = rte_memzone_lookup(ENG_MSTER_CONTROLLER);
        if (mz) {
            ctrl = mz->addr;
            MasterCtrl = ctrl;
        }
    }
    ENG_PANIC(!ctrl, "Not found master controller");

    return ctrl;
}

struct eng_master_ctroller_s *
eng_find_master_ctrl(void)
{
    return find_master_ctrl();
}

/*
 *
 */
static struct eng_master_ctroller_s *
create_master_ctrl(void)
{
    struct eng_master_ctroller_s *ctrl = MasterCtrl;

    if (!ctrl) {
        const struct rte_memzone *mz;

        mz = rte_memzone_reserve(ENG_MSTER_CONTROLLER,
                                 sizeof(*ctrl), rte_socket_id(),
                                 RTE_MEMZONE_2MB | RTE_MEMZONE_1GB |
                                 RTE_MEMZONE_SIZE_HINT_ONLY);
        if (mz) {
            ctrl = mz->addr;

            memset(ctrl, 0, sizeof(*ctrl));
            rte_spinlock_init(&ctrl->cmd_mutex);
            MasterCtrl = ctrl;
        }
    }
    return ctrl;
}

/*
 * change Slave state by Master
 */
int
eng_thread_cmd_slaves(struct eng_master_ctroller_s *ctrl,
                      enum eng_thread_state_e cmd)
{
    if (cmd != ENG_THREAD_STATE_STOP &&
        cmd != ENG_THREAD_STATE_RUNNING)
        return -EINVAL;

    for (unsigned i = 1; i < ctrl->nb_threads; i++)
        set_thread_cmd(ctrl->th_info[i], cmd);

    for (unsigned i = 1; i < ctrl->nb_threads; i++) {
        while (read_thread_state(ctrl->th_info[i]) != cmd)
            rte_pause();
    }
    return 0;
}

/*
 * change Master state by CLI
 */
int
eng_thread_cmd_master(struct eng_master_ctroller_s *ctrl,
                      enum eng_thread_state_e cmd)
{
    int ret = 0;

    if (cmd < ENG_THREAD_STATE_STOP || ENG_THREAD_STATE_EXIT < cmd)
        return -EINVAL;

    ctrl->ret = 0;
    set_thread_cmd(ctrl->th_info[0], cmd);

    while (read_thread_state(ctrl->th_info[0])
           != read_thread_cmd(ctrl->th_info[0]))
        rte_pause();

    ret = ctrl->ret;
    return ret;
}

/*
 * return: next state
 */
static inline enum eng_thread_state_e
exec_cmd(struct eng_master_ctroller_s *ctrl,
         enum eng_thread_state_e state)
{
    if (ctrl->cmd < 0 || (int) RTE_DIM(CmdHandlers) <= ctrl->cmd) {
        ENG_ERR(CORE, "invalid cmd:%d\n", ctrl->cmd);
        ctrl->ret = -EINVAL;
    } else {
        state = CmdHandlers[ctrl->cmd](ctrl, state);
    }

    return state;
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
        unsigned ret;
        uint64_t last, sub;
#if 0
        ENG_ERR(CORE, "th:%s tsk:%s", th->name, task->name);
#endif
        ret = task->entry(th, task, now);

        last = now;
        now = rte_rdtsc();
        sub = now - last;

        if (ret) {
            task->usage.events += ret;
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
        th_cnt += ret;
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

/*
 *
 */
static void
thread_loop(struct eng_thread_s *th)
{
    th->start_tsc = rte_rdtsc();
    ENG_WARN(CORE, "waked up: %s %"PRIu64, th->name, th->start_tsc);

    bool is_master = (rte_lcore_id() == rte_get_master_lcore());

   if (is_master)
        set_thread_cmd(th, ENG_THREAD_STATE_RUNNING);

   struct eng_master_ctroller_s *ctrl = find_master_ctrl();
   enum eng_thread_state_e cmd, state = read_thread_state(th);
   while ((cmd = read_thread_cmd(th)) != ENG_THREAD_STATE_EXIT) {

       if (cmd != state) {
           enum eng_thread_state_e next_state = cmd;

           switch (cmd) {
           case ENG_THREAD_STATE_STOP:
               /* flush all ports */
               th->flush_window_pos
                   = eng_port_flush_ports(&th->ports,
                                         STAILQ_FIRST(&th->ports),
                                         th->nb_ports);
               if (is_master)
                   eng_thread_cmd_slaves(ctrl, ENG_THREAD_STATE_STOP);

               ENG_DEBUG(CORE, "stop %s", th->name);
               break;

           case ENG_THREAD_STATE_RUNNING:
               if (is_master)
                   eng_thread_cmd_slaves(ctrl, ENG_THREAD_STATE_RUNNING);

               th->flush_window_pos = STAILQ_FIRST(&th->ports);
               ENG_DEBUG(CORE, "start %s %"PRIu64, th->name, th->start_tsc);
               break;

           case ENG_THREAD_STATE_CMD:
               if (is_master)
                   next_state = exec_cmd(find_master_ctrl(), state);
               break;

           case ENG_THREAD_STATE_EXIT:
               /* unreach */
               break;

           default:
               ENG_ERR(CORE, "unknown cmd:%d ignored\n", cmd);
               next_state = state;
               break;
           }

           if (state != next_state)
               state = set_thread_state(th, next_state);

           if (state != cmd)
               set_thread_cmd(th, state);
       }

       if (state == ENG_THREAD_STATE_RUNNING) {
           task_sched(th);

           th->flush_window_pos
               = eng_port_flush_ports(&th->ports,
                                     th->flush_window_pos,
                                     th->flush_window_size);
       }
   }

   if (is_master)
       eng_thread_cmd_slaves(ctrl, ENG_THREAD_STATE_EXIT);
   set_thread_state(th, cmd);

   ENG_WARN(CORE, "bye: %s", th->name);
}

struct eng_thread_s *
eng_thread_info(void)
{
    return LCoreInfo[rte_lcore_id()];
}

/*
 *
 */
static int
thread_entry(void *arg __rte_unused)
{
    thread_loop(eng_thread_info());
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

        if (th->nb_ports < ENG_FLUSH_WINDOW_SIZE) {
            th->flush_window_size = th->nb_ports;
        } else {
            th->flush_window_size = ENG_FLUSH_WINDOW_SIZE;
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
eng_thread_second(char *prog,
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

        len = snprintf(p, size, "--lcores=%u", lcore);
        SET_ARG(ac, av, p);
        p += (len + 1);
        size -= (len + 1);

        len = snprintf(p, size, "--proc-type=secondary");
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

    int xxx = ENG_ERR(CORE, "start\n");
    fprintf(stderr, "xxx:%d\n", xxx);

    if (!db)
        return -EINVAL;

    struct eng_master_ctroller_s *ctrl = create_master_ctrl();
    if (!ctrl)
        goto end;

    if (create_signal_thread(eng_signal))
        goto end;

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

        ctrl->th_info[thread_id] = th;
        LCoreInfo[lcore_id] = th;

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
            ctrl->th_info[i]->nb_slaves = nb_slaves;
            STAILQ_INSERT_TAIL(&th->slaves, ctrl->th_info[i], node);
        }

        ctrl->th_info[0] = th;
        LCoreInfo[lcore_id] = th;
        ctrl->nb_threads = nb_slaves + 1;

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
        for (thread_id = 0; thread_id < ctrl->nb_threads; thread_id++) {
            if (setup_thread(db, ctrl->th_info[thread_id]))
                goto end;
        }
        ctrl->th_info[0]->conf_db = db;
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
