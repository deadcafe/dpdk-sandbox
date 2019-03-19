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
 * @file        eng_thread.h
 * @brief       FastPath Engine core library ( thread part )
 */

#ifndef _ENG_THREAD_H_
#define _ENG_THREAD_H_

#include <sys/queue.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>

#include <rte_ring.h>
#include <rte_mbuf.h>

#include "eng_port.h"

struct eng_port_s;

/*
 *
 */
struct eng_usage_s {
    uint64_t tsc_sum;
    uint64_t events;
    uint64_t execs;
    uint64_t update;

    /* ext */
    uint64_t idle_tsc;
    uint64_t idles;
    uint64_t busies;
    uint64_t exceptions;
};

struct eng_thread_s;


/*
 *
 */
enum eng_thread_state_e {
    ENG_THREAD_STATE_STOP = 0,	/*!< stop running */
    ENG_THREAD_STATE_RUNNING,	/*!< normal */
    ENG_THREAD_STATE_EXIT,	/*!< do exit */
};

struct eng_thread_s;
STAILQ_HEAD(eng_thread_head_s, eng_thread_s);

#define ENG_TASK_BURST_SIZE_DEFAULT	64
#define ENG_MAX_NB_OUT_PORTS		64
#define ENG_MAX_NB_TASKS			8

/*
 * task
 */
struct eng_task_s {
    MARKER cacheline0;
    struct eng_thread_s *th;
    struct eng_port_s *in_port;
    unsigned func_id;
    unsigned task_id;
    unsigned nb_out_ports;
    unsigned burst_size;
    unsigned (*entry)(struct eng_thread_s *, struct eng_task_s *,
                      uint64_t);

    STAILQ_ENTRY(eng_task_s) node;

    MARKER cacheline1 __rte_cache_min_aligned;
    struct eng_usage_s usage;
    char private_area[RTE_CACHE_LINE_SIZE];
    struct eng_port_s *out_ports[ENG_MAX_NB_OUT_PORTS];

    char name[32];
} __rte_cache_aligned;
STAILQ_HEAD(eng_task_head_s, eng_task_s);

/*
 * thread
 */
struct eng_thread_s {
    MARKER cacheline0;
    STAILQ_ENTRY(eng_thread_s) node;
    uint64_t start_tsc;

    unsigned thread_id;
    unsigned lcore_id;
    unsigned nb_tasks;
    unsigned nb_ports;

    rte_atomic32_t cmd;		/* request from Other(Master or CLI) */

    MARKER cacheline1 __rte_cache_min_aligned;
    struct eng_usage_s usage;

    struct rte_mempool *mp;
    void *addon_thread_ext;

    rte_atomic32_t state;	/* changed by self */

    MARKER cacheline2 __rte_cache_min_aligned;
    struct eng_task_head_s tasks;
    struct eng_port_head_s ports;
    struct eng_thread_head_s slaves;	/* master only */
    unsigned nb_slaves;

    struct eng_conf_db_s *conf_db;	/* master only */
    char name[32];
} __rte_cache_aligned;

/*
 * prototypes
 */
struct eng_conf_db_s;

struct eng_signal_s {
    sigset_t sigset;
    void (*handler)(int);
};

/*
 *
 */
extern int
eng_thread_launch(struct eng_conf_db_s *db,
                  struct eng_signal_s *eng_signal);

/*
 *
 */
extern unsigned
eng_thread_lcores(struct eng_conf_db_s *db,
                  char *buff,
                  size_t size);

/*
 *
 */
extern int
eng_thread_second(const char *prog,
                  unsigned lcore);

/*
 *
 */
extern struct eng_thread_s *
eng_thread_self_info(void);

extern void
eng_thread_cmd_set(struct eng_thread_s *self,
                   enum eng_thread_state_e cmd);

extern unsigned
eng_thread_nb_threads(void);

struct eng_thread_s *
eng_thread_info_th(unsigned th_id);

extern bool
eng_primary_is_dead(void);

extern void
eng_thread_master_exit(void);

extern bool
eng_thread_is_valid(unsigned thread_id);

extern int
eng_thread2lcore(unsigned thread_id);

extern int
eng_lcore2thread(unsigned lcore_id);

#endif /* !_ENG_THREAD_H_ */
