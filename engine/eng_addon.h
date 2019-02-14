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
 * @file        eng_addon.h
 * @brief       Engine addon
 */

#ifndef _ENG_ADDON_H_
#define _ENG_ADDON_H_

#include <sys/queue.h>
#include <stdbool.h>
#include <stdint.h>

struct eng_conf_db_s;
struct eng_thread_s;
struct eng_task_s;

/*
 * Task addon
 */
struct eng_addon_s {
    const char *name;
    bool is_global;	/* else then task */

    union {
        int (*task_init)(struct eng_conf_db_s *,
                         struct eng_thread_s *, struct eng_task_s *);
        int (*global_init)(struct eng_conf_db_s *);
    };
    int (*outport_type)(int seq);
    void (*set_outport_order)(int type, int order);
    unsigned (*task_entry)(struct eng_thread_s *, struct eng_task_s *, uint64_t);
    unsigned func_id;
} __attribute__((aligned(64)));


struct eng_addon_constructor_s {
    const struct eng_addon_s *addon;
    TAILQ_ENTRY(eng_addon_constructor_s) entry;
};

/*
 *
 */
extern int
eng_addon_register(struct eng_addon_constructor_s *node);

/*
 *
 */
extern int
eng_conf_setup_addon(struct eng_conf_db_s *db);

/*
 *
 */
extern int
eng_addon_task_init(struct eng_conf_db_s *db,
                    const char *name,
                    struct eng_thread_s *th,
                    struct eng_task_s *task);

/*
 *
 */
extern int
eng_addon_global_init(struct eng_conf_db_s *db);

#endif	/* !_ENG_ADDON_H_ */
