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
 * @file        eng_addon.c
 * @brief       FastPath Engine core library ( addon part )
 */
#include <sys/queue.h>

#include <stdio.h>
#include <assert.h>

#include "conf.h"
#include "eng_thread.h"
#include "eng_log.h"
#include "eng_addon.h"

/*
 *
 */
TAILQ_HEAD(eng_addon_constructor_head_s, eng_addon_constructor_s);

static struct eng_addon_constructor_head_s constructor_head =
    TAILQ_HEAD_INITIALIZER(constructor_head);

/*
 *
 */
int
eng_addon_register(struct eng_addon_constructor_s *node)
{
    if (!node->addon->name)
        rte_panic("invalid addon node:%s\n", node->addon->name);
    if (node->addon->is_global) {
        if (!node->addon->global_init)
            rte_panic("invalid addon node:%s\n", node->addon->name);
    } else {
        if (!node->addon->task_entry ||
            !node->addon->task_init) {
            rte_panic("invalid addon node:%s\n", node->addon->name);
        }

        if (!((!node->addon->outport_type && !node->addon->set_outport_order) ||
              (node->addon->outport_type && node->addon->set_outport_order)))
            rte_panic("invalid addon node:%s\n", node->addon->name);
    }
    TAILQ_INSERT_TAIL(&constructor_head, node, entry);
    return 0;
}

/*
 *
 */
int
eng_conf_setup_addon(struct eng_conf_db_s *db)
{
    struct eng_addon_constructor_s *node;

    TAILQ_FOREACH(node, &constructor_head, entry) {
        if (eng_conf_add_addon(db, node->addon->name, node->addon)) {
            fprintf(stderr, "failed to add Addon:%s\n", node->addon->name);
            return -1;
        }
    }
    return 0;
}

/*
 *
 */
int
eng_addon_task_init(struct eng_conf_db_s *db,
                    const char *name,
                    struct eng_thread_s *th,
                    struct eng_task_s *task)
{
    const struct eng_addon_s *addon;

    addon = (const struct eng_addon_s *) eng_conf_addon(db, name);
    if (!addon || addon->is_global)
        return -1;

    task->entry = addon->task_entry;
    return addon->task_init(db, th, task);
}

/*
 *
 */
int
eng_addon_global_init(struct eng_conf_db_s *db)
{
    const char *entries[16];
    char buff[1024];
    int nb;
    int ret = 0;

    ENG_ERR(CORE, "start");

    nb = eng_conf_global_initializer_list(db, entries, 16,
                                          buff, sizeof(buff));
    for (int i = 0; i < nb; i++) {
        const struct eng_addon_s *addon;

        addon = (const struct eng_addon_s *) eng_conf_addon(db, entries[i]);
        if (!addon || !addon->is_global) {
            ENG_ERR(CORE, "no addon:%s", entries[i]);
            return -1;
        }

        ret = addon->global_init(db);
        if (ret) {
            ENG_ERR(CORE, "failed in global initializer:%s", entries[i]);
            break;
        }
    }

    ENG_ERR(CORE, "end: %d", ret);
    return ret;
}
