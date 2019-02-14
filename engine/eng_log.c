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
 * @file        eng_log.c
 * @brief       Engine log
 */

#include <stdio.h>

#include <rte_log.h>
#include <rte_memzone.h>
#include <rte_lcore.h>

#include "eng_log.h"

#define LOG_MZ_NAME     "ENG_LOG"
#define ENG_LOG_ID_CORE	0
#define ENG_LOG_ID_NB	64

struct eng_logname_s {
    char val[32];
};

struct eng_log_tbl_s {
    unsigned rte_log_types[ENG_LOG_ID_NB];
    struct eng_logname_s names[ENG_LOG_ID_NB];
    const struct rte_memzone *mz;
};

static struct eng_log_tbl_s StaticTbl;
static struct eng_log_tbl_s *eng_log_tbl = &StaticTbl;

static inline int
eng_log_get_type(int id)
{
    if (id < 0 || id >= ENG_LOG_ID_NB)
        return -EINVAL;
    return eng_log_tbl->rte_log_types[id];
}

static inline int
name2id(const char *name)
{
    for (unsigned i = 0; i < RTE_DIM(eng_log_tbl->names); i++) {
        if (!strncasecmp(eng_log_tbl->names[i].val, name,
                         sizeof(eng_log_tbl->names[i].val) + 1))
            return i;
    }
    return -EINVAL;
}

static inline const char *
id2name(int id)
{
    if (id >= 0 && id < ENG_LOG_ID_NB) {
        if (eng_log_tbl->rte_log_types[id] != -1u)
            return eng_log_tbl->names[id].val;
    }
    return NULL;
}

static inline unsigned
id2type(int id)
{
    if (id >= 0 && id < ENG_LOG_ID_NB)
        return eng_log_tbl->rte_log_types[id];
    return -EINVAL;
}

/*
 *
 */
static struct eng_log_tbl_s *
find_log_mz(void)
{
    struct eng_log_tbl_s *logs;
    const struct rte_memzone *mz;

    mz = rte_memzone_lookup(LOG_MZ_NAME);
    if (mz) {
        logs = mz->addr;
    } else {
        logs = NULL;
    }
    return logs;
}

unsigned
eng_log_id2type(int id)
{
    return id2type(id);
}

const char *
eng_log_id2name(int id)
{
    return id2name(id);
}

/*
 *
 */
int
eng_log_register(int id,
                 const char *name)
{
    if (id < 0 || id >= ENG_LOG_ID_NB || !name)
        return -EINVAL;

    if (eng_log_tbl->rte_log_types[id] != -1u)
        return -EEXIST;

    if (name2id(name) >= 0)
        return -EEXIST;

    int ret = rte_log_register(name);
    if (ret >= 0)
        eng_log_tbl->rte_log_types[id] = ret;
    return ret;
}

/*
 *
 */
int
eng_log_set_level(int id,
                  unsigned level)
{
    if (level < RTE_LOG_EMERG || level > RTE_LOG_DEBUG)
        return -EINVAL;

    int type = id2type(id);
    if (type < 0)
        return type;

    return rte_log_set_level(type, level);
}

unsigned
eng_log_get_level(int id)
{
    int type = id2type(id);
    if (type < 0)
        return -1;
    return rte_log_get_level(type);
}

/*
 *
 */
int
eng_log_init(int global_level,
             int core_level,
             bool enable_stderr)
{
    int ret = 0;
    struct eng_log_tbl_s *src, *dst, *tbl = find_log_mz();
    if (tbl) {
        /* for 2nd process */
        src = tbl;
        dst = &StaticTbl;
    } else {
        const struct rte_memzone *mz;

        mz = rte_memzone_reserve(LOG_MZ_NAME,
                                 sizeof(*tbl),
                                 rte_socket_id(),
                                 RTE_MEMZONE_1GB | RTE_MEMZONE_SIZE_HINT_ONLY);
        if (!mz) {
            ret = -ENOMEM;
            goto end;
        }

        tbl = mz->addr;
        tbl->mz = mz;

        dst = tbl;
        src = &StaticTbl;
    }

    for (unsigned i = 0; !ret && i < RTE_DIM(dst->rte_log_types); i++) {
        if (strlen(src->names[i].val)) {
            strcpy(dst->names[i].val, src->names[i].val);
            ret = rte_log_register(dst->names[i].val);
            dst->rte_log_types[i] = ret;
        } else {
            dst->names[i].val[0] = '\0';
            dst->rte_log_types[i] = -1;
        }
    }

    if (!ret) {
        eng_log_register(ENG_LOG_ID_CORE, ENG_LOG_NAME_CORE);
        if (enable_stderr)
            rte_openlog_stream(stderr);

        rte_log_set_global_level(global_level);
        eng_log_set_level(ENG_LOG_ID_CORE, core_level);
    }
 end:
    return ret;
}

