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
 * @file        eng_mbuf.c
 * @brief       Engine mbuf
 */

#include <stdio.h>

#include <rte_mbuf.h>
#include <rte_errno.h>

#include "conf.h"
#include "eng_log.h"
#include "eng_mbuf.h"

struct rte_mempool *
eng_mbufpool_find(const char *name)
{
    struct rte_mempool *mp = rte_mempool_lookup(name);

    if (mp)
        ENG_DEBUG(CORE, "found mp: %s", name);
    else
        ENG_NOTICE(CORE, "not found mp: %s", name);
    return mp;
}

struct rte_mempool *
eng_mbufpool(struct eng_conf_db_s *db,
             const char *name)
{
    struct rte_mempool *mp;

    if (!name)
        return NULL;

    mp = eng_mbufpool_find(name);
    if (!mp) {
        int nb_mb;
        int cache_size;
        int ext_size;

        nb_mb = eng_conf_mbufpool_size(db, name);
        if (nb_mb < 0)
            goto end;

        cache_size = eng_conf_mbufpool_cache_size(db, name);
        if (cache_size < 0)
            goto end;

        ext_size = eng_conf_mbufpool_ext_size(db, name);
        if (ext_size < 0)
            goto end;

        mp = rte_pktmbuf_pool_create(name,
                                     nb_mb * 1024,
                                     cache_size,
                                     ext_size,
                                     RTE_MBUF_DEFAULT_DATAROOM,
                                     rte_socket_id());

        if (mp) {
            ENG_DEBUG(CORE, "Ok: mbuf pool:%s number-of-mbufs:%d cache:%d ext:%d",
                      name, nb_mb, cache_size, ext_size);
        } else {
            ENG_ERR(CORE, "Ng: mbuf pool:%s number-of-mbufs:%d cache:%d ext:%d",
                    name, nb_mb, cache_size, ext_size);
        }
    }
 end:
    return mp;
}
