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
 * @file        eng_mbuf.h
 * @brief       FastPath Engine core library ( mbuf part )
 */

#ifndef _ENG_MBUF_H_
#define _ENG_MBUF_H_

#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include <rte_mbuf_ptype.h>

struct eng_conf_db_s;

extern struct rte_mempool *eng_mbufpool_find(const char *name);
extern struct rte_mempool *eng_mbufpool(struct eng_conf_db_s *db,
                                        const char *name);

#endif	/* !_ENG_MBUF_H_ */
