/*
 * Copyright (c) 2019 deadcafe.beef@gmail.com All Rights Reserved.
 *
 * Unauthorized inspection, duplication, utilization or modification
 * of this file is prohibited.  Other related documents, whether
 * explicitly marked or implied, may also fall under this copyright.
 * Distribution of information obtained from this file and other related
 * documents to a third party is not permitted under any circumstances.
 */

#ifndef _ENG_PDUMP_H_
#define _ENG_PDUMP_H_

/**
 * @file        eng_pdump.h
 * @brief       Engine packet dump
 */

#include <rte_mbuf.h>

/**
 * @brief packet dump direction
 *
 */
#define ENG_PDUMP_DIR_RX (1u << 0)
#define ENG_PDUMP_DIR_TX (1u << 1)
#define ENG_PDUMP_DIR_BOTH  (ENG_PDUMP_DIR_RX | ENG_PDUMP_DIR_TX)


/**
 * @brief start packet dump
 *
 * @retval
 *   OK: Zero
 *   NG: not Zero
 *
 * @note  thread unsafe (only for master)
 * @note  multi segment mbufs are not supported
 */
extern int
eng_pdump_start(int fd, uint16_t port_id, uint32_t dir);

/**
 * @brief finish packet dump
 * @retval
 *   OK: Zero
 *   NG: not Zero
 *
 * @note  thread unsafe (only for master)
 */
extern int
eng_pdump_finish(int fd, uint16_t port_id,
                 uint64_t *pkts_success, uint64_t *pkts_failure);

/**
 * @brief get statistics for current dump
 *
 * @note  thread unsafe (only for master)
 * @retval
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_pdump_get_stats(int fd, uint16_t port_id, uint32_t dir,
                    uint64_t *pkts_success, uint64_t *pkts_failure);

#endif /* !_ENG_PDUMP_H_ */
