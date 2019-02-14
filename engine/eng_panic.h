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
 * @file        eng_panic.h
 * @brief       Engine panic
 */

#ifndef _ENG_PANIC_H_
#define _ENG_PANIC_H_

#include <rte_debug.h>
#include <rte_branch_prediction.h>

#include "eng_log.h"

/* Restore tty and abort if there is a problem */
#define ENG_PANIC(cond, ...)                                            \
do {                                                                    \
    if (unlikely(cond)) {                                               \
        ENG_ERR(CORE, "%s", __VA_ARGS__);                               \
        rte_panic("PANIC at %s:%u, callstack:", __FILE__, __LINE__);    \
    }                                                                   \
 } while (0)

#endif /* !_ENG_PANIC_H_ */
