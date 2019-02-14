/*
 * Copyright (c) 2019 deadcafe.beef@gmail.com Rights Reserved.
 *
 * Unauthorized inspection, duplication, utilization or modification
 * of this file is prohibited.  Other related documents, whether
 * explicitly marked or implied, may also fall under this copyright.
 * Distribution of information obtained from this file and other related
 * documents to a third party is not permitted under any circumstances.
 */

/**
 * @file        eng_log.h
 * @brief       Engine log
 */


#ifndef _ENG_LOG_H_
#define _ENG_LOG_H_

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include <rte_log.h>


extern int
eng_log_init(int global_level,
             int core_level,
             bool enable_stderr);

extern int
eng_log_register(int id,
                 const char *name);

extern int
eng_log_set_level(int id,
                  unsigned level);

extern unsigned
eng_log_get_level(int id);

extern unsigned
eng_log_id2type(int id);

extern const char *
eng_log_id2name(int id);

#define ENG_LOG_ID_CORE		0
#define ENG_LOG_NAME_CORE	"Core"

#define ENG_LOG(_lv,_id,_fmt, args...)                                  \
    rte_log(RTE_LOG_ ## _lv,                                            \
            eng_log_id2type((_id)),                                     \
            "%s: %s(%d) " _fmt "\n",                                    \
            eng_log_id2name((_id)), __func__, __LINE__, ##args)

#define ENG_DEBUG(_id, _fmt, args...)	ENG_LOG(DEBUG,   ENG_LOG_ID_ ## _id, _fmt, ## args)
#define ENG_INFO(_id, _fmt, args...)	ENG_LOG(INFO,    ENG_LOG_ID_ ## _id, _fmt, ## args)
#define ENG_NOTICE(_id, _fmt, args...)	ENG_LOG(NOTICE,  ENG_LOG_ID_ ## _id, _fmt, ## args)
#define ENG_WARN(_id, _fmt, args...)	ENG_LOG(WARNING, ENG_LOG_ID_ ## _id, _fmt, ## args)
#define ENG_ERR(_id, _fmt, args...)	ENG_LOG(ERR,     ENG_LOG_ID_ ## _id, _fmt, ## args)

#endif	/* !_ENG_LOG_H_ */
