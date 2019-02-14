
/*
 * Engine conf API
 */


#ifndef _ENG_CONF_H_
#define _ENG_CONF_H_

#include <sys/types.h>
#include <errno.h>

#define NB_DIM(a)	(sizeof(a) / sizeof(a[0]))

struct eng_conf_db_s;

/**
 * @brief configuration DB record
 */
struct eng_conf_s {
    const char *name;
    const char *val;
};

/**
 * @brief DB を create する
 *
 * @param db_name
 *   DB name
 * @return
 *   DB pointer
 */
extern struct eng_conf_db_s *
eng_conf_create(const char *db_name);

/**
 * @brief DB を destroy する
 *        - delete all record  and free() DB memory
 *
 * @param db_name
 *   DB name
 */
extern void
eng_conf_destroy(struct eng_conf_db_s *db);

/**
 * @brief file から db を構築する
 *
 * @param path
 *   path to configration file
 * @param db
 *   DB pointer
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_read_file(struct eng_conf_db_s *db,
                   const char *path);

/**
 * @brief DB を walk し、record に対して指定関数を実行する
 *
 * @param db
 *   DB pointer
 * @param cb
 *   callback function for each records in DB
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_walk(struct eng_conf_db_s *db,
              int (*cb)(const char *db_name,
                        const struct eng_conf_s *conf,
                        void *arg),
              void *arg);

/**
 * @brief DB に従い dpdk を初期化する
 *
 * @param db
 *   config DB
 * @param prog
 *   program name
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_init_rte(struct eng_conf_db_s *db,
                  const char *prog);

#endif	/* !_ENG_CONF_H_ */
