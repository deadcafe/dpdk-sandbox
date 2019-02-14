/*
 * Copyright (c) 201p Deadcafe.beef@gmail.com All Rights Reserved.
 *
 * Unauthorized inspection, duplication, utilization or modification
 * of this file is prohibited.  Other related documents, whether
 * explicitly marked or implied, may also fall under this copyright.
 * Distribution of information obtained from this file and other related
 * documents to a third party is not permitted under any circumstances.
 */

/**
 * @file        conf.h
 * @brief       conf private header
 */

#ifndef _CONF_H_
#define _CONF_H_

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <rte_ether.h>

#include "eng_conf.h"
#include "eng_log.h"


#define ENG_CONF_STRING_MAX	256

/**
 * @brief key に対する record を find する
 *
 * @param db
 *   DB pointer
 * @param db
 *   key string
 * @return
 *   found: record pointer
 *   Not found: NULL
 */
extern const struct eng_conf_s *
eng_conf_find(struct eng_conf_db_s *db,
              const char *key);

/**
 * @brief key に対する value ( string ) を取得する
 *
 * @param db
 *   DB pointer
 * @param key
 *   key string
 * @return
 *   found: string
 *   Not found: NULL
 */
extern const char *
eng_conf_find_val(struct eng_conf_db_s *db,
                  const char *key);

/**
 * @brief key に対する record を nfind する
 *        - "nfind" finds the first node greater than or equal to the search key.
 *
 * @param db
 *   DB pointer
 * @param key
 *   key string
 * @return
 *   found: record pointer
 *   Not found: NULL
 */
extern const struct eng_conf_s *
eng_conf_nfind(struct eng_conf_db_s *db,
               const char *key);

/**
 * @brief DB に record を add する
 *
 * @param db
 *   DB pointer
 * @param key
 *   key string
 * @param value
 *   value string
 * @return
 *   OK: not NULL
 *   NG: NULL
 */
extern const struct eng_conf_s *
eng_conf_add(struct eng_conf_db_s *db,
             const char *key,
             const char *val);

/**
 * @brief DB の record を update する
 *
 * @param db
 *   DB pointer
 * @param key
 *   key string
 * @param value
 *   value string
 * @return
 *   OK: not NULL
 *   NG: NULL
 */
extern const struct eng_conf_s *
eng_conf_update(struct eng_conf_db_s *db,
                const char *key,
                const char *val);

/**
 * @brief key に対する value ( list ) を取得する
 *
 * @param db
 *   DB pointer
 * @param key
 *   key string
 * @param list
 *   list value pointer
 * @return
 *   number of list entry
 */
extern unsigned
eng_conf_list(struct eng_conf_db_s *db,
              const char *key,
              char *list,
              unsigned size);

/**
 * @brief DB の record を delete する
 *
 * @param db
 *   DB pointer
 * @param key
 *   key string
 * @param list
 *   list value pointer
 * @return
 *   number of list entry
 */
extern void
eng_conf_delete(struct eng_conf_db_s *db,
                const char *key);

/**
 * @brief DB の全ての record を delete する
 *
 * @param db
 *   DB pointer
 */
extern void
eng_conf_delete_all(struct eng_conf_db_s *db);



/* XXX: needed ? */
extern unsigned
eng_conf_thread(struct eng_conf_db_s *db,
                char *buff,
                size_t size);

/* XXX: needed ? */
extern int
eng_init_rte(struct eng_conf_db_s *db,
             const char *prog);

/*
 * thread op
 */

/**
 * @brief thread に対する lcore id を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   thread name
 *   ( must be NULL terminated )
 * @return
 *   lcore_id
 */
extern int
eng_conf_thread_lcore(struct eng_conf_db_s *db,
                      const char *name);

/**
 * @brief thread に対する lcore id を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   thread name
 *   ( must be NULL terminated )
 * @return
 *   lcore_id
 */
extern int
eng_conf_add_thread_lcore(struct eng_conf_db_s *db,
                          const char *name,
                          int lcore_id);

/**
 * @brief name で指定された thread が master thread かを判定する
 *
 * @param db
 *   DB pointer
 * @param name
 *   thread name
 *   ( must be NULL terminated )
 *
 * @return
 *   ture: master thread
 *   false: not master thread
 */
extern bool
eng_conf_is_master_thread(struct eng_conf_db_s *db,
                          const char *name);

/**
 * @brief name で指定された thread を master thread として DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   thread name
 *   ( must be NULL terminated )
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_add_master_thread(struct eng_conf_db_s *db,
                           const char *name);

/**
 * @brief 指定した lcore id を master thread として DB に登録する
 *
 * @param db
 *   DB pointer
 * @param lcore_id
 *   lcore id
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_add_master_lcore(struct eng_conf_db_s *db,
                          int lcore_id);

/**
 * @brief master thread の lcore id を DB から取得する
 *
 * @param db
 *   DB pointer
 * @return
 *   lcore_id
 */
extern int eng_conf_master_lcore(struct eng_conf_db_s *db);

/**
 * @brief 現在の thread name の次の thread name を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param node
 *   current record
 * @param buff
 *   next name buffer
 *   (領域は関数コール側で確保すること)
 * @param buff_size
 *   buff の size
 * @return
 *   next record
 */
extern struct eng_conf_node_s *
eng_conf_thread_name_next(struct eng_conf_db_s *db,
                          struct eng_conf_node_s *node,
                          char *buff,
                          size_t buff_size);

/**
 * @brief lcore id に対する thread name を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param lcore_id
 *   lcore id
 * @return
 *   found: thread name
 *   not found: NULL
 */
extern const char *
eng_conf_lcore_thread(struct eng_conf_db_s *db,
                      unsigned lcore_id);

/**
 * @brief lcore id に対する thread name を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param lcore_id
 *   lcore id
 * @param name
 *   thread name
 *   ( must be NULL terminated )
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_add_lcore_thread(struct eng_conf_db_s *db,
                          unsigned lcore_id,
                          const char *name);

/**
 * @brief thread に対する mbufpool name を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   thread name
 *   ( must be NULL terminated )
 * @return
 *   found: mbufpool name
 *   not found: NULL
 */
extern const char *
eng_conf_thread_mbufpool(struct eng_conf_db_s *db,
                         const char *name);

/**
 * @brief thread に対する mbufpool name を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   thread name
 *   ( must be NULL terminated )
 * @param mbufpool
 *   mbufpool name
 *   ( must be NULL terminated )
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_add_thread_mbufpool(struct eng_conf_db_s *db,
                             const char *name,
                             const char *mbufpool);

/**
 * @brief thread に対する task list を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param th_name
 *   thread name
 * @param tasks
 *   task name list (array)
 *   (領域は関数コール側で確保すること)
 * @param max_ports
 *   tasks の array 要素数
 * @param buff
 *   task name list (string)
 *   (領域は関数コール側で確保すること)
 * @param buff_size
 *   buff の size
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_thread_task_list(struct eng_conf_db_s *db,
                          const char *th_name,
                          const char **tasks,
                          unsigned max_tasks,
                          char *buff,
                          size_t buff_size);
/**
 * @brief thread に対する task を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param th_name
 *   thread name
 * @param tasks
 *   task name
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_add_thread_task(struct eng_conf_db_s *db,
                         const char *th_name,
                         const char *task);

/**
 * @brief task に対する addon name を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   task name
 *   ( must be NULL terminated )
 * @return
 *   found: addon name
 *   not found: NULL
 */
extern const char *
eng_conf_task_addon(struct eng_conf_db_s *db,
                    const char *name);

/**
 * @brief task name を key として addon name を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   task name
 *   ( must be NULL terminated )
 * @param addon
 *   addon name
 *   ( must be NULL terminated )
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_add_task_addon(struct eng_conf_db_s *db,
                        const char *name,
                        const char *addon);

/**
 * @brief task に対する in-port name を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   task name
 *   ( must be NULL terminated )
 * @return
 *   found: in-port name
 *   not found: NULL
 */
extern const char *
eng_conf_task_in_port(struct eng_conf_db_s *db,
                      const char *name);

/**
 * @brief task name を key として in-port name を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   task name
 *   ( must be NULL terminated )
 * @param port
 *   port name
 *   ( must be NULL terminated )
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_add_task_in_port(struct eng_conf_db_s *db,
                          const char *name,
                          const char *port);

/**
 * @brief task に対する out-port name の list を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   task name
 *   ( must be NULL terminated )
 * @param ports
 *   port name list (array)
 *   (領域は関数コール側で確保すること)
 * @param max_ports
 *   ports の array 要素数
 * @param buff
 *   port name list (string)
 *   (領域は関数コール側で確保すること)
 * @param buff_size
 *   buff の size
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_task_out_port_list(struct eng_conf_db_s *db,
                            const char *name,
                            const char **ports,
                            unsigned max_ports,
                            char *buff,
                            size_t buff_size);

/**
 * @brief task name を key として out-port name を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   task name
 *   ( must be NULL terminated )
 * @param port
 *   port name
 *   ( must be NULL terminated )
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_add_task_out_port(struct eng_conf_db_s *db,
                           const char *name,
                           const char *port);

/**
 * @brief 現在の task name の次の task name を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param node
 *   current record
 * @param buff
 *   next name buffer
 *   (領域は関数コール側で確保すること)
 * @param buff_size
 *   buff の size
 * @return
 *   next record
 */
extern struct eng_conf_node_s *
eng_conf_task_name_next(struct eng_conf_db_s *db,
                        struct eng_conf_node_s *node,
                        char *buff,
                        size_t buff_size);

/**
 * @brief ring に対する ring size を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   ring name
 *   ( must be NULL terminated )
 * @return
 *   ring size
 */
extern int
eng_conf_ring_size(struct eng_conf_db_s *db,
                   const char *name);

/**
 * @brief ring に対する ring size を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   ring name
 *   ( must be NULL terminated )
 * @param size
 *   ring size
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_add_ring_size(struct eng_conf_db_s *db,
                       const char *name,
                       int size);

/**
 * @brief 現在の ring name の次の ring name を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param node
 *   current record
 * @param buff
 *   next name buffer
 *   (領域は関数コール側で確保すること)
 * @param buff_size
 *   buff の size
 * @return
 *   next record
 */
extern struct eng_conf_node_s *
eng_conf_ring_name_next(struct eng_conf_db_s *db,
                        struct eng_conf_node_s *node,
                        char *buff,
                        size_t buff_size);

/*
 * netdev
 */

/**
 * @brief netdev に対する netdev type を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @return
 *   found: netdev type string
 *   not found: NULL
 */
extern const char *
eng_conf_netdev_type(struct eng_conf_db_s *db,
                     const char *name);

/**
 * @brief netdev id に対する netdev name を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param id
 *   netdev id
 * @return
 *   found: netdev name string
 *   not found: NULL
 */
extern const char *
eng_conf_netdev_id_name(struct eng_conf_db_s *db,
                        uint16_t id);

/**
 * @brief netdev id に対する netdev name を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param
 *   netdev id
 * @return
 */
extern int
eng_conf_netdev_name_id(struct eng_conf_db_s *db,
                        const char *name,
                        int use_err);

/**
 * @brief netdev id を key として netdev name を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param
 *   netdev id
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_add_netdev_id_name(struct eng_conf_db_s *db,
                            uint16_t id,
                            const char *name);

/**
 * @brief netdev name を key として netdev id を DB に追加する。
 *
 * @param db
 *   DB pointer
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @param id
 *   netdev id
 * @param with_name
 *    true 指定の場合、netdev id を key とした netdev_name も同時に追加する
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int eng_conf_add_netdev_name_id(struct eng_conf_db_s *db,
                                      const char *name,
                                      uint16_t id,
                                      bool with_name);

/**
 * @brief netdev name を key として netdev type を DB に追加する。
 *
 * @param db
 *   DB pointer
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @param type
 *   netdev type
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int eng_conf_add_netdev_name_type(struct eng_conf_db_s *db,
                                         const char *name,
                                         const char *type);
/**
 * @brief netdev に対する rx queue 数を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @return
 *   queue 数
 */
extern int
eng_conf_netdev_nb_rx_queues(struct eng_conf_db_s *db,
                             const char *name);

/**
 * @brief netdev に対する rx queue 数を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @param rx_queues
 *   queue 数
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_add_netdev_nb_rx_queues(struct eng_conf_db_s *db,
                                 const char *name,
                                 int rx_queues);

/**
 * @brief netdev に対する tx queue 数を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @return
 *   queue 数
 */
extern int
eng_conf_netdev_nb_tx_queues(struct eng_conf_db_s *db,
                             const char *name);

/**
 * @brief netdev に対する tx queue 数を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @param tx_queues
 *   queue 数
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_add_netdev_nb_tx_queues(struct eng_conf_db_s *db,
                                 const char *name,
                                 int tx_queues);

/**
 * @brief netdev に対する mbufpool name を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @return
 *   mbufpool name
 */
extern const char *
eng_conf_netdev_mbufpool(struct eng_conf_db_s *db,
                         const char *name);

/**
 * @brief netdev に対する mbufpool name を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @param mbufpool
 *   mbufpool name
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_add_netdev_mbufpool(struct eng_conf_db_s *db,
                             const char *name,
                             const char *mbufpool);

/**
 * @brief netdev に対する mac address を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @param addr
 *   mac address
 * @return
 *   OK: Zero
 *   NG: Not Zero
 *
 */
extern int
eng_conf_netdev_mac(struct eng_conf_db_s *db,
                    const char *name,
                    struct ether_addr *addr);

/**
 * @brief netdev に対する mac address を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @param addr
 *   mac address
 * @return
 *   OK: Zero
 *   NG: Not Zero
 *
 */
extern int
eng_conf_add_netdev_mac(struct eng_conf_db_s *db,
                        const char *name,
                        const struct ether_addr *addr);

/**
 * @brief bonding netdev に対する bonding mode を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @return
 *   bonding mode string
 *
 */
extern const char *
eng_conf_bonding_mode(struct eng_conf_db_s *db,
                      const char *name);

/**
 * @brief bonding netdev に対する bonding mode を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @param mode
 *   bonding mode string
 * @return
 *   OK: Zero
 *   NG: Not Zero
 */
extern int
eng_conf_add_bonding_mode(struct eng_conf_db_s *db,
                          const char *name,
                          const char *mode);

/**
 * @brief bonding netdev に対する bonding interval msec を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @return
 *   bonding interval msec
 *
 */
extern int
eng_conf_bondig_interval(struct eng_conf_db_s *db,
                         const char *name);

/**
 * @brief bonding netdev に対する bonding interval msec を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @param interval
 *   bonding interval msec
 * @return
 *   OK: Zero
 *   NG: Not Zero
 *
 */
extern int
eng_conf_add_bonding_interval(struct eng_conf_db_s *db,
                              const char *name,
                              int interval);

/**
 * @brief bonding netdev に対する bonding downdelay msec を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @return
 *   bonding downdelay msec
 *
 */
extern int eng_conf_bondig_downdelay(struct eng_conf_db_s *db,
                                     const char *name);

/**
 * @brief bonding netdev に対する bonding downdelay msec を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @param downdelay
 *   bonding downdelay msec
 * @return
 *   OK: Zero
 *   NG: Not Zero
 */
extern int
eng_conf_add_bonding_downdelay(struct eng_conf_db_s *db,
                               const char *name,
                               int downdelay);

/**
 * @brief bonding netdev に対する bonding updelay msec を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @return
 *   bonding updelay msec
 *
 */
extern int
eng_conf_bondig_updelay(struct eng_conf_db_s *db,
                        const char *name);

/**
 * @brief bonding netdev に対する bonding updelay msec を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @param updelay
 *   bonding updelay msec
 * @return
 *   OK: Zero
 *   NG: Not Zero
 */
extern int
eng_conf_add_bonding_updelay(struct eng_conf_db_s *db,
                             const char *name,
                             int updelay);

/**
 * @brief bonding netdev に対する slave list を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @param slaves
 *   slave name list (array)
 *   (領域は関数コール側で確保すること)
 * @param max_slaves
 *   slaves の array 要素数
 * @param buff
 *   slave name list (string)
 *   (領域は関数コール側で確保すること)
 * @param buff_size
 *   buff の size
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_bonding_slave_list(struct eng_conf_db_s *db,
                            const char *name,
                            const char **slaves,
                            unsigned max_slaves,
                            char *buff,
                            size_t buff_size);

/**
 * @brief bonding netdev に対する slave netdev を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @param slave
 *   slave netdev name
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_add_bonding_slave(struct eng_conf_db_s *db,
                           const char *name,
                           const char *slave);

/**
 * @brief netdev に対する depend netdev を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @return
 *   depend netdev name
 *
 */
extern const char *
eng_conf_netdev_depend(struct eng_conf_db_s *db,
                       const char *name);

/**
 * @brief netdev に対する depend netdev を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   netdev name
 *   ( must be NULL terminated )
 * @param depend
 *   depend netdev name
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_add_netdev_depend(struct eng_conf_db_s *db,
                           const char *name,
                           const char *depend);

/**
 * @brief 現在の netdev name の次の netdev name を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param node
 *   current record
 * @param buff
 *   next name buffer
 *   (領域は関数コール側で確保すること)
 * @param buff_size
 *   buff の size
 * @return
 *   next record
 */
extern struct eng_conf_node_s *
eng_conf_netdev_name_next(struct eng_conf_db_s *db,
                          struct eng_conf_node_s *node,
                          char *buff,
                          size_t buff_size);

/**
 * @brief port に対する rx queue 番号を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   port name
 *   ( must be NULL terminated )
 * @return
 *   rx queue 番号
 *
 */
extern int
eng_conf_port_rx_queue(struct eng_conf_db_s *db,
                       const char *name);
/**
 * @brief port name を key として rx queue 番号を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   port name
 *   ( must be NULL terminated )
 * @param queue_no
 *   queue 番号
 * @return
 *   OK: Zero
 *   NG: not Zero
 *
 */
extern int
eng_conf_add_port_rx_queue(struct eng_conf_db_s *db,
                           const char *name,
                           int queue_no);

/**
 * @brief port に対する tx queue 番号を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   port name
 *   ( must be NULL terminated )
 * @return
 *   tx queue 番号
 *
 */
extern int
eng_conf_port_tx_queue(struct eng_conf_db_s *db,
                       const char *name);

/**
 * @brief port name を key として tx queue 番号を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   port name
 *   ( must be NULL terminated )
 * @param queue_no
 *   queue 番号
 * @return
 *   OK: Zero
 *   NG: not Zero
 *
 */
extern int
eng_conf_add_port_tx_queue(struct eng_conf_db_s *db,
                           const char *name,
                           int queue_no);

/**
 * @brief port に対する retry 回数を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   port name
 *   ( must be NULL terminated )
 * @return
 *   tx queue 番号
 *
 */
extern int
eng_conf_port_retry(struct eng_conf_db_s *db,
                    const char *name);

/**
 * @brief port name を key として retry 回数を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   port name
 *   ( must be NULL terminated )
 * @param retry
 *   retry 回数
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_add_port_retry(struct eng_conf_db_s *db,
                        const char *name,
                        int retry);

/**
 * @brief port に対する depend name を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   port name
 *   ( must be NULL terminated )
 * @return
 *   depend name
 *
 */
extern const char *
eng_conf_port_depend(struct eng_conf_db_s *db,
                     const char *name);

/**
 * @brief port に対する depend name を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   port name
 *   ( must be NULL terminated )
 * @param depend
 *   depend name
 *   ( must be NULL terminated )
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_add_port_depend(struct eng_conf_db_s *db,
                         const char *name,
                         const char *depend);

/**
 * @brief 現在の port name の次の port name を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param node
 *   current record
 * @param buff
 *   next name buffer
 *   (領域は関数コール側で確保すること)
 * @param buff_size
 *   buff の size
 * @return
 *   next record
 */
extern struct eng_conf_node_s *
eng_conf_port_name_next(struct eng_conf_db_s *db,
                        struct eng_conf_node_s *node,
                        char *buff,
                        size_t buff_size);

/*
 * addon
 */

/**
 * @brief addon name を key として addon 情報を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   addon name
 *   ( must be NULL terminated )
 * @param p
 *   pointer to addon
 * @return
 *   OK: Zero
 *   NG: not Zero
 *
 */
extern int
eng_conf_add_addon(struct eng_conf_db_s *db,
                   const char *name,
                   const void *p);
/**
 * @brief addon name に対する addon 情報を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   addon name
 *   ( must be NULL terminated )
 * @return
 *   pointer to addon
 *
 */
extern const void *
eng_conf_addon(struct eng_conf_db_s *db,
               const char *name);

/*
 * mbuf
 */

/**
 * @brief mbufpool に対する pool size を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   mbufpool name
 *   ( must be NULL terminated )
 * @return
 *   number of mbufs_k
 *
 */
extern int
eng_conf_mbufpool_size(struct eng_conf_db_s *db,
                       const char *name);
/**
 * @brief mbufpool に対する pool size を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   mbufpool name
 *   ( must be NULL terminated )
 * @param size
 *   number of mbufs_k
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_add_mbufpool_size(struct eng_conf_db_s *db,
                           const char *name,
                           int size);

/**
 * @brief mbufpool に対する cache size を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   mbufpool name
 *   ( must be NULL terminated )
 * @return
 *   cache size byte
 *
 */
extern int
eng_conf_mbufpool_cache_size(struct eng_conf_db_s *db,
                             const char *name);

/**
 * @brief mbufpool に対する cache size を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   mbufpool name
 *   ( must be NULL terminated )
 * @param cache_size
 *   cache size byte
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_add_mbufpool_cache_size(struct eng_conf_db_s *db,
                                 const char *name,
                                 int cache_size);

/**
 * @brief mbufpool に対する external area size を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param name
 *   mbufpool name
 *   ( must be NULL terminated )
 * @return
 *   external area size byte
 *
 */
extern int
eng_conf_mbufpool_ext_size(struct eng_conf_db_s *db,
                           const char *name);

/**
 * @brief mbufpool に対する external area size を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param name
 *   mbufpool name
 *   ( must be NULL terminated )
 * @param ext_size
 *   external area size byte
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_add_mbufpool_ext_size(struct eng_conf_db_s *db,
                               const char *name,
                               int ext_size);

/**
 * @brief 現在の mbufpool name の次の mbufpool name を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param node
 *   current record
 * @param buff
 *   next name buffer
 *   (領域は関数コール側で確保すること)
 * @param buff_size
 *   buff の size
 * @return
 *   next record
 */
extern struct eng_conf_node_s *
eng_conf_mbufpool_name_next(struct eng_conf_db_s *db,
                            struct eng_conf_node_s *node,
                            char *buff,
                            size_t buff_size);

/**
 * @brief global initializer list を DB から取得する
 *
 * @param db
 *   DB pointer
 * @param entries
 *   initializer name list (array)
 *   (領域は関数コール側で確保すること)
 * @param max_entries
 *   entries の array 要素数
 * @param buff
 *   initializer name list (string)
 *   (領域は関数コール側で確保すること)
 * @param buff_size
 *   buff の size
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_global_initializer_list(struct eng_conf_db_s *db,
                                 const char **entries,
                                 unsigned max_entries,
                                 char *buff,
                                 size_t buff_size);

/**
 * @brief global initializer を DB に追加する
 *
 * @param db
 *   DB pointer
 * @param entry
 *   initializer name
 * @return
 *   OK: Zero
 *   NG: not Zero
 */
extern int
eng_conf_add_global_initializer(struct eng_conf_db_s *db,
                                const char *entry);

#define USE_ERR_LEVEL	1
#define NOT_ERR_LEVEL	0

/*
 * conf tools
 */
static inline int
eng_conf_get_integer(struct eng_conf_db_s *db,
                     int use_error,
                     const char *fmt,
                     ...)
{
    char key[ENG_CONF_STRING_MAX];
    int ret = -1;
    const char *v;
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(key, sizeof(key), fmt, ap);
    va_end(ap);

    v = eng_conf_find_val(db, key);
    if (v) {
        errno = 0;
        ret = strtol(v, NULL, 10);
        if (errno) {
            ENG_ERR(CORE, "invalid key:%s value:%s", key, v);
            ret = -1;
        }
    } else {
        if (use_error)
            ENG_ERR(CORE, "nothing %s", key);
        else
            ENG_NOTICE(CORE, "nothing %s", key);
    }
    return ret;
}

/*
 *
 */
static inline const void *
eng_conf_get_pointer(struct eng_conf_db_s *db,
                     const char *fmt,
                     ...)
{
    char key[ENG_CONF_STRING_MAX];
    const char *v;
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(key, sizeof(key), fmt, ap);
    va_end(ap);

    v = eng_conf_find_val(db, key);
    if (v) {
        uintptr_t p;

        errno = 0;
        p = strtoull(v, NULL, 16);
        if (errno) {
            ENG_ERR(CORE, "invalid key:%s value:%s", key, v);
            return NULL;
        }
        return (const void *) p;
    }
    return NULL;
}

/*
 *
 */
static inline inline bool
eng_conf_get_boolean(struct eng_conf_db_s *db,
                     const char *fmt,
                     ...)
{
    char key[ENG_CONF_STRING_MAX];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(key, sizeof(key), fmt, ap);
    va_end(ap);

    return (eng_conf_find(db, key) != NULL);
}

/*
 *
 */
static inline const char *
eng_conf_get_string(struct eng_conf_db_s *db,
                    const char *fmt,
                    ...)
{
    char key[ENG_CONF_STRING_MAX];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(key, sizeof(key), fmt, ap);
    va_end(ap);

    return eng_conf_find_val(db, key);
}

/*
 *
 */
static inline int
eng_conf_get_string_list(struct eng_conf_db_s *db,
                         const char **list,
                         size_t list_size,
                         char *buff,
                         size_t buff_size,
                         const char *fmt,
                         ...)
{
    char key[ENG_CONF_STRING_MAX];
    unsigned nb;
    const char *p = buff;
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(key, sizeof(key), fmt, ap);
    va_end(ap);

    nb = eng_conf_list(db, key, buff, buff_size);
    if (list_size < nb) {
        ENG_ERR(CORE, "too many lists key:%s nb:%u", key, nb);
        return -1;
    }
    for (unsigned i = 0; i < nb; i++) {
        list[i] = p;
        p += (strlen(p) + 1);
    }
    return (int) nb;
}

/*
 *
 */
static inline int
eng_conf_get_integer_list(struct eng_conf_db_s *db,
                          int *list,
                          size_t list_size,
                          char *buff,
                          size_t buff_size,
                          const char *fmt,
                          ...)
{
    char key[ENG_CONF_STRING_MAX];
    unsigned nb;
    const char *p = buff;
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(key, sizeof(key), fmt, ap);
    va_end(ap);

    nb = eng_conf_list(db, key, buff, buff_size);
    if (list_size < nb) {
        ENG_ERR(CORE, "too many lists key:%s nb:%u", key, nb);
        return -1;
    }
    for (unsigned i = 0; i < nb; i++) {
        char *end_p;

        errno = 0;
        list[i] = strtol(p, &end_p, 10);
        if (errno || *end_p != '\0') {
            ENG_ERR(CORE, "invalid key:%s value:%s", key, p);
            return -1;
        }
        p = ++end_p;
    }
    return (int) nb;
}

/*
 *
 */
static inline int
eng_conf_add_integer(struct eng_conf_db_s *db,
                     int val,
                     const char *fmt,
                     ...)
{
    char key[ENG_CONF_STRING_MAX];
    char str[32];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(key, sizeof(key), fmt, ap);
    va_end(ap);

    snprintf(str, sizeof(str), "%d", val);
    if (eng_conf_add(db, key, str))
        return 0;
    return -1;
}

/*
 *
 */
static inline int
eng_conf_add_string(struct eng_conf_db_s *db,
                    const char *str,
                    const char *fmt,
                    ...)
{
    char key[ENG_CONF_STRING_MAX];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(key, sizeof(key), fmt, ap);
    va_end(ap);

    if (eng_conf_add(db, key, str))
        return 0;
    return -1;
}

/*
 *
 */
static inline int
eng_conf_add_pointer(struct eng_conf_db_s *db,
                     const void *p,
                     const char *fmt,
                     ...)
{
    char str[64];
    char key[ENG_CONF_STRING_MAX];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(key, sizeof(key), fmt, ap);
    va_end(ap);

    snprintf(str, sizeof(str), "%p", p);
    if (eng_conf_add(db, key, str))
        return 0;
    return -1;
}

/*
 *
 */
static inline int
eng_conf_add_boolean(struct eng_conf_db_s *db,
                     const char *fmt,
                     ...)
{
    char key[128];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(key, sizeof(key), fmt, ap);
    va_end(ap);

    if (eng_conf_add(db, key, NULL))
        return 0;
    return -1;
}

/*
 *
 */
static inline int
eng_conf_apend_string_list(struct eng_conf_db_s *db,
                           const char *str,
                           const char *fmt,
                           ...)
{
    char buf[ENG_CONF_STRING_MAX * 2];
    char key[ENG_CONF_STRING_MAX];
    const char *v;
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(key, sizeof(key), fmt, ap);
    va_end(ap);

    v = eng_conf_find_val(db, key);
    if (v) {
        snprintf(buf, sizeof(buf), "%s,%s", v, str);
        str = buf;
    }

    if (eng_conf_update(db, key, str))
        return 0;
    return -1;
}

/*
 *
 */
static inline int
eng_conf_apend_integer_list(struct eng_conf_db_s *db,
                            int val,
                            const char *fmt,
                            ...)
{
    char buf[ENG_CONF_STRING_MAX * 2];
    char key[ENG_CONF_STRING_MAX];
    const char *v;
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(key, sizeof(key), fmt, ap);
    va_end(ap);

    v = eng_conf_find_val(db, key);
    if (v)
        snprintf(buf, sizeof(buf), "%s,%d", v, val);
    else
        snprintf(buf, sizeof(buf), "%d", val);

    if (eng_conf_update(db, key, buf))
        return 0;
    return -1;
}

#endif /* !_ENG_CONF_H_ */
