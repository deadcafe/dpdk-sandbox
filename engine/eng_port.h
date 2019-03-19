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
 * @file        eng_port.h
 * @brief       Engine port
 */

#ifndef _ENG_PORT_H_
#define _ENG_PORT_H_

#include <sys/queue.h>
#include <string.h>
#include <stdint.h>

#include <rte_port.h>
#include <rte_mbuf.h>
#include <rte_net.h>

/**
 * @brief number of default descriptors
 */
#define ENG_NETDEV_RX_DESC_DEFAULT	(1024 * 4)
#define ENG_NETDEV_TX_DESC_DEFAULT	(1024 * 4)

#define ENG_PORT_INVALID_ID	UINT16_MAX

#define ENG_PORT_PMD_TX_BURST	4
#define ENG_PORT_RING_TX_BURST	4

struct eng_conf_db_s;

/**
 * @brief port type
 */
enum eng_port_type_e {
    ENG_PORT_TYPE_PMD = 0,
    ENG_PORT_TYPE_RING,

    ENG_PORT_TYPE_INVALID,
};

/**
 * @brief direction
 */
enum eng_port_dir_e {
    ENG_PORT_DIR_IN = 0,
    ENG_PORT_DIR_OUT,
};

/**
 * @brief netdevice type
 */
enum eng_netdev_type_e {
    ENG_NETDEV_TYPE_INVALID = -1,

    ENG_NETDEV_TYPE_ETHDEV = 0,
    ENG_NETDEV_TYPE_BONDING,
    ENG_NETDEV_TYPE_KNI,
    ENG_NETDEV_TYPE_NULL,

    ENG_NETDEV_TYPE_NB,
};

struct eng_netdev_info_s {
    enum eng_netdev_type_e netdev_type;
    uint16_t depend_port;
    uint16_t sub;	/* n th in type */
    char port_name[32];	/* DPDK port name */
};

struct rte_net_hdr_lens;

/**
 * @brief port 構造体
 */
struct eng_port_s {
    MARKER cacheline0;

    char name[32];

    STAILQ_ENTRY(eng_port_s) node;

    union {
        struct {
            enum eng_netdev_type_e netdev_type;
            uint16_t port_id;
            uint16_t queue_id;
            uint16_t nb_slaves;
            uint16_t slaves[2];	/*!< slave port_id */
        };
        struct rte_ring *ring;
    };

    enum eng_port_type_e type;
    enum eng_port_dir_e dir;


    uint64_t tx_capa;	/* Tx offload capabilities */
    uint64_t rx_capa;	/* Rx offload capabilities */
    int (*tx_ol_handler)(struct rte_mbuf *);
    uint32_t (*rx_ol_handler)(struct rte_mbuf *, struct rte_net_hdr_lens *,
                              uint32_t);

    void *op;

    union {
        const struct rte_port_in_ops *in;
        const struct rte_port_out_ops *out;
    } ops;

} __rte_cache_aligned;

static inline uint32_t
eng_port_packet_type(struct eng_port_s *port,
                     struct rte_mbuf *m,
                     struct rte_net_hdr_lens *hdr_lens,
                     uint32_t layers)
{
    if (port->rx_ol_handler)
        return port->rx_ol_handler(m, hdr_lens, layers);
    return rte_net_get_ptype(m, hdr_lens, layers);
}

static inline int
eng_port_set_cksum(struct eng_port_s *port,
                   struct rte_mbuf *m)
{
    if (port->tx_ol_handler)
        return port->tx_ol_handler(m);
    return 0;
}

/**
 * @brief port 統計情報
 */
union eng_port_stats_u {
    uint64_t val[2];
    struct rte_port_in_stats in;
    struct rte_port_out_stats out;
};


STAILQ_HEAD(eng_port_head_s, eng_port_s);

/**
 * @brief name と direction に対する port を取得する
 *
 */
static inline struct eng_port_s *
eng_port_find(struct eng_port_head_s *head,
              const char *name,
              enum eng_port_dir_e dir)
{
    struct eng_port_s *port;

    STAILQ_FOREACH(port, head, node) {
        if (port->dir == dir &&
            !strcmp(port->name, name)) {
            return port;
        }
    }
    return NULL;
}


/**
 * @brief out port を生成する
 *
 */
extern struct eng_port_s *
eng_port_out_create(struct eng_conf_db_s *db,
                    const char *name);

/**
 * @brief in port を生成する
 *
 */
extern struct eng_port_s *
eng_port_in_create(struct eng_conf_db_s *db,
                   const char *name);

static inline int
eng_port_recv(struct eng_port_s *port,
              struct rte_mbuf **pkts,
              unsigned n_pkts)
{
    return port->ops.in->f_rx(port->op, pkts, n_pkts);
}

static inline int
eng_port_send(struct eng_port_s *port,
              struct rte_mbuf *pkts)
{
    return port->ops.out->f_tx(port->op, pkts);
}

static inline int
eng_port_send_bulk(struct eng_port_s *port,
                   struct rte_mbuf **pkts,
                   uint64_t mask)
{
    return port->ops.out->f_tx_bulk(port->op, pkts, mask);
}

static inline int
eng_port_flush(struct eng_port_s *port)
{
    return port->ops.out->f_flush(port->op);
}

static inline void
eng_port_flush_ports(struct eng_port_head_s *head)
{
    struct eng_port_s *p;

    STAILQ_FOREACH(p, head, node) {
        if (p->dir == ENG_PORT_DIR_OUT)
            eng_port_flush(p);
    }
}

static inline void
eng_port_stats(const struct eng_port_s *port,
               union eng_port_stats_u *stats)
{
    if (port->dir == ENG_PORT_DIR_IN)
        port->ops.in->f_stats(port->op, &stats->in, 0);
    else
        port->ops.out->f_stats(port->op, &stats->out, 0);
}

static inline unsigned
eng_port_count(struct eng_port_head_s *head)
{
    unsigned nb = 0;
    struct eng_port_s *port;

    STAILQ_FOREACH(port, head, node)
        nb++;
    return nb;
}

extern const char *
eng_netdev_type2str(enum eng_netdev_type_e type);

extern const struct eng_netdev_info_s *
eng_port_find_netdev_info(void);

extern const struct eng_netdev_info_s *
eng_netdev_info(uint16_t port_id);

extern enum eng_netdev_type_e
eng_netdev_type(uint16_t port_id);

struct ether_addr;

extern int
eng_set_kni_mac(const char *name,
                const struct ether_addr *mac);

extern int
eng_set_kni_mtu(const char *name,
                uint16_t mtu);

extern int
eng_set_kni_flags(const char *name,
                  short req_flags,
                  int ope);

extern uint16_t
eng_eth_dev_count_avail(void);

#endif	/* !_ENG_PORT_H_ */
