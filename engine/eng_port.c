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
 * @file        eng_port.c
 * @brief       Engine port
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#include <rte_ethdev.h>
#include <rte_eth_bond.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_port.h>
#include <rte_port_ethdev.h>
#include <rte_port_kni.h>
#include <rte_port_ring.h>
#include <rte_bus_vdev.h>
#include <rte_icmp.h>

#include <rte_version.h>
#define RTE_VER	((RTE_VER_YEAR * 10000) + (RTE_VER_MONTH * 100) + RTE_VER_MINOR)
#if (RTE_VER >= 181100)
# define ENABLE_DPDK1811
#endif

#include "conf.h"
#include "eng_mbuf.h"
#include "eng_log.h"
#include "eng_port.h"

#define RTE_RX_DESC_DEFAULT ENG_NETDEV_RX_DESC_DEFAULT
#define RTE_TX_DESC_DEFAULT ENG_NETDEV_TX_DESC_DEFAULT

/* return port_id */
static int get_netdev(struct eng_conf_db_s *db,
                      const char *name);

/*****************************************************************************
 *	CheckSum Handler
 *****************************************************************************/
union l3_hdr_u {
    struct ipv4_hdr ipv4;
    struct ipv6_hdr ipv6;
};

union l4_hdr_u {
    struct tcp_hdr tcp;
    struct udp_hdr udp;
    struct sctp_hdr sctp;
    struct icmp_hdr icmp;
};

/*
 * L3(v4,v6),L4(TCP,UDP) Tx offload NOT ready
 */
static int
tx_ol_handler_l3_l4_sw(struct rte_mbuf *m)
{
    uint64_t inner_l3_offset = m->l2_len;
    uint64_t ol_flags = m->ol_flags;
    int ret = 0;

    if ((ol_flags & PKT_TX_OUTER_IP_CKSUM) || (ol_flags & PKT_TX_OUTER_IPV6))
        inner_l3_offset += m->outer_l2_len + m->outer_l3_len;

    union l3_hdr_u *l3_hdr =
        rte_pktmbuf_mtod_offset(m,
                                union l3_hdr_u *,
                                inner_l3_offset);
    union l4_hdr_u *l4_hdr =
        rte_pktmbuf_mtod_offset(m,
                                union l4_hdr_u *,
                                inner_l3_offset + m->l3_len);

    if ((ol_flags & PKT_TX_L4_MASK) == PKT_TX_UDP_CKSUM) {

        if (ol_flags & PKT_TX_IPV4) {
            if (ol_flags & PKT_TX_IP_CKSUM) {
                l3_hdr->ipv4.hdr_checksum = 0;
                l3_hdr->ipv4.hdr_checksum = rte_ipv4_cksum(&l3_hdr->ipv4);
                ol_flags &= ~PKT_TX_IP_CKSUM;
            }
            l4_hdr->udp.dgram_cksum = 0;
            l4_hdr->udp.dgram_cksum = rte_ipv4_udptcp_cksum(&l3_hdr->ipv4,
                                                            &l4_hdr->udp);
        } else if (ol_flags & PKT_TX_IPV6) {
            if (ol_flags & PKT_TX_IP_CKSUM)
                ol_flags &= ~PKT_TX_IP_CKSUM;
            l4_hdr->udp.dgram_cksum = 0;
            l4_hdr->udp.dgram_cksum = rte_ipv6_udptcp_cksum(&l3_hdr->ipv6,
                                                            &l4_hdr->udp);
        } else {
            /* invalid IP */
            ret = -EINVAL;
        }
        ol_flags &= ~PKT_TX_UDP_CKSUM;

    } else if (((ol_flags & PKT_TX_L4_MASK) == PKT_TX_TCP_CKSUM) ||
               (ol_flags & PKT_TX_TCP_SEG)) {
        if (ol_flags & PKT_TX_IPV4) {
            if (ol_flags & PKT_TX_IP_CKSUM) {
                l3_hdr->ipv4.hdr_checksum = 0;
                l3_hdr->ipv4.hdr_checksum = rte_ipv4_cksum(&l3_hdr->ipv4);
                ol_flags &= ~PKT_TX_IP_CKSUM;
            }
            l4_hdr->tcp.cksum = 0;
            rte_ipv4_udptcp_cksum(&l3_hdr->ipv4, &l4_hdr->tcp);
        } else if (ol_flags & PKT_TX_IPV6) {
            if (ol_flags & PKT_TX_IP_CKSUM)
                ol_flags &= ~PKT_TX_IP_CKSUM;
            l4_hdr->tcp.cksum = 0;
            rte_ipv6_udptcp_cksum(&l3_hdr->ipv6, &l4_hdr->tcp);
        } else {
            /* invalid IP */
            ret = -EINVAL;
        }
        ol_flags &= ~(PKT_TX_TCP_CKSUM | PKT_TX_TCP_SEG);
    } else if ((ol_flags & PKT_TX_L4_MASK) == PKT_TX_SCTP_CKSUM) {
        /* XXX not yet */
    }

    if (m->ol_flags != ol_flags)
        m->ol_flags = ol_flags;
    return ret;
}

/*
 * Rx offload NOT ready, then sw cksum
 */
static uint32_t
rx_ol_handler_no_offload(struct rte_mbuf *m,
                         struct rte_net_hdr_lens *hdr_lens,
                         uint32_t layers)
{
    uint32_t ptype = rte_net_get_ptype(m, hdr_lens, layers);

    if (!m->packet_type)
        m->packet_type = ptype;


    uint32_t l3 = ptype & RTE_PTYPE_L3_MASK;
    uint32_t l4 = ptype & RTE_PTYPE_L4_MASK;

    const union l3_hdr_u *l3_hdr =
        rte_pktmbuf_mtod_offset(m,
                                const union l3_hdr_u *,
                                hdr_lens->l2_len);

    const union l4_hdr_u *l4_hdr =
        rte_pktmbuf_mtod_offset(m,
                                const union l4_hdr_u *,
                                hdr_lens->l2_len + hdr_lens->l3_len);

    uint64_t ol_flags = m->ol_flags;

    if (l3 == RTE_PTYPE_L3_IPV4 || l3 == RTE_PTYPE_L3_IPV4_EXT) {
        unsigned l3_len = 4 * (l3_hdr->ipv4.version_ihl & 0xf);

        if (hdr_lens->l2_len + l3_len > rte_pktmbuf_data_len(m))
            goto end;

        if ((ol_flags & PKT_RX_IP_CKSUM_MASK) == PKT_RX_IP_CKSUM_UNKNOWN) {
            if (l3_hdr->ipv4.hdr_checksum) {
                uint16_t cksum = ~rte_raw_cksum(&l3_hdr->ipv4, l3_len);
                ol_flags |= cksum ?
                            PKT_RX_IP_CKSUM_BAD : PKT_RX_IP_CKSUM_GOOD;
            } else {
                ol_flags |= PKT_RX_IP_CKSUM_NONE;
            }
        }

        if ((ol_flags & PKT_RX_L4_CKSUM_MASK) == PKT_RX_L4_CKSUM_UNKNOWN) {
            switch (l4) {
            case RTE_PTYPE_L4_UDP:
                if (l4_hdr->udp.dgram_cksum) {
                    uint16_t cksum = ~rte_ipv4_udptcp_cksum(&l3_hdr->ipv4,
                                                            l4_hdr);
                    ol_flags |= cksum ?
                                PKT_RX_L4_CKSUM_BAD : PKT_RX_L4_CKSUM_GOOD;
                } else {
                    ol_flags |= PKT_RX_L4_CKSUM_NONE;
                }
                break;

            case RTE_PTYPE_L4_TCP:
                if (l4_hdr->tcp.cksum) {
                    uint16_t cksum = ~rte_ipv4_udptcp_cksum(&l3_hdr->ipv4,
                                                            l4_hdr);
                    ol_flags |= cksum ?
                                PKT_RX_L4_CKSUM_BAD : PKT_RX_L4_CKSUM_GOOD;
                } else {
                    ol_flags |= PKT_RX_L4_CKSUM_NONE;
                }
                break;

            case RTE_PTYPE_L4_SCTP:
                /* XXX: not yet */
                break;

            default:
                break;
            }
        }

    } else if(l3 == RTE_PTYPE_L3_IPV6 || l3 == RTE_PTYPE_L3_IPV6_EXT) {
        unsigned l3_len = rte_be_to_cpu_16(l3_hdr->ipv6.payload_len);

        if (hdr_lens->l2_len + l3_len > rte_pktmbuf_data_len(m))
            goto end;

        if ((ol_flags & PKT_RX_IP_CKSUM_MASK) == PKT_RX_IP_CKSUM_UNKNOWN)
            ol_flags = PKT_RX_IP_CKSUM_NONE;

        if ((ol_flags & PKT_RX_L4_CKSUM_MASK) == PKT_RX_L4_CKSUM_UNKNOWN) {
            switch (l4) {
            case RTE_PTYPE_L4_UDP:
                if (l4_hdr->udp.dgram_cksum) {
                    uint16_t cksum = ~rte_ipv6_udptcp_cksum(&l3_hdr->ipv6,
                                                            l4_hdr);
                    ol_flags |= cksum ?
                                PKT_RX_L4_CKSUM_BAD : PKT_RX_L4_CKSUM_GOOD;
                } else {
                    ol_flags |= PKT_RX_L4_CKSUM_NONE;
                }
                break;

            case RTE_PTYPE_L4_TCP:
                if (l4_hdr->tcp.cksum) {
                    uint16_t cksum = ~rte_ipv6_udptcp_cksum(&l3_hdr->ipv6,
                                                            l4_hdr);
                    ol_flags |= cksum ?
                                PKT_RX_L4_CKSUM_BAD : PKT_RX_L4_CKSUM_GOOD;
                } else {
                    ol_flags |= PKT_RX_L4_CKSUM_NONE;
                }
                break;

            case RTE_PTYPE_L4_SCTP:
                /* XXX: not yet */
                break;

            default:
                break;
            }
        }
    }

    if (m->ol_flags != ol_flags)
        m->ol_flags = ol_flags;
 end:
    return ptype;
}

static void
set_ol_handlers(struct eng_port_s *port)
{
    if (port->netdev_type == ENG_NETDEV_TYPE_ETHDEV ||
        port->netdev_type == ENG_NETDEV_TYPE_BONDING) {
        struct rte_eth_dev_info dev_info;
        uint64_t cap;

        rte_eth_dev_info_get(port->port_id, &dev_info);

        port->tx_capa = dev_info.tx_offload_capa;
        cap = port->tx_capa & (DEV_TX_OFFLOAD_IPV4_CKSUM |
                               DEV_TX_OFFLOAD_UDP_CKSUM |
                               DEV_TX_OFFLOAD_TCP_CKSUM |
                               DEV_TX_OFFLOAD_SCTP_CKSUM);

        if (cap == (DEV_TX_OFFLOAD_IPV4_CKSUM |
                    DEV_TX_OFFLOAD_UDP_CKSUM |
                    DEV_TX_OFFLOAD_TCP_CKSUM |
                    DEV_TX_OFFLOAD_SCTP_CKSUM))
            port->tx_ol_handler = NULL;
        else {
            port->tx_ol_handler = tx_ol_handler_l3_l4_sw;
#if 1	/* XXX: VIRTIO PATCH */
            port->tx_capa = UINT64_C(0);
#endif
        }

        port->rx_capa = dev_info.rx_offload_capa;
        cap = port->rx_capa & DEV_RX_OFFLOAD_CHECKSUM;

        if (cap == DEV_RX_OFFLOAD_CHECKSUM)
            port->rx_ol_handler = NULL;
        else {
            port->rx_ol_handler = rx_ol_handler_no_offload;
#if 1	/* XXX: VIRTIO PATCH */
            port->rx_capa = UINT64_C(0);
#endif
        }
    }
}

/*****************************************************************************
 *	ether device
 *****************************************************************************/
static const char *netdev_type_name[ENG_NETDEV_TYPE_NB + 1] = {
    "invalid",
    "ethdev",
    "bonding",
    "kni",
    "null",
};

static inline const char *
netdev_type2str(enum eng_netdev_type_e type)
{
    if (type < ENG_NETDEV_TYPE_INVALID ||
        type >= ENG_NETDEV_TYPE_NB)
        type = ENG_NETDEV_TYPE_INVALID;
    return netdev_type_name[type + 1];
}

const char *
eng_netdev_type2str(enum eng_netdev_type_e type)
{
    return netdev_type2str(type);
}

enum eng_netdev_type_e
eng_netdev_type(uint16_t port_id)
{
    const struct eng_netdev_info_s *info = eng_port_find_netdev_info();
    if (info && port_id < RTE_MAX_ETHPORTS)
        return info[port_id].netdev_type;
    return ENG_NETDEV_TYPE_INVALID;
}

const struct eng_netdev_info_s *
eng_netdev_info(uint16_t port_id)
{
    const struct eng_netdev_info_s *info = eng_port_find_netdev_info();
    if (info && port_id < RTE_MAX_ETHPORTS)
        return &info[port_id];
    return NULL;
}

static enum eng_netdev_type_e
get_netdev_type(struct eng_conf_db_s *db,
                const char *name)
{
    const char *p = eng_conf_netdev_type(db, name);
    if (p) {
        for (enum eng_netdev_type_e type = 0;
             type < ENG_NETDEV_TYPE_NB;
             type++) {
            if (!strcmp(netdev_type2str(type), p)) {
                ENG_DEBUG(CORE, "found netdev type: %s", p);
                return type;
            }
        }
        ENG_ERR(CORE, "mismatched %s: %s", name, p);
    }
    return ENG_NETDEV_TYPE_INVALID;
}

/* netdev usage */
struct eng_netdev_usage_s {
    struct eng_netdev_info_s info[RTE_MAX_ETHPORTS];
    unsigned type_cnt[ENG_NETDEV_TYPE_NB];
    const struct rte_memzone *mz;
};

#define NETDEV_USEAGE_NAME	"NetdevUsage"

static struct eng_netdev_usage_s *
find_netdev_usage(void)
{
    const struct rte_memzone *mz;
    struct eng_netdev_usage_s *db = NULL;

    mz = rte_memzone_lookup(NETDEV_USEAGE_NAME);
    if (mz)
        db = mz->addr;
    return db;
}

const struct eng_netdev_info_s *
eng_port_find_netdev_info(void)
{
    struct eng_netdev_usage_s *usage = find_netdev_usage();

    if (usage)
        return usage->info;
    return NULL;
}

static struct eng_netdev_usage_s *
create_netdev_usage(void)
{
    struct eng_netdev_usage_s *db = find_netdev_usage();

    if (!db) {
        const struct rte_memzone *mz;

        mz = rte_memzone_reserve(NETDEV_USEAGE_NAME,
                                 sizeof(*db),
                                 rte_socket_id(),
                                 RTE_MEMZONE_1GB | RTE_MEMZONE_SIZE_HINT_ONLY);
        if (!mz)
            return NULL;
        db = mz->addr;
        memset(db, 0, sizeof(*db));
        db->mz = mz;
        for (unsigned i = 0; i < RTE_DIM(db->info); i++) {
            db->info[i].netdev_type = ENG_NETDEV_TYPE_INVALID;
            db->info[i].depend_port = ENG_PORT_INVALID_ID;
            db->info[i].sub = 0;
        }
    }
    return db;
}

static void
set_netdev_type(uint16_t port_id,
                uint16_t depend_port,
                enum eng_netdev_type_e type)
{
    if (rte_eth_dev_is_valid_port(port_id)) {
        struct eng_netdev_usage_s *usage = create_netdev_usage();
        if (usage) {
            usage->info[port_id].netdev_type = type;
            usage->info[port_id].depend_port = depend_port;

            if (rte_eth_dev_get_name_by_port(port_id,
                                             usage->info[port_id].port_name))
                usage->info[port_id].port_name[0] ='\0';

            if (depend_port == ENG_PORT_INVALID_ID) {
                usage->info[port_id].sub = usage->type_cnt[type];
                usage->type_cnt[type] += 1;
            } else if (rte_eth_dev_is_valid_port(depend_port)) {
                usage->info[port_id].sub = usage->info[depend_port].sub;
            }
        }
    } else {
        ENG_ERR(CORE, "invalid port_id:%u", port_id);
    }
}

static int
get_port_id_ethdev(struct eng_conf_db_s *db,
                   const char *name)
{
    uint16_t nb_dev = eng_eth_dev_count_avail();

    for (uint16_t i = 0; i < nb_dev; i++) {
        const char *p = eng_conf_netdev_id_name(db, i);

        if (p && !strcmp(p, name))
            return i;
    }
    ENG_NOTICE(CORE, "not found ethdev: %s", name);
    return -1;
}

static struct rte_mempool *
netdev_mbufpool(struct eng_conf_db_s *db,
                const char *name)
{
    return eng_mbufpool(db, eng_conf_netdev_mbufpool(db, name));
}

static inline int
set_mac_addr(struct eng_conf_db_s *db,
             const char *name,
             uint16_t id)
{
    struct ether_addr addr;
    int ret = 0;

    ret = eng_conf_netdev_mac(db, name, &addr);
    if (ret) {
        ENG_INFO(CORE, "use MAC in NIC");
        rte_eth_macaddr_get(id, &addr);
        ret = eng_conf_add_netdev_mac(db, name, &addr);
    } else {
        ret = rte_eth_dev_default_mac_addr_set(id, &addr);
        if (ret) {
            ENG_ERR(CORE, "failed rte_eth_dev_default_mac_addr_set(): %s",
                    name);
        }
    }

    return ret;
}

/*
 * common queue setup module
 */
static inline int
queue_setup(const char *name,
            uint16_t portid,
            int nb_rxq,
            int nb_txq,
            uint16_t nb_rxd,
            uint16_t nb_txd,
            const struct rte_eth_conf *port_conf,
            struct rte_mempool *mp)
{
    struct rte_eth_conf local_port_conf = *port_conf;
    int socketid = rte_eth_dev_socket_id(portid);
    int ret = -1;

    if (nb_rxq < 0)
        nb_rxq = 0;
    if (nb_txq < 0)
        nb_txq = 0;

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(portid, &dev_info);

    /*
     * made off offloads, not supported by device
     */
    local_port_conf.rxmode.offloads &= dev_info.rx_offload_capa;
    local_port_conf.txmode.offloads &= dev_info.tx_offload_capa;
    local_port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;

    {
        uint64_t rx_ol = local_port_conf.rxmode.offloads ^ port_conf->rxmode.offloads;
        uint64_t tx_ol = local_port_conf.txmode.offloads ^ port_conf->txmode.offloads;
        uint64_t rss_hf = local_port_conf.rx_adv_conf.rss_conf.rss_hf ^ port_conf->rx_adv_conf.rss_conf.rss_hf;

        /*
         * check offloads
         */
        if (rx_ol || tx_ol || rss_hf) {
            ENG_WARN(CORE, "warning: not enough offloads: %s(%u) Rx:%"PRIx64" Tx:%"PRIx64" RSS:%"PRIx64,
                     name, portid, rx_ol, tx_ol, rss_hf);
            /* not end */
        }
    }

    /*
     * add option
     */
    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
        local_port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

    ret = rte_eth_dev_configure(portid, nb_rxq, nb_txq, &local_port_conf);
    if (ret) {
        ENG_ERR(CORE, "failed eth dev confiure: %s(%u) nb_rxq:%d nb_txq:%d",
                name, portid, nb_rxq, nb_txq);
        goto end;
    }

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
    if (ret) {
        ENG_ERR(CORE, "failed eth dev adjust(): %s(%u) nb_rxd:%u nb_txd:%u",
                name, portid, nb_rxd, nb_txd);
        goto end;
     }

    {
        /* Rx setup */
        struct rte_eth_rxconf rxq_conf = dev_info.default_rxconf;
        rxq_conf.offloads = local_port_conf.rxmode.offloads;

        for (int q = 0; q < nb_rxq; q++) {
            ret = rte_eth_rx_queue_setup(portid, q, nb_rxd, socketid, &rxq_conf, mp);
            if (ret) {
                ENG_ERR(CORE, "failed Rx queue setup: %s(%u) q:%d des:%u offloads:%"PRIx64,
                        name, portid, q,
                        nb_rxd, rxq_conf.offloads);
                goto end;
            }
        }
    }

    {
        /* Tx setup */
        struct rte_eth_txconf txq_conf = dev_info.default_txconf;
        txq_conf.offloads = local_port_conf.txmode.offloads;

        for (int q = 0; q < nb_txq; q++) {
            ret = rte_eth_tx_queue_setup(portid, q, nb_txd, socketid, &txq_conf);
            if (ret) {
                ENG_ERR(CORE,
                        "failed Tx queue setup: %s(%u) q:%d des:%u offloads:%"PRIx64,
                        name, portid, q,
                        nb_rxd, txq_conf.offloads);
                goto end;
            }
        }
    }

 end:
    return ret;
}

static const struct rte_eth_conf PortConfEth = {
    .rxmode = {
        .mq_mode = ETH_MQ_RX_RSS,
        .max_rx_pkt_len = ETHER_MAX_LEN,
        .split_hdr_size = 0,
        .offloads = DEV_RX_OFFLOAD_CHECKSUM,

#ifndef ENABLE_DPDK1811
        .header_split   = 0, /**< Header Split disabled */
        .hw_ip_checksum = 1, /**< IP checksum offload enabled */
        .hw_vlan_filter = 0, /**< VLAN filtering disabled */
        .jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
        .hw_strip_crc   = 1, /**< CRC stripped by hardware */
#endif
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf =  (
                        ETH_RSS_IP   |
                        ETH_RSS_UDP  |
                        ETH_RSS_TCP
                        ),
        },
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
        .offloads = (
                     DEV_TX_OFFLOAD_IPV4_CKSUM |
                     DEV_TX_OFFLOAD_UDP_CKSUM |
                     DEV_TX_OFFLOAD_TCP_CKSUM
                     ),
    },
    .intr_conf = {
        .lsc = 1,
    },
};

/*
 *
 */
static int
create_netdev_ethdev(struct eng_conf_db_s *db,
                     const char *name)
{
    int id;

    id = get_port_id_ethdev(db, name);
    if (id < 0) {
        ENG_ERR(CORE, "not configured id ethdev: %s", name);
        goto err;
    }

    if (queue_setup(name, id,
                    eng_conf_netdev_nb_rx_queues(db, name),
                    eng_conf_netdev_nb_tx_queues(db, name),
                    RTE_RX_DESC_DEFAULT,
                    RTE_TX_DESC_DEFAULT,
                    &PortConfEth,
                    netdev_mbufpool(db, name)))
        goto err;

#if 1
    if (set_mac_addr(db, name, id))
        goto err;
#endif

    if (rte_eth_dev_start(id)) {
        ENG_ERR(CORE, "failed rte_eth_dev_start(): %s", name);
        goto err;
    }

    if (eng_conf_add_netdev_name_id(db, name, id, false))
        goto err;

    set_netdev_type(id, ENG_PORT_INVALID_ID,
                    ENG_NETDEV_TYPE_ETHDEV);
    return id;

 err:
    return -1;
}

#if 0
/*
 *
 */
static int
add_pci_devices(struct eng_conf_db_s *db)
{
    unsigned nb = eng_eth_dev_count_avail();
    int ret = 0;

    for (uint16_t i = 0; i < nb && ret; i++) {
        const char *name;

        name = find_netdev_name_by_id(db, i);
        if (name)
            ret = add_netdev_id(db, name, i, false);
        ret |= add_netdev_type(db, name,
                               netdev_type_name[ENG_NETDEV_TYPE_ETHDEV]);
    }

    if (ret)
        ENG_ERR(CORE, "failed to %s", __func__);
    return ret;
}
#endif

/*****************************************************************************
 *	bonding device
 *****************************************************************************/
#define BONDING_MODE_INVALID	7
#define BONDING_MODE_NB		BONDING_MODE_INVALID

static char *bonding_mode_name[] = {
    "round_robin",
    "active_backup",
    "balance",
    "broadcast",
    "8023ad",
    "tlb",
    "alb",
};

static unsigned
get_bonding_mode(struct eng_conf_db_s *db,
                 const char *name)
{
    unsigned mode;

    const char *p = eng_conf_bonding_mode(db, name);
    if (!p)
        return BONDING_MODE_INVALID;

    for (mode = BONDING_MODE_ROUND_ROBIN;
         mode < BONDING_MODE_NB;
         mode++) {
        if (!strcmp(bonding_mode_name[mode], p))
            return mode;
    }

    ENG_ERR(CORE, "mismatched bonding mode: %s", p);
    return BONDING_MODE_INVALID;
}

static const struct rte_eth_conf PortConfBond = {
    .rxmode = {
        .mq_mode = ETH_MQ_RX_RSS,
        .max_rx_pkt_len = ETHER_MAX_LEN,
        .split_hdr_size = 0,
        .offloads = DEV_RX_OFFLOAD_CHECKSUM,
#ifndef ENABLE_DPDK1811
        .header_split   = 0, /**< Header Split disabled */
        .hw_ip_checksum = 1, /**< IP checksum offload enabled */
        .hw_vlan_filter = 0, /**< VLAN filtering disabled */
        .jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
        .hw_strip_crc   = 1, /**< CRC stripped by hardware */
#endif
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf =  (
                        ETH_RSS_IP   |
                        ETH_RSS_UDP  |
                        ETH_RSS_TCP
                        ),
        },
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
        .offloads = (
                     DEV_TX_OFFLOAD_IPV4_CKSUM |
                     DEV_TX_OFFLOAD_UDP_CKSUM |
                     DEV_TX_OFFLOAD_TCP_CKSUM
                     ),
    },
    .intr_conf = {
        .lsc = 1,
    },
};

static int
create_netdev_bonding(struct eng_conf_db_s *db,
                      const char *name)
{
    const char *slaves[16];
    char buff[256];
    int nb_slaves;
    uint8_t socket_id;
    int id = -1;

    nb_slaves = eng_conf_bonding_slave_list(db, name,
                                                 slaves, RTE_DIM(slaves),
                                                 buff, sizeof(buff));
    if (nb_slaves <= 0) {
        ENG_ERR(CORE, "nothing valid slaves: %s", name);
        goto err;
    }

    for (int i = 0; i < nb_slaves; i++) {
        int slave_id = get_netdev(db, slaves[i]);

        if (slave_id < 0)
            goto err;
        socket_id = rte_eth_dev_socket_id(slave_id);
    }

    unsigned mode = get_bonding_mode(db, name);
    if (mode == BONDING_MODE_INVALID)
        goto err;

    {
        char key[128];

        snprintf(key, sizeof(key), "net_bonding_%s", name);
        id = rte_eth_bond_create(key, mode, socket_id);
        if (id < 0) {
            ENG_ERR(CORE, "failed rte_eth_bond_create(): %s", name);
            goto err;
        }
    }

    int msec = eng_conf_bondig_interval(db, name);
    if (msec >= 0) {
        if (rte_eth_bond_link_monitoring_set(id, msec)) {
            ENG_ERR(CORE, "failed rte_eth_bond_link_monitoring_set(): %s",
                    name);
            goto err;
        }
    }

    msec = eng_conf_bondig_downdelay(db, name);
    if (msec >= 0) {
        if (rte_eth_bond_link_down_prop_delay_set(id, msec)) {
            ENG_ERR(CORE, "failed rte_eth_bond_link_down_prop_delay_set(): %s",
                    name);
            goto err;
        }
    }

    msec = eng_conf_bondig_updelay(db, name);
    if (msec >= 0) {
        if (rte_eth_bond_link_up_prop_delay_set(id, msec)) {
            ENG_ERR(CORE, "failed rte_eth_bond_link_up_prop_delay_set(): %s",
                    name);
            goto err;
        }
    }

    for (int i = 0; i < nb_slaves; i++) {
        int slave_id = eng_conf_netdev_name_id(db, slaves[i], USE_ERR_LEVEL);

        if (slave_id < 0)
            goto err;

        if (rte_eth_bond_slave_add(id, slave_id)) {
            ENG_ERR(CORE, "failed rte_eth_bond_slave_add(): %s",
                    name);
            goto err;
        }
        if ((i == 0) && rte_eth_bond_primary_set(id, slave_id)) {
            ENG_ERR(CORE, "failed rte_eth_bond_primary_set(): %s",
                    name);
            goto err;
        }
        rte_eth_promiscuous_enable(slave_id);
    }


    if (queue_setup(name, id,
                    eng_conf_netdev_nb_rx_queues(db, name),
                    eng_conf_netdev_nb_tx_queues(db, name),
                    RTE_RX_DESC_DEFAULT,
                    RTE_TX_DESC_DEFAULT,
                    &PortConfBond,
                    netdev_mbufpool(db, name)))
        goto err;

    rte_eth_promiscuous_enable(id);
#if 1
    if (set_mac_addr(db, name, id))
        goto err;
#endif

    if (rte_eth_dev_start(id)) {
        ENG_ERR(CORE, "failed rte_eth_dev_start(): %s", name);
        goto err;
    }

    if (eng_conf_add_netdev_name_id(db, name, id, true))
        goto err;
    set_netdev_type(id, ENG_PORT_INVALID_ID,
                    ENG_NETDEV_TYPE_BONDING);
    return id;

 err:
    return -1;
}

/*****************************************************************************
 *	kni device
 *****************************************************************************/
static inline int
req_ioctl(int request,
          struct ifreq *ifr)
{
    int ret = -1;
    int fd = socket(AF_PACKET, SOCK_DGRAM, 0);

    if (fd >= 0) {
        ret = ioctl(fd, request, ifr);
        if (ret)
            ENG_ERR(CORE, "ioctl: %s request:%d", ifr->ifr_name, request);
        close(fd);
    } else {
        ENG_ERR(CORE, "socket: error");
    }
    return ret;
}

int
eng_set_kni_mac(const char *name,
                const struct ether_addr *mac)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "kni-%s", name);
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    rte_memcpy(&ifr.ifr_hwaddr.sa_data[0], mac, sizeof(*mac));

    return req_ioctl(SIOCSIFHWADDR, &ifr);
}

int
eng_set_kni_mtu(const char *name,
                uint16_t mtu)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "kni-%s", name);
    ifr.ifr_mtu = mtu;

    return req_ioctl(SIOCSIFMTU, &ifr);
}

int
eng_set_kni_flags(const char *name,
                  short req_flags,
                  int ope)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "kni-%s", name);

    int ret = req_ioctl(SIOCGIFFLAGS, &ifr);
    if (!ret) {
        if (ope)
            ifr.ifr_flags |= req_flags;
        else
            ifr.ifr_flags &= ~req_flags;

        ret = req_ioctl(SIOCSIFFLAGS, &ifr);
    } else {
        ENG_ERR(CORE, "%s: failed to get", __func__);
    }
    return ret;
}

static inline int
set_linux_if_mtu(const char *raw,
                 int depend_id)
{
    uint16_t mtu;

    if (depend_id < 0)
        mtu = ETHER_MTU;
    else
        rte_eth_dev_get_mtu(depend_id, &mtu);

    return eng_set_kni_mtu(raw, mtu);
}

static inline int
set_linux_if_mac(const char *raw,
                 uint16_t depend_id)
{
    struct ether_addr addr;

    rte_eth_macaddr_get(depend_id, &addr);
    return eng_set_kni_mac(raw, &addr);
}

static inline int
set_linux_if_flags(const char *raw,
                   short req_flags)
{
    return eng_set_kni_flags(raw, req_flags, 1);
}

static int
get_kni_port_id(const char *raw)
{
    uint16_t id;
    char name[128];

    snprintf(name, sizeof(name), "net_kni-%s", raw);
    if (rte_eth_dev_get_port_by_name(name, &id)) {
        char args[128];

        memset(args, 0, sizeof(args));
        if (rte_vdev_init(name, args)) {
            ENG_ERR(CORE, "failed rte_vdev_init: %s", raw);
            return -1;
        }
    }

    if (rte_eth_dev_get_port_by_name(name, &id)) {
        ENG_ERR(CORE, "failed rte_eth_dev_get_port_by_name: %s", name);
        return -1;
    }

    if (!rte_eth_dev_is_valid_port(id)) {
        ENG_ERR(CORE, "invalid port: %u", id);
        return -1;
    }

    return id;
}

static const struct rte_eth_conf PortConfNull = {
    /* all zero */
    0,
};

static int
create_netdev_kni(struct eng_conf_db_s *db,
                  const char *raw)
{
    const char *depend_dev;
    int depend_id = -1;
    int id;

    depend_dev = eng_conf_netdev_depend(db, raw);
    if (depend_dev) {
        depend_id = get_netdev(db, depend_dev);
        if (depend_id < 0)
            goto err;
    }

    id = get_kni_port_id(raw);
    if (id < 0)
        goto err;

    if (queue_setup(raw, id,
                    1, 1,
                    0, 0,
                    &PortConfNull,
                    netdev_mbufpool(db, raw)))
        goto err;

    if (rte_eth_dev_start(id)) {
        ENG_ERR(CORE, "failed rte_eth_dev_start(): %s", raw);
        goto err;
    }

#if 0
    /* cause fixed initialization liakage in DPDK */
    if (set_linux_if_mtu(raw, depend_id))
        goto err;
#endif

    if (depend_id >= 0) {
        if (set_linux_if_mac(raw, depend_id))
            goto err;
        if (set_linux_if_flags(raw, IFF_NOARP))
            goto err;
    } else {
        if (set_linux_if_flags(raw, (IFF_NOARP | IFF_UP)))
            goto err;
    }

    ENG_DEBUG(CORE, "started netdev: %s %u", raw, id);
    if (eng_conf_add_netdev_name_id(db, raw, id, true))
        goto err;

    uint16_t depend_port = ENG_PORT_INVALID_ID;
    if (depend_id >= 0)
        depend_port = depend_id;
    set_netdev_type(id, depend_port, ENG_NETDEV_TYPE_KNI);
    return id;

 err:
    return -1;
}

#if 0
/*****************************************************************************
 *	pcap device
 *****************************************************************************/
static int
create_netdev_pcap(struct eng_conf_db_s *db,
                   const char *name)
{
    (void) db;
    (void) name;
    return -1;
}
#endif

/*****************************************************************************
 *	null device
 *****************************************************************************/
static int
get_null_port_id(const char *raw)
{
    char name[128];
    uint16_t port_id;

    snprintf(name, sizeof(name), "net_null_%s", raw);
    if (rte_eth_dev_get_port_by_name(name, &port_id)) {
        char args[128];

        ENG_DEBUG(CORE, "dev_null: %s", raw);

        snprintf(args, sizeof(args), "size=%u,copy=0",
                 RTE_MBUF_DEFAULT_BUF_SIZE);

        if (rte_vdev_init(name, args)) {
            ENG_ERR(CORE, "failed rte_vdev_init: %s", raw);
            return -1;
        }
    }

    if (rte_eth_dev_get_port_by_name(name, &port_id)) {
        ENG_ERR(CORE, "failed rte_eth_dev_get_port_by_name: %s", name);
        return -1;
    }

    if (!rte_eth_dev_is_valid_port(port_id)) {
        ENG_ERR(CORE, "invalid port: %u", port_id);
        return -1;
    }

    return port_id;
}

static int
create_netdev_null(struct eng_conf_db_s *db,
                   const char *raw)
{
    int id;

    id = get_null_port_id(raw);
    if (id < 0)
        goto err;

    if (queue_setup(raw, id,
                    0, 1,	/* nothing Rx */
                    0, 0,
                    &PortConfNull,
                    NULL))
        goto err;

    if (rte_eth_dev_start(id)) {
        ENG_ERR(CORE, "failed rte_eth_dev_start(): %s", raw);
        goto err;
    }

    ENG_DEBUG(CORE, "started netdev: %s %u", raw, id);
    if (eng_conf_add_netdev_name_id(db, raw, id, true))
        goto err;

    set_netdev_type(id, ENG_PORT_INVALID_ID,
                    ENG_NETDEV_TYPE_NULL);
    return id;

 err:
    return -1;
}

static int
create_netdev(struct eng_conf_db_s *db,
              const char *name)
{
    int id;

    ENG_DEBUG(CORE, "creating netdev: %s", name);

    switch (get_netdev_type(db, name)) {
    case ENG_NETDEV_TYPE_ETHDEV:
        id = create_netdev_ethdev(db, name);
        break;

    case ENG_NETDEV_TYPE_BONDING:
        id = create_netdev_bonding(db, name);
        break;

    case ENG_NETDEV_TYPE_KNI:
        id = create_netdev_kni(db, name);
        break;

    case ENG_NETDEV_TYPE_NULL:
        id = create_netdev_null(db, name);
        break;

    case ENG_NETDEV_TYPE_INVALID:
    default:
        id = -1;
        break;
    }

    if (id < 0)
        ENG_ERR(CORE, "failed to create netdev: %s", name);
    else
        ENG_DEBUG(CORE, "created netdev: %s", name);
    return id;
}

static int
get_netdev(struct eng_conf_db_s *db,
           const char *name)
{
    int id;

    ENG_DEBUG(CORE, "getting netdev: %s", name);

    id = eng_conf_netdev_name_id(db, name, NOT_ERR_LEVEL);
    if (id < 0) {
        id = create_netdev(db, name);
        if (id < 0)
            ENG_ERR(CORE, "failed to get netdev: %s", name);
    }
    return id;
}

/*
 * return nb_slaves
 */
static int
get_netdev_slave_id(struct eng_conf_db_s *db,
                    const char *name,
                    uint16_t slave_id[],
                    int sz_slaves)
{
    switch (get_netdev_type(db, name)) {
    case ENG_NETDEV_TYPE_BONDING:
        {
            int n;
            const char *slaves[16];
            char buff[256];

            n = eng_conf_bonding_slave_list(db, name,
                                            slaves,
                                            RTE_DIM(slaves),
                                            buff,
                                            sizeof(buff));
            if (0 <= n && n <= sz_slaves) {
                for (int i = 0; i < n; i++)
                    slave_id[i] = get_netdev(db, slaves[i]);
                return n;
            }
        }
        return -1;

    case ENG_NETDEV_TYPE_KNI:
        {
            const char *depend;

            depend = eng_conf_netdev_depend(db, name);
            if (depend) {
                int id = get_netdev(db, depend);

                if (id < 0)
                    return -1;
                slave_id[0] = id;
                return 1;
            }
        }
        return 0;

    case ENG_NETDEV_TYPE_ETHDEV:
    case ENG_NETDEV_TYPE_NULL:
        return 0;

    case ENG_NETDEV_TYPE_INVALID:
    default:
        return -1;
    }

    return -1;
}

static struct eng_port_s *
create_port_pmd(struct eng_conf_db_s *db,
                const char *port_name,
                const char *dev_name,
                enum eng_port_dir_e dir)
{
    struct eng_port_s *port;
    int port_id;
    int nb_slaves;

    ENG_DEBUG(CORE, "creating port netdev: %s %s",
              port_name, dev_name);

    port_id = get_netdev(db, dev_name);
    if (port_id < 0)
        return NULL;

    port = rte_zmalloc_socket(port_name, sizeof(*port),
                              RTE_CACHE_LINE_SIZE,
                              rte_socket_id());
    if (!port) {
        ENG_ERR(CORE, "failed to alloc porn");
        return NULL;
    }

    snprintf(port->name, sizeof(port->name), "%s", port_name);

    port->op = NULL;
    port->dir = dir;
    port->port_id = port_id;
    port->netdev_type = get_netdev_type(db, dev_name);

    set_ol_handlers(port);
    nb_slaves = get_netdev_slave_id(db, dev_name,
                                    port->slaves, RTE_DIM(port->slaves));
    if (nb_slaves < 0)
        goto end;

    port->nb_slaves = nb_slaves;

    if (dir == ENG_PORT_DIR_IN) {
        struct rte_port_ethdev_reader_params params;
        struct rte_port_in_ops *ops = &rte_port_ethdev_reader_ops;

        int q_id = eng_conf_port_rx_queue(db, port_name);
        if (q_id < 0)
            goto end;

        port->ops.in = ops;
        port->queue_id = q_id;

        params.port_id = port->port_id;
        params.queue_id = q_id;
        port->op = ops->f_create(&params, rte_socket_id());
    } else {
        union {
            struct rte_port_ethdev_writer_params normal;
            struct rte_port_ethdev_writer_nodrop_params nodrop;
        } params;
        struct rte_port_out_ops *ops = NULL;

        int q_id = eng_conf_port_tx_queue(db, port_name);
        if (q_id < 0)
            goto end;

        int retries = eng_conf_port_retry(db, port_name);
        if (retries < 0) {
            params.normal.port_id = port->port_id;
            params.normal.queue_id = q_id;
            params.normal.tx_burst_sz = ENG_PORT_PMD_TX_BURST;

            ops = &rte_port_ethdev_writer_ops;
        } else {
            params.nodrop.port_id = port->port_id;
            params.nodrop.queue_id = q_id;
            params.nodrop.tx_burst_sz = ENG_PORT_PMD_TX_BURST;
            params.nodrop.n_retries = retries;	/* Zero: no limit */

            ops = &rte_port_ethdev_writer_nodrop_ops;
        }
        port->queue_id = q_id;
        port->ops.out = ops;
        port->op = ops->f_create(&params, rte_socket_id());
    }

 end:
    if (port->op == NULL) {
        ENG_ERR(CORE, "failed to create: %s", port_name);
        rte_free(port);
        port = NULL;
    } else {
        ENG_DEBUG(CORE, "created port: %s", port_name);
    }
    return port;
}

static struct rte_ring *
get_ring(struct eng_conf_db_s *db,
         const char *name)
{
    struct rte_ring *ring;

    while ((ring = rte_ring_lookup(name)) == NULL) {
        int size = eng_conf_ring_size(db, name);

        if (size <= 0)
            return NULL;

        ring = rte_ring_create(name, size,
                               rte_socket_id(), RING_F_SC_DEQ);
        if (!ring) {
            ENG_ERR(CORE, "failed to rte_ring_create(): %s", name);
            return NULL;
        } else {
            ENG_DEBUG(CORE, "created ring:%s", name);
        }
    }
    ENG_DEBUG(CORE, "found ring: %s", name);
    return ring;
}

static struct eng_port_s *
create_port_ring(struct eng_conf_db_s *db,
                 const char *port_name,
                 const char *ring_name,
                 enum eng_port_dir_e dir)
{
    struct rte_ring *ring;
    struct eng_port_s *port;

    ring = get_ring(db, ring_name);
    if (!ring)
        return NULL;

    port = rte_zmalloc_socket(port_name, sizeof(*port),
                              RTE_CACHE_LINE_SIZE,
                              rte_socket_id());
    if (!port) {
        ENG_ERR(CORE, "failed to alloc porn");
        return NULL;
    }

    snprintf(port->name, sizeof(port->name), "%s", port_name);

    port->dir = dir;
    port->port_id = ENG_PORT_INVALID_ID;
    port->queue_id = ENG_PORT_INVALID_ID;
    port->netdev_type = ENG_NETDEV_TYPE_INVALID;
    port->nb_slaves = 0;

    if (dir == ENG_PORT_DIR_IN) {
        struct rte_port_ring_reader_params params;
        struct rte_port_in_ops *ops = &rte_port_ring_reader_ops;

        port->ops.in = ops;

        params.ring = ring;
        port->op = ops->f_create(&params, rte_socket_id());
    } else {
        union {
            struct rte_port_ring_writer_params normal;
            struct rte_port_ring_writer_nodrop_params nodrop;
        } params;
        struct rte_port_out_ops *ops = NULL;
        int retries = eng_conf_port_retry(db, port_name);

        if (retries < 0) {
            params.normal.ring = ring;
            params.normal.tx_burst_sz = 16;

            ops = &rte_port_ring_multi_writer_ops;
        } else {
            params.nodrop.ring = ring;
            params.nodrop.tx_burst_sz = 16;
            params.nodrop.n_retries = retries;

            ops = &rte_port_ring_multi_writer_nodrop_ops;
        }
        port->ops.out = ops;
        port->op = ops->f_create(&params, rte_socket_id());
    }

    if (port->op == NULL) {
        ENG_ERR(CORE, "failed to create: %s", port_name);
        rte_free(port);
        port = NULL;
    } else {
        ENG_DEBUG(CORE, "created port: %s", port_name);
    }
    return port;
}

static enum eng_port_type_e
get_port_type(const char *depend)
{
    const char *type_name[ENG_PORT_TYPE_INVALID] = {
        "netdev",
        "ring",
    };
    char key[128];
    char *p;

    p = strchr(depend, '/');
    if (!p)
        return ENG_PORT_TYPE_INVALID;
    snprintf(key, sizeof(key), "%s", ++p);
    p = strchr(key, '/');
    if (p)
        *p = '\0';

    for (enum eng_port_type_e type = ENG_PORT_TYPE_PMD;
         type < ENG_PORT_TYPE_INVALID;
         type++) {
        if (!strcmp(type_name[type], key)) {
            ENG_DEBUG(CORE, "found port type: %s", key);
            return type;
        }
    }

    ENG_ERR(CORE, "mismatched port type: %s", key);
    return ENG_PORT_TYPE_INVALID;
}

static struct eng_port_s *
port_create(struct eng_conf_db_s *db,
            const char *name,
            bool is_in)
{
    const char *depend = eng_conf_port_depend(db, name);
    if (!depend)
        return NULL;

    enum eng_port_type_e type = get_port_type(depend);

    depend = strrchr(depend, '/');
    if (!depend) {
        ENG_ERR(CORE, "invalid port depend: %s", name);
        return NULL;
    }
    depend++;
    switch (type) {
    case ENG_PORT_TYPE_PMD:
        return create_port_pmd(db, name, depend, is_in);

    case ENG_PORT_TYPE_RING:
        return create_port_ring(db, name, depend, is_in);

    case ENG_PORT_TYPE_INVALID:
    default:
        return NULL;
    }
    return NULL;
}

struct eng_port_s *
eng_port_in_create(struct eng_conf_db_s *db,
                   const char *name)
{
    return port_create(db, name, ENG_PORT_DIR_IN);
}

struct eng_port_s *
eng_port_out_create(struct eng_conf_db_s *db,
                    const char *name)
{
    return port_create(db, name, ENG_PORT_DIR_OUT);
}

/*
 * for DPDK18.11 ready
 */
uint16_t
eng_eth_dev_count_avail(void)
{
#if 1	/* after DPDK v1811 */
    return rte_eth_dev_count_avail();
#else
    return rte_eth_dev_count();
#endif
}
