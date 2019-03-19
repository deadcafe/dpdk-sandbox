#include <immintrin.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>

#include <rte_spinlock.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_hash_crc.h>

#include <eng_thread.h>
#include <eng_addon.h>

#include "app_modules.h"
#include "global_db.h"
#include "task_rx.h"
#include "app_mbuf.h"
#include "mbuf_ext.h"
#include "eng_gtp.h"

/****************************************************************************
 * Rx task
 ****************************************************************************/

#define RX_BURST_SIZE	32	/* 2 ~ 32 */
#define NB_CLASS	8

struct qos_queue_s {
    uint8_t num[NB_CLASS];
    struct rte_mbuf *queue[RX_BURST_SIZE][NB_CLASS];
};

static struct qos_queue_s *
qos_queue_create(unsigned socket)
{
    return rte_zmalloc_socket("QoS q", sizeof(struct qos_queue_s),
                              RTE_CACHE_LINE_SIZE,
                              socket);
}

static inline void
qos_queue_enqueue(struct qos_queue_s *que,
                  struct rte_mbuf *m,
                  unsigned class)
{
    unsigned p = que->num[class];

    que->queue[p][class] = m;
    que->num[class] += 1;
}

static inline unsigned
qos_queue_dequeue(struct qos_queue_s *que,
                  unsigned sz __rte_unused,
                  struct rte_mbuf **buff)
{
    unsigned nb = 0;
    for (unsigned i = 0; i < 8; i++) {
        for (unsigned j = 0; j < que->num[i]; j++)
            buff[nb++] = que->queue[j][i];
        que->num[i] = 0;
    }
    return nb;
}

struct private_s {
    struct qos_queue_s *qos_queue;
    uint64_t cnt;
};

static unsigned NB_RX_TASKS;

static int
RxTaskInit(struct eng_conf_db_s *conf __rte_unused,
           struct eng_thread_s *th,
           struct eng_task_s *task)
{
    int ret = 0;

    ENG_ERR(TASKRX, "lcore:%u", th->lcore_id);
    struct private_s *priv = (struct private_s *) task->private_area;

    priv->cnt = 0;
    priv->qos_queue = qos_queue_create(rte_lcore_to_socket_id(th->lcore_id));

    ret = app_global_db_add_task(task);
    if (!ret)
        task->task_id = NB_RX_TASKS++;

    ENG_ERR(TASKRX, "end. ret:%d", ret);
    return ret;
}

static char Sentinel[1024] __rte_cache_aligned;

static inline void
prefetch_mbuf(struct rte_mbuf *m)
{
#if 1
    rte_prefetch0(m);
#if 1
    struct mbuf_ext_s *ext = eng_mbuf2ext(m);
    rte_prefetch0(ext);
    rte_prefetch0((char *)(ext + 1) + RTE_PKTMBUF_HEADROOM);
#endif

#else
    (void) m;
#endif
}

static inline uint32_t
ipv4_hash(uint32_t hash,
          struct rte_mbuf *m,
          unsigned offset)
{
    const struct ipv4_hdr *ipv4_hd;
    struct ipv4_hdr ipv4;

    ipv4_hd = rte_pktmbuf_read(m, offset, sizeof(ipv4), &ipv4);
    hash = rte_hash_crc_4byte(ipv4_hd->src_addr, hash);
    return rte_hash_crc_4byte(ipv4_hd->dst_addr, hash);
}

static inline uint32_t
ipv6_hash(uint32_t hash,
          struct rte_mbuf *m,
          unsigned offset)
{
    const struct ipv6_hdr *ipv6_hd;
    struct ipv6_hdr ipv6;

    ipv6_hd = rte_pktmbuf_read(m, offset, sizeof(ipv6), &ipv6);
    const uint64_t *s = (const uint64_t *) ipv6_hd->src_addr;
    const uint64_t *d = (const uint64_t *) ipv6_hd->dst_addr;

    hash = rte_hash_crc_8byte(*(s + 0), hash);
    hash = rte_hash_crc_8byte(*(s + 1), hash);
    hash = rte_hash_crc_8byte(*(d + 0), hash);
    hash = rte_hash_crc_8byte(*(d + 1), hash);
    return hash;
}

static inline uint32_t
tcp_hash(uint32_t hash,
         struct rte_mbuf *m,
         unsigned offset)
{
    const struct tcp_hdr *tcp_hd;
    struct tcp_hdr tcp;

    tcp_hd = rte_pktmbuf_read(m, offset, sizeof(tcp), &tcp);
    hash = rte_hash_crc_2byte(tcp_hd->src_port, hash);
    hash = rte_hash_crc_2byte(tcp_hd->dst_port, hash);
    return hash;
}

static inline uint32_t
udp_hash(uint32_t hash,
         struct rte_mbuf *m,
         unsigned offset)
{
    const struct udp_hdr *udp_hd;
    struct udp_hdr udp;

    udp_hd = rte_pktmbuf_read(m, offset, sizeof(udp), &udp);
    hash = rte_hash_crc_2byte(udp_hd->src_port, hash);
    hash = rte_hash_crc_2byte(udp_hd->dst_port, hash);
    return hash;
}

static inline uint32_t
sctp_hash(uint32_t hash,
          struct rte_mbuf *m,
          unsigned offset)
{
    const struct sctp_hdr *sctp_hd;
    struct sctp_hdr sctp;

    sctp_hd = rte_pktmbuf_read(m, offset, sizeof(sctp), &sctp);
    hash = rte_hash_crc_2byte(sctp_hd->src_port, hash);
    hash = rte_hash_crc_2byte(sctp_hd->dst_port, hash);
    return hash;
}

static inline struct eng_port_s *
get_next_hop(struct eng_task_s *task,
             struct rte_mbuf *m)
{
    struct eng_port_s *next_hop = task->out_ports[(m->hash.rss % task->nb_out_ports)];
    return next_hop;
}

static inline uint32_t
calc_rss_hash(struct rte_mbuf *m)
{
    uint32_t hash = 0;

#if 1
    struct mbuf_ext_s *ext = eng_mbuf2ext(m);
    const struct rte_net_hdr_lens *hdr_lens = &ext->hdr_lens;
    uint32_t ptype = m->packet_type;

    if ((ptype & RTE_PTYPE_TUNNEL_MASK) == RTE_PTYPE_TUNNEL_GTPU) {
        unsigned offset =  hdr_lens->l2_len +
                           hdr_lens->l3_len +
                           hdr_lens->l4_len +
                           hdr_lens->tunnel_len +
                           hdr_lens->inner_l2_len;
        switch (ptype & RTE_PTYPE_INNER_L3_MASK) {
        case RTE_PTYPE_INNER_L3_IPV4:
            hash = ipv4_hash(hash, m, offset);
            break;

        case RTE_PTYPE_INNER_L3_IPV6:
            hash = ipv6_hash(hash, m, offset);
            break;

        default:
            goto end;
        }

        offset += hdr_lens->inner_l3_len;
        switch (ptype & RTE_PTYPE_INNER_L4_MASK) {
        case RTE_PTYPE_INNER_L4_TCP:
            hash = tcp_hash(hash, m, offset);
            break;

        case RTE_PTYPE_INNER_L4_UDP:
            hash = udp_hash(hash, m, offset);
            break;

        case RTE_PTYPE_INNER_L4_SCTP:
            hash = sctp_hash(hash, m, offset);
            break;

        default:
            goto end;
        }

    } else {
        unsigned offset =  hdr_lens->l2_len;

        switch (ptype & RTE_PTYPE_L3_MASK) {
        case RTE_PTYPE_L3_IPV4:
            hash = ipv4_hash(hash, m, offset);
            break;

        case RTE_PTYPE_L3_IPV6:
            hash = ipv6_hash(hash, m, offset);
            break;

        default:
            goto end;
        }

        offset += hdr_lens->l3_len;
        switch (ptype & RTE_PTYPE_L4_MASK) {
        case RTE_PTYPE_L4_TCP:
            hash = tcp_hash(hash, m, offset);
            break;

        case RTE_PTYPE_L4_UDP:
            hash = udp_hash(hash, m, offset);
            break;

        case RTE_PTYPE_L4_SCTP:
            hash = sctp_hash(hash, m, offset);
            break;

        default:
            goto end;
        }
    }
 end:
#endif

    m->hash.rss = hash;
    return hash;
}

static inline uint32_t
ptype_inner_l3_ipv4(uint8_t ipv_ihl)
{
    uint32_t ptype;

    switch (ipv_ihl) {
    case 0x45:
        ptype = RTE_PTYPE_INNER_L3_IPV4;
        break;

    case 0x46 ... 0x4f:
        ptype = RTE_PTYPE_INNER_L3_IPV4_EXT;
        break;

    default:
        ptype = 0;
        break;
    }
    return ptype;
}

static inline uint32_t
ptype_inner_l3_ipv6(uint8_t ip6_proto)
{
    uint32_t ptype;

    switch (ip6_proto) {
    case IPPROTO_HOPOPTS:
    case IPPROTO_ROUTING:
    case IPPROTO_FRAGMENT:
    case IPPROTO_ESP:
    case IPPROTO_AH:
    case IPPROTO_DSTOPTS:
        ptype = RTE_PTYPE_INNER_L3_IPV6_EXT;
        break;

    default:
        ptype = RTE_PTYPE_INNER_L3_IPV6;
        break;
    }
    return ptype;
}

static inline uint32_t
ptype_inner_l4(uint8_t proto)
{
    uint32_t ptype;

    switch (proto) {
    case IPPROTO_UDP:
        ptype = RTE_PTYPE_INNER_L4_UDP;
        break;

    case IPPROTO_TCP:
        ptype = RTE_PTYPE_INNER_L4_TCP;
        break;

    case IPPROTO_SCTP:
        ptype = RTE_PTYPE_INNER_L4_SCTP;
        break;

    default:
        ptype = 0;
        break;
    }
    return ptype;
}

static inline uint32_t
ptype_tunnel_gtp(uint16_t proto,
                 const struct rte_mbuf *m,
                 uint32_t off,
                 struct rte_net_hdr_lens *hdr_lens)
{
    uint32_t pkt_type = 0;
    char headers[64];

    hdr_lens->inner_l2_len = 0;
    if (proto == RTE_BE16(ETHER_TYPE_IPv4)) {
        const struct ipv4_hdr *ip4h;

        ip4h = rte_pktmbuf_read(m, off, sizeof(*ip4h), headers);
        if (unlikely(ip4h == NULL))
            return pkt_type;

        pkt_type |= ptype_inner_l3_ipv4(ip4h->version_ihl);
        hdr_lens->inner_l3_len = (ip4h->version_ihl & 0xf) * 4;
        off += hdr_lens->inner_l3_len;

        if (ip4h->fragment_offset &
            RTE_BE16(IPV4_HDR_OFFSET_MASK | IPV4_HDR_MF_FLAG)) {
            pkt_type |= RTE_PTYPE_INNER_L4_FRAG;
            hdr_lens->inner_l4_len = 0;
            return pkt_type;
        }
        proto = ip4h->next_proto_id;
        pkt_type |= ptype_inner_l4(proto);
    } else if (proto == RTE_BE16(ETHER_TYPE_IPv6)) {
        const struct ipv6_hdr *ip6h;
        int frag = 0;

        ip6h = rte_pktmbuf_read(m, off, sizeof(*ip6h), headers);
        if (unlikely(ip6h == NULL))
            return pkt_type;

        proto = ip6h->proto;
        hdr_lens->inner_l3_len = sizeof(*ip6h);
        off += hdr_lens->inner_l3_len;
        pkt_type |= ptype_inner_l3_ipv6(proto);
        if ((pkt_type & RTE_PTYPE_INNER_L3_MASK) == RTE_PTYPE_INNER_L3_IPV6_EXT) {
#if 0
            uint32_t prev_off;

            prev_off = off;
            ret = rte_net_skip_ip6_ext(proto, m, &off, &frag);
            if (ret < 0)
                return pkt_type;
            proto = ret;
            hdr_lens->inner_l3_len += off - prev_off;
#endif
        }
        if (proto == 0)
            return pkt_type;

        if (frag) {
            pkt_type |= RTE_PTYPE_INNER_L4_FRAG;
            hdr_lens->inner_l4_len = 0;
            return pkt_type;
        }
        pkt_type |= ptype_inner_l4(proto);
    }

    if ((pkt_type & RTE_PTYPE_INNER_L4_MASK) == RTE_PTYPE_INNER_L4_UDP) {
        hdr_lens->inner_l4_len = sizeof(struct udp_hdr);
    } else if ((pkt_type & RTE_PTYPE_INNER_L4_MASK) ==
               RTE_PTYPE_INNER_L4_TCP) {
        const struct tcp_hdr *th;

        th = rte_pktmbuf_read(m, off, sizeof(*th), headers);
        if (unlikely(th == NULL))
            return pkt_type &
                (RTE_PTYPE_INNER_L2_MASK | RTE_PTYPE_INNER_L3_MASK);
        hdr_lens->inner_l4_len = (th->data_off & 0xf0) >> 2;
    } else if ((pkt_type & RTE_PTYPE_INNER_L4_MASK) == RTE_PTYPE_INNER_L4_SCTP) {
        hdr_lens->inner_l4_len = sizeof(struct sctp_hdr);
    } else {
        hdr_lens->inner_l4_len = 0;
    }

    return pkt_type;
}

static inline uint32_t
parse_header(struct rte_mbuf *m)
{
    uint32_t ptype;
    struct mbuf_ext_s *ext = eng_mbuf2ext(m);
    struct rte_net_hdr_lens *hdrs = &ext->hdr_lens;

    memset(hdrs, 0, sizeof(*hdrs));
    ptype = rte_net_get_ptype(m, hdrs, RTE_PTYPE_ALL_MASK);
    if ((ptype & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_UDP) {
        unsigned offset = hdrs->l2_len + hdrs->l3_len;
        const struct udp_hdr *udp_hd;
        char headers[64];

        udp_hd = rte_pktmbuf_read(m, offset, sizeof(*udp_hd), headers);
        if (udp_hd->dst_port == RTE_BE16(GTPU_PORT)) {
            const struct rte_flow_item_gtp *gtp_hd;

            offset += hdrs->l4_len;
            gtp_hd = rte_pktmbuf_read(m, offset, sizeof(*gtp_hd), headers);
            if (likely(gtp_hd)) {
                /* XXX not length check */

                ptype |= RTE_PTYPE_TUNNEL_GTPU;
                hdrs->tunnel_len += sizeof(*gtp_hd);
                offset += sizeof(*gtp_hd);

                ptype |= ptype_tunnel_gtp(RTE_BE16(ETHER_TYPE_IPv4),
                                          m,
                                          offset,
                                          hdrs);
            }
        }
    }

    return ptype;
}

static inline unsigned
get_qos_class(struct rte_mbuf *m)
{
    struct mbuf_ext_s *ext = eng_mbuf2ext(m);
    struct rte_net_hdr_lens *hdrs = &ext->hdr_lens;
    const struct ipv4_hdr *ipv4_hd;
    struct ipv4_hdr ipv4;
    unsigned class = 0;

    ipv4_hd = rte_pktmbuf_read(m, hdrs->l2_len, sizeof(*ipv4_hd), &ipv4);
    if (ipv4_hd) {
        class = (ipv4_hd->type_of_service >> 2) & 7;
    }
    return class;
}

static unsigned
RxTaskEntry(struct eng_thread_s *th __rte_unused,
            struct eng_task_s *task,
            uint64_t now __rte_unused)
{
    struct private_s *priv = (struct private_s *) task->private_area;
    struct rte_mbuf *buff[RX_BURST_SIZE + 4];
    unsigned nb_pkt;

    nb_pkt = eng_port_recv(task->in_port, buff, RTE_DIM(buff) - 4);
    if (nb_pkt) {
        buff[nb_pkt + 0] = (struct rte_mbuf *) &Sentinel;
        buff[nb_pkt + 1] = (struct rte_mbuf *) &Sentinel;
        buff[nb_pkt + 2] = (struct rte_mbuf *) &Sentinel;
        buff[nb_pkt + 3] = (struct rte_mbuf *) &Sentinel;

        prefetch_mbuf(buff[0]);
        prefetch_mbuf(buff[1]);

        unsigned idx = 0;
        switch (nb_pkt % 2) {
        case 0:
            while (idx < nb_pkt) {
                unsigned class;
                struct rte_mbuf *m;

                m = buff[idx];
                m->packet_type = parse_header(m);
                m->hash.rss = calc_rss_hash(m);
                class = get_qos_class(m);
                qos_queue_enqueue(priv->qos_queue, m, class);
                idx++;

                prefetch_mbuf(buff[idx + 1]);

                /* fall-through */
        case 1:
                m = buff[idx];
                m->packet_type = parse_header(m);
                m->hash.rss = calc_rss_hash(m);
                class = get_qos_class(m);
                qos_queue_enqueue(priv->qos_queue, m, class);
                idx++;

                prefetch_mbuf(buff[idx + 1]);

                /* fall-through */
            }
        }

        nb_pkt = qos_queue_dequeue(priv->qos_queue, RX_BURST_SIZE, buff);
        rte_prefetch0(buff[0]);
        rte_prefetch0(buff[1]);
        rte_prefetch0(buff[2]);
        rte_prefetch0(buff[3]);

        idx = 0;

        switch (nb_pkt % 4) {
        case 0:
            while (idx < nb_pkt) {
                struct eng_port_s *next_hop;
                struct rte_mbuf *m;

                rte_prefetch0(buff[idx + 4]);
                m = buff[idx];
                next_hop = get_next_hop(task, m);
                eng_port_send(next_hop, m);
                idx++;
                /* fall-through */
        case 1:
                rte_prefetch0(buff[idx + 4]);
                m = buff[idx];
                next_hop = get_next_hop(task, m);
                eng_port_send(next_hop, m);
                idx++;
                /* fall-through */
        case 2:
                rte_prefetch0(buff[idx + 4]);
                m = buff[idx];
                next_hop = get_next_hop(task, m);
                eng_port_send(next_hop, m);
                idx++;
                /* fall-through */
        case 3:
                rte_prefetch0(buff[idx + 4]);
                m = buff[idx];
                next_hop = get_next_hop(task, m);
                eng_port_send(next_hop, m);
                idx++;
                /* fall-through */
            }
        }
    }
    return nb_pkt;
}

/*
 *
 */
static const struct eng_addon_s Addon = {
    .name       = "TkRx",
    .task_init  = RxTaskInit,
    .task_entry = RxTaskEntry,
};

static struct eng_addon_constructor_s AddonConstructor = {
    .addon = &Addon,
};

void
app_task_rx_register(void)
{
    eng_addon_register(&AddonConstructor);
}
