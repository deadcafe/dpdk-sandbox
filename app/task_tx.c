#include <immintrin.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>

#include <rte_spinlock.h>
#include <rte_malloc.h>
#include <rte_net.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_ether.h>
#include <rte_byteorder.h>

#include <eng_thread.h>
#include <eng_addon.h>

#include "app_modules.h"
#include "global_db.h"
#include "task_tx.h"
#include "app_mbuf.h"
#include "mbuf_ext.h"
#include "eng_gtp.h"

/****************************************************************************
 * Tx task
 ****************************************************************************/


struct base_frame_s {
    struct ether_hdr eth_hd;
    struct ipv4_hdr ip_hd;
    struct udp_hdr udp_hd;
    struct rte_flow_item_gtp gtp_hd;
    struct ipv4_hdr ip_hd_inner;
    struct udp_hdr udp_hd_inner;
    uint8_t body[16 + 2 + 32 + 128];
} __attribute__((packed));

static void xxx(void) __attribute__((constructor));


static void
xxx(void)
{
    printf("Frame size %zu\n", sizeof(struct base_frame_s));
}


struct private_s {
    struct base_frame_s *base;
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t tos;
};

static unsigned NB_TX_TASKS;

#define IP_DEFTTL  64   /* from RFC 1340. */
#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)

#define MY_IP_ADDR	0x01020304
#define PEER_IP_ADDR	0x05060708

#define TEID	0x33445566



static int
TxTaskInit(struct eng_conf_db_s *conf __rte_unused,
           struct eng_thread_s *th __rte_unused,
           struct eng_task_s *task)
{
    int ret;

    ENG_ERR(TASKTX, "lcore:%u", th->lcore_id);
    struct private_s *priv = (struct private_s *) task->private_area;

    priv->base = rte_zmalloc("FrameBase", sizeof(*(priv->base)),
                             RTE_CACHE_LINE_SIZE);
    if (!priv->base) {
        ret = -ENOMEM;
        goto end;
    }

    uint16_t len = sizeof(priv->base->body);
    for (unsigned i = 0; i < len; i++)
        priv->base->body[i] = (i + 1) & 15;

    len += sizeof(priv->base->udp_hd_inner);
    priv->base->udp_hd_inner.src_port    = 0;
    priv->base->udp_hd_inner.dst_port    = 0;
    priv->base->udp_hd_inner.dgram_len   = rte_cpu_to_be_16(len);
    priv->base->udp_hd_inner.dgram_cksum = 0;

    len += sizeof(priv->base->ip_hd_inner);
    priv->base->ip_hd_inner.version_ihl     = IP_VHL_DEF;
    priv->base->ip_hd_inner.type_of_service = 0;
    priv->base->ip_hd_inner.fragment_offset = 0;
    priv->base->ip_hd_inner.time_to_live    = IP_DEFTTL;
    priv->base->ip_hd_inner.next_proto_id   = IPPROTO_UDP;
    priv->base->ip_hd_inner.packet_id       = 0;
    priv->base->ip_hd_inner.src_addr        = 0;
    priv->base->ip_hd_inner.dst_addr        = 0;

    len += sizeof(priv->base->gtp_hd);
    priv->base->gtp_hd.v_pt_rsv_flags = 0;
    priv->base->gtp_hd.msg_type = 0;
    priv->base->gtp_hd.msg_len  = rte_cpu_to_be_16(len);
    priv->base->gtp_hd.teid     = rte_cpu_to_be_32(TEID);

    len += sizeof(priv->base->udp_hd);
    priv->base->udp_hd.src_port    = rte_cpu_to_be_16(8888);
    priv->base->udp_hd.dst_port    = rte_cpu_to_be_16(GTPU_PORT);
    priv->base->udp_hd.dgram_len   = rte_cpu_to_be_16(len);
    priv->base->udp_hd.dgram_cksum = 0;

    len += sizeof(priv->base->ip_hd);
    priv->base->ip_hd.version_ihl     = IP_VHL_DEF;
    priv->base->ip_hd.type_of_service = 0;
    priv->base->ip_hd.fragment_offset = 0;
    priv->base->ip_hd.time_to_live    = IP_DEFTTL;
    priv->base->ip_hd.next_proto_id   = IPPROTO_UDP;
    priv->base->ip_hd.packet_id       = 0;
    priv->base->ip_hd.src_addr        = rte_cpu_to_be_32(PEER_IP_ADDR);
    priv->base->ip_hd.dst_addr        = rte_cpu_to_be_32(MY_IP_ADDR);
    priv->base->ip_hd.total_length    = rte_cpu_to_be_16(len);
    priv->base->ip_hd.hdr_checksum    = 0;

    len += sizeof(priv->base->eth_hd);
    eth_random_addr(priv->base->eth_hd.d_addr.addr_bytes);
    eth_random_addr(priv->base->eth_hd.s_addr.addr_bytes);
    priv->base->eth_hd.ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    priv->src_addr = rte_rand();
    priv->dst_addr = rte_rand();
    priv->src_port = rte_rand();
    priv->dst_port = rte_rand();
    priv->tos      = rte_rand();

    ret = app_global_db_add_task(task);
 end:
    if (!ret)
        task->task_id = NB_TX_TASKS++;
    ENG_ERR(TASKTX, "end. ret:%d", ret);
    return ret;
}

static inline void
prefetch_mbuf(struct rte_mbuf *m)
{
    struct mbuf_ext_s *ext = eng_mbuf2ext(m);

    rte_prefetch0(m);
    rte_prefetch0((char *)(ext + 1) + RTE_PKTMBUF_HEADROOM);
    rte_prefetch0((char *)(ext + 1) + RTE_PKTMBUF_HEADROOM + RTE_CACHE_LINE_SIZE);
}

static void
clflushopt_raw(volatile void *p)
{
#if 0
    asm volatile (".byte 0x66, 0x0f, 0xae, 0x3b" : : "b" p);
#else
    asm volatile (".byte 0x66; clflush %P0" : "+m" (*(volatile char *) p));
#endif
}

static void
nop(volatile void *p __rte_unused)
{
    ;
}

static void (*clflushopt)(volatile void *) = nop;

RTE_INIT(reg_clflushopt)
{
    FILE *fp = fopen("/proc/cpuinfo", "r");

    if (fp) {
        char buff[256];

        while (fgets(buff, sizeof(buff), fp) != NULL) {

            buff[255] = '\0';
            if (strstr(buff, "clflushopt")) {
                clflushopt = clflushopt_raw;
                break;
            }
        }
        fclose(fp);
    }

    if (clflushopt == nop)
        fprintf(stderr, "No CLFLUSHOPT\n");
    else
        fprintf(stderr, "Yes CLFLUSHOPT\n");
}

static inline void
clflush_mbuf(struct rte_mbuf *m)
{
    struct mbuf_ext_s *ext = eng_mbuf2ext(m);

   clflushopt(m);
   clflushopt((char *)(ext + 1) + RTE_PKTMBUF_HEADROOM);
   clflushopt((char *)(ext + 1) + RTE_PKTMBUF_HEADROOM + RTE_CACHE_LINE_SIZE);
}


static void
send_frame(struct eng_task_s *task,
           struct rte_mbuf **mbufs,
           const unsigned nb_mbufs)
{
    struct private_s *priv = (struct private_s *) task->private_area;

    /*
     * nb_mbufs := 2 * n (MUST)
     */
    prefetch_mbuf(mbufs[0]);
    prefetch_mbuf(mbufs[1]);

    unsigned idx = 0;

    switch (nb_mbufs % 2) {
    case 0:
        while (idx < nb_mbufs) {
            struct rte_mbuf *m;
            struct base_frame_s *f;

            m = mbufs[idx];
            MBUF_RAW_ALLOC_CHECK(m);
            rte_pktmbuf_reset(m);

            f = (struct base_frame_s *) rte_pktmbuf_append(m, sizeof(*f));
            rte_memcpy(f, priv->base, sizeof(*f));
            f->ip_hd.type_of_service = (priv->tos++ & 7) << 2;
            f->ip_hd_inner.src_addr  = priv->src_addr++;
            f->ip_hd_inner.dst_addr  = priv->dst_addr++;
            f->udp_hd_inner.src_port = priv->src_port++;
            f->udp_hd_inner.dst_port = priv->dst_port++;

            clflush_mbuf(m);
            eng_port_send(task->out_ports[0], m);
            idx++;
            prefetch_mbuf(mbufs[idx + 1]);

            /* fall-through */
    case 1:
            m = mbufs[idx];
            MBUF_RAW_ALLOC_CHECK(m);
            rte_pktmbuf_reset(m);

            f = (struct base_frame_s *) rte_pktmbuf_append(m, sizeof(*f));
            rte_memcpy(f, priv->base, sizeof(*f));
            f->ip_hd.type_of_service = (priv->tos++ & 7) << 2;
            f->ip_hd_inner.src_addr  = priv->src_addr++;
            f->ip_hd_inner.dst_addr  = priv->dst_addr++;
            f->udp_hd_inner.src_port = priv->src_port++;
            f->udp_hd_inner.dst_port = priv->dst_port++;

            clflush_mbuf(m);
            eng_port_send(task->out_ports[0], m);
            idx++;
            prefetch_mbuf(mbufs[idx + 1]);

            /* fall-through */
        }
    }
}

static char Sentinel[1024] __rte_cache_aligned;

static unsigned
TxTaskEntry(struct eng_thread_s *th,
            struct eng_task_s *task,
            uint64_t now __rte_unused)
{
#define TX_BUFS	8
    struct rte_mbuf *buff[TX_BUFS + 2];

    buff[TX_BUFS + 0] = (struct rte_mbuf *) &Sentinel;
    buff[TX_BUFS + 1] = (struct rte_mbuf *) &Sentinel;

    if (!rte_mempool_get_bulk(th->mp, (void **) buff, TX_BUFS)) {
        send_frame(task, buff, TX_BUFS);
        return TX_BUFS;
    }
    return 0;
}

/*
 *
 */
static const struct eng_addon_s Addon = {
    .name       = "TkTx",
    .task_init  = TxTaskInit,
    .task_entry = TxTaskEntry,
};

static struct eng_addon_constructor_s AddonConstructor = {
    .addon = &Addon,
};

void
app_task_tx_register(void)
{
    eng_addon_register(&AddonConstructor);
}
