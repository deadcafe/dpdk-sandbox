
#include <sys/queue.h>
#include <stdbool.h>

#include <rte_mbuf.h>
#include <rte_net.h>
#include <rte_thash.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>

#include "task_if.h"

static char *Sentinel[1024] __attribute__((aligned(RTE_CACHE_LINE_SIZE)));

#define MBUF_BURST_SIZE	32

static const  uint8_t Default_RSS_Key[] = {
    0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
    0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
    0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
    0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
    0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
};

static inline uint32_t
tuple_hash(struct rte_mbuf *mb,
           const struct rte_net_hdr_lens *hdr_lens,
           uint32_t ptype)	/* SW packet type */
{
    struct ipv4_hdr *ipv4_hdr;
    struct ipv6_hdr *ipv6_hdr;
    struct tcp_hdr *tcp_hdr;
    struct udp_hdr *udp_hdr;
    struct sctp_hdr *sctp_hdr;
    unsigned l3_offset = hdr_lens->l2_len;
    unsigned l4_offset = hdr_lens->l2_len + hdr_lens->l3_len;
    union rte_thash_tuple tuple;
    unsigned len;
    bool is_v4 = true;

    if (RTE_ETH_IS_TUNNEL_PKT(ptype)) {
        unsigned tunnel_offset = (hdr_lens->l3_len +
                                  hdr_lens->l4_len +
                                  hdr_lens->tunnel_len +
                                  hdr_lens->inner_l2_len);
        l3_offset += tunnel_offset;
        l4_offset += tunnel_offset;

        switch (ptype & RTE_PTYPE_INNER_L3_MASK) {
        case RTE_PTYPE_INNER_L3_IPV4:
        case RTE_PTYPE_INNER_L3_IPV4_EXT:
            ipv4_hdr =  rte_pktmbuf_mtod_offset(mb,
                                                struct ipv4_hdr *,
                                                l3_offset);
            tuple.v4.dst_addr = ipv4_hdr->dst_addr;
            tuple.v4.src_addr = ipv4_hdr->src_addr;
            len = RTE_THASH_V4_L3_LEN;
            break;

        case RTE_PTYPE_INNER_L3_IPV6:
        case RTE_PTYPE_INNER_L3_IPV6_EXT:
            ipv6_hdr =  rte_pktmbuf_mtod_offset(mb,
                                                struct ipv6_hdr *,
                                                l3_offset);
            rte_thash_load_v6_addrs(ipv6_hdr, &tuple);
            len = RTE_THASH_V6_L3_LEN;
            is_v4 = false;
            break;

        default:
            return 0;
        }

        switch (ptype & RTE_PTYPE_INNER_L4_MASK) {
        case RTE_PTYPE_INNER_L4_TCP:
            tcp_hdr = rte_pktmbuf_mtod_offset(mb,
                                              struct tcp_hdr *,
                                              l4_offset);
            if (is_v4) {
                tuple.v4.dport = tcp_hdr->dst_port;
                tuple.v4.sport = tcp_hdr->src_port;
            } else {
                tuple.v6.dport = tcp_hdr->dst_port;
                tuple.v6.sport = tcp_hdr->src_port;
            }
            len += 1;
            break;

        case RTE_PTYPE_INNER_L4_UDP:
            udp_hdr = rte_pktmbuf_mtod_offset(mb,
                                              struct udp_hdr *,
                                              l4_offset);
            if (is_v4) {
                tuple.v4.dport = udp_hdr->dst_port;
                tuple.v4.sport = udp_hdr->src_port;
            } else {
                tuple.v6.dport = udp_hdr->dst_port;
                tuple.v6.sport = udp_hdr->src_port;
            }
            len += 1;
            break;

        case RTE_PTYPE_INNER_L4_SCTP:
            sctp_hdr = rte_pktmbuf_mtod_offset(mb,
                                               struct sctp_hdr *,
                                               l4_offset);
            if (is_v4)
                tuple.v4.sctp_tag = sctp_hdr->tag;
            else
                tuple.v6.sctp_tag = sctp_hdr->tag;
            len += 1;
            break;

        default:
            /* l3 only */
            break;
        }

    } else {
        switch (ptype & RTE_PTYPE_L3_MASK) {
        case RTE_PTYPE_L3_IPV4:
        case RTE_PTYPE_L3_IPV4_EXT:
            ipv4_hdr =  rte_pktmbuf_mtod_offset(mb,
                                                struct ipv4_hdr *,
                                                hdr_lens->l2_len);
            tuple.v4.src_addr = ipv4_hdr->src_addr;
            tuple.v4.dst_addr = ipv4_hdr->dst_addr;
            break;

        case RTE_PTYPE_L3_IPV6:
        case RTE_PTYPE_L3_IPV6_EXT:
            ipv6_hdr =  rte_pktmbuf_mtod_offset(mb,
                                                struct ipv6_hdr *,
                                                hdr_lens->l2_len);
            rte_thash_load_v6_addrs(ipv6_hdr, &tuple);
            is_v4 = false;
            break;

        default:
            return 0;
        }

        switch (ptype & RTE_PTYPE_L4_MASK) {
        case RTE_PTYPE_L4_TCP:
            tcp_hdr = rte_pktmbuf_mtod_offset(mb,
                                              struct tcp_hdr *,
                                              l4_offset);
            if (is_v4) {
                tuple.v4.dport = tcp_hdr->dst_port;
                tuple.v4.sport = tcp_hdr->src_port;
            } else {
                tuple.v6.dport = tcp_hdr->dst_port;
                tuple.v6.sport = tcp_hdr->src_port;
            }
            len += 1;
            break;

        case RTE_PTYPE_L4_UDP:
            udp_hdr = rte_pktmbuf_mtod_offset(mb,
                                              struct udp_hdr *,
                                              l4_offset);
            if (is_v4) {
                tuple.v4.dport = udp_hdr->dst_port;
                tuple.v4.sport = udp_hdr->src_port;
            } else {
                tuple.v6.dport = udp_hdr->dst_port;
                tuple.v6.sport = udp_hdr->src_port;
            }
            len += 1;
            break;

        case RTE_PTYPE_L4_SCTP:
            sctp_hdr = rte_pktmbuf_mtod_offset(mb,
                                               struct sctp_hdr *,
                                               l4_offset);
            if (is_v4)
                tuple.v4.sctp_tag = sctp_hdr->tag;
            else
                tuple.v6.sctp_tag = sctp_hdr->tag;
            len += 1;
            break;

        default:
            /* l3 only */
            break;
        }

    }
    return rte_softrss_be((uint32_t *) &tuple, len, Default_RSS_Key);
}

static inline void
prefetch_mbuf(struct rte_mbuf *m)
{
    char *p = (char *) m;

    rte_prefetch0(p);
    rte_prefetch0(p + 128);
    rte_prefetch0(p + 256 + RTE_PKTMBUF_HEADROOM);
}

struct thread_s;
struct task_s;

enum func_id_e {
    FUNC_ID_INVALID = 0,

    FUNC_ID_RX,
    FUNC_ID_FORWARD,
    FUNC_ID_USER,
    FUNC_ID_QOS,
    FUNC_ID_ACCT,

    NB_FUNCTIONS,
};

struct function_s {
    unsigned func_id;
    uint16_t in_port_id;
    uint16_t use_port;
    int task_initializer(const struct function_s *, struct task_s *,);
    unsigned (*entry_f)(struct task_s *);

    enum func_id_e nexthop[NB_FUNCTIONS];
    char name[32];
} __attribute__((aligned(RTE_CACHE_LINE_SIZE)));

static struct function_s FunctionTable[NB_FUNCTIONS] __attribute__((aligned(RTE_CACHE_LINE_SIZE)));


struct task_s {
    struct thread_s *thread;
    unsigned (*entry_f)(struct task_s *);
    uint64_t exec_cnt;
    uint64_t exec_tsc;
    uint64_t nb_mbufs;
    uint64_t nb_inst;	/* unused */

    unsigned flush_cnt;
    unsigned nb_out_ifs;

    unsigned func_id;
    unsigned task_id;

    struct eng_task_if_s *in_if;
    struct eng_task_if_s *out_if[32];
    char name[32];
} __attribute__((aligned(RTE_CACHE_LINE_SIZE)));


struct thread_s {
    unsigned lcore;
    uint64_t exec_cnt;
    uint64_t exec_tsc;
    uint64_t nb_mbufs;
    uint64_t nb_inst;	/* unused */

    int nb_tasks;
    int cur_task;
    struct task_s tasks[8] __attribute__((aligned(RTE_CACHE_LINE_SIZE)));
    struct eng_task_if_s *functions[NB_FUNCTIONS][64];
    char name[32];
} __attribute__((aligned(RTE_CACHE_LINE_SIZE)));



static struct task_s *TaskTbl[NB_FUNCTIONS][64] __attribute__((aligned(RTE_CACHE_LINE_SIZE)));

int
func_task_send(struct rte_mbuf *mb,
               unsigned func_id,
               unsigned task_id)
{


}

/*
 * function register
 */
static int
func_register(unsigned id,
              const char *name,
              unsigned (*entry_f)(struct task_s *),
              int socket_id)
{
    if (id >= RTE_DIM(FunctionTable) || !entry_f || !name)
        return -EINVAL;

    if (FunctionTable[id].entry_f)
        return -EEXIST;

    struct function_s *func = &FunctionTable[id];

    snprintf(func->name, sizeof(func->name), "%s", name);
    func->id = id;

    if (rte_eth_dev_is_valid_port(port_id)) {
        func->in_port_id = in_port_id;
        func->use_port = 1;
    }

    func->entry_f = entry_f;
    return 0;
}

/*
 *
 */
struct thread_s *
thread_create(const char *name,
              unsigned lcore)
{
    struct thread_s *th;

    th = rte_zmalloc_socket("thread", sizeof(*th), RTE_CACHE_LINE_SIZE,
                            rte_lcore_to_socket_id(lcore));
    if (th) {
        snprintf(th->name, sizeof(th->name), "%s", name);
        th->lcore = lcore;
    }
    return th;
}

static struct *TaskTbl[][]


/*
 *
 */
int
task_add(struct thread_s *th,
         unsigned func_id,
         unsigned task_id)
{
    if (func_id >= RTE_DIM(FunctionTable) ||
        task_id >= RTE_DIM(TaskTbl[NB_FUNCTIONS]) ||
        !th ||
        !FunctionTable[func_id].entry_f)
        return -EINVAL;

    if (TaskTbl[func_id][task_id])
        return -EEXIST;

    struct function_s *func = &FunctionTable[func_id];
    int socket_id = rte_lcore_to_socket_id(th->lcore);
    struct rte_ring *ring = NULL;

    if (!func->use_port) {
        char nbuf[32];

        snprintf(nbuf, sizeof(nbuf), "%s_ring_%u", func->name, task_id);
        ring = rte_ring_create(nbuf, TASK_RING_SIZE, socket_id,
                               RING_F_MP_ENQ | RING_F_SC_DEQ);
        if (!ring)
            return -ENOMEM;
    }

    struct task_s *task = th->tasks[th->nb_tasks];
    task->thread  = th;
    task->func_id = func_id;
    task->task_id = task_id;

    task->in_if = eng_task_if_create(socket_id, TASK_IF_FLUSH_SIZE);
    if (!task->in_if)
        return -ENOMEM;

    if (ring)
        eng_task_if_bind_ring(task->in_if, ENG_TASK_IF_DIR_IN, ring);
    else
        eng_task_if_bind_port(task->in_if, ENG_TASK_IF_DIR_IN,
                              func->in_port_id, task_id);

    snprintf(task->name, sizeof(task->name), "%s", name);
    th->nb_tasks++;

    return 0;
}

static struct thread_s * ThreadTbl[64];

/*
 *
 */
int
thread_create_rx(uint64_t lcores,
                 uint16_t port_id)
{
    unsigned nb_cores = pcnt(lcores);
    unsigned sub_id = 0;

    if (!nb_cores ||
        rte_eth_dev_is_valid_port(port_id))
        return -EINVAL;

    for (unsigned i = 0; i < 64; i++) {
        if (cores & UINT64_C(1) << i) {
            struct thread_s *th = ThreadTbl[i];

            if (th)
                return -EEXIST;

            char name[32];
            snprintf(name, sizeof(name), "RxThread%u", sub_id);
            th = thread_create(name, i);
            if (!th)
                return -NOMEM;

            

            ThreadTbl[i] = th;
            sub_id++;
        }
    }

    return sub_id;
}

/*
 * task scheduler
 */
static inline unsigned
task_sched(struct thread_s *thread)
{
    unsigned nb, sum = 0;
    uint64_t now, last, tsc = UINT64_C(0);
    struct task_s *task;

    last = rte_rdtsc();
    for (int i = 0; i < th->nb_tasks; i++) {
        struct task_s *task = &th->tasks[i];

        nb = task->entry_f(task);
        now = rte_rdtsc();

        task->nb_mbufs += nb;
        task->exec_cnt += 1;
        task->exec_tsc += (now - last);
        tsc += (now - last);

        last = now;
    }

    thread->exec_cnt += 1;
    thread->exec_tsc += tsc;
    thread->nb_mbufs += sum;

    return sum
}

/*
 * RPS task
 */
static unsigned
task_rps(struct eng_task_if_s *in_if,
         struct eng_task_if_s **out_if,
         unsigned nb_out_if,
         void *arg)
{
    struct rte_mbuf *mbufs[MBUF_BURST_SIZE + 1];
    unsigned nb;
    unsigned *flush_cnt = arg;

    nb = eng_task_recv(in_if, mbufs, MBUF_BURST_SIZE);
    mbufs[nb] = (struct rte_mbuf *) Sentinel;

    prefetch_mbuf(mbufs[0]);
    for (unsigned i = 0; i < nb; i++) {
        prefetch_mbuf(mbufs[i + 1]);

        struct rte_mbuf *mb = mbufs[i];
        uint32_t ptype;
        struct rte_net_hdr_lens hdr_lens;
        uint32_t thash;

        //        mb->port = in_if->port.port_id;
        ptype = rte_net_get_ptype(mb, &hdr_lens, RTE_PTYPE_ALL_MASK);
        thash = tuple_hash(mb, &hdr_lens, ptype);
        mb->hash.rss = thash;

        if (!eng_task_send(out_if[thash % nb_out_if], &mb, 1)) {

            /* drop */
        }
    }

    {
        *flush_cnt += 1;
        *flush_cnt %= nb_out_if;

        eng_task_flush(out_if[*flush_cnt]);
    }
    return nb;
}




/*
 * Forward task
 */
static unsigned
task_forward(struct eng_task_if_s *in_if,
             struct eng_task_if_s **out_if,
             unsigned nb_out_if,
             void *arg)
{

}

/*
 * User task
 */
static unsigned
task_user(struct eng_task_if_s *in_if,
          struct eng_task_if_s **out_if,
          unsigned nb_out_if,
          void *arg)
{

}

/*
 * Forward task
 */
static unsigned
task_forward(struct eng_task_if_s *in_if,
             struct eng_task_if_s **out_if,
             unsigned nb_out_if,
             void *arg)
{

}

/*
 * Engreee QoS task
 */
static unsigned
task_eqos(struct eng_task_if_s *in_if,
          unsigned port_id,
          unsigned queue_id,
          struct eng_task_if_s **out_if,
          unsigned nb_out_if,
          void *arg)
{
    struct rte_mbuf *mbufs[MBUF_BURST_SIZE + 1];
    unsigned nb, ret;

    nb = eng_task_recv(in_if, mbufs, MBUF_BURST_SIZE);
    if (nb)
        qos_enqueue(mbufs, nb);

    nb = qos_dequeue(mbufs, MBUF_BURST_SIZE);
    ret = nb;
    if (nb) {
        mbufs[nb] = (struct rte_mbuf *) Sentinel;
        struct rte_mbuf **buff = mbufs;

        while (nb) {
            prefetch_mbuf(buff[0]);
            n = rte_eth_tx_burst(port_id, queue_id, buff, nb);
            for (unsigned i = 0; i < n; i++) {
                prefetch_mbuf(buff[i + 1]);

                struct rte_mbuf *mb = buff[i];
                unsigned acct_task = get_acct_task(mb);
                eng_task_send(out_if[acct_task], &mb, 1);
            }
            buff += n;
            nb -= n;
        }
    }
    return ret;
}

/*
 * Accounting task
 */
static unsigned
acct_user(struct eng_task_if_s *in_if,
          struct eng_task_if_s **out_if,
          unsigned nb_out_if,
          void *arg)
{

}

