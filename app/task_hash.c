/*
 * Hash test module
 */

#include <sys/queue.h>
#include <immintrin.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>

#include <rte_spinlock.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_hash_crc.h>
#include <rte_hash.h>
#include <rte_malloc.h>

#include <eng_thread.h>
#include <eng_addon.h>

#include "app_modules.h"
#include "global_db.h"
#include "task_hash.h"

#define ARRAYOF(_a)     (sizeof(_a)/sizeof(_a[0]))

struct test_pkt_s {
        struct ether_hdr eth;
        struct ipv4_hdr ip;
        struct udp_hdr udp;
        TAILQ_ENTRY(test_pkt_s) node;
} __attribute__((packed, aligned(64)));


#define NB_TEST_DATA (128 * 1024 * 1024)

struct flow_key_s {
        uint32_t ip[2];		/* network byte order */
        uint16_t port[2];	/* network byte order */
        union {
                uint32_t pad;
                struct {
                        uint8_t id;
                        uint8_t reserve[3];
                } proto;
        } u;
} __attribute__((packed));


struct flow_s {
        struct flow_key_s key;

        uint64_t cnt;
        uint8_t data[128] __attribute__((aligned(64)));
} __attribute__((aligned(128)));


static struct test_pkt_s *
create_test_pkt(unsigned nb_data)
{
        struct test_pkt_s *top = rte_calloc(NULL, nb_data, sizeof(*top), 64);
        if (top) {
                TAILQ_HEAD(pkt_list_s, test_pkt_s) head =
                        TAILQ_HEAD_INITIALIZER(head);

                for (unsigned i = 0; i < nb_data; i++) {
                        if (i & 1)
                                TAILQ_INSERT_TAIL(&head, &top[i], node);
                        else
                                TAILQ_INSERT_HEAD(&head, &top[i], node);
                }

                struct test_pkt_s *pkt;
                for (unsigned i = 0; i < nb_data; i++) {
                        uint64_t r = rte_rand();

                        r %= nb_data;
                        pkt = &top[r];

                        TAILQ_REMOVE(&head, pkt, node);
                        TAILQ_INSERT_TAIL(&head, pkt, node);
                }

                uint32_t sip = 0x80000000;
                uint32_t dip = 0xa0000000;
                uint16_t sport = 1000;
                uint16_t dport = 8000;
                TAILQ_FOREACH(pkt, &head, node) {
                        pkt->ip.src_addr = sip++;
                        pkt->ip.dst_addr = dip++;
                        pkt->ip.next_proto_id = IPPROTO_UDP;
                        pkt->udp.src_port = sport++;
                        pkt->udp.dst_port = dport++;
                }
        } else {
                fprintf(stderr, "failed to allocate memory.\n");
        }
        return top;
}

static void
create_key(unsigned nb,
           struct flow_key_s key[],
           struct test_pkt_s *pkt[])
{
        for (unsigned i = 0; i < nb; i++) {
                key[i].ip[0]   = pkt[i]->ip.src_addr;
                key[i].ip[1]   = pkt[i]->ip.dst_addr;
                key[i].port[0] = pkt[i]->udp.src_port;
                key[i].port[1] = pkt[i]->udp.dst_port;
                key[i].u.pad   = 0;
                key[i].u.proto.id = pkt[i]->ip.next_proto_id;
        }
}

static struct flow_s *
create_flow(const struct rte_hash *h,
            unsigned nb,
            struct test_pkt_s pkt[])
{
        struct flow_s *flow = rte_calloc(NULL, nb, sizeof(*flow), 64);
        if (flow) {
                for (unsigned i = 0; i < nb; i++) {
                        struct test_pkt_s *pkt_p = &pkt[i];

                        create_key(1, &flow[i].key, &pkt_p);
                        if (rte_hash_add_key_data(h, &flow[i].key, &flow[i]))
                                break;
                }
        } else {
                fprintf(stderr, "failed to allocate memory\n");
        }
        return flow;
}

struct hash_test_s {
        struct rte_hash *hash;
        struct test_pkt_s *pkt_array;
        struct flow_s *flow_array;
        unsigned nb_data;
};

static int
HashTaskInit(struct eng_conf_db_s *conf __rte_unused,
             struct eng_thread_s *th __rte_unused,
             struct eng_task_s *task)
{
        struct hash_test_s *test = (struct hash_test_s *) task->private_area;

        memset(test, 0, sizeof(*test));
        test->nb_data = NB_TEST_DATA;

        test->pkt_array = create_test_pkt(test->nb_data);

        unsigned exf = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF;
        if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_RTM))
                exf |= RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT;

        struct rte_hash_parameters param = {
                .name = "test hash",
                .entries = rte_align32pow2(NB_TEST_DATA + 1),
                .key_len = sizeof(struct flow_key_s),
                .hash_func = rte_hash_crc,
                .hash_func_init_val = 0,
                .socket_id = rte_socket_id(),
                .extra_flag = exf,
        };

        test->hash = rte_hash_create(&param);
        test->flow_array = create_flow(test->hash, test->nb_data,
                                       test->pkt_array);

        return 0;
}

static unsigned
HashTaskEntry(struct eng_thread_s *th __rte_unused,
              struct eng_task_s *task,
              uint64_t now __rte_unused)
{
        struct hash_test_s *test = (struct hash_test_s *) task->private_area;
        unsigned ret = 0;

        for (unsigned i = 0; i < test->nb_data; i += 32) {
                struct flow_key_s key[32];
                struct flow_key_s *key_p[32];
                struct test_pkt_s *pkt[32];
                struct flow_s *flow[32 + 4];
                struct flow_s dummy;

                flow[32 + 0]  = &dummy;
                flow[32 + 1]  = &dummy;
                flow[32 + 2]  = &dummy;
                flow[32 + 3]  = &dummy;
                for (unsigned j = 0; j < ARRAYOF(key); j++) {
                        pkt[j]   = &test->pkt_array[i + j];
                        key_p[j] = &key[j];
                        flow[j]  = &dummy;
                }

                create_key(32, key, pkt);

                uint64_t mask = 0;
                int num = rte_hash_lookup_bulk_data(test->hash,
                                                    (const void **) key_p,
                                                    ARRAYOF(key_p),
                                                    &mask,
                                                    (void **) flow);
                rte_prefetch0(flow[0]);
                rte_prefetch0(flow[1]);
                rte_prefetch0(flow[2]);
                rte_prefetch0(flow[3]);
                for (int i = 0; i < 32; i++) {
                        flow[i]->cnt += 1;
                        rte_prefetch0(flow[i + 4]);
                }
                if (num != 32)
                        fprintf(stderr, "not found some data:%u\n", num);

                ret += num;
        }

        return ret;
}

/*
 *
 */
static const struct eng_addon_s Addon = {
    .name       = "TkHash",
    .task_init  = HashTaskInit,
    .task_entry = HashTaskEntry,
};

static struct eng_addon_constructor_s AddonConstructor = {
    .addon = &Addon,
};

void
app_task_hash_register(void)
{
    eng_addon_register(&AddonConstructor);
}
