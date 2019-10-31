/*
 * Toeplitz Hash test module
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
#include <rte_thash.h>
#include <rte_hash.h>

#include <eng_thread.h>
#include <eng_addon.h>

#include "app_modules.h"
#include "global_db.h"
#include "task_toeplitz.h"

struct toeplitz_test_s {
        uint32_t addr;		/* IPv4 host byte order */
        uint32_t mask;
        uint32_t cur;
        uint8_t rss_key[40];
};

static const uint8_t default_rss_key[40] = {
        0x6D, 0x5A, 0x56, 0xDA, 0x25, 0x5B, 0x0E, 0xC2, 0x41, 0x67, 0x25, 0x3D,
        0x43, 0xA3, 0x8F, 0xB0, 0xD0, 0xCA, 0x2B, 0xCB, 0xAE, 0x7B, 0x30, 0xB4,
        0x77, 0xCB, 0x2D, 0xA3, 0x80, 0x30, 0xF2, 0x0C, 0x6A, 0x42, 0xB7, 0x3B,
        0xBE, 0xAC, 0x01, 0xFA
};

static const uint8_t random_key_byte_stream[52] = {
        0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
        0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
        0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
        0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
        0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
};


struct gtp_hdr {
        uint8_t flags;
        uint8_t msg_type;
        uint16_t msg_len;
        uint32_t teid;
} __attribute__((packed));

struct gtp_opt {
        uint16_t seq_nub;
        uint8_t nbdu_num;
        uint8_t next_ext;
} __attribute__((packed));

struct packet_s {
        struct ipv4_hdr outer_ip;
        struct udp_hdr outer_udp;
        struct gtp_hdr gtp;
        struct ipv4_hdr inner_ip;
        struct udp_hdr inner_udp;
};


static int
ToeplitzTaskInit(struct eng_conf_db_s *conf __rte_unused,
                 struct eng_thread_s *th __rte_unused,
                 struct eng_task_s *task)
{
        struct toeplitz_test_s *test =
                (struct toeplitz_test_s *) task->private_area;

        test->addr = 0x03030300;
        test->mask = test->addr & 0xffffff00;	/* /24 */
        test->cur  = test->mask;

        rte_convert_rss_key((uint32_t *) default_rss_key,
                            (uint32_t *) test->rss_key,
                            RTE_DIM(default_rss_key));

        for (unsigned i = 0; i < 256; i++) {
                uint32_t addr = test->addr | i;

                addr = rte_cpu_to_be_32(addr);
                uint32_t hash = rte_softrss(&addr, 1, test->rss_key);

                fprintf(stderr, "%u: 0x%x\n", i, hash);
        }
        return -1;
}

static unsigned
ToeplitzTaskEntry(struct eng_thread_s *th __rte_unused,
                  struct eng_task_s *task,
                  uint64_t now __rte_unused)
{
        struct toeplitz_test_s *test =
                (struct toeplitz_test_s *) task->private_area;

        uint32_t addr = test->cur;
        for (unsigned i = 0; i < 32; i++) {

                addr++;
                addr &= test->mask;
        }
        test->cur = addr;

        return 0;
}

/*
 *
 */
static const struct eng_addon_s Addon = {
    .name       = "TkToeplitz",
    .task_init  = ToeplitzTaskInit,
    .task_entry = ToeplitzTaskEntry,
};

static struct eng_addon_constructor_s AddonConstructor = {
    .addon = &Addon,
};

void
app_task_toeplitz_register(void)
{
    eng_addon_register(&AddonConstructor);
}
