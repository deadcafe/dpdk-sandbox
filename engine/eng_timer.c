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
 * @file        eng_timer.c
 * @brief       FastPath Engine core library ( timer part )
 */

/*
 * Tiny Timer, poor function
 */

#include <sys/tree.h>
#include <sys/queue.h>

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

struct eng_timer_tree_s;

#define CACHELINE_SIZE 64

#define MALLOC(s)	malloc((s))
#define FREE(p)		free((p))

enum eng_timer_state_e {
    TIMER_STATE_USED = 0,
    TIMER_STATE_EXPIRED,
    TIMER_STATE_PERIODIC,
};


struct eng_timer_node_s {
    uint64_t tsc;
    uint64_t duration;

    void (*func)(unsigned, void *);
    void *arg;

    SPLAY_ENTRY(eng_timer_node_s) entry;
    unsigned state;
    unsigned id;	/* 1 <-> nb_entries */
} __attribute__((aligned(CACHELINE_SIZE)));

SPLAY_HEAD(eng_timer_tree_s, eng_timer_node_s);

/*
 *
 */
struct eng_timer_s {
    struct eng_timer_node_s *min_node;
    uint64_t min_tsc;
    struct eng_timer_tree_s tree;
    struct eng_timer_node_s *nodes;

    unsigned write;		/* next write position */
    unsigned read;		/* next read position */
    unsigned nb_elm;	/* number of buffer elements */
    unsigned reserved;
    unsigned buff[0];	/* element: 1 ~ nb_elm */
};

static inline void
set_used(struct eng_timer_node_s *node)
{
    node->state = (1u << TIMER_STATE_USED);
}

static inline void
set_periodic(struct eng_timer_node_s *node)
{
    node->state |= (1u << TIMER_STATE_PERIODIC);
}

static inline void
clear_used(struct eng_timer_node_s *node)
{
    node->state = 0u;
}

static inline void
set_expired(struct eng_timer_node_s *node)
{
    node->state |= (1u << TIMER_STATE_EXPIRED);
}

static inline void
clear_expired(struct eng_timer_node_s *node)
{
    node->state &= ~(1u << TIMER_STATE_EXPIRED);
}

static inline unsigned
is_periodic(const struct eng_timer_node_s *node)
{
    return node->state & (1u << TIMER_STATE_PERIODIC);
}

static inline unsigned
is_used(const struct eng_timer_node_s *node)
{
    return node->state & (1u << TIMER_STATE_USED);
}

static inline void
node_put(struct eng_timer_s *tm,
         struct eng_timer_node_s *node)
{
    unsigned fifo_write = tm->write;
    unsigned len = tm->nb_elm;

    clear_used(node);
    tm->buff[(fifo_write + 1) & (len - 1)] = node->id;
    tm->write = fifo_write + 1;
}

static inline  struct eng_timer_node_s *
node_get(struct eng_timer_s *tm)
{
    unsigned fifo_read = tm->read;
    unsigned fifo_write = tm->write;
    unsigned len = tm->nb_elm;
    struct eng_timer_node_s *node = NULL;

    if (fifo_read != fifo_write) {
        unsigned id = tm->buff[(fifo_read + 1) & (len - 1)];

        tm->read = fifo_read + 1;
        node = &tm->nodes[id];
        set_used(node);
    }
    return node;
}

static inline int
cmp_node(const struct eng_timer_node_s *n1,
         const struct eng_timer_node_s *n2)
{
    if (n1->tsc + n1->duration > n2->tsc + n2->duration)
        return 1;
    if (n1->tsc + n1->duration < n2->tsc + n2->duration)
        return -1;

    if (n1->tsc > n2->tsc)
        return 1;
    if (n1->tsc < n2->tsc)
        return -1;

    return (int) (n1->id) - (int) (n2->id);
}

SPLAY_GENERATE_STATIC(eng_timer_tree_s, eng_timer_node_s, entry, cmp_node)


static inline uint64_t
RDTSC(void)
{
    union {
        uint64_t tsc_64;
        struct {
            uint32_t lo_32;
            uint32_t hi_32;
        };
    } tsc;
    tsc.tsc_64 = 0;

    asm volatile("rdtsc" :
                 "=a" (tsc.lo_32),
                 "=d" (tsc.hi_32));
    return tsc.tsc_64;
}

struct eng_timer_s *
eng_timer_create(unsigned nb_entries)
{
    struct eng_timer_s *tm = NULL;

    if (__builtin_popcount(nb_entries) - 1)
        goto end;

    tm = MALLOC(sizeof(*tm) +
                (nb_entries * sizeof(tm->buff[0])) +
                (nb_entries * sizeof(struct eng_timer_node_s)));
    if (tm) {
        tm->min_tsc = UINT64_C(-1);
        tm->min_node = NULL;
        tm->write = 0;
        tm->read = 0;
        tm->nb_elm = nb_entries;
        tm->nodes = (struct eng_timer_node_s *) &tm->buff[nb_entries];

        SPLAY_INIT(&tm->tree);

        for (unsigned i = 0; i < nb_entries; i++) {
            struct eng_timer_node_s *node = &tm->nodes[i];

            node->id = i + 1;
            node_put(tm, node);
        }
    }
 end:
    return tm;
}

int
eng_timer_destroy(struct eng_timer_s *tm)
{
    int ret = 0;

    if (tm) {
        /* check empty */
        if (SPLAY_EMPTY(&tm->tree))
            FREE(tm);
        else
            ret = -1;
    }
    return ret;
}

unsigned
eng_timer_add(struct eng_timer_s *tm,
                   int is_periodic,
                   uint64_t duration,
                   void (*func)(unsigned, void *),
                   void *arg)
{
    unsigned id = 0;

    if (func) {
        struct eng_timer_node_s *node = node_get(tm);

        if (node) {
            if (is_periodic)
                set_periodic(node);
            node->tsc = RDTSC();
            node->duration = duration;
            node->func = func;
            node->arg = arg;

            SPLAY_INSERT(eng_timer_tree_s, &tm->tree, node);
            id = node->id;

            if (tm->min_node == NULL ||
                cmp_node(tm->min_node, node) > 0) {
                tm->min_node = node;
                tm->min_tsc = node->tsc + duration;
            }
        }
    }
    return id;
}

int
eng_timer_cancel(struct eng_timer_s *tm,
                      unsigned id)
{
    struct eng_timer_node_s *node = &tm->nodes[id - 1];
    int ret = -1;

    if (is_used(node)) {
        if (tm->min_node == node) {
            tm->min_node = SPLAY_NEXT(eng_timer_tree_s,
                                      &tm->tree, node);
            if (tm->min_node)
                tm->min_tsc = tm->min_node->tsc + tm->min_node->duration;
            else
                tm->min_tsc = UINT64_C(-1);
        }
        SPLAY_REMOVE(eng_timer_tree_s, &tm->tree, node);

        node_put(tm, node);
        ret = 0;
    }
    return ret;
}

unsigned
eng_timer_exec(struct eng_timer_s *tm)
{
    uint64_t now = RDTSC();
    unsigned num = 0;

    while (tm->min_tsc <= now) {
        struct eng_timer_node_s *node = tm->min_node;

        set_expired(node);

        tm->min_node = SPLAY_NEXT(eng_timer_tree_s,
                                  &tm->tree, node);
        if (tm->min_node)
            tm->min_tsc = tm->min_node->tsc + tm->min_node->duration;
        else
            tm->min_tsc = UINT64_C(-1);

        SPLAY_REMOVE(eng_timer_tree_s, &tm->tree, node);
        if (is_periodic(node)) {
            node->tsc = now;
            SPLAY_INSERT(eng_timer_tree_s, &tm->tree, node);
            if (tm->min_node == NULL ||
                cmp_node(tm->min_node, node) > 0) {
                tm->min_node = node;
                tm->min_tsc = node->tsc + node->duration;
            }
        }

        node->func(node->id, node->arg);
        clear_expired(node);

        if (!is_periodic(node))
            node_put(tm, node);

        now = RDTSC();
        num += 1;
    }
    return num;
}
