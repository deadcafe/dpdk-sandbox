
#include <stdint.h>
#include <stdbool.h>

#include <rte_ring.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>

#include "task_if.h"

#define ENG_TASK_IF_BUFFER_SIZE	32

struct eng_task_if_s {
    union {
        struct rte_ring *ring;
        struct {
            uint16_t port_id;
            uint16_t queue_id;
        } port;
    };

    union {
        void *handler;
        uint16_t (*rx_f)(struct eng_task_if_s *, struct rte_mbuf **, uint16_t);
        uint16_t (*tx_f)(struct eng_task_if_s *, struct rte_mbuf **, uint16_t);
    };

    unsigned bpos;
    unsigned len;
    unsigned burst_sz;
    unsigned bmask;
    uint64_t oks;
    uint64_t fails;
    struct rte_mbuf *buffer[ENG_TASK_IF_BUFFER_SIZE];
};


unsigned
eng_task_recv(struct eng_task_if_s *tk_if,
              struct rte_mbuf **buff,
              unsigned buff_sz)
{
    return (tk_if->rx_f)(tk_if, buff, buff_sz);
}

unsigned
eng_task_send(struct eng_task_if_s *tk_if,
              struct rte_mbuf **buff,
              unsigned buff_sz)
{
    return (tk_if->tx_f)(tk_if, buff, buff_sz);
}

struct eng_task_if_s *
eng_task_if_create(int socket,
                   unsigned flush_len)
{
    struct eng_task_if_s *tk_if;

    if (flush_len > ENG_TASK_IF_BUFFER_SIZE)
        return NULL;
    if (flush_len == 0)
        flush_len = ENG_TASK_IF_BUFFER_SIZE;

    tk_if = rte_zmalloc_socket("task_if", sizeof(*tk_if),
                               RTE_CACHE_LINE_SIZE, socket);
    if (tk_if) {
        tk_if->bmask = RTE_DIM(tk_if->buffer) - 1;

    }
    return tk_if;
}

/*
 * ethdev handler
 */
static uint16_t
eng_task_if_port_recv(struct eng_task_if_s *tk_if,
                      struct rte_mbuf **buff,
                      uint16_t buff_sz)
{
    return rte_eth_rx_burst(tk_if->port.port_id, tk_if->port.queue_id,
                            buff, buff_sz);
}

static inline unsigned
flush_port(struct eng_task_if_s *tk_if,
           bool all)
{
    unsigned len = tk_if->len;
    unsigned nb = 0;

    if (len) {
        unsigned bpos = tk_if->bpos;

        while (len >= tk_if->burst_sz || (len && all)) {
            unsigned n = rte_eth_tx_burst(tk_if->port.port_id,
                                          tk_if->port.queue_id,
                                          &tk_if->buffer[bpos],
                                          len);
            if (!n)
                break;

            bpos += n;
            len -= n;
            nb += n;

            if (len == 0)
                bpos = 0;
        }

        if (nb) {
            if (bpos) {
                memmove(&tk_if->buffer[0], &tk_if->buffer[bpos],
                        len * sizeof(tk_if->buffer[0]));
            }
            tk_if->len = len;
            tk_if->bpos = bpos;
        }
    }
    return nb;
}

static uint16_t
eng_task_if_port_send(struct eng_task_if_s *tk_if,
                      struct rte_mbuf **mbufs,
                      uint16_t nb_mbufs)
{
    uint16_t nb = 0;

    for (uint16_t i = 0;
         i < nb_mbufs && tk_if->len < ENG_TASK_IF_BUFFER_SIZE;
         i++) {

        tk_if->buffer[tk_if->bpos + tk_if->len] = mbufs[i];
        nb += 1;
        tk_if->len += 1;

        flush_port(tk_if, false);
    }
    return nb;
}

/*
 * ring handler
 */
static uint16_t
eng_task_if_ring_recv(struct eng_task_if_s *tk_if,
                      struct rte_mbuf **buff,
                      uint16_t buff_sz)
{
    return rte_ring_dequeue_burst(tk_if->ring, (void **) buff, buff_sz, NULL);
}

static inline unsigned
flush_ring(struct eng_task_if_s *tk_if,
           bool all)
{
    unsigned len = tk_if->len;
    unsigned nb = 0;

    if (len) {
        unsigned bpos = tk_if->bpos;

        while (len >= tk_if->burst_sz || (len && all)) {
            unsigned n = rte_ring_enqueue_burst(tk_if->ring,
                                                (void **) &tk_if->buffer[bpos],
                                                len, NULL);
            if (!n)
                break;

            bpos += n;
            len -= n;
            nb += n;

            if (len == 0)
                bpos = 0;
        }

        if (nb) {
            if (bpos) {
                memmove(&tk_if->buffer[0], &tk_if->buffer[bpos],
                        len * sizeof(tk_if->buffer[0]));
            }
            tk_if->len = len;
            tk_if->bpos = bpos;
        }
    }
    return nb;
}

static uint16_t
eng_task_if_ring_send(struct eng_task_if_s *tk_if,
                      struct rte_mbuf **buff,
                      uint16_t buff_sz)
{
    uint16_t nb = 0;

    for (uint16_t i = 0;
         i < buff_sz && tk_if->len < ENG_TASK_IF_BUFFER_SIZE;
         i++) {

        tk_if->buffer[tk_if->bpos + tk_if->len] = buff[i];
        nb += 1;
        tk_if->len += 1;

        flush_ring(tk_if, false);
    }
    return nb;
}

static int
task_if_bind(struct eng_task_if_s *tk_if,
             bool is_port,
             enum eng_task_if_dir_e dir,
             unsigned port_id,
             unsigned queue_id,
             struct rte_ring *ring)
{
    if (tk_if->handler)
        return -EEXIST;

    switch (dir) {
    case ENG_TASK_IF_DIR_IN:
        if (is_port) {
            tk_if->rx_f = eng_task_if_port_recv;
            tk_if->port.port_id = port_id;
            tk_if->port.queue_id = queue_id;
        } else {
            tk_if->rx_f = eng_task_if_ring_recv;
            tk_if->ring = ring;
        }
        break;

    case ENG_TASK_IF_DIR_OUT:
        if (is_port) {
            tk_if->tx_f = eng_task_if_port_send;
            tk_if->port.port_id = port_id;
            tk_if->port.queue_id = queue_id;
        } else {
            tk_if->tx_f = eng_task_if_ring_send;
            tk_if->ring = ring;
        }
        break;

    default:
        return -EINVAL;
    }
    return 0;
}

int
eng_task_if_bind_port(struct eng_task_if_s *tk_if,
                      enum eng_task_if_dir_e dir,
                      unsigned port_id,
                      unsigned queue_id)
{
    return task_if_bind(tk_if, dir, true, port_id, queue_id, NULL);
}

int
eng_task_if_bind_ring(struct eng_task_if_s *tk_if,
                      enum eng_task_if_dir_e dir,
                      struct rte_ring *ring)
{
    return task_if_bind(tk_if, dir, false, -1, -1, ring);
}

struct rte_ring *
eng_task_if_get_ring(struct eng_task_if_s *tk_if)
{
    return tk_if->ring;
}


