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
 * @file        eng_pdump.c
 * @brief       FastPath Engine core library (packet dump)
 */

#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <sys/tree.h>
#include <fcntl.h>
#include <unistd.h>
#include <pcap.h>
#include <errno.h>

#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_atomic.h>
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_errno.h>

#include "eng_pdump.h"
#include "eng_log.h"

#define MAX_DUMP_SIZE RTE_MBUF_DEFAULT_DATAROOM
#define MAX_QUEUES_PER_PORT 32 /* XXX */

/*
 * callback function db
 */
struct cb_args_s {
    pcap_dumper_t *dumper;
    rte_spinlock_t *lock;
    struct dump_stats_s *stats;
    struct timeval *start_time;
    uint64_t *start_tsc;
};

enum dump_dir_e {
    DUMP_DIR_RX = 0,
    DUMP_DIR_TX,
    DUMP_DIR_NUM,
};

struct pdump_cb_s {
    struct {
        int fd;
        uint16_t port_id;
        uint16_t queue_id;
        enum dump_dir_e dir;
    } key;
    const struct rte_eth_rxtx_callback *cb;
    struct cb_args_s args;
    RB_ENTRY(pdump_cb_s) node;
};
static RB_HEAD(pdump_cbs_s, pdump_cb_s) cbs_head = RB_INITIALIZER(cbs_head);

static inline int
cmp_cb(const struct pdump_cb_s *c0,
       const struct pdump_cb_s *c1)
{
    return memcmp(&c0->key, &c1->key, sizeof(c0->key));
}
RB_GENERATE_STATIC(pdump_cbs_s, pdump_cb_s, node, cmp_cb);

static inline struct pdump_cb_s *
find_cb(uint16_t port_id,
        uint16_t queue_id,
        uint32_t dir,
        int fd)
{
    struct pdump_cb_s cb;
    cb.key.port_id = port_id;
    cb.key.queue_id = queue_id;
    cb.key.fd = fd;
    cb.key.dir = dir;
    return RB_FIND(pdump_cbs_s, &cbs_head, &cb);
}

static inline void
add_cb(struct pdump_cb_s *node)
{
    RB_INSERT(pdump_cbs_s, &cbs_head, node);
}

static inline void
del_cb(struct pdump_cb_s *node)
{
    RB_REMOVE(pdump_cbs_s, &cbs_head, node);
    if (node->cb) {
	/* XXX: already removed callback, but cb is NOT free */
        void *p = (void *) node->cb;	/* maybe C11 ready */
        rte_free(p);
    }
    rte_free(node);
}

/*
 * file descriptor handle db
 */
struct dump_stats_s {
    uint64_t success;
    uint64_t failure;
};

struct fd_handle_s {
    int fd; /* key */
    unsigned refcnt;
    FILE *fp;
    pcap_t *pcap_handle;
    pcap_dumper_t *pcap_dumper;
    rte_spinlock_t lock;
    struct timeval start_time;
    uint64_t start_tsc;
    struct {
        struct dump_stats_s stats[RTE_MAX_ETHPORTS][MAX_QUEUES_PER_PORT];
    } dump_stats[DUMP_DIR_NUM];
    STAILQ_ENTRY(fd_handle_s) node;
};

STAILQ_HEAD(fd_handle_head_s, fd_handle_s);
static struct fd_handle_head_s handle_head = STAILQ_HEAD_INITIALIZER(handle_head);

struct fd_handle_s *
find_fd_handle(int fd)
{
    struct fd_handle_s *hd;
    STAILQ_FOREACH(hd, &handle_head, node) {
        if(fd == hd->fd) {
            return hd;
        }
    }
    return NULL;
}

static struct fd_handle_s *
create_fd_handle(int fd)
{
    struct fd_handle_s *hd = rte_zmalloc_socket(NULL, sizeof(*hd),
                                                RTE_CACHE_LINE_SIZE,
                                                rte_socket_id());
    if(!hd) {
        ENG_ERR(CORE, "failed to alloc handle.\n");
        return NULL;
    }
    hd->fd = fd;

    int dupfd = fcntl(hd->fd, F_DUPFD); /* for pcap */
    if (dupfd < 0) {
        ENG_ERR(CORE, "failed in fctl(). fd:%d, %s\n",
                fd, strerror(errno));
        rte_free(hd);
        return NULL;
    }

    hd->fp = fdopen(dupfd, "wb");
    if (!hd->fp) {
        ENG_ERR(CORE, "failed in fdopen(). fd:%d, %s\n",
                fd, strerror(errno));
        while (close(dupfd) && (errno == EINTR))
            ;
        rte_free(hd);
        return NULL;
    }

    hd->pcap_handle = pcap_open_dead(DLT_EN10MB, MAX_DUMP_SIZE);
    if (!hd->pcap_handle) {
        ENG_ERR(CORE, "failed in pcap_open_dead(). fd:%d\n", fd);
        fclose(hd->fp);
        rte_free(hd);
        return NULL;
    }
    hd->pcap_dumper =  pcap_dump_fopen(hd->pcap_handle, hd->fp);
    if (!hd->pcap_dumper) {
        ENG_ERR(CORE, "failed in pcap_dump_fopen(). fd:%d, %s\n",
                fd, pcap_geterr(hd->pcap_handle));
        fclose(hd->fp);
        rte_free(hd);
        return NULL;
    }

    hd->refcnt = 0;
    gettimeofday(&hd->start_time, NULL);
    hd->start_tsc = rte_rdtsc();
    memset(&hd->dump_stats[DUMP_DIR_RX], 0,
           sizeof(hd->dump_stats[DUMP_DIR_RX]));
    memset(&hd->dump_stats[DUMP_DIR_TX], 0,
           sizeof(hd->dump_stats[DUMP_DIR_TX]));
    rte_spinlock_init(&hd->lock);
    STAILQ_INSERT_TAIL(&handle_head, hd, node);
    return hd;
}

static void
delete_fd_handle(struct fd_handle_s *hd)
{
    STAILQ_REMOVE(&handle_head, hd, fd_handle_s, node);
    pcap_dump_close(hd->pcap_dumper); /* fclose() inside */
    pcap_close(hd->pcap_handle);
    rte_free(hd);
}

static void
attach_fd_handle(struct fd_handle_s *hd)
{
    hd->refcnt++;
}

static void
detach_fd_handle(struct fd_handle_s *hd)
{
    hd->refcnt--;
}

static unsigned
refcnt_fd_handle(struct fd_handle_s *hd)
{
    return hd->refcnt;
}

static void
dump_stats(struct fd_handle_s *hd,
           uint16_t port_id,
           uint16_t queue_id,
           enum dump_dir_e dir,
           uint64_t *pkts_success,
           uint64_t *pkts_failure)
{
    *pkts_success = hd->dump_stats[dir].stats[port_id][queue_id].success;
    *pkts_failure = hd->dump_stats[dir].stats[port_id][queue_id].failure;
}

/*
 * local funcs
 */
static inline void
calculate_timestamp(struct timeval *ts,
                    struct timeval start_time,
                    uint64_t start_tsc)
{

    uint64_t tsc_hz = rte_get_tsc_hz();
    uint64_t tsc_diff = rte_rdtsc() - start_tsc;
    struct timeval diff_time = {
     .tv_sec = tsc_diff / tsc_hz,
     .tv_usec =  (tsc_diff % tsc_hz) * 1e6 / tsc_hz,
    };

    timeradd(&start_time, &diff_time, ts);
}

static inline void
dump_exec(struct rte_mbuf **pkts,
          uint16_t nb_pkts,
          void *user_params)
{
    unsigned i;
    struct cb_args_s *args = user_params;
    struct dump_stats_s *stats = args->stats;

    args  = user_params;
    rte_spinlock_lock(args->lock);
    for (i = 0; i < nb_pkts; i++) {
        struct pcap_pkthdr header;
        calculate_timestamp(&header.ts, *args->start_time, *args->start_tsc);
        header.len = pkts[i]->pkt_len;
        header.caplen = header.len;
        pcap_dump((u_char *)args->dumper, &header,
                  rte_pktmbuf_mtod(pkts[i], void*));
    }
    pcap_dump_flush(args->dumper); /* for real-time displaying */
    stats->success += nb_pkts;
    rte_spinlock_unlock(args->lock);

}

static uint16_t
dump_rx(uint16_t port __rte_unused,
        uint16_t qidx __rte_unused,
        struct rte_mbuf **pkts,
        uint16_t nb_pkts,
        uint16_t max_pkts __rte_unused,
        void *user_params)
{
    if (nb_pkts) {
        dump_exec(pkts, nb_pkts, user_params);
    }
    return nb_pkts;
}

static uint16_t
dump_tx(uint16_t port __rte_unused,
        uint16_t qidx __rte_unused,
        struct rte_mbuf **pkts,
        uint16_t nb_pkts,
        void *user_params)
{
    if (nb_pkts) {
        dump_exec(pkts, nb_pkts, user_params);
    }
    return nb_pkts;
}

static int
register_callback(struct fd_handle_s *hd,
                  uint16_t port_id,
                  uint16_t queue_id,
                  enum dump_dir_e dir)
{

    if(find_cb(port_id, queue_id, dir, hd->fd)) {
        ENG_INFO(CORE, "callback func is already registered."
                 "port=%d queue=%d dir=%d fd=%d",
                 port_id, queue_id, dir, hd->fd);
        return -EEXIST;
    }

    struct pdump_cb_s *cb;
    cb = rte_zmalloc_socket(NULL, sizeof(*cb),
                            RTE_CACHE_LINE_SIZE,
                            rte_socket_id());
    if (!cb) {
        ENG_ERR(CORE, "failed to alloc callback.\n");
       return -ENOMEM;
    }
    cb->key.port_id = port_id;
    cb->key.queue_id = queue_id;
    cb->key.fd = hd->fd;
    cb->key.dir = dir;
    cb->args.dumper = hd->pcap_dumper;
    cb->args.lock = &hd->lock;
    cb->args.start_time = &hd->start_time;
    cb->args.start_tsc = &hd->start_tsc;
    cb->args.stats = &hd->dump_stats[dir].stats[port_id][queue_id];
    if (dir == DUMP_DIR_RX) {
        cb->cb = rte_eth_add_rx_callback(port_id, queue_id, dump_rx, &cb->args);
    } else {
        cb->cb = rte_eth_add_tx_callback(port_id, queue_id, dump_tx, &cb->args);
    }
    if (!cb->cb) {
        ENG_ERR(CORE, "failed to register callback func. "
                 "error_no=%d port=%d queue=%d dir=%d fd=%d\n",
                 rte_errno, port_id, queue_id, dir, hd->fd);
        rte_free(cb);
        return -EIO;
    }
    add_cb(cb);

    return 0;
}

static inline int
eth_remove_rxtx_callback(uint16_t port_id,
                         uint16_t queue_id,
                         enum dump_dir_e dir,
                         const struct rte_eth_rxtx_callback *user_cb)
{
    void *p = (void *) user_cb;	/* for DPDK18.11 ready */
    int ret;

    if (dir == DUMP_DIR_RX)
        ret = rte_eth_remove_rx_callback(port_id, queue_id, p);
    else
        ret = rte_eth_remove_tx_callback(port_id, queue_id, p);
    return ret;
}

static int
remove_callback(struct fd_handle_s *hd,
                uint16_t port_id,
                uint16_t queue_id,
                enum dump_dir_e dir)
{
    struct pdump_cb_s *cb;
    cb = find_cb(port_id, queue_id, dir, hd->fd);
    if (!cb) {
        ENG_INFO(CORE, "callback func not registered. port=%d queue=%d fd=%d\n",
                 port_id, queue_id, hd->fd);
        return -ENOENT;
    }
    int ret = eth_remove_rxtx_callback(port_id, queue_id, dir, cb->cb);
    if (ret < 0) {
        ENG_ERR(CORE, "failed to remove callback func. "
                "error_no=%d port=%d and queue=%d dir=%d fd=%d\n",
                rte_errno, port_id, queue_id, dir, hd->fd);
        return -EIO;
    }
    pcap_dump_flush(cb->args.dumper);
    del_cb(cb);

    return 0;
}

static int
pdump_start(int fd,
            uint16_t port_id,
            uint16_t queue_id,
            enum dump_dir_e dir)
{
    struct fd_handle_s *hd = find_fd_handle(fd);
    if (!hd) {
        hd = create_fd_handle(fd);
        if (!hd) {
            return -1;
        }
    }

    int ret;
    switch (register_callback(hd, port_id, queue_id, dir)) {
    case 0:
        attach_fd_handle(hd);
        ret = 0;
        break;
    case -EEXIST:
        ENG_INFO(CORE, "dump is already started, ignored. port=%d queue=%d dir=%d fd=%d\n",
                 port_id, queue_id, dir, hd->fd);
        ret = 0;
        break;
    default:
        ret = -1;
    }

    if (refcnt_fd_handle(hd) == 0) {
        delete_fd_handle(hd);
    }

    return ret;
}

static int
pdump_finish(int fd,
             uint16_t port_id,
             uint16_t queue_id,
             enum dump_dir_e dir,
             uint64_t *pkts_success,
             uint64_t *pkts_failure)
{
    struct fd_handle_s *hd = find_fd_handle(fd);
    if (!hd) {
        ENG_INFO(CORE, "handle not found, ignored. port=%d queue=%d\n" ,
                 port_id, queue_id);
        return 0;
    }

    int ret;
    switch (remove_callback(hd, port_id, queue_id, dir)) {
    case 0:
        dump_stats(hd, port_id, queue_id, dir, pkts_success, pkts_failure);
        detach_fd_handle(hd);
        ret = 0;
        break;

    case -ENOENT:
        ENG_INFO(CORE, "dump is not started, ignored. port=%d queue=%d dir=%d fd=%d\n",
                 port_id, queue_id, dir, hd->fd);
        ret = 0;
        break;
    default:
        ret = -1;
    }

    if (refcnt_fd_handle(hd) == 0) {
        delete_fd_handle(hd);
    }

    return ret;
}

static void
pdump_get_stats(int fd,
                uint16_t port_id,
                uint16_t queue_id,
                enum dump_dir_e dir,
                uint64_t *pkts_success,
                uint64_t *pkts_failure)
{
    struct fd_handle_s *hd = find_fd_handle(fd);
    if (!hd) {
        ENG_INFO(CORE, "handle not found, ignored. port=%d queue=%d\n" ,
                 port_id, queue_id);
        *pkts_success = 0;
        *pkts_failure = 0;
        return;
    }
    dump_stats(hd, port_id, queue_id, dir, pkts_success, pkts_failure);
}


/*
 * APIs
 */
__attribute__((unused)) int
eng_pdump_start(int fd,
                uint16_t port_id,
                uint32_t dir)
{
    int ret = 0;

    if (!rte_eth_dev_is_valid_port(port_id)) {
        ENG_ERR(CORE, "invalid port id. fd=%d, port_id=%d, dir=%d\n",
                fd, port_id, dir);
        ret = -1;
        goto end;
    }

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(port_id, &dev_info);

    uint16_t queue_id;
    if (dir & ENG_PDUMP_DIR_RX) {
        for(queue_id = 0; queue_id < dev_info.nb_rx_queues; queue_id++) {
            ret = pdump_start(fd, port_id, queue_id, DUMP_DIR_RX);
            if (ret < 0) {
                goto end;
            }
        }
    }

    if (dir & ENG_PDUMP_DIR_TX) {
        for(queue_id = 0; queue_id < dev_info.nb_tx_queues; queue_id++) {
            ret = pdump_start(fd, port_id, queue_id, DUMP_DIR_TX);
            if (ret < 0) {
                goto end;
            }
        }
    }
end:
    return ret;
}

__attribute__((unused)) int
eng_pdump_finish(int fd,
                 uint16_t port_id,
                 uint64_t *pkts_success,
                 uint64_t *pkts_failure)
{
    int ret = 0;
    if (!rte_eth_dev_is_valid_port(port_id)) {
        ENG_ERR(CORE, "invalid port id. fd=%d, port_id=%d\n",
                fd, port_id);
        ret = -1;
        goto end;
    }

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(port_id, &dev_info);
    uint64_t s, f;
    *pkts_success = 0;
    *pkts_failure = 0;
    uint16_t queue_id;
    for(queue_id = 0; queue_id < dev_info.nb_rx_queues; queue_id++) {
        s = 0;
        f = 0;
        ret = pdump_finish(fd, port_id, queue_id, DUMP_DIR_RX, &s, &f);
        if (ret < 0) {
            goto end;
        }
        *pkts_success += s;
        *pkts_failure += f;
    }
    for(queue_id = 0; queue_id < dev_info.nb_tx_queues; queue_id++) {
        s = 0;
        f = 0;
        ret = pdump_finish(fd, port_id, queue_id, DUMP_DIR_TX, &s, &f);
        if (ret < 0) {
            goto end;
        }
        *pkts_success += s;
        *pkts_failure += f;
    }
end:
    return ret;
}

__attribute__((unused)) int
eng_pdump_get_stats(int fd,
                    uint16_t port_id,
                    uint32_t dir,
                    uint64_t *pkts_success,
                    uint64_t *pkts_failure)
{
    if (!rte_eth_dev_is_valid_port(port_id)) {
        ENG_ERR(CORE, "invalid port id. fd=%d, port_id=%d, dir=%d\n",
               fd, port_id, dir);
        return -1;
    }

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(port_id, &dev_info);
    uint64_t s, f;
    *pkts_success = 0;
    *pkts_failure = 0;
    uint16_t queue_id;
    if (dir & ENG_PDUMP_DIR_RX) {
        for(queue_id = 0; queue_id < dev_info.nb_rx_queues; queue_id++) {
            s = 0;
            f = 0;
            pdump_get_stats(fd, port_id, queue_id, DUMP_DIR_RX, &s, &f);
            *pkts_success += s;
            *pkts_failure += f;
        }
    }
    if (dir & ENG_PDUMP_DIR_TX) {
        for(queue_id = 0; queue_id < dev_info.nb_tx_queues; queue_id++) {
            s = 0;
            f = 0;
            pdump_get_stats(fd, port_id, queue_id, DUMP_DIR_TX, &s, &f);
            *pkts_success += s;
            *pkts_failure += f;
        }
    }
    return 0;
}
