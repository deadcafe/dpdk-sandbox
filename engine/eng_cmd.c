#include <sys/types.h>
#include <sys/tree.h>
#include <unistd.h>
#include <string.h>

#include <rte_atomic.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_mempool.h>

#include "eng_log.h"
#include "eng_thread.h"
#include "eng_cmd.h"

struct eng_cmd_handler_s {
    RB_ENTRY(eng_cmd_handler_s) entry;
    eng_cmd_handler_t handler;
    const char *name;
    char name_buff[32];
} __attribute__((aligned(RTE_CACHE_LINE_SIZE)));

static inline int
cmp_cmd_handler(const struct eng_cmd_handler_s *h0,
                const struct eng_cmd_handler_s *h1)
{
    return strncmp(h0->name, h1->name, sizeof(h0->name_buff));
}

#define NB_CLIENTS	8

struct eng_cmd_mng_s {
    struct rte_ring *threads[RTE_MAX_LCORE];
    struct rte_ring *rsp[NB_CLIENTS];
    const struct rte_memzone *mz;

    RB_HEAD(eng_cmd_tree_s, eng_cmd_handler_s) cmd_tree;

    rte_spinlock_t lock;
    pid_t pid[NB_CLIENTS];

    struct eng_cmd_s cmd_pool[NB_CLIENTS] __rte_cache_aligned;
};

RB_GENERATE_STATIC(eng_cmd_tree_s, eng_cmd_handler_s, entry, cmp_cmd_handler);

#define ENG_CMD_MANAGER "XXXCmdManager"
static struct eng_cmd_mng_s *Mng;

static inline struct eng_cmd_mng_s *
find_mng(void)
{
    struct eng_cmd_mng_s *mng = Mng;

    if (!mng) {
        const struct rte_memzone *mz;

        mz = rte_memzone_lookup(ENG_CMD_MANAGER);
        if (mz) {
            mng = mz->addr;
            Mng = mng;
        }
    }
    return mng;
}

int
eng_cmd_init(void)
{
    struct eng_cmd_mng_s *mng = find_mng();

    if (!mng) {
        const struct rte_memzone *mz;

        mz = rte_memzone_reserve(ENG_CMD_MANAGER,
                                 sizeof(*mng),
                                 rte_socket_id(),
                                 RTE_MEMZONE_2MB | RTE_MEMZONE_1GB |
                                 RTE_MEMZONE_SIZE_HINT_ONLY);
        if (!mz) {
            ENG_ERR(CORE, "can not alloc mem zone:%s", ENG_CMD_MANAGER);
            return -ENOMEM;
        }

        mng = mz->addr;
        memset(mng, 0, sizeof(*mng));
        mng->mz = mz;
        RB_INIT(&mng->cmd_tree);
        rte_spinlock_init(&mng->lock);

        for (unsigned i = 0; i < RTE_DIM(mng->pid); i++)
            mng->pid[i] = 0;

        for (unsigned i = 0; i < RTE_DIM(mng->threads); i++)
            mng->threads[i] = NULL;

        for (unsigned i = 0; i < RTE_DIM(mng->rsp); i++) {
            char name[32];

            snprintf(name, sizeof(name), "CmdResp_%u", i);
            mng->rsp[i] = rte_ring_create(name, 8, rte_socket_id(),
                                          RING_F_SP_ENQ | RING_F_SC_DEQ);
            if (!mng->rsp[i]) {
                ENG_ERR(CORE, "can not alloc ring:%s", name);
                return -ENOMEM;
            }
        }
        Mng = mng;
    }
    return 0;
}

/*
 *
 */
int
eng_cmd_ring_register(unsigned thread_id,
                      struct rte_ring *ring)
{
    struct eng_cmd_mng_s *mng = find_mng();

    if (!mng) {
        ENG_ERR(CORE, "not found cmd mng");
        return -EINVAL;
    }

    if (mng->threads[thread_id]) {
        ENG_ERR(CORE, "already exist cmd ring:%u", thread_id);
        return -EEXIST;
    }

    mng->threads[thread_id] = ring;
    return 0;
}

static inline void
detach(struct eng_cmd_mng_s *mng)
{
    rte_spinlock_lock(&mng->lock);
    for (unsigned i = 0; i < RTE_DIM(mng->pid); i++) {
        if (mng->pid[i] == getpid()) {
            mng->pid[i] = 0;
            break;
        }
    }
    rte_spinlock_unlock(&mng->lock);
}

static inline int
attach(struct eng_cmd_mng_s *mng)
{
    int ret = -EBUSY;

    rte_spinlock_lock(&mng->lock);
    for (unsigned i = 0; i < RTE_DIM(mng->pid); i++) {
        if (mng->pid[i] == 0) {
            mng->pid[i] = getpid();
            ret = (int) i;
            break;
        }
    }
    rte_spinlock_unlock(&mng->lock);
    return ret;
}

static void cmd_destructor(void) __attribute__((destructor));

static void
cmd_destructor(void)
{
    struct eng_cmd_mng_s *mng = Mng;

    if (mng)
        detach(mng);
}

int
eng_cmd_register(const char *name,
                 eng_cmd_handler_t handler)
{
    struct eng_cmd_mng_s *mng = find_mng();

    ENG_ERR(CORE, "start mng:%p name:%p handler:%p", mng, name, handler);

    if (!mng || !name || !handler)
        return -EINVAL;

    struct eng_cmd_handler_s *node;
    node = rte_zmalloc_socket("CmdNode", sizeof(*node), RTE_CACHE_LINE_SIZE,
                              rte_socket_id());
    if (!node) {
        ENG_ERR(CORE, "can not alloc memory:%s", "CmdNode");
        return -ENOMEM;
    }

    snprintf(node->name_buff, sizeof(node->name_buff), "%s", name);
    node->name = node->name_buff;
    node->handler = handler;
    if (RB_INSERT(eng_cmd_tree_s, &mng->cmd_tree, node)) {
        rte_free(node);
        ENG_ERR(CORE, "already exist cmd handler:%s", name);
        return -EEXIST;
    }

    ENG_ERR(CORE, "done:%s", name);
    return 0;
}

unsigned
eng_cmd_exec(struct rte_ring *ring)
{
    unsigned ret = 0;
    struct eng_cmd_s *cmd;

    if (!rte_ring_dequeue(ring, (void **) &cmd)) {

        cmd->rsp = cmd->handler(cmd);

        while (rte_ring_enqueue(cmd->rsp_ring, cmd))
            rte_pause();
        ret = 1;
    }
    return ret;
}

/*
 *
 */
int
eng_cmd_request(unsigned thread_id,
                const char *name,
                void *arg,
                unsigned len)
{
    struct eng_cmd_mng_s *mng = find_mng();
    struct eng_cmd_handler_s key, *handle;
    struct eng_cmd_s *cmd;

    len = RTE_MIN(len, sizeof(cmd->data));
    if (!len || !arg) {
        len = 0;
        arg = NULL;
    }

    ENG_DEBUG(CORE, "start thread:%u name:%s arg:%p len:%u",
              thread_id, name, arg, len);

    key.name = name;
    handle = RB_FIND(eng_cmd_tree_s, &mng->cmd_tree, &key);

    if (!mng || !handle) {
        ENG_ERR(CORE, "invalid mng:%p handle:%p", mng, handle);
        return -EINVAL;
    }
    if (!eng_thread_is_valid(thread_id)) {
        ENG_ERR(CORE, "invalid thread:%u", thread_id);
        return -EINVAL;
    }
    if (!mng->threads[thread_id]) {
        ENG_ERR(CORE, "nothing cmd task:%u", thread_id);
        return -EINVAL;
    }

    int client_id = attach(mng);
    if (client_id < 0)
        return client_id;

    /* clean old responses */
    while (!rte_ring_dequeue(mng->rsp[client_id], (void **) &cmd))
        rte_pause();

    cmd = &mng->cmd_pool[client_id];
    cmd->handler = handle->handler;
    cmd->rsp_ring = mng->rsp[client_id];

    if (arg) {
        cmd->len = len;
        rte_memcpy(cmd->data, arg, len);
    } else {
        cmd->len = 0;
    }

    while (rte_ring_enqueue(mng->threads[thread_id], cmd))
        rte_pause();

    while (rte_ring_dequeue(mng->rsp[client_id], (void **) &cmd))
        rte_pause();

    if (cmd->len)
        rte_memcpy(arg, cmd->data, cmd->len);

    int ret = cmd->rsp;

    detach(mng);
    return ret;
}
