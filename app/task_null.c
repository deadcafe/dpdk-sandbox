

#include <errno.h>

#include <eng_thread.h>
#include <eng_addon.h>

#include "app_modules.h"
#include "global_db.h"
#include "task_null.h"
#include "app_mbuf.h"

/****************************************************************************
 * Null task
 ****************************************************************************/
static int
NullTaskInit(struct eng_conf_db_s *conf __rte_unused,
             struct eng_thread_s *th __rte_unused,
             struct eng_task_s *task)
{
    int ret = -EINVAL;

    if (!task->in_port) {
        ENG_ERR(APP,
                "%s nothing in-port :%p\n",
                __func__, task->in_port);
    } else {
        ret = app_global_db_add_task(task);
    }

    ENG_DEBUG(APP, "%s end. ret:%d\n", __func__, ret);
    return ret;
}

static struct rte_mbuf MbufSentinel __rte_cache_aligned;

static unsigned
NullTaskEntry(struct eng_thread_s *th __rte_unused,
              struct eng_task_s *task,
              uint64_t now __rte_unused)
{
    unsigned nb;
    struct rte_mbuf *buff[32 + 4];

    nb = eng_port_recv(task->in_port, buff, RTE_DIM(buff) - 4);
    if (nb) {
        buff[nb + 0] = &MbufSentinel;
        buff[nb + 1] = &MbufSentinel;
        buff[nb + 2] = &MbufSentinel;
        buff[nb + 3] = &MbufSentinel;

        rte_prefetch0(buff[0]);
        rte_prefetch0(buff[1]);
        rte_prefetch0(buff[2]);
        rte_prefetch0(buff[3]);

        unsigned cnt = 0;
        switch (nb % 4) {
        case 0:
            while (cnt != nb) {
                rte_prefetch0(buff[cnt + 4]);
                rte_pktmbuf_free(buff[cnt]);
                cnt++;
                /* fall-through */
        case 3:
                rte_prefetch0(buff[cnt + 4]);
                rte_pktmbuf_free(buff[cnt]);
                cnt++;
                /* fall-through */
        case 2:
                rte_prefetch0(buff[cnt + 4]);
                rte_pktmbuf_free(buff[cnt]);
                cnt++;
                /* fall-through */
        case 1:
                rte_prefetch0(buff[cnt + 4]);
                rte_pktmbuf_free(buff[cnt]);
                cnt++;
                /* fall-through */
            }
        }
    }
    return nb;
}

static const struct eng_addon_s Addon = {
    .name       = "TkNull",
    .task_init  = NullTaskInit,
    .task_entry = NullTaskEntry,
};

static struct eng_addon_constructor_s AddonConstructor = {
    .addon = &Addon,
};

void
app_task_null_register(void)
{
    eng_addon_register(&AddonConstructor);
}
