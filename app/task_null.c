

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

    if (!task->in_port || task->nb_out_ports != 1) {
        ENG_ERR(APP,
                "%s invalid ports. in_port:%p out_ports:%u\n",
                __func__, task->in_port, task->nb_out_ports);
    } else {
        ret = app_global_db_add_task(task);
    }

    ENG_DEBUG(APP, "%s end. ret:%d\n", __func__, ret);
    return ret;
}

static char MbufSentinel[1024] __rte_cache_aligned;

static unsigned
NullTaskEntry(struct eng_thread_s *th __rte_unused,
              struct eng_task_s *task,
              uint64_t now __rte_unused)
{
    unsigned nb, nb_pkt = 0;
    struct rte_mbuf *buff[32 + 1];

    while((nb = eng_port_recv(task->in_port, buff, RTE_DIM(buff) - 1)) > 0) {
        buff[nb] = (struct rte_mbuf *) MbufSentinel;

        unsigned shift = ((RTE_DIM(buff) - 1) - nb);
        uint64_t mask = UINT64_C(-1);

        mask <<= shift;
        mask >>= shift;
        eng_port_send_bulk(task->out_ports[0], buff, mask);

        nb_pkt += nb;
    }
    return nb_pkt;
}

static const struct eng_addon_s Addon = {
    .name       = "NullTask",
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
