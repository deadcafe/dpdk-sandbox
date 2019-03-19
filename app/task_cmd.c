
#include <errno.h>

#include <eng_thread.h>
#include <eng_addon.h>
#include <eng_cmd.h>

#include "app_modules.h"
#include "global_db.h"
#include "task_cmd.h"
#include "app_mbuf.h"

static int
CmdTaskInit(struct eng_conf_db_s *conf __rte_unused,
            struct eng_thread_s *th,
            struct eng_task_s *task)
{
    if (!task->in_port ||
        task->in_port->type != ENG_PORT_TYPE_RING)
        return -EINVAL;

    return eng_cmd_ring_register(th->thread_id, task->in_port->ring);
}

static unsigned
CmdTaskEntry(struct eng_thread_s *th __rte_unused,
             struct eng_task_s *task,
             uint64_t now __rte_unused)
{
    return eng_cmd_exec(task->in_port->ring);
}

static const struct eng_addon_s Addon = {
    .name       = "TkCmd",
    .task_init  = CmdTaskInit,
    .task_entry = CmdTaskEntry,
};

static struct eng_addon_constructor_s AddonConstructor = {
    .addon = &Addon,
};

void
app_task_cmd_register(void)
{
    eng_addon_register(&AddonConstructor);
}
