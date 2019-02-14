
#include <string.h>

#include <rte_spinlock.h>
#include <rte_memzone.h>
#include <rte_malloc.h>

#include <eng_thread.h>

#include "global_db.h"
#include "app_modules.h"

struct app_global_db_s {
    rte_spinlock_t lock;
    unsigned nb_threads;
    unsigned _reserved;
    const struct rte_memzone *mz;

    struct eng_thread_s *threads[RTE_MAX_LCORE];
};

#define ENG_MZ_NAME_GLOBAL_DB	"GlobalDb"

static struct app_global_db_s *GlobalDb;

/*
 *
 */
int
app_global_db_init(void)
{
    const struct rte_memzone *mz;
    struct app_global_db_s *db;
    int ret = -1;

    ENG_DEBUG(GLOBALDB, "start.");

    db = GlobalDb;
    if (!db) {
        mz = rte_memzone_reserve(ENG_MZ_NAME_GLOBAL_DB,
                                 sizeof(*db),
                                 rte_socket_id(),
                                 RTE_MEMZONE_1GB | RTE_MEMZONE_SIZE_HINT_ONLY);
        if (!mz) {
            ENG_ERR(GLOBALDB, "failed in rte_memzone_reserve()");
            goto end;
        }
        db = mz->addr;
        memset(db, 0, sizeof(*db));

        db->mz = mz;
        /* create sub DB */
        rte_spinlock_init(&db->lock);
        GlobalDb = db;
        ret = 0;
    }

 end:
    ENG_DEBUG(GLOBALDB, "end. ret:%d", ret);
    return ret;
}

/*
 *
 */
struct app_global_db_s *
app_global_db_find(void)
{
    const struct rte_memzone *mz;
    struct app_global_db_s *db = GlobalDb;

    ENG_DEBUG(GLOBALDB, "start.");

    if (!db) {
        mz = rte_memzone_lookup(ENG_MZ_NAME_GLOBAL_DB);
        if (mz) {
            db = mz->addr;
            GlobalDb = db;
        }
    }

    ENG_DEBUG(GLOBALDB, "end. db:%p", db);
    return db;
}

int
app_global_db_add_task(const struct eng_task_s *task)
{
    struct app_global_db_s *db = app_global_db_find();
    int ret = -1;

    ENG_DEBUG(GLOBALDB, "start. th:%s id:%u lcore:%u task:%s",
              task->th->name,
              task->th->thread_id,
              task->th->lcore_id,
              task->name);

    if (db->nb_threads <= task->th->thread_id) {
        db->nb_threads = task->th->thread_id + 1;
        db->threads[task->th->thread_id] = task->th;
    }
    ret = 0;

    ENG_DEBUG(GLOBALDB, "end. ret:%d", ret);
    return ret;
}
