
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#include <papi.h>

#include <rte_log.h>
#include <rte_errno.h>

/* engine APIs */
#include <eng_conf.h>
#include <eng_addon.h>
#include <eng_thread.h>
#include <eng_log.h>
#include <eng_cli.h>
#include <eng_cmd.h>

#include "app_modules.h"
#include "global_db.h"
#include "task_null.h"
#include "task_busy.h"
#include "task_rx.h"
#include "task_tx.h"
#include "task_hash.h"
#include "task_cmd.h"
#include "cmd_perf.h"

/****************************************************************************
 *
 ****************************************************************************/
static int
_conf_dump(const char *db_name,
          const struct eng_conf_s *conf,
          void *arg)
{
    (void) db_name;
    (void) arg;
    fprintf(stderr, "%s %s\n", conf->name, conf->val);
    return 0;
}

static int
db_dump(struct eng_conf_db_s *db)
{
    return eng_conf_walk(db, _conf_dump, NULL);
}

/*
 * called from master thread
 */
static void
signal_handler(int sig_no)
{
    fprintf(stderr, "catch signal:%d\n", sig_no);

    switch (sig_no) {
    case SIGINT:
        eng_thread_master_exit();
        break;

    case SIGTERM:
        eng_thread_master_exit();
        rte_exit(1, "xxx");
        break;

    default:
        break;
    }
}

static struct eng_signal_s EngSignal = {
    .handler = signal_handler,
};

static int
init_papi(void)
{
    int ret = PAPI_library_init(PAPI_VER_CURRENT);
    if (ret < 0) {
        fprintf(stderr, "failed init PAPI library. %d\n", ret);
        goto end;
    } else if (ret != PAPI_VER_CURRENT) {
        fprintf(stderr, "PAPI library version mismatch\n");
        ret = -ENODEV;
        goto end;
    }

    if (PAPI_is_initialized() != PAPI_LOW_LEVEL_INITED)
        fprintf(stderr, "PAPI is un-initialized.\n");

    ret = PAPI_thread_init(pthread_self);
    if (ret != PAPI_OK) {
        fprintf(stderr, "not supported PAPI threads. %d\n", ret);
        goto end;
    }

    ret = PAPI_num_counters();
    if (ret <= 0) {
        fprintf(stderr, "not supported PAPI counters. %d\n", ret);
        goto end;
    }
    fprintf(stderr, "PAPI counters:%d\n", ret);
    ret = 0;

 end:
    return ret;
}

static int
primay_process(const char *prog,
               const char *fconf,
               struct eng_signal_s *eng_signal)
{
    struct eng_conf_db_s *db = NULL;

    int ret = init_papi();
    if (ret)
        goto end;

    db = eng_conf_create("Deadcafe");
    if (!db) {
        fprintf(stderr, "cannot create configuration DB.\n");
        ret = -1;
        goto end;
    }

    /*
     * apps
     */
    app_task_null_register();
    app_task_busy_register();
    app_task_rx_register();
    app_task_tx_register();
    app_task_hash_register();
    app_task_cmd_register();

    if (eng_conf_setup_addon(db)) {
        fprintf(stderr, "failed to setup addon.\n");
        goto end;
    }

    if (eng_conf_read_file(db, fconf)) {
        fprintf(stderr, "failed to read config file.\n");
        goto end;
    }

    sigemptyset(&eng_signal->sigset);

    /*
     * set some signals ,,, not yet
     */
    sigaddset(&eng_signal->sigset, SIGINT);
    sigaddset(&eng_signal->sigset, SIGTERM);

    if (!sigisemptyset(&eng_signal->sigset)) {
        if (sigprocmask(SIG_BLOCK, &eng_signal->sigset, NULL)) {
            fprintf(stderr, "failed to set procmask\n");
            goto end;
        }
    }

    db_dump(db);

    fprintf(stderr, "begin init\n");
    ret = eng_conf_init_rte(db, prog);
    if (0 < ret) {
        /*
         * app log
         */
        eng_log_register(ENG_LOG_ID_APP, ENG_LOG_NAME_APP);
        eng_log_register(ENG_LOG_ID_GLOBALDB, ENG_LOG_NAME_GLOBALDB);
        eng_log_register(ENG_LOG_ID_TASKNULL, ENG_LOG_NAME_TASKNULL);
        eng_log_register(ENG_LOG_ID_TASKBUSY, ENG_LOG_NAME_TASKBUSY);
        eng_log_register(ENG_LOG_ID_TASKRX,   ENG_LOG_NAME_TASKRX);
        eng_log_register(ENG_LOG_ID_TASKTX,   ENG_LOG_NAME_TASKTX);
        eng_log_register(ENG_LOG_ID_TASKCMD,  ENG_LOG_NAME_TASKCMD);

        ret = app_global_db_init();
        if (ret)
            goto end;

        ret = eng_cmd_init();
        if (ret)
            goto end;

        ret = cmd_perf_init();
        if (ret)
            goto end;

        fprintf(stderr, "begin launching\n");
        ret = eng_thread_launch(db, eng_signal);
    }

 end:
    if (db)
        eng_conf_destroy(db);
    return ret;
}

static const char *LogLevel[] = {
    "emerg",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "info",
    "debug",
};


static inline int
str2loglevel(const char *name)
{
    for (unsigned i = 0; i < RTE_DIM(LogLevel); i++) {
        if (!strncasecmp(LogLevel[i], name, strlen(LogLevel[i])))
            return i;
    }
    return -1;
}

static int
secondary_process(const char *prog,
                  const char *hname,
                  struct eng_signal_s *eng_signal)
{
    (void) eng_signal;
    int ret = eng_thread_second(prog, 0);

    if (!ret)
        ret = eng_cmd_loop(NULL, hname);
    return ret;
}

static void
usage(const char *prog)
{
    fprintf(stderr,
            "%s [-f FNAME] [-2]\n"
            "-f FNAME	configuration file name\n"
            "-i HNAME	history file name\n"
            "-2		Secondary process mode\n",
            prog);
}

int
main(int ac,
     char **av)
{
    int opt;
    char *fname = NULL;
    bool is_2nd = false;
    char *prog = strrchr(av[0], '/');
    char *hname = "./hoge.history";

    if (prog)
        prog++;
    else
        prog = av[0];

    while ((opt = getopt(ac, av, "f:i:2h")) != -1) {
        switch (opt) {
        case 'f':
            fname = optarg;
            break;

        case '2':
            is_2nd = true;
            break;

        case 'i':
            hname = optarg;
            break;

        case 'h':
        default:
            usage(prog);
            exit(0);
        }
    }

    if (is_2nd)
        secondary_process(prog, hname, &EngSignal);
    else
        primay_process(prog, fname, &EngSignal);

    return 0;
}
