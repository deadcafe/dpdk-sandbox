
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#include <rte_log.h>

/* engine APIs */
#include <eng_conf.h>
#include <eng_addon.h>
#include <eng_thread.h>
#include <eng_log.h>

#include "app_modules.h"
#include "global_db.h"
#include "task_null.h"
#include "task_busy.h"


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
    (void) sig_no;

    /* not yet */
}

static struct eng_signal_s EngSignal = {
    .handler = signal_handler,
};

static int
primay_process(const char *prog,
               const char *fconf,
               struct eng_signal_s *eng_signal)
{
    int ret = -1;
    struct eng_conf_db_s *db = eng_conf_create("Deadcafe");
    if (!db) {
        fprintf(stderr, "cannot create configuration DB.\n");
        goto end;
    }

    /*
     * apps
     */
    app_task_null_register();
    app_task_busy_register();

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

    if (sigisemptyset(&eng_signal->sigset)) {
        if (sigprocmask(SIG_BLOCK, &eng_signal->sigset, NULL)) {
            fprintf(stderr, "failed to set procmask\n");
            goto end;
        }
    }

    db_dump(db);

    fprintf(stderr, "begin init\n");
    ret = eng_conf_init_rte(db, prog);
    if (0 < ret) {
        ret = app_global_db_init();
        if (ret)
            goto end;
        /*
         * app log
         */
        eng_log_register(ENG_LOG_ID_APP, ENG_LOG_NAME_APP);
        eng_log_register(ENG_LOG_ID_GLOBALDB, ENG_LOG_NAME_GLOBALDB);
        eng_log_register(ENG_LOG_ID_TASKNULL, ENG_LOG_NAME_TASKNULL);
        eng_log_register(ENG_LOG_ID_TASKBUSY, ENG_LOG_NAME_TASKBUSY);

        fprintf(stderr, "begin launching\n");
        ret = eng_thread_launch(db, eng_signal);
    }

 end:
    if (db)
        eng_conf_destroy(db);
    return ret;
}

static int
secondary_process(struct eng_signal_s *eng_signal)
{
    (void) eng_signal;

    /* XXX: not yet */
    return -1;
}

static void
usage(const char *prog)
{
    fprintf(stderr,
            "%s [-f ConfigFile] [-n NUM] [-2] [-s | -c | -a | -l | -r]\n"
            "-s	spinlock(default)\n"
            "-c	CAS\n"
            "-a	Atomic\n"
            "-l	HLE\n"
            "-r	RTM\n",
            prog);
}

int
main(int ac,
     char **av)
{
    char *prog = strrchr(av[0], '/');
    int opt;
    char *fname = NULL;
    bool is_2nd = false;
    enum busy_type_e type = TYPE_SPINLOCK;
    unsigned nb = 0;

    if (prog)
        prog++;
    else
        prog = av[0];

    while ((opt = getopt(ac, av, "n:f:2scalrh")) != -1) {
        switch (opt) {
        case 'n':
            nb = atoi(optarg);
            break;

        case 'f':
            fname = optarg;
            break;

        case '2':
            is_2nd = true;
            break;

        case 's':
            type = TYPE_SPINLOCK;
            break;

        case 'c':
            type = TYPE_CAS;
            break;

        case 'a':
            type = TYPE_ATOMIC;
            break;

        case 'l':
            type = TYPE_HLE;
            break;

        case 'r':
            type = TYPE_RTM;
            break;

        case 'h':
        default:
            usage(prog);
            exit(0);
        }
    }

    if (app_task_busy_set_type(type))
        return -1;
    if (nb)
        app_task_busy_set_nb(nb);

    if (is_2nd) {
        secondary_process(&EngSignal);
    } else {
        primay_process(prog, fname, &EngSignal);
    }

    return 0;
}
