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
 * @file        eng_conf.c
 * @brief       Engine config
 */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <sys/tree.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ether.h>

#include "eng_mbuf.h"
#include "eng_thread.h"
#include "eng_log.h"

#include "conf.h"

#define TREE_INIT(x)		RB_INIT(x)
#define TREE_ENTRY(x)		RB_ENTRY(x)
#define TREE_HEAD(x,y)		RB_HEAD(x,y)
#define TREE_GENERATE(x,y,z,c)	RB_GENERATE_STATIC(x,y,z,c)
#define TREE_FIND(x,y,z)	RB_FIND(x,y,z)
#define TREE_NFIND(x,y,z)	RB_NFIND(x,y,z)
#define TREE_INSERT(x,y,z)	RB_INSERT(x,y,z)
#define TREE_REMOVE(x,y,z)	RB_REMOVE(x,y,z)
#define TREE_ROOT(x)		RB_ROOT(x)
#define TREE_FOREACH(x,y,z)	RB_FOREACH(x,y,z)
#define TREE_NEXT(x,y,z)	RB_NEXT(x,y,z)

#ifndef RTE_MAX_LCORE
# define RTE_MAX_LCORE		128
#endif

#ifndef RTE_MAX_ETHPORTS
# define RTE_MAX_ETHPORTS	32
#endif

/*
 *
 */
struct eng_conf_node_s {
    struct eng_conf_s conf;

    TREE_ENTRY(eng_conf_node_s) entry;
    char buff[0];
};

TREE_HEAD(eng_conf_head_s, eng_conf_node_s);

struct eng_conf_db_s {
    char name[ENG_CONF_STRING_MAX];
    struct eng_conf_head_s head;
};

static inline int
cmp_conf(const struct eng_conf_node_s *node0,
         const struct eng_conf_node_s *node1)
{
    return strncmp(node0->conf.name, node1->conf.name, ENG_CONF_STRING_MAX);
}

TREE_GENERATE(eng_conf_head_s, eng_conf_node_s, entry, cmp_conf);

/*****************************************************************************
 * Raw operations
 *****************************************************************************/
/*
 *
 */
static inline struct eng_conf_node_s *
conf_find(struct eng_conf_head_s *head,
          const char *name)
{
    if (name) {
        struct eng_conf_node_s key;

        key.conf.name = name;
        return TREE_FIND(eng_conf_head_s, head, &key);
    }
    return NULL;
}

/*
 *
 */
static inline struct eng_conf_node_s *
conf_nfind(struct eng_conf_head_s *head,
           const char *name)
{
    if (name) {
        struct eng_conf_node_s key;

        key.conf.name = name;
        return TREE_NFIND(eng_conf_head_s, head, &key);
    }
    return NULL;
}

/*
 *
 */
static inline char *
cat_names(char *buff,
          int bsize,
          const char *array[])
{
    int n = 0;

    for (int i = 0; n < bsize && array[i]; i++)
        n += snprintf(&buff[n], bsize - n, "/%s", array[i]);
    if (n >= bsize)
        return NULL;
    return buff;
}

/*
 *
 */
static inline void
destroy_conf(struct eng_conf_head_s *head,
             struct eng_conf_node_s *node)
{
    TREE_REMOVE(eng_conf_head_s, head, node);
    node->conf.val  = NULL;
    node->conf.name = NULL;
    free(node);
}

/*
 *
 */
static const struct eng_conf_node_s *
conf_add(struct eng_conf_head_s *head,
         const char *name,
         const char *val)
{
    struct eng_conf_node_s *node;

    if (!name)
        return NULL;

    node = malloc(sizeof(*node) + (ENG_CONF_STRING_MAX * 2));
    if (node) {
        char *name_p = &node->buff[0];

        strncpy(name_p, name, ENG_CONF_STRING_MAX - 1);
        name_p[ENG_CONF_STRING_MAX - 1] = '\0';
        node->conf.name = name_p;

        if (val) {
            char *val_p  = &node->buff[ENG_CONF_STRING_MAX];

            strncpy(val_p, val, ENG_CONF_STRING_MAX - 1);
            val_p[ENG_CONF_STRING_MAX - 1] = '\0';
            node->conf.val = val_p;
        } else {
            node->conf.val = NULL;
        }

        if (TREE_INSERT(eng_conf_head_s, head, node)) {
            free(node);
            node = NULL;
        }
    }
    return node;
}

/*
 *
 */
static const struct eng_conf_node_s *
conf_update(struct eng_conf_head_s *head,
            const char *name,
            const char *val)
{
    if (!name)
        return NULL;

    struct eng_conf_node_s *node = conf_find(head, name);
    if (node) {
        if (val) {
            char *val_p  = &node->buff[ENG_CONF_STRING_MAX];

            strncpy(val_p, val, ENG_CONF_STRING_MAX - 1);
            val_p[ENG_CONF_STRING_MAX - 1] = '\0';
            node->conf.val = val_p;
        } else {
            node->conf.val = NULL;
        }
        return node;
    }
    return conf_add(head, name, val);
}

/*****************************************************************************
 * Basic Operations
 *****************************************************************************/
/*
 *
 */
const struct eng_conf_s *
eng_conf_find(struct eng_conf_db_s *db,
              const char *key)
{
    struct eng_conf_node_s *node;

    node = conf_find(&db->head, key);
    if (node) {
        ENG_DEBUG(CORE, "found %s %s", key, node->conf.val);
        return &node->conf;
    }

    ENG_INFO(CORE, "not found %s", key);
    return NULL;
}

/*
 *
 */
const char *
eng_conf_find_val(struct eng_conf_db_s *db,
                  const char *key)
{
    struct eng_conf_node_s *node;

    node = conf_find(&db->head, key);
    if (node) {
        ENG_DEBUG(CORE, "found %s %s", key, node->conf.val);
        return node->conf.val;
    }

    ENG_INFO(CORE, "not found %s", key);
    return NULL;
}

/*
 *
 */
const struct eng_conf_s *
eng_conf_nfind(struct eng_conf_db_s *db,
               const char *key)
{
    struct eng_conf_node_s *node;

    node = conf_nfind(&db->head, key);
    if (node) {
        ENG_DEBUG(CORE, "found %s %s", key, node->conf.val);
        return &node->conf;
    }
    ENG_INFO(CORE, "not found %s", key);
    return NULL;
}

/*
 *
 */
const struct eng_conf_s *
eng_conf_add(struct eng_conf_db_s *db,
             const char *key,
             const char *val)
{
    const struct eng_conf_node_s *node = conf_add(&db->head, key, val);
    if (node) {
        ENG_DEBUG(CORE, "added %s %s", key, val);
        return &node->conf;
    }
    ENG_ERR(CORE, "failed to add %s", key);
    return NULL;
}

/*
 *
 */
const struct eng_conf_s *
eng_conf_update(struct eng_conf_db_s *db,
                const char *key,
                const char *val)
{
    const struct eng_conf_node_s *node = conf_update(&db->head, key, val);
    if (node)
        return &node->conf;
    return NULL;
}

/*
 *
 */
void
eng_conf_delete(struct eng_conf_db_s *db,
                const char *key)
{
    struct eng_conf_node_s *node = conf_find(&db->head, key);

    if (node)
        destroy_conf(&db->head, node);
}

/*
 *
 */
void
eng_conf_delete_all(struct eng_conf_db_s *db)
{
    struct eng_conf_node_s *node;

    while ((node = TREE_ROOT(&db->head)) != NULL)
        destroy_conf(&db->head, node);
}

/*
 *
 */
int
eng_conf_walk(struct eng_conf_db_s *db,
              int (*cb)(const char *db_name,
                        const struct eng_conf_s *,
                        void *arg),
              void *arg)
{
    int ret = -1;
    struct eng_conf_node_s *node;

    TREE_FOREACH(node, eng_conf_head_s, &db->head) {
        ret = cb(db->name, &node->conf, arg);
        if (ret)
            break;
    }
    return ret;
}

/*
 *
 */
struct eng_conf_db_s *
eng_conf_create(const char *db_name)
{
    struct eng_conf_db_s *db;

    db = malloc(sizeof(*db));
    if (db) {
        snprintf(db->name, sizeof(db->name), "%s", db_name);
        TREE_INIT(&db->head);
    }
    return db;
}

/*
 *
 */
void
eng_conf_destroy(struct eng_conf_db_s *db)
{
    if (db) {
        eng_conf_delete_all(db);
        free(db);
    }
}

/******************************************************************************
 *	Generic Operations
 ******************************************************************************/
/*
 *
 */
static inline void
eng_conf_dir_delete(struct eng_conf_db_s *db,
                    const char *key)
{
    char name[ENG_CONF_STRING_MAX];
    struct eng_conf_node_s *node;

    if (!key)
        return;

    snprintf(name, sizeof(name), "%s/", key);
    unsigned len = strlen(name);
    while ((node = conf_nfind(&db->head, name)) != NULL) {
        if (strncmp(name, node->conf.name, len))
            break;
        destroy_conf(&db->head, node);
    }
    name[len] = '\0';
    node = conf_find(&db->head, name);
    if (node)
        destroy_conf(&db->head, node);
}

static char *
find_head(char *buff)
{
    char *p = buff;

    while (*p != '\0') {
        if (!isspace(*p))
            return p;
        p++;
    }
    return NULL;
}

static char *
next_head(char *head)
{
    char *p = head;

    while (*p != '\0') {
        if (isspace(*p)) {
            *p = '\0';
            return find_head(++p);
        }
        p++;
    }
    return NULL;
}

static void
cut_tail(char *h)
{
    unsigned len = strlen(h);

    while (len) {
        len--;

        if (!isspace(h[len]))
            break;

        h[len] = '\0';
    }
}

static int
tokens(char *buff,
       char **name_p,
       char **val_p)
{
    char *name = find_head(buff);
    char *val;

    if (name) {
        val = next_head(name);
        if (val)
            cut_tail(val);
    } else
        val = NULL;

    if (name && *name == '#') {
        name = NULL;
        val = NULL;
    }

    *name_p = name;
    *val_p  = val;

    return 0;
}

int
eng_conf_read_file(struct eng_conf_db_s *db,
                   const char *path)
{
    if (!path || !db)
        return -EINVAL;

    FILE *fp = fopen(path, "r");
    if (!fp)
        return -errno;

    char buff[1024];
    char *s;
    unsigned line = 0;

    while ((s = fgets(buff, sizeof(buff), fp)) != NULL) {
        char *name, *val;

        line++;
        tokens(buff, &name, &val);
        if (name) {
            if (!eng_conf_add(db, name, val)) {
                ENG_NOTICE(CORE, "(%u) ignored:%s", line, name);
            }
        }
    }
    fclose(fp);
    return 0;
}

/******************************************************************************
 *	Directory Operations
 ******************************************************************************/

/*
 * token separator: ','
 */
static const char *
get_token(char *dst,
          size_t size,
          const char *src)
{
    memset(dst, 0, size);

    while (*src != '\0' && isspace(*src))
        ++src;

    if (*src == '\0') {
        src = NULL;
        goto end;
    }

    for (unsigned i = 0; i < size && *src != '\0'; i++, src++) {
        if (*src == ',') {
            src++;
            goto end;
        }
        dst[i] = *src;
    }
    src = NULL;
 end:
    return src;
}

/*
 * ID: 0 ~ 63
 * 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
 * 0-15,16-63,
 * 0 < size <= 64
 */
unsigned
eng_conf_list(struct eng_conf_db_s *db,
              const char *key,
              char *list,
              unsigned size)
{
    const char *v = eng_conf_find_val(db, key);
    unsigned nb = 0;

    ENG_DEBUG(CORE, "key:%s val:%s", key, v);

    while (v && size) {
        unsigned len = size - 1;

        v = get_token(list, len, v);

        len = strlen(list);
        if (!len)
            break;
        list += (len + 1);
        size -= (len + 1);
        nb++;
    }
    return nb;
}

/*
 * /BASE_NAME/TARGET_NAME
 *
 */
static struct eng_conf_node_s *
eng_conf_dir(struct eng_conf_db_s *db,
             const char *base,
             char *target,
             size_t size)
{
    struct eng_conf_node_s *node;
    char name[size];

    snprintf(name, size, "%s/", base);

    node = conf_nfind(&db->head, name);
    if (node) {
        size_t len = strlen(name);

        if (strncmp(name, node->conf.name, len)) {
            node = NULL;
        } else {
            snprintf(target, size, "%s", &node->conf.name[len]);

            char *p = strstr(target, "/");
            if (p)
                *p = '\0';
            else
                node = NULL;
        }
    }
    return node;
}

static struct eng_conf_node_s *
eng_conf_next_dir(struct eng_conf_db_s *db,
                  struct eng_conf_node_s *node,
                  const char *base,
                  char *target,
                  size_t size)
{
    char name[size];
    size_t len;
    (void) db;

    snprintf(name, size, "%s/%s/", base, target);
    len = strlen(name);

    while ((node = TREE_NEXT(eng_conf_head_s, &db->head, node)) != NULL) {

        ENG_DEBUG(CORE, "key:%s name:%s", name, node->conf.name);

        if (strncmp(name, node->conf.name, len))
            break;
    }

    if (node) {
        snprintf(name, size, "%s/", base);
        len = strlen(name);

        if (strncmp(name, node->conf.name, len)) {
            node = NULL;
        } else {
            snprintf(target, size, "%s",
                     &node->conf.name[len]);
            char *p = strstr(target, "/");
            if (p)
                *p = '\0';
            else
                node = NULL;
        }
    }
    return node;
}


/*****************************************************************************
 *	DPDK initializing:
 *****************************************************************************/

#define ARRAYOF(_a)	(sizeof(_a)/sizeof(_a[0]))

#define SET_ARG(_ac,_av,_v)                                     \
    do {                                                        \
        if (ARRAYOF(_av) - 1 > (unsigned) (_ac)) {              \
            (_av)[(_ac)] = (_v);                                \
            (_ac) += 1;                                         \
            (_av)[(_ac)] = NULL;                                \
        }                                                       \
    } while (0)

/*
 *
 */
#define RTE_OPTIONS	"/rte-options"

const char *
eng_conf_get_rte_options(struct eng_conf_db_s *db)
{
    return eng_conf_get_string(db, RTE_OPTIONS);
}

static int
store_rte_options(struct eng_conf_db_s *db,
                  int ac,
                  char *av[])
{
    char buff[1024];
    unsigned len = 0;

    for (int i = 0; i < ac && len < sizeof(buff); i++)
        len += snprintf(&buff[len], sizeof(buff) - len, " %s", av[i]);

    if (len >= sizeof(buff))
        return -1;
#if 1
    fprintf(stderr, RTE_OPTIONS " %s\n", &buff[1]);
#endif

    if (!eng_conf_update(db, RTE_OPTIONS, &buff[1]))
        return -1;
    return 0;
}

static void
dump_args(const char *msg,
          int ac,
          char **av)
{
    fprintf(stderr, "%s\n", msg);
    for (int i = 0; i < ac; i++)
        fprintf(stderr, "\t%d %s\n", i, av[i]);
}

/*
 *
 */
int
eng_conf_init_rte(struct eng_conf_db_s *db,
                  const char *prog)
{
    char *args;
    int ac = 0;
    char *av[64];
    size_t size = 1024 * 4;
    int ret = -1;

    args = calloc(1, size);
    if (args) {
        char *p = args;
        size_t len;
        unsigned nb_th;

        len = snprintf(p, size, "%s", prog);
        SET_ARG(ac, av, p);
        p += (len + 1);
        size -= (len + 1);

        char lcores[256];
        nb_th = eng_thread_lcores(db, lcores, sizeof(lcores));
        if (nb_th) {
            len = snprintf(p, size, "--lcores=%s", lcores);
            SET_ARG(ac, av, p);
            p += (len + 1);
            size -= (len + 1);

            int master = eng_conf_master_lcore(db);
            if (master >= 0) {
                len = snprintf(p, size, "--master-lcore=%d", master);
                SET_ARG(ac, av, p);
                p += (len + 1);
                size -= (len + 1);
            }
        }

        /*
         * XXX: read rte options from DB, not yet
         */
        {
            const char *opt = eng_conf_get_rte_options(db);

            if (opt) {
                len = snprintf(p, size, "%s", opt);
                SET_ARG(ac, av, p);
                p += (len + 1);
                size -= (len + 1);;;
            }
        }

        store_rte_options(db, ac, av);

        optind = 0;	/* reset getopt */
        ret = rte_eal_init(ac, av);

        if (ret < 0) {
            fprintf(stderr, "init faile. ret:%d %s",
                    ret, rte_strerror(rte_errno));
            dump_args("eal options:", ac, av);
        } else {
            eng_log_init(RTE_LOG_DEBUG, RTE_LOG_DEBUG, true);
        }

        free(args);
    }
    return ret;
}

/* master */
#define	MASTER	"/master-lcore"

/*
 *
 */
int
eng_conf_master_lcore(struct eng_conf_db_s *db)
{
    return eng_conf_get_integer(db, USE_ERR_LEVEL, MASTER);
}

/*
 *
 */
int
eng_conf_add_master_lcore(struct eng_conf_db_s *db,
                          int lcore_id)
{
    return eng_conf_add_integer(db, lcore_id, MASTER);
}

/* lcore */
#define LCORE	"/lcore"

/*
 *
 */
const char *
eng_conf_lcore_thread(struct eng_conf_db_s *db,
                      unsigned lcore_id)
{
    return eng_conf_get_string(db, "%s/%u", LCORE, lcore_id);
}

/*
 *
 */
int
eng_conf_add_lcore_thread(struct eng_conf_db_s *db,
                          unsigned lcore_id,
                          const char *name)
{
    return eng_conf_add_string(db, name, "%s/%u", LCORE, lcore_id);
}

/* thread */
#define	THREAD	"/thread"

/*
 *
 */
bool
eng_conf_is_master_thread(struct eng_conf_db_s *db,
                          const char *name)
{
    return eng_conf_get_boolean(db, "%s/%s/is_master", THREAD, name);
}

/*
 *
 */
int
eng_conf_add_master_thread(struct eng_conf_db_s *db,
                           const char *name)
{
    return eng_conf_add_boolean(db, "%s/%s/is_master", THREAD, name);
}

/*
 *
 */
int
eng_conf_thread_lcore(struct eng_conf_db_s *db,
                      const char *name)
{
    return eng_conf_get_integer(db, USE_ERR_LEVEL, "%s/%s/lcore", THREAD, name);
}

/*
 *
 */
int
eng_conf_add_thread_lcore(struct eng_conf_db_s *db,
                          const char *name,
                          int lcore_id)
{
    return eng_conf_add_integer(db, lcore_id, "%s/%s/lcore", THREAD, name);
}

/*
 *
 */
struct eng_conf_node_s *
eng_conf_thread_name_next(struct eng_conf_db_s *db,
                          struct eng_conf_node_s *node,
                          char *buff,
                          size_t buff_size)
{
    if (node)
        return eng_conf_next_dir(db, node, THREAD, buff, buff_size);
    return eng_conf_dir(db, THREAD, buff, buff_size);
}

/*
 *
 */
const char *
eng_conf_thread_mbufpool(struct eng_conf_db_s *db,
                         const char *name)
{
    return eng_conf_get_string(db, "%s/%s/mbufpool", THREAD, name);
}

/*
 *
 */
int
eng_conf_add_thread_mbufpool(struct eng_conf_db_s *db,
                             const char *name,
                             const char *mbufpool)
{
    return eng_conf_add_string(db, mbufpool, "%s/%s/mbufpool", THREAD, name);
}

/*
 *
 */
int
eng_conf_thread_task_list(struct eng_conf_db_s *db,
                          const char *th_name,
                          const char **tasks,
                          unsigned max_tasks,
                          char *buff,
                          size_t buff_size)
{
    return eng_conf_get_string_list(db, tasks, max_tasks, buff, buff_size,
                                    "%s/%s/tasks", THREAD, th_name);
}

/*
 *
 */
int
eng_conf_add_thread_task(struct eng_conf_db_s *db,
                         const char *th_name,
                         const char *task)
{
    return eng_conf_apend_string_list(db, task,
                                      "%s/%s/tasks", THREAD, th_name);
}

/* task */
#define TASK	"/task"

/*
 *
 */
const char *
eng_conf_task_addon(struct eng_conf_db_s *db,
                    const char *name)
{
    return eng_conf_get_string(db, "%s/%s/addon", TASK, name);
}

/*
 *
 */
int
eng_conf_add_task_addon(struct eng_conf_db_s *db,
                        const char *name,
                        const char *addon)
{
    return eng_conf_add_string(db, addon, "%s/%s/addon", TASK, name);
}

/*
 *
 */
const char *
eng_conf_task_in_port(struct eng_conf_db_s *db,
                      const char *name)
{
    return eng_conf_get_string(db, "%s/%s/in-port", TASK, name);
}

/*
 *
 */
int
eng_conf_add_task_in_port(struct eng_conf_db_s *db,
                          const char *name,
                          const char *port)
{
    return eng_conf_add_string(db, port, "%s/%s/in-port", TASK, name);
}

/*
 *
 */
int
eng_conf_task_out_port_list(struct eng_conf_db_s *db,
                            const char *name,
                            const char **ports,
                            unsigned max_ports,
                            char *buff,
                            size_t buff_size)
{
    return eng_conf_get_string_list(db, ports, max_ports, buff, buff_size,
                                    "%s/%s/out-ports", TASK, name);
}

/*
 *
 */
int
eng_conf_add_task_out_port(struct eng_conf_db_s *db,
                           const char *name,
                           const char *port)
{
    return eng_conf_apend_string_list(db, port,
                                      "%s/%s/out-ports", TASK, name);
}

struct eng_conf_node_s *
eng_conf_task_name_next(struct eng_conf_db_s *db,
                        struct eng_conf_node_s *node,
                        char *buff,
                        size_t buff_size)

{
    if (node)
        return eng_conf_next_dir(db, node, TASK, buff, buff_size);
    return eng_conf_dir(db, TASK, buff, buff_size);
}

/*
 * ring
 */
#define RING	"/ring"

int
eng_conf_ring_size(struct eng_conf_db_s *db,
                   const char *name)
{
    return eng_conf_get_integer(db, USE_ERR_LEVEL, "%s/%s/size", RING, name);
}

/*
 *
 */
int
eng_conf_add_ring_size(struct eng_conf_db_s *db,
                       const char *name, int size)
{
    return eng_conf_add_integer(db, size, "%s/%s/size", RING, name);
}

/*
 *
 */
struct eng_conf_node_s *
eng_conf_ring_name_next(struct eng_conf_db_s *db,
                        struct eng_conf_node_s *node,
                        char *buff,
                        size_t buff_size)

{
    if (node)
        return eng_conf_next_dir(db, node, RING, buff, buff_size);
    return eng_conf_dir(db, RING, buff, buff_size);
}

/*
 * netdev
 */
#define NETDEV	"netdev"

const char *
eng_conf_netdev_type(struct eng_conf_db_s *db,
                     const char *name)
{
    return eng_conf_get_string(db, "%s/%s/type", NETDEV, name);
}

/*
 *
 */
const char *
eng_conf_netdev_id_name(struct eng_conf_db_s *db,
                        uint16_t id)
{
    return eng_conf_get_string(db, "%s/id/%u", NETDEV, id);
}

/*
 *
 */
int
eng_conf_netdev_name_id(struct eng_conf_db_s *db,
                        const char *name,
                        int use_err)
{
    return eng_conf_get_integer(db, use_err, "%s/%s/id", NETDEV, name);
}

/*
 *
 */
int
eng_conf_add_netdev_id_name(struct eng_conf_db_s *db,
                            uint16_t id,
                            const char *name)
{
    return eng_conf_add_string(db, name, "%s/id/%u", NETDEV, id);
}

/*
 *
 */
int
eng_conf_add_netdev_name_id(struct eng_conf_db_s *db,
                            const char *name,
                            uint16_t id,
                            bool with_name)
{
    if (eng_conf_add_integer(db, id, "%s/%s/id", NETDEV, name))
        return -1;
    if (with_name)
        return eng_conf_add_netdev_id_name(db, id, name);
    return 0;
}

/*
 *
 */
int
eng_conf_add_netdev_name_type(struct eng_conf_db_s *db,
                              const char *name,
                              const char *type)
{
    return eng_conf_add_string(db, type, "%s/%s/type", NETDEV, name);
}

/*
 *
 */
int
eng_conf_netdev_nb_rx_queues(struct eng_conf_db_s *db,
                             const char *name)
{
    return eng_conf_get_integer(db, USE_ERR_LEVEL,
                                "%s/%s/number_of_rx_queues", NETDEV, name);
}

/*
 *
 */
int
eng_conf_add_netdev_nb_rx_queues(struct eng_conf_db_s *db,
                                 const char *name,
                                 int rx_queues)
{
    return eng_conf_add_integer(db, rx_queues,
                                "%s/%s/number_of_rx_queues", NETDEV, name);
}

/*
 *
 */
int
eng_conf_netdev_nb_tx_queues(struct eng_conf_db_s *db,
                             const char *name)
{
    return eng_conf_get_integer(db, USE_ERR_LEVEL,
                                "%s/%s/number_of_tx_queues", NETDEV, name);
}

/*
 *
 */
int
eng_conf_add_netdev_nb_tx_queues(struct eng_conf_db_s *db,
                                 const char *name,
                                 int tx_queues)
{
        return eng_conf_add_integer(db, tx_queues,
                                    "%s/%s/number_of_tx_queues", NETDEV, name);
}

/*
 *
 */
const char *
eng_conf_netdev_mbufpool(struct eng_conf_db_s *db,
                         const char *name)
{
    return eng_conf_get_string(db, "%s/%s/mbufpool", NETDEV, name);
}

/*
 *
 */
int
eng_conf_add_netdev_mbufpool(struct eng_conf_db_s *db,
                             const char *name,
                             const char *mbufpool)
{
    return eng_conf_add_string(db, mbufpool, "%s/%s/mbufpool", NETDEV, name);
}

/*
 * XXX: conflict <netinet/ether.h>
 */
extern struct ether_addr *ether_aton_r (const char *__asc,
                                        struct ether_addr *__addr) __THROW;

int
eng_conf_netdev_mac(struct eng_conf_db_s *db,
                    const char *name,
                    struct ether_addr *addr)
{
    const char *asc = eng_conf_get_string(db, "%s/%s/mac", NETDEV, name);
    if (asc) {
        if (ether_aton_r(asc, addr))
            return 0;
    }
    return -1;
}

/*
 *
 */
int
eng_conf_add_netdev_mac(struct eng_conf_db_s *db,
                        const char *name,
                        const struct ether_addr *addr)
{
    char mac_asc[80];

    ether_format_addr(mac_asc, sizeof(mac_asc), addr);

    return eng_conf_add_string(db, mac_asc, "%s/%s/mac", NETDEV, name);
}

/*
 *
 */
const char *
eng_conf_bonding_mode(struct eng_conf_db_s *db,
                      const char *name)
{
    return eng_conf_get_string(db, "%s/%s/mode", NETDEV, name);
}

/*
 *
 */
int
eng_conf_add_bonding_mode(struct eng_conf_db_s *db,
                          const char *name,
                          const char *mode)
{
    return eng_conf_add_string(db, mode, "%s/%s/mode", NETDEV, name);
}

/*
 *
 */
int
eng_conf_bondig_interval(struct eng_conf_db_s *db,
                         const char *name)
{
    return eng_conf_get_integer(db, NOT_ERR_LEVEL,
                                "%s/%s/interval_ms", NETDEV, name);
}

/*
 *
 */
int
eng_conf_add_bonding_interval(struct eng_conf_db_s *db,
                              const char *name,
                              int interval)
{
    return eng_conf_add_integer(db, interval, "%s/%s/interval_ms", NETDEV, name);
}

/*
 *
 */
int
eng_conf_bondig_downdelay(struct eng_conf_db_s *db,
                          const char *name)
{
    return eng_conf_get_integer(db, NOT_ERR_LEVEL,
                                "%s/%s/downdelay_ms", NETDEV, name);
}

/*
 *
 */
int
eng_conf_add_bonding_downdelay(struct eng_conf_db_s *db,
                               const char *name,
                               int downdelay)
{
    return eng_conf_add_integer(db, downdelay,
                                "%s/%s/downdelay_ms", NETDEV, name);
}

/*
 *
 */
int
eng_conf_bondig_updelay(struct eng_conf_db_s *db,
                        const char *name)
{
    return eng_conf_get_integer(db, NOT_ERR_LEVEL,
                                "%s/%s/updelay_ms", NETDEV, name);
}

/*
 *
 */
int
eng_conf_add_bonding_updelay(struct eng_conf_db_s *db,
                             const char *name,
                             int updelay)
{
    return eng_conf_add_integer(db, updelay, "%s/%s/updelay_ms", NETDEV, name);
}

/*
 *
 */
int
eng_conf_bonding_slave_list(struct eng_conf_db_s *db,
                            const char *name,
                            const char **slaves,
                            unsigned max_slaves,
                            char *buff,
                            size_t buff_size)
{
    return eng_conf_get_string_list(db, slaves, max_slaves,
                                    buff, buff_size,
                                    "%s/%s/slaves", NETDEV, name);
}

/*
 *
 */
int
eng_conf_add_bonding_slave(struct eng_conf_db_s *db,
                           const char *name,
                           const char *slave)
{
    return eng_conf_apend_string_list(db, slave,
                                      "%s/%s/slaves", NETDEV, name);
}

/*
 *
 */
const char *
eng_conf_netdev_depend(struct eng_conf_db_s *db,
                       const char *name)
{
    return eng_conf_get_string(db, "%s/%s/depend", NETDEV, name);
}

/*
 *
 */
int
eng_conf_add_netdev_depend(struct eng_conf_db_s *db,
                           const char *name,
                           const char *depend)
{
    return eng_conf_add_string(db, depend, "%s/%s/depend", NETDEV, name);
}

/*
 *
 */
struct eng_conf_node_s *
eng_conf_netdev_name_next(struct eng_conf_db_s *db,
                          struct eng_conf_node_s *node,
                          char *buff,
                          size_t buff_size)

{
    if (node)
        return eng_conf_next_dir(db, node, NETDEV, buff, buff_size);
    return eng_conf_dir(db, NETDEV, buff, buff_size);
}

/* port */
#define PORT	"/port"
/*
 *
 */
const char *
eng_conf_port_depend(struct eng_conf_db_s *db,
                     const char *name)
{
    return eng_conf_get_string(db, "%s/%s/depend", PORT, name);
}

/*
 *
 */
int
eng_conf_add_port_depend(struct eng_conf_db_s *db,
                         const char *name,
                         const char *depend)
{
    return eng_conf_add_string(db, depend, "%s/%s/depend", PORT, name);
}

/*
 *
 */
int
eng_conf_port_rx_queue(struct eng_conf_db_s *db,
                       const char *name)
{
    return eng_conf_get_integer(db, USE_ERR_LEVEL,
                                "%s/%s/rx-queue", PORT, name);
}

/*
 *
 */
int
eng_conf_add_port_rx_queue(struct eng_conf_db_s *db,
                           const char *name,
                           int queue_no)
{
    return eng_conf_add_integer(db, queue_no, "%/%s/rx-queue", PORT, name);
}

/*
 *
 */
int
eng_conf_port_tx_queue(struct eng_conf_db_s *db,
                       const char *name)
{
    return eng_conf_get_integer(db, USE_ERR_LEVEL,
                                "%s/%s/tx-queue", PORT, name);
}

/*
 *
 */
int
eng_conf_add_port_tx_queue(struct eng_conf_db_s *db,
                           const char *name,
                           int queue_no)
{
    return eng_conf_add_integer(db, queue_no, "%s/%s/tx-queue", PORT, name);
}

/*
 *
 */
int
eng_conf_port_retry(struct eng_conf_db_s *db,
                   const char *name)
{
    return eng_conf_get_integer(db, NOT_ERR_LEVEL,
                                "%s/%s/retry", PORT, name);
}

/*
 *
 */
int
eng_conf_add_port_retry(struct eng_conf_db_s *db,
                       const char *name, int retry)
{
    return eng_conf_add_integer(db, retry, "%s/%s/retry", PORT, name);
}

/*
 *
 */
struct eng_conf_node_s *
eng_conf_port_name_next(struct eng_conf_db_s *db,
                        struct eng_conf_node_s *node,
                        char *buff,
                        size_t buff_size)
{
    if (node)
        return eng_conf_next_dir(db, node, PORT, buff, buff_size);
    return eng_conf_dir(db, PORT, buff, buff_size);
}

/*
 * addon
 */
#define ADDON	"/addon"
int
eng_conf_add_addon(struct eng_conf_db_s *db,
                   const char *name,
                   const void *p)
{
    return eng_conf_add_pointer(db, p, "%s/%s", ADDON, name);
}

/*
 *
 */
const void *
eng_conf_addon(struct eng_conf_db_s *db,
               const char *name)
{
    return eng_conf_get_pointer(db, "%s/%s", ADDON, name);
}

/*
 * mbuf
 */
#define MBUFPOOL	"/mbufpool"

int
eng_conf_mbufpool_size(struct eng_conf_db_s *db,
                       const char *name)
{
    return eng_conf_get_integer(db, USE_ERR_LEVEL,
                               "%s/%s/number-of-mbufs_k",
                                MBUFPOOL, name);
}

/*
 *
 */
int
eng_conf_add_mbufpool_size(struct eng_conf_db_s *db,
                           const char *name,
                           int size)
{
    return eng_conf_add_integer(db, size,
                               "%s/%s/number-of-mbufs_k",
                                MBUFPOOL, name);
}

/*
 *
 */
int
eng_conf_mbufpool_cache_size(struct eng_conf_db_s *db,
                             const char *name)
{
    return eng_conf_get_integer(db, USE_ERR_LEVEL,
                               "%s/%s/cache-size",
                                MBUFPOOL, name);
}

/*
 *
 */
int
eng_conf_add_mbufpool_cache_size(struct eng_conf_db_s *db,
                                 const char *name,
                                 int cache_size)
{
    return eng_conf_add_integer(db, cache_size,
                               "%s/%s/cache-size",
                                MBUFPOOL, name);
}

/*
 *
 */
int
eng_conf_mbufpool_ext_size(struct eng_conf_db_s *db,
                          const char *name)
{
    return eng_conf_get_integer(db, USE_ERR_LEVEL,
                                "%s/%s/ext-size",
                                MBUFPOOL, name);
}

/*
 *
 */
int
eng_conf_add_mbufpool_ext_size(struct eng_conf_db_s *db,
                               const char *name,
                               int ext_size)
{
    return eng_conf_add_integer(db, ext_size,
                                "%s/%s/ext-size",
                                MBUFPOOL, name);
}

/*
 *
 */
struct eng_conf_node_s *
eng_conf_mbufpool_name_next(struct eng_conf_db_s *db,
                            struct eng_conf_node_s *node,
                            char *buff,
                            size_t buff_size)
{
    if (node)
        return eng_conf_next_dir(db, node, MBUFPOOL, buff, buff_size);
    return eng_conf_dir(db, MBUFPOOL, buff, buff_size);
}

/* global */
#define	GLOBAL	"global"

/*
 *
 */
int
eng_conf_global_initializer_list(struct eng_conf_db_s *db,
                                 const char **entries,
                                 unsigned max_entries,
                                 char *buff,
                                 size_t buff_size)
{
    return eng_conf_get_string_list(db, entries, max_entries,
                                    buff, buff_size,
                                    "/%s/initializer",
                                    GLOBAL);
}

/*
 *
 */
int
eng_conf_add_global_initializer(struct eng_conf_db_s *db,
                                const char *entry)
{
    return eng_conf_apend_string_list(db, entry, "/%s/initializer", GLOBAL);
}

