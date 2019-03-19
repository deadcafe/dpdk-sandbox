#include <sys/tree.h>
#include <sys/types.h>

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <locale.h>
#include <getopt.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_version.h>

#include "eng_cli.h"
#include "linenoise.h"


struct line_s {
    const char *prompt;
    FILE *fd;
    const char *cmd_file;
    void *reserved;
    uint64_t tsc;
    uint64_t hz;
};

FILE *eng_stdout;
static FILE *FileOut;

static struct line_s LineInfo;

/*
 *
 */
static RB_HEAD(cmd_tree_s, eng_cli_entry_s) CmdHead = RB_INITIALIZER(CmdHead);

static inline int
cmp_cli_entry(const struct eng_cli_entry_s *e0,
                  const struct eng_cli_entry_s *e1)
{
    return strcasecmp(e0->cmd, e1->cmd);
}

RB_GENERATE_STATIC(cmd_tree_s, eng_cli_entry_s, node, cmp_cli_entry);

/*
 *
 */
static void
add_cmd(struct eng_cli_entry_s *new)
{
    if (RB_INSERT(cmd_tree_s, &CmdHead, new))
        fprintf(stderr, "ignored %s\n", new->cmd);
}

/*
 *
 */
static inline struct eng_cli_entry_s *
find_cmd(const char *cmd)
{
    struct eng_cli_entry_s key;

    key.cmd = cmd;
    return RB_FIND(cmd_tree_s, &CmdHead, &key);
}

/*
 *
 */
static inline struct eng_cli_entry_s *
nfind_cmd(const char *cmd)
{
    struct eng_cli_entry_s key;

    key.cmd = cmd;
    return RB_NFIND(cmd_tree_s, &CmdHead, &key);
}

/*
 *
 */
static inline struct eng_cli_entry_s *
next_cmd(struct eng_cli_entry_s *cmd)
{
    return RB_NEXT(cmd_tree_s, &CmdHead, cmd);
}

/*
 *
 */
void
eng_cli_register(struct eng_cli_entry_s *entry)
{
    for (unsigned i = 0; i < entry->nb_info; i++) {
        if (!entry->info[i].name)
            fprintf(stderr, "%s not defined %u th command\n", entry->cmd, i);
    }
    add_cmd(entry);
}

/*
 *
 */
#define REG_CMD(_Name, _Cmd)                            \
static struct eng_cli_entry_s Constructor_##_Name = {   \
    .cmd = _Cmd,                                        \
    .func = MAIN_##_Name,                               \
    .hints = HINTS_##_Name,                             \
};                                                      \
RTE_INIT(Reg_##_Name);                                  \
static void                                             \
Reg_##_Name(void)                                       \
{                                                       \
    add_cmd(&Constructor_##_Name);                      \
}

/*****************************************************************************
 * Commands
 *****************************************************************************/
enum eng_cli_cmd_type_e {
    CMD_INVALID = ENG_CLI_INVALID_CMD,

    CMD_EXEC,
    CMD_DIR,
    CMD_DATE,
    CMD_TOGGLE,

    NB_CMDs,
};

//static const struct eng_cli_cmd_info_s CmdInfos[1];

/*
 * Exit
 */
static int
cmd_exit(int ac __rte_unused,
         char *av[] __rte_unused)
{
    fprintf(stderr, "bye\n");
    return -1;
}

/*
 * Help
 */
static int
cmd_help(int ac __rte_unused,
         char *av[] __rte_unused)
{
    struct eng_cli_entry_s *entry;

    RB_FOREACH(entry, cmd_tree_s, &CmdHead)
        fprintf(stderr, "  %s\n", entry->cmd);
    return 0;
}

/*
 * Batch
 * batch --cmd exec --file FILE
 */

static const struct eng_cli_cmd_info_s BatchInfos[NB_CMDs] = {
    [CMD_EXEC] = { "exec", "--file FILE", },
    [CMD_DIR]  = { "dir", "--path PATH", },
    [CMD_DATE] = { "date", "", },
    [CMD_TOGGLE]= { "toggle", "toggle output", },
};

/* constructor */
ENG_GENERATE_CLI(Batch, "batch", BatchInfos, cmd_batch);

static const struct option LongOptions[] = {
    { "cmd",    required_argument, NULL, 'c', },
    { "file",   required_argument, NULL, 'f', },
    { "path",   required_argument, NULL, 'p', },
    { NULL,     0,                 NULL, 0,   },
};

static int
show_dir(const char *path)
{
    DIR *dir;
    int ret = 0;

    if (!path)
        path = "./";

    dir = opendir(path);
    if (dir) {
        struct dirent *dent;

        while ((dent = readdir(dir)) != NULL) {
            if (dent->d_name[0] != '.') {
                const char *cr;

                if (dent->d_type == DT_DIR)
                    cr = "/\n";
                else
                    cr = "\n";
                fprintf(eng_stdout, "%s%s", dent->d_name, cr);
            }
        }
        closedir(dir);
    } else
        ret = -errno;
    return ret;
}

static int
show_date(void)
{
    struct timespec ts;
    struct tm tm;

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);

    // fprintf(stderr, "tv_sec=%ld  tv_nsec=%ld\n",ts.tv_sec,ts.tv_nsec);
    fprintf(eng_stdout, "%d/%02d/%02d %02d:%02d:%02d.%09ld\n",
            tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour,
            tm.tm_min, tm.tm_sec, ts.tv_nsec);
    return 0;
}

static int
cmd_batch(int ac,
          char *av[])
{
    int opt, index;
    int err = 0;
    enum eng_cli_cmd_type_e cmd = CMD_INVALID;
    char *file = NULL;
    struct line_s *info = &LineInfo;
    char *path = NULL;

    while ((opt = getopt_long(ac, av, "c:f:p:h",
                              LongOptions, &index)) != EOF && !err) {
        switch (opt) {
        case 'c':       /* cmd */
            cmd = eng_cli_get_cmd_type(optarg);
            break;

        case 'f':
            file = optarg;
            break;

        case 'p':
            path = optarg;
            break;

        case 'h':       /* help */
            CMD_USAGE(Batch);
            return 0;

        default:
            err = -EINVAL;
            break;
        }
    }

    if (cmd == CMD_INVALID)
        err = -EINVAL;

    if (!err) {
        switch (cmd) {
        case CMD_EXEC:
            if (!file)
                err = -EINVAL;
            else if (info->cmd_file || info->fd)
                err = -EBUSY;
            else
                info->cmd_file = file;
            break;

        case CMD_DIR:
            err = show_dir(path);
            break;

        case CMD_DATE:
            err = show_date();
            break;

        case CMD_TOGGLE:
            if (FileOut) {
                if (eng_stdout == FileOut) {
                    eng_stdout = stdout;
                    fprintf(eng_stdout, "toggle stdout\n");
                } else {
                    fprintf(eng_stdout, "toggle FILE out\n");
                    eng_stdout = FileOut;
                }
            }
            break;

        case CMD_INVALID:
        default:
            err = -EINVAL;
            break;
        }
    }

    if (err) {
        char buff[80];
        fprintf(stderr, "%s\n", strerror_r(-(err), buff, sizeof(buff)));

        if (err == -EINVAL)
            CMD_USAGE(Batch);
    }
    return 0;
}
static struct eng_cli_entry_s constructor_exit = {
    .cmd = "exit",
    .func = cmd_exit,
};

static struct eng_cli_entry_s constructor_quit = {
    .cmd = "quit",
    .func = cmd_exit,
};

static struct eng_cli_entry_s constructor_help = {
    .cmd = "help",
    .func = cmd_help,
};

static struct eng_cli_entry_s constructor_help2 = {
    .cmd = "?",
    .func = cmd_help,
};

RTE_INIT(Reg_cmd);
static void Reg_cmd(void)
{
    eng_cli_register(&constructor_exit);
    eng_cli_register(&constructor_quit);
    eng_cli_register(&constructor_help);
    eng_cli_register(&constructor_help2);
};
/*****************************************************************************
 * main
 *****************************************************************************/
static int
line2av(char *line,
        char *av[],
        int size_av,
        char buff[],
        int size_buff)
{
    int ac = 0;
    char *p = line;
    char *c;
    char *b = buff;
    int len;

    while ((c = strsep(&p, " \t")) != NULL) {
        if (*c == '\0')
            continue;
        av[ac] = c;
        if (ac)
            len = snprintf(b, size_buff, " %s", av[ac]);
        else
            len = snprintf(b, size_buff, "%s", av[ac]);

        b += len;
        size_buff -= len;

        if (++ac >= size_av || size_buff < 0)
            return -1;
    }
    return ac;
}

/*
 *
 */
static void
completion(const char *buf, linenoiseCompletions *lc)
{
    struct eng_cli_entry_s key;
    char word[32];
    char *p;

    snprintf(word, sizeof(word), "%s", buf);
    key.cmd = word;
    p = strchr(word, ' ');
    if (p)
        *p = '\0';
    struct eng_cli_entry_s *cur = nfind_cmd(word);

    while (cur) {

        if (cmp_cli_entry(&key, cur) >= 0)
            break;
        linenoiseAddCompletion(lc, cur->cmd);
        cur = next_cmd(cur);
    }
}

/*
 *
 */
static char *
hints(const char *buf, int *color, int *bold)
{
    char word[32];
    char *p;

    snprintf(word, sizeof(word), "%s", buf);
    p = strchr(word, ' ');
    if (p)
        *p = '\0';
    struct eng_cli_entry_s *cur = find_cmd(word);

    if (cur) {
        *color = 35;
        *bold = 0;
        return (char *) cur->hints;
    }
    return NULL;
}

/*
 *
 */
static inline char *
read_line(struct line_s *info)
{
    char *line = NULL;

    if (info->cmd_file) {
        if (info->fd)
            fclose(info->fd);
        info->fd = fopen(info->cmd_file, "r");
        if (info->fd)
            info->tsc = rte_rdtsc();
        else
            fprintf(stderr, "cannot open file:%s\n", info->cmd_file);
        info->cmd_file = NULL;
    }

    if (info->fd) {
        char *buffer = malloc(1024);
        if (buffer) {
            if ((line = fgets(buffer, 1024, info->fd)) == NULL) {
                free(buffer);
                fclose(info->fd);
                info->fd = NULL;
            } else {
                fprintf(eng_stdout, "%s", line);
                char *p = strrchr(line, '\n');
                if (p)
                    *p = '\0';
            }
        }
    }

    if (!line) {
        char prompt[80];
        uint64_t dt = rte_rdtsc() - info->tsc;

        snprintf(prompt, sizeof(prompt), "%s(%.6f)> ",
                 info->prompt, (double) dt / (double) info->hz);
        line = linenoise(prompt);
        info->tsc = rte_rdtsc();
    }
    return line;
}

/*
 *
 */
int
eng_cmd_loop(const char *cmd_file_name,
             const char *hist_file_name)
{
    char *line = NULL;
    int ret = 0;
    struct line_s *info = &LineInfo;

    info->prompt = "Engine";
    info->fd = NULL;
    info->cmd_file = cmd_file_name;
    info->tsc = rte_rdtsc();
    info->hz = rte_get_tsc_hz();

    linenoiseSetCompletionCallback(completion);
    linenoiseSetHintsCallback(hints);
    linenoiseHistorySetMaxLen(256);

    if (hist_file_name)
        linenoiseHistoryLoad(hist_file_name);

    eng_stdout = stdout;

    while(!ret && (line = read_line(info)) != NULL) {
        char *av[64];
        size_t len = strlen(line) + 1;

        char *buffer = malloc(len);
        if (buffer) {
            int ac = line2av(line, av, RTE_DIM(av), buffer, len);
            if (ac > 0) {

                if (!info->fd) {
                    linenoiseHistoryAdd(buffer);

                    if (hist_file_name)
                        linenoiseHistorySave(hist_file_name);
                }
#if 0
                for (int i = 0; i < ac; i++)
                    fprintf(stderr, "ac:%d av:%s\n", i, av[i]);
#endif
                optind = 0;     /* clear getopt */

                const struct eng_cli_entry_s *entry = find_cmd(av[0]);
                if (entry)
                    ret = entry->func(ac, av);
                else
                    fprintf(stderr, "unknown: %s\n", av[0]);
            }
            free(buffer);
        } else {
            ret = -ENOMEM;
        }

        linenoiseFree(line);
        line = NULL;
    }

    if (line)
        linenoiseFree(line);
    return ret;
}

