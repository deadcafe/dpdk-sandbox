#ifndef _ENG_CLI_H_
#define _ENG_CLI_H_

#include <sys/tree.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <stdio.h>

struct eng_cli_cmd_info_s {
    const char *name;           /*!< command name */
    const char *options;        /*!< command options */
};

struct eng_cli_entry_s {
    const char *cmd;            /*!< module name */
    const char *hints;          /*!< hint of input  */
    const struct eng_cli_cmd_info_s *info;
    size_t nb_info;
    int (*func)(int, char *[]);

    RB_ENTRY(eng_cli_entry_s) node;
};

enum eng_cli_cmd_type_e;
extern FILE *eng_stdout;

#define ENG_CLI_INVALID_CMD     (-1)

extern void
eng_cli_register(struct eng_cli_entry_s *);

#define CMD_HINTS       "--cmd=CMD [--OPTIONS]"

#define ENG_GENERATE_CLI(_Name, _Cmd, _INFO, _Func)                     \
static int _Func(int, char **);                                         \
static struct eng_cli_entry_s Constructor_##_Name = {                   \
    .cmd     = (_Cmd),                                                  \
    .hints   = CMD_HINTS,                                               \
    .info    = (_INFO),                                                 \
    .nb_info = RTE_DIM(_INFO),                                          \
    .func    = (_Func),                                                 \
};                                                                      \
RTE_INIT(Reg_##_Name);                                                  \
static void Reg_##_Name(void)                                           \
{                                                                       \
    eng_cli_register(&Constructor_##_Name);                             \
}                                                                       \
static inline enum eng_cli_cmd_type_e                                   \
eng_cli_get_cmd_type(const char *name)                                  \
{                                                                       \
    for (int i = 0; i < (int) RTE_DIM(_INFO); i++) {                    \
        if (!strncasecmp(_INFO[i].name, name, strlen(_INFO[i].name) + 1)) \
            return (enum eng_cli_cmd_type_e) i;                         \
    }                                                                   \
    return (enum eng_cli_cmd_type_e) ENG_CLI_INVALID_CMD;               \
}                                                                       \
static inline void                                                      \
_Name##_usage(void)                                                     \
{                                                                       \
    fprintf(stderr, "%s %s\n", _Cmd, CMD_HINTS);                        \
    fprintf(stderr, "  CMD:\n");                                        \
    for (unsigned i = 0; i < RTE_DIM(_INFO); i++)                       \
        fprintf(stderr, "\t%s %s\n", _INFO[i].name, _INFO[i].options);  \
}                                                                       \

#define CMD_USAGE(_Name)         _Name##_usage()


extern int eng_cmd_loop(const char *cmd_file_name,
                        const char *hist_file_name);

#endif /* !_ENG_CLI_H_ */
