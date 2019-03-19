#ifndef _ENG_CMD_H_
#define _ENG_CMD_H_

#include <rte_ring.h>

struct eng_task_s;
struct eng_cmd_s;

typedef int (*eng_cmd_handler_t)(struct eng_cmd_s *);

struct eng_cmd_s {
    struct rte_ring *rsp_ring;
    eng_cmd_handler_t handler;

    int rsp;
    unsigned len;

    uint8_t data[2048];
} __attribute__((aligned(4096)));

extern int eng_cmd_init(void);

extern int eng_cmd_ring_register(unsigned thread_id,
                                 struct rte_ring *ring);

extern int eng_cmd_register(const char *name,
                            eng_cmd_handler_t handler);

extern unsigned eng_cmd_exec(struct rte_ring *ring);
extern int eng_cmd_request(unsigned thread_id,
                           const char *name,
                           void *arg, unsigned len);

#endif /* !_ENG_CMD_H_ */
