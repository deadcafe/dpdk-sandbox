
#ifndef _TASK_IF_H_
#define _TASK_IF_H_


#include <rte_mbuf.h>
#include <rte_ring.h>

struct eng_task_if_s;

enum eng_task_if_dir_e {
    ENG_TASK_IF_DIR_IN = 0,
    ENG_TASK_IF_DIR_OUT,
};

extern unsigned
eng_task_recv(struct eng_task_if_s *tk_if,
              struct rte_mbuf **buff,
              unsigned buff_sz);

extern unsigned
eng_task_send(struct eng_task_if_s *tk_if,
              struct rte_mbuf **buff,
              unsigned buff_sz);

extern unsigned
eng_task_flush(struct eng_task_if_s *tk_if);

extern struct eng_task_if_s *
eng_task_if_create(int socket,
                   unsigned flush_len);

extern int
eng_task_if_bind_port(struct eng_task_if_s *tk_if,
                      enum eng_task_if_dir_e dir,
                      unsigned port_id,
                      unsigned queue_id);

extern int
eng_task_if_bind_ring(struct eng_task_if_s *tk_if,
                      enum eng_task_if_dir_e dir,
                      struct rte_ring *ring);

#endif	/* !_TASK_IF_H_ */
