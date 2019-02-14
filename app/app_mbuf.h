#ifndef _APP_MBUF_H_
#define _APP_MBUF_H_

#include <rte_mbuf.h>
#include <rte_prefetch.h>

static inline void
app_mbuf_prefetch(struct rte_mbuf *m)
{
    (void) m;
}

#endif /* !_APP_MBUF_H_ */
