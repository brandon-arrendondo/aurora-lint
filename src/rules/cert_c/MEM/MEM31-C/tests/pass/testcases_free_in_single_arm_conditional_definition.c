/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - a deallocator defined under a one-arm #if still frees its
 * argument: that arm compiles in some configuration, so the caller's
 * allocation is released, not leaked
 */

#include <stdlib.h>

struct conn { char *buf; };

#ifdef WITH_CONN
void conn_free(struct conn *c)
{
    free(c->buf);
    free(c);
}
#endif

int use_conn(void)
{
    struct conn *c = malloc(sizeof(*c));
    if (c == NULL)
        return -1;
    c->buf = NULL;
    conn_free(c);
    return 0;
}
