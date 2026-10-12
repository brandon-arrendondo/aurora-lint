/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: PASS - the call does not receive the object holding the freed member
 */

#include <stdlib.h>

struct state {
    char *buf;
};

void log_count(int n);

void drop(struct state *s, int n) {
    free(s->buf);
    log_count(n);
    s->buf = NULL;
}
