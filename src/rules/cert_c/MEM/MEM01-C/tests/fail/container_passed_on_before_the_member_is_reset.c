/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the object holding the freed member is handed to a function before the member is set
 */

#include <stdlib.h>

struct state {
    char *buf;
};

void log_state(struct state *s);

void drop(struct state *s) {
    free(s->buf);
    log_state(s);
    s->buf = NULL;
}
