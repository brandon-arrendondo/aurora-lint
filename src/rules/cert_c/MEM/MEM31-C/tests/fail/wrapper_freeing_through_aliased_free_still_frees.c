/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: Guard for trusting a callee's summary over its `*_free`
 * name. `wrapper_free` really does release its parameter -- through
 * `port_free`, which is `#define port_free free`. The summary is credited
 * only for a literal `free`, and the alias lives in a header the wrapper's
 * file never parses, so the pass-through edge to `port_free` has to be
 * resolved through the project's alias map when frees are propagated.
 * Without that the wrapper's summary says "frees nothing", the name guess
 * is overruled, and this double free goes silent.
 */

#include <stdlib.h>

#define port_free free

static void wrapper_free(void *p) {
    port_free(p);
}

int frees_twice(void) {
    char *p = malloc(8);
    if (p == NULL) {
        return -1;
    }
    wrapper_free(p);
    free(p);
    return 0;
}
