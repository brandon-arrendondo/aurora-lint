/*
 * Rule: ENV03-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ENV03-C violation.
 *
 * The global's only writer calls functions whose names END in a taint
 * source's name -- spread, do_accept, thread_read -- and none of them is
 * one. A text search for "read(" or "accept(" matched inside each and
 * judged the writer tainted.
 */

#include <stdlib.h>

char *env03_lookalike_cmd;

static int spread(char *b) { b[0] = 'l'; b[1] = 's'; b[2] = '\0'; return 0; }
static int do_accept(int x) { return x; }
static int thread_read(int x) { return x; }

static void env03_lookalike_init(void) {
    static char buf[100];
    spread(buf);
    (void)do_accept(0);
    (void)thread_read(0);
    env03_lookalike_cmd = buf;
}

static void env03_lookalike_execute(void) {
    char *data = env03_lookalike_cmd;
    system(data);
}
