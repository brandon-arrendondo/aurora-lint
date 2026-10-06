/*
 * Rule: ENV03-C
 * Source: testcases
 * Status: FAIL - Should trigger ENV03-C violation
 *
 * The writer reads through a function-like macro whose replacement list
 * calls fgets. The invocation is a call to a taint source, so the writer is
 * tainted and the sink is flagged.
 */

#include <stdio.h>
#include <stdlib.h>

#define READ_LINE(b, n) fgets (b, n, stdin)

char *env03_macro_cmd;

static void env03_macro_init(void) {
    static char buf[100];
    if (READ_LINE(buf, sizeof buf) != NULL) {
        env03_macro_cmd = buf;
    }
}

static void env03_macro_execute(void) {
    char *data = env03_macro_cmd;
    system(data);
}
