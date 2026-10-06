/*
 * Rule: ENV03-C
 * Source: testcases (Juliet spelling)
 * Status: FAIL - Should trigger ENV03-C violation
 *
 * The global's only writer reads it with `fscanf (stdin, ...)`, a space
 * between the name and the parenthesis, as Juliet writes it. That is a call
 * to a taint source like any other, so the writer is tainted and the sink's
 * system() call is flagged. A text search for "fscanf(" used to miss it and
 * judge the writer clean.
 */

#include <stdio.h>
#include <stdlib.h>

char *env03_spaced_cmd;

static void env03_spaced_init(void) {
    static char buf[100];
    if (fscanf (stdin, "%99s", buf) == 1) {
        env03_spaced_cmd = buf;
    }
}

static void env03_spaced_execute(void) {
    char *data = env03_spaced_cmd;
    system(data);
}
