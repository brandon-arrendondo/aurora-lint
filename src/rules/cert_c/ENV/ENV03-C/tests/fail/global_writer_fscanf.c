/*
 * Rule: ENV03-C
 * Source: testcases
 * Status: FAIL - Should trigger ENV03-C violation
 *
 * Control for global_writer_spaced_fscanf.c: the same writer, spelled
 * `fscanf(stdin, ...)`.
 */

#include <stdio.h>
#include <stdlib.h>

char *env03_unspaced_cmd;

static void env03_unspaced_init(void) {
    static char buf[100];
    if (fscanf(stdin, "%99s", buf) == 1) {
        env03_unspaced_cmd = buf;
    }
}

static void env03_unspaced_execute(void) {
    char *data = env03_unspaced_cmd;
    system(data);
}
