/*
 * Rule: FIO21-C
 * Source: regression
 * Status: PASS - Should NOT trigger FIO21-C violation
 *
 * A path variable's value is the write that every path to the open runs
 * last. A shared-directory literal written only in a branch that returns,
 * in one arm of an if/else, or after the open in a loop body is not the
 * value the open receives on every path, so none of these opens is judged
 * by it. Flags that clear O_CREAT create nothing, and a macro that expands
 * to tmpnam() invoked where a parameter is named tmpnam calls the
 * parameter.
 */

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define TEMP_NAME(b) tmpnam(b)

void written_in_a_branch_that_returns(int c) {
    const char *p = "/home/u/out";
    if (c) {
        p = "/tmp/lock";
        unlink(p);
        return;
    }
    FILE *fp = fopen(p, "w");
    if (fp != NULL) {
        fclose(fp);
    }
}

void shared_in_the_else_arm(int c) {
    const char *p;
    if (c)
        p = "/home/u/out";
    else
        p = "/tmp/out";
    FILE *fp = fopen(p, "w");
    if (fp != NULL) {
        fclose(fp);
    }
}

void shared_in_the_then_arm(int c) {
    const char *p;
    if (c)
        p = "/tmp/out";
    else
        p = "/home/u/out";
    FILE *fp = fopen(p, "w");
    if (fp != NULL) {
        fclose(fp);
    }
}

void shared_after_the_open_in_a_loop(int n) {
    const char *p = "/home/u/out";
    for (int i = 0; i < n; i++) {
        FILE *fp = fopen(p, "w");
        if (fp != NULL) {
            fclose(fp);
        }
        p = "/tmp/out";
    }
}

void flags_that_clear_o_creat(int flags) {
    int fd = open("/tmp/out", flags & ~O_CREAT);
    if (fd != -1) {
        close(fd);
    }
}

void macro_over_a_parameter(char *(*tmpnam)(char *)) {
    char name[64];
    TEMP_NAME(name);
}
