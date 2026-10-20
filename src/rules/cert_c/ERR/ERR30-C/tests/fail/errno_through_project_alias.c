/*
 * Rule: ERR30-C
 * Source: aurora-lint
 * Status: FAIL - errno is read through a project alias after ftell()
 * without checking its return
 *
 * `ERRNO` is defined as errno itself, so the condition reads errno.
 */
#include <errno.h>
#include <stdio.h>

#define ERRNO errno

long position_or_fail(FILE *fp) {
    long pos = ftell(fp);
    if (ERRNO != 0) {
        return -1;
    }
    return pos;
}
