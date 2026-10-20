/*
 * Rule: ERR30-C
 * Source: aurora-lint
 * Status: FAIL - errno is read after ftell() without checking its return
 *
 * The same function as the substring pass case, but this condition reads
 * errno itself; the counter whose name contains "errno" is beside it.
 */
#include <errno.h>
#include <stdio.h>

static int my_errno_count;

long position_or_fail(FILE *fp) {
    long pos = ftell(fp);
    if (errno != 0 && my_errno_count > 0) {
        return -1;
    }
    return pos;
}
