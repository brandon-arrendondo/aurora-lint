/*
 * Rule: ERR30-C
 * Source: aurora-lint (misfire: errno matched as a substring)
 * Status: PASS - Should NOT trigger ERR30-C violation
 *
 * The condition reads `my_errno_count`, a counter whose name contains the
 * spelling "errno". It is not errno, so nothing here examines errno after
 * ftell().
 */
#include <errno.h>
#include <stdio.h>

static int my_errno_count;

long position_or_fail(FILE *fp) {
    long pos = ftell(fp);
    if (my_errno_count > 0) {
        return -1;
    }
    return pos;
}
