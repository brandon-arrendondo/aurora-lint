/*
 * Rule: ERR32-C
 * Source: aurora-lint
 * Status: PASS - a function named sig* that is never registered is not a signal handler
 */

#include <errno.h>
#include <stdlib.h>

int sigfig_parse(const char *s) {
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno != 0) {
        return -1;
    }
    return (int)v;
}
