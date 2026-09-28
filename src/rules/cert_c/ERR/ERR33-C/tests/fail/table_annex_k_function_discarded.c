/*
 * Rule: ERR33-C
 * Status: FAIL - fopen_s() returns a nonzero errno_t on failure, leaving the
 * stream pointer null. The result is discarded.
 */

#define __STDC_WANT_LIB_EXT1__ 1
#include <stdio.h>

void open_log(FILE **fp) {
    fopen_s(fp, "log.txt", "w");
}
