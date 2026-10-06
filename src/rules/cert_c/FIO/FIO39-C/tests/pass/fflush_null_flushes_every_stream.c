/*
 * Rule: FIO39-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FIO39-C violation
 *
 * fflush(NULL) flushes every output stream (C11 7.21.5.2p3), so the write
 * then read on `fp` has an intervening flush.
 */

#include <stdio.h>

void update(FILE *fp, char *buf, size_t n) {
    fwrite(buf, 1, n, fp);
    fflush(NULL);
    fread(buf, 1, n, fp);
}
