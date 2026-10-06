/*
 * Rule: FIO39-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO39-C violation
 *
 * The positioning call is on a different stream. It resets that stream
 * only, so the write then read on `fp` still alternates with nothing in
 * between on `fp` itself.
 */

#include <stdio.h>

void update(FILE *fp, FILE *log, char *buf, size_t n) {
    fwrite(buf, 1, n, fp);
    fseek(log, 0, SEEK_END);
    fread(buf, 1, n, fp);
}
