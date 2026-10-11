/*
 * Rule: FIO40-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO40-C violation
 *
 * The file defines its own memset, and its body writes nothing, so a call
 * to it after the failed fgets is no reset: the buffer is still read
 * before anything writes it.
 */

#include <stdio.h>
#include <stddef.h>

static void *memset(void *p, int c, size_t n) {
    (void) c;
    (void) n;
    return p;
}

void read_or_blank(FILE *fp) {
    char buf[32];
    if (fgets(buf, sizeof buf, fp) == NULL) {
        memset(buf, 0, sizeof buf);
    }
    puts(buf);
}
