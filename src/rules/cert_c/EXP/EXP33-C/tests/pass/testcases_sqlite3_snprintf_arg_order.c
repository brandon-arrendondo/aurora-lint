/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation.
 * sqlite3_snprintf(size, dest, fmt, ...) puts its destination buffer at
 * argument 1 (size at 0), the reverse of libc snprintf(dest, size, fmt,
 * ...). Before task 458, match_initializing_function's suffix match
 * canonicalized "sqlite3_snprintf" to plain "snprintf" and checked
 * argument 0 (the size, not the buffer) for initialization, so `rtag`
 * was never recognized as written and the read on the next line flagged
 * as uninitialized -- mirrors sqlite's ext/fts3/tool/fts3view.c:503 and
 * src/vdbeaux.c:3654.
 */
#include <stdio.h>

extern void sqlite3_snprintf(int size, char *dest, const char *fmt, ...);

void f(long long value) {
    char rtag[20];
    sqlite3_snprintf(sizeof(rtag), rtag, "r%lld", value);
    printf("%s\n", rtag);
}
