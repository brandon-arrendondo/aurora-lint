/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: sum writes only its own locals and parameter, so it has no side
 * effect (PRE31-C-EX1).
 */

#include <assert.h>

static int sum(const int *v, int n) {
    int total = 0;
    int buf[4];
    for (int i = 0; i < n; i++) {
        total += v[i];
    }
    buf[0] = total;
    n = 0;
    return buf[0];
}

void a(const int *v) {
    assert(sum(v, 4) > 0);
}
