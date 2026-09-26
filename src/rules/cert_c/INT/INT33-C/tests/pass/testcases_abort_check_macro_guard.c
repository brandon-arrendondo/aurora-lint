/*
 * Rule: INT33-C
 * Source: testcases (valkey serverAssert shape)
 * Status: PASS - Divisor proven non-zero by a check no configuration strips
 *
 * serverAssert here has no NDEBUG arm and aborts when its condition is false,
 * so the division after it is guarded in every configuration. It is credited
 * because of what it expands to, not because of its name (check_macros).
 */

#include <stdlib.h>

#define serverAssert(_e) ((_e) ? (void)0 : abort())

int per_entry(long bytes, long count) {
    serverAssert(count != 0);
    int scaled = (int)bytes * 2;
    return scaled / (int)count;
}

long sum_over(long *v, long total_size, int n) {
    long acc = 0;
    serverAssert(total_size);
    for (int i = 0; i < n; i++) {
        acc += v[i] / total_size;
    }
    return acc;
}
