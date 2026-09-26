/*
 * Rule: INT33-C
 * Source: testcases (valkey serverAssert shape)
 * Status: PASS - Divisor proven non-zero by a check no configuration strips
 *
 * serverAssert here has no NDEBUG arm and aborts when its condition is false,
 * so the division after it is guarded in every configuration. It is credited
 * because of what it expands to, not because of its name (check_macros).
 *
 * Settings: stdlib_noreturn=true
 * The library contract that abort/exit never return is held on under every
 * preset: it is not what this fixture tests (the strict preset's
 * freestanding environment withdraws it; see
 * src/rules/cert_c/MEM/MEM30-C/tests/pass/stdlib_exit_branch_needs_stdlib_noreturn.c).
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
