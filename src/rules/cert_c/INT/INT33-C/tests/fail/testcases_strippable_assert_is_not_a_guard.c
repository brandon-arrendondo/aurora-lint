/*
 * Rule: INT33-C
 * Source: testcases
 * Status: FAIL - Should trigger INT33-C violation
 *
 * An assert that the divisor is non-zero is not a guard when NDEBUG strips
 * it: in the release configuration the division is unchecked (ADR-0010 D5).
 * The name does not matter. Here serverAssert is a plain wrapper around
 * assert, so it is stripped just the same; valkey's real serverAssert aborts
 * in every configuration and is credited (pass/testcases_abort_check_macro_guard.c).
 */

#include <assert.h>
#define serverAssert(e) assert(e)

/* Preceding assert, plain and project-spelled, with statements in between */
int per_reg(int total, int regs) {
    assert(regs > 0);
    int scaled = total * 2;
    return scaled / regs;
}

int per_entry(long bytes, long count) {
    serverAssert(count != 0);
    return (int)(bytes / count);
}

/* Assert on the truthy value, then division inside a loop below it */
long sum_over(long *v, long total_size, int n) {
    long acc = 0;
    assert(total_size);
    for (int i = 0; i < n; i++) {
        acc += v[i] / total_size;
    }
    return acc;
}

