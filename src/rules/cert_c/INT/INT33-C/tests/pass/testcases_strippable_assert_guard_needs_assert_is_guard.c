/*
 * Rule: INT33-C
 * Source: testcases
 * Status: PASS under the default preset; VIOLATION under strict
 * Expect: default=clean strict=violation
 *
 * An assert that the divisor is non-zero guards the division under the
 * default policy (assert_is_guard), whatever the macro is called. The strict
 * policy reads the release configuration, where NDEBUG strips it and the
 * division is unchecked (ADR-0010 D5). Here serverAssert is a plain wrapper
 * around assert, so it is stripped just the same; valkey's real serverAssert
 * aborts in every configuration and guards under both policies
 * (testcases_abort_check_macro_guard.c).
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

