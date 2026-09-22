/*
 * Rule: MSC13-C
 * Source: mbedtls library/aria.c self-test (task 1387)
 * Status: PASS - No violation
 *
 * `int ret = 1;` IS the value the function returns when an assertion
 * macro bails out: the macro's `goto exit` skips the `ret = 0`, and
 * `exit: return ret` reads the initial value. The jump lives in the macro
 * body, so the CFG has to take the edge from the invocation.
 */

#include <stdio.h>

#define SELF_TEST_ASSERT(cond)                  \
    do {                                        \
        if (cond) {                             \
            if (verbose) printf("failed\n");    \
            goto exit;                          \
        }                                       \
    } while (0)

int step(int i);

int self_test(int verbose)
{
    int ret = 1;
    int i;

    for (i = 0; i < 3; i++) {
        SELF_TEST_ASSERT(step(i) != 0);
    }

    ret = 0;

exit:
    return ret;
}
