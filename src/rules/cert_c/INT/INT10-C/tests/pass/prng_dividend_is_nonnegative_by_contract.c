/*
 * Rule: INT10-C
 * Source: real-world (valkey src/fuzzer_command_generator.c:437 and 127 more
 *         rows of one batch; src/cluster_legacy.c:5705 `random() % delay`)
 * Status: PASS - Should NOT trigger INT10-C violation
 * Reason: C11 7.22.2.1 confines `rand()` to `[0, RAND_MAX]` and POSIX
 *         confines `random()` / `lrand48()` to `[0, 2^31)`, so a remainder
 *         whose dividend is one of these calls carries a non-negative sign
 *         whatever the divisor is (C99 6.5.5p6: the result takes the sign of
 *         the dividend). The call was opaque to the range engine, so the
 *         dividend read as "potentially signed". `const_eval::
 *         contract_return_range` now bounds these by their specification.
 *         The divisor's sign is deliberately NOT what clears these: see the
 *         FAIL twin.
 */

#include <stdlib.h>

int pick(int n, int delay)
{
    int a = rand() % 60;
    long b = random() % 1000;
    long c = lrand48() % 7;
    int d = rand() % n;
    long e = delay ? random() % delay : 0;
    return a + (int)b + (int)c + d + (int)e;
}
