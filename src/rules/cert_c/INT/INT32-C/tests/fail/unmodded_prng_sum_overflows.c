/*
 * Rule: INT32-C
 * Source: real-world
 * Status: FAIL - `1 + rand()` overflows when `rand()` returns `RAND_MAX`,
 *         which glibc defines as `INT_MAX`.
 *
 * The contract range `[0, RAND_MAX]` that clears `1 + rand() % 60` is also
 * what proves this one CAN overflow: the range engine knows the bound now,
 * and the sum does not fit. The only flaggable line.
 */

#include <stdlib.h>

int next_id(void)
{
    return 1 + rand();
}
