/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: the release arm is variadic and empty, so it evaluates the
 * variadic arguments zero times.
 */

#include <stdio.h>

#ifdef DEBUG
#define LOG(fmt, ...) printf(fmt, __VA_ARGS__)
#else
#define LOG(...)
#endif

void v(int i) {
    LOG("%d\n", i++);  // VIOLATION
}
