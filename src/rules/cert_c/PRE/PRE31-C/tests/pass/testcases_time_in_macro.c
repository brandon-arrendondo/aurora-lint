/*
 * Rule: PRE31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger PRE31-C violation
 */

/*
 * Rule: PRE31-C - Avoid side effects in arguments to unsafe macros
 * Status: PASS
 * Reason: IS_POSITIVE's parameter `x` is referenced exactly once, with no
 * short-circuit/ternary branching in the body, so time() runs exactly
 * once here — identical to a plain function call. There is no PRE31-C
 * hazard without multiple (or unpredictable) evaluation.
 */

#include <time.h>

#define IS_POSITIVE(x) ((x) > 0)

void check_time(void) {
    if (IS_POSITIVE(time(NULL))) {
        // time() evaluated exactly once - COMPLIANT
    }
}

int main(void) {
    check_time();
    return 0;
}
