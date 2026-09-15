/*
 * Rule: PRE31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger PRE31-C violation
 */

/*
 * Rule: PRE31-C - Avoid side effects in arguments to unsafe macros
 * Status: PASS
 * Reason: CHECK_NULL's parameter `ptr` is referenced exactly once, with no
 * short-circuit/ternary branching in the body, so malloc() runs exactly
 * once here — identical to a plain function call. There is no PRE31-C
 * hazard without multiple (or unpredictable) evaluation.
 */

#include <stdlib.h>

#define CHECK_NULL(ptr) ((ptr) != NULL)

void allocate_memory(void) {
    if (CHECK_NULL(malloc(100))) {
        // malloc() evaluated exactly once - COMPLIANT
    }
}

int main(void) {
    allocate_memory();
    return 0;
}
