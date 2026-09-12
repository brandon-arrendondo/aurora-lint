/*
 * Rule: PRE31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger PRE31-C violation
 */

/*
 * Rule: PRE31-C - Avoid side effects in arguments to unsafe macros
 * Status: PASS
 * Reason: IS_VALID_FILE's parameter `f` is referenced exactly once, with no
 * short-circuit/ternary branching in the body, so fopen() runs exactly
 * once here — identical to a plain function call. There is no PRE31-C
 * hazard without multiple (or unpredictable) evaluation.
 */

#include <stdio.h>

#define IS_VALID_FILE(f) ((f) != NULL)

void open_file(void) {
    if (IS_VALID_FILE(fopen("test.txt", "r"))) {
        // fopen() evaluated exactly once - COMPLIANT
    }
}

int main(void) {
    open_file();
    return 0;
}
