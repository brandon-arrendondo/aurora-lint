/*
 * Rule: PRE31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger PRE31-C violation
 */

/*
 * Rule: PRE31-C - Avoid side effects in arguments to unsafe macros
 * Status: PASS
 * Reason: CHECK_NULL's parameter `ptr` is referenced exactly once, with no
 * short-circuit/ternary branching in the body, so strtok() runs exactly
 * once per loop iteration here — identical to a plain function call.
 * There is no PRE31-C hazard without multiple (or unpredictable)
 * evaluation.
 */

#include <string.h>

#define CHECK_NULL(ptr) ((ptr) != NULL)

void tokenize_string(char *str) {
    while (CHECK_NULL(strtok(str, " "))) {
        // strtok() evaluated exactly once per iteration - COMPLIANT
        str = NULL;
    }
}

int main(void) {
    char buffer[] = "hello world test";
    tokenize_string(buffer);
    return 0;
}
