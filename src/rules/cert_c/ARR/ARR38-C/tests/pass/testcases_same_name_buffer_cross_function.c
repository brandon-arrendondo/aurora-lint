/*
 * Rule: ARR38-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR38-C violation
 */

/*
 * Rule: ARR38-C - Guarantee that library functions do not form invalid pointers
 * Status: PASS
 * Reason: task 410 regression companion — two functions each declare a
 * local buffer named "buf" of a *different* size, and each function's use
 * is safe relative to its own buffer. Per-function-scoped buffer tracking
 * must not spuriously flag either function just because a same-named
 * buffer of a different size exists elsewhere in the file.
 */

#include <string.h>

void smallOk(void) {
    char buf[10];
    memset(buf, 'A', 10);  // compliant: fits this function's own buf[10]
}

void largeOk(void) {
    char buf[100];
    memset(buf, 'A', 100);  // compliant: fits this function's own buf[100]
}

int main(void) {
    smallOk();
    largeOk();
    return 0;
}
