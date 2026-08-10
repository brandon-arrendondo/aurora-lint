/*
 * Rule: ARR38-C
 * Source: testcases
 * Status: FAIL - Should trigger ARR38-C violation
 */

/*
 * Rule: ARR38-C - Guarantee that library functions do not form invalid pointers
 * Status: FAIL
 * Reason: task 410 regression — buffer_info was previously a file-wide,
 * name-keyed map. Two functions each declaring a local buffer named "buf"
 * of a *different* size could conflate each other's size: whichever
 * function's declaration was processed last in the file-wide first pass won
 * the map entry for "buf", so this function's own genuine overflow was
 * checked against a *different* function's (larger) buffer size and masked
 * as a false negative. goodFunction's buf[100] is declared after
 * badFunction's buf[10] in this file, which reproduces the masking under
 * the old file-wide map.
 */

#include <string.h>

void badFunction(void) {
    char buf[10];
    memset(buf, 'A', 20);  // VIOLATION: 20 exceeds this function's own buf[10]
}

void goodFunction(void) {
    char buf[100];
    memset(buf, 'A', 50);  // compliant: 50 fits this function's own buf[100]
}

int main(void) {
    badFunction();
    goodFunction();
    return 0;
}
