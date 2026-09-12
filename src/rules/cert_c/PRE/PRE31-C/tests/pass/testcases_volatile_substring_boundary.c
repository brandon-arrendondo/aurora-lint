/*
 * Rule: PRE31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger PRE31-C violation
 */

/*
 * Rule: PRE31-C - Avoid side effects in arguments to unsafe macros
 * Status: PASS
 * Reason: A short identifier ("i") must not be misdetected as volatile
 * just because it is a text-substring of an unrelated volatile
 * declaration's own name ("in") elsewhere in the file.
 */

#define MAX(a, b) ((a) > (b) ? (a) : (b))  /* double-evaluates its args */

volatile int in;

void func(int i) {
    // "i" is a plain (non-volatile) parameter, unrelated to volatile "in" -
    // COMPLIANT, no side effect in either operand.
    int m = MAX(i, 0);
}

int main(void) {
    func(5);
    return 0;
}
