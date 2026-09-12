/*
 * Rule: PRE31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger PRE31-C violation
 */

/*
 * Rule: PRE31-C - Avoid side effects in arguments to unsafe macros
 * Status: PASS
 * Reason: do-while(0) wrapper references its parameter exactly once, so
 * the argument's side effect only ever runs a single time.
 */

#define TRACE(x) \
    do {          \
        log_value(x); \
    } while (0)

void log_value(int v);
int next_value(void);

void func(void) {
    // Single-evaluation wrapper macro - COMPLIANT
    TRACE(next_value());
}

int main(void) {
    func();
    return 0;
}
