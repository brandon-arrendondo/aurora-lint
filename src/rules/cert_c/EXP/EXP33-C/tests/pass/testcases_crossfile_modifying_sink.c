// sqc-test: prescan
/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation. `data` is passed
 * by address to initSink(), which writes through its parameter
 * (*ptr = ...) before any read. Detected via intra-file prescan:
 * initSink's summary shows param 0 is modified, so this is a genuine
 * out-parameter initialization, not a read of uninitialized memory.
 */

void initSink(int *ptr) {
    *ptr = 42;
}

void f(void) {
    int data;
    initSink(&data);
    (void)data;
}
