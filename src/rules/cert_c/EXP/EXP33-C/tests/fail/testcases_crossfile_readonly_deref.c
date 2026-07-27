// sqc-test: prescan
/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP33-C violation. `data` is passed by
 * address to badSink(), which dereferences its parameter (reads *ptr)
 * but never writes through it. Detected via intra-file prescan: badSink's
 * summary shows a read-only dereference of param 0, so passing an
 * uninitialized variable's address to it is still a read of uninitialized
 * memory, not an initialization.
 */

void badSink(int *ptr) {
    int local = *ptr;
    (void)local;
}

void f(void) {
    int data;
    badSink(&data);
}
