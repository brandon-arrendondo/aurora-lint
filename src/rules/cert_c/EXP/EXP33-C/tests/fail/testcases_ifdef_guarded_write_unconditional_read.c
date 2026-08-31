/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP33-C violation. `rfds` is written ONLY
 * inside an `#ifdef CONFIG_A` block, but read UNCONDITIONALLY (outside any
 * guard) afterwards. Task 590's correlated-#ifdef-guard fix must not
 * suppress this: unlike the correlated case (same guard on both the write
 * and the read), an unconditional read has no guard of its own to compare
 * against the write's, so if `CONFIG_A` is undefined in some real build,
 * this read genuinely sees uninitialized memory.
 */
void use(int *p);

void f(void) {
    int *rfds;
#ifdef CONFIG_A
    rfds = (int *)malloc(sizeof(int));
#endif
    use(rfds);
}
