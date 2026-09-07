/*
 * Rule: MSC12-C
 * Status: FAIL - a genuinely no-effect statement that merely happens to sit
 *         inside a conditional-compilation block. The preprocessor-fragment
 *         guard must not swallow this: the line before the `#ifdef` ends a
 *         statement, so nothing here is being continued.
 */

void f(int x, int y)
{
    int total = 0;
#ifdef SQC_TEST_DEBUG
    x + y;  /* VIOLATION: result discarded */
#endif
    total = x + y;
    (void)total;
}
