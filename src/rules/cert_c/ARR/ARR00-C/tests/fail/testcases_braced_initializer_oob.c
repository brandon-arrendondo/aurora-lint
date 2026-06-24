/*
 * Rule: ARR00-C
 * Source: testcases
 * Status: FAIL - Should trigger ARR00-C violation
 */

/*
 * ARR00-C FAIL Case: genuine out-of-bounds access on braced-initialized arrays
 *
 * Confirms the AST size resolver (task 234) still detects real overflows:
 *   - size taken from an explicit dimension with a braced initializer, and
 *   - size inferred from the initializer element count when no size is given.
 */

void explicit_size_oob(void)
{
    int a[3] = { 1, 2, 3 };
    a[5] = 0; /* 5 >= 3: out of bounds */
}

void inferred_size_oob(void)
{
    int b[] = { 1, 2 }; /* size 2 from the initializer */
    b[7] = 0;           /* 7 >= 2: out of bounds */
}
