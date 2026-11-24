/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - The in-range store may not run, so 99 may reach the read
 * Expect: count=5
 *
 * The masked store sits in a GNU statement expression under `&&`, under an
 * `if` inside a statement expression, braced or in a nested block, or in
 * the operand of `sizeof`, which is never evaluated. Each leaves `n`
 * holding 99 for `buf[64]`.
 */

extern int get(void);

int statement_expression_under_and(int c)
{
    int buf[64] = {0};
    int n = 99;
    (void)(c && ({ n = get() & 63; 1; }));
    return buf[n]; /* Expect: here */
}

int branch_in_a_statement_expression(int c)
{
    int buf[64] = {0};
    int n = 99;
    (void)({ if (c) n = get() & 63; 1; });
    return buf[n]; /* Expect: here */
}

int braced_branch_in_a_statement_expression(int c)
{
    int buf[64] = {0};
    int n = 99;
    (void)({ if (c) { n = get() & 63; } 1; });
    return buf[n]; /* Expect: here */
}

int nested_block_in_a_statement_expression(int c)
{
    int buf[64] = {0};
    int n = 99;
    (void)({ { if (c) n = get() & 63; } 1; });
    return buf[n]; /* Expect: here */
}

int under_sizeof(void)
{
    int buf[64] = {0};
    int n = 99;
    (void)sizeof(n = get() & 63);
    return buf[n]; /* Expect: here */
}
