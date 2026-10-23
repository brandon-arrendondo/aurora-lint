/*
 * Rule: EXP19-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP19-C violation
 */

/*
 * Rule: EXP19-C - Use braces for the body of an if, for, or while statement
 * Status: PASS
 * Reason: The body sits in every arm of an #if chain that ends in #else,
 *         and each arm holds one braced block. Every configuration picks
 *         one arm, so in each the body is braced. tree-sitter parses the
 *         chain as the statement's next sibling and gives the statement an
 *         empty recovered body, which is not the body the code has.
 */

void use_a(void);
void use_b(void);
void use_c(void);

void two_arms(int x)
{
    if (x)
#ifdef FEATURE_A
    {
        use_a();
    }
#else
    {
        use_b();
    }
#endif
}

void three_arms(int x)
{
    while (x-- > 0)
#if defined(FEATURE_A)
    {
        use_a();
    }
#elif defined(FEATURE_B)
    {
        use_b();
    }
#else
    {
        /* Neither feature: nothing to do. */
        use_c();
    }
#endif
}

void loop_arms(int n)
{
    int i;
    for (i = 0; i < n; i++)
#ifdef FEATURE_A
    {
        use_a();
    }
#else
    {
        use_b();
    }
#endif
}

int main(void)
{
    two_arms(1);
    three_arms(2);
    loop_arms(3);
    return 0;
}
