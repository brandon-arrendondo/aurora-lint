/*
 * Rule: EXP19-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP19-C violation
 */

/*
 * Rule: EXP19-C - Use braces for the body of an if, for, or while statement
 * Status: FAIL
 * Reason: The body is split across #if arms, but some configuration still
 *         gives the statement an unbraced body: one arm holds a bare
 *         statement (ADR-0010: each arm is a configuration that counts), or
 *         the chain has no #else, so without the macro the body is whatever
 *         follows the #endif.
 */

void use_a(void);
void use_b(void);

void one_arm_unbraced(int x)
{
    if (x)
#ifdef FEATURE_A
    {
        use_a();
    }
#else
        use_b();
#endif
}

void no_else_arm(int x)
{
    while (x-- > 0)
#ifdef FEATURE_A
    {
        use_a();
    }
#endif
    use_b();
}

int main(void)
{
    one_arm_unbraced(1);
    no_else_arm(2);
    return 0;
}
