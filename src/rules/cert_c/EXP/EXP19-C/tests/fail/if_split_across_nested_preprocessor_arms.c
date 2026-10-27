/*
 * Rule: EXP19-C
 * Source: custom
 * Status: FAIL - Should trigger EXP19-C violation
 * Description: An if whose condition is split across arms that sit inside
 * another #if chain has its body after the outermost #endif that holds the
 * split. It is reported there, once. It is also reported once when a do
 * whose body comes through a #pragma arm, later in the block, keeps the
 * parse from closing the chain: each arm's if still names the same
 * statement.
 * Expect: count=4
 */

int split_inside_an_else(int a, int b)
{
#ifdef FEATURE_A
    if (a && b)
#else
#ifdef FEATURE_B
    if (b)
#else
    if (a)
#endif
#endif
        return 1; /* Expect: here */
    return 0;
}

int split_three_deep(int a, int b)
{
#ifdef FEATURE_A
#ifdef FEATURE_B
#ifdef FEATURE_C
    if (a && b)
#else
    if (a)
#endif
#endif
#endif
        return 1; /* Expect: here */
    return 0;
}

int split_before_a_pragma_do(int a, int b)
{
#ifdef FEATURE_A
    if (a && b)
#else
    if (a)
#endif
        return 1; /* Expect: here */
    do /* Expect: here */
#ifdef FEATURE_A
#pragma message("counting down")
#endif
        a--;
    while (a);
    return 0;
}
