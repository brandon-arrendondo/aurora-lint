/*
 * Rule: EXP19-C
 * Source: custom
 * Status: PASS - Should not trigger EXP19-C violation
 * Description: Each body here comes through #if arms and is braced in every
 * configuration: through a nested chain, in an arm whose braced body has
 * another statement after it, after an if whose condition is split across
 * arms, and in a do statement after an arm of directives.
 */

void use_a(void);
void use_b(void);
void use_c(void);

void nested_chains(void)
{
    for (;;)
#ifdef FEATURE_A
#  ifdef FEATURE_B
    {
        use_a();
    }
#  else
    {
        use_b();
    }
#  endif
#else
    {
        use_c();
    }
#endif
}

void braced_then_more(int x)
{
    if (x)
#ifdef FEATURE_A
    {
        use_a();
    }
    use_a();
#else
    {
        use_b();
    }
#endif
}

int split_condition(int a, int b)
{
#ifdef FEATURE_A
    if (a && b)
#else
    if (a)
#endif
    {
        return 1;
    }
    return 0;
}

void count_down(int x)
{
    do
#ifdef FEATURE_A
#pragma message("counting down")
#endif
    {
        x--;
    }
    while (x);
}
