/*
 * Rule: EXP33-C
 * Source: custom
 * Status: PASS - Should NOT trigger EXP33-C violation
 * Description: GET expands through INNER, which is defined two ways, and
 * both assign the argument. GET(w) writes w in every build, so neither
 * GET(w) nor the return reads it uninitialized.
 */

int f1(void);
int f2(void);

#ifdef X
#define INNER(v) ((v) = f1())
#else
#define INNER(v) ((v) = f2())
#endif

#define GET(v) INNER(v)

int g(void)
{
    int w;
    GET(w);
    return w;
}
