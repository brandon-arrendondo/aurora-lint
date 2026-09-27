/*
 * Rule: EXP33-C
 * Source: custom
 * Status: FAIL - Should trigger EXP33-C violation
 * Description: GET assigns its argument when X is defined and expands to
 * `0` otherwise. Without X, v is never written and use(v) reads it
 * uninitialized. A definition that drops the argument is a build that does
 * not write it.
 */

int f(void);
int use(int v);

#ifdef X
#define GET(v) ((v) = f())
#else
#define GET(v) 0
#endif

int g(void)
{
    int v;
    GET(v);
    return use(v);
}
