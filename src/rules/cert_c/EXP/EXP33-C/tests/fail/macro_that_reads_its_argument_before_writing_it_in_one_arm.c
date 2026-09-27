/*
 * Rule: EXP33-C
 * Source: custom
 * Status: FAIL - Should trigger EXP33-C violation
 * Description: BUMP reads its argument before assigning it when X is
 * defined, and drops it otherwise. With X, BUMP(v) reads the
 * uninitialized v. An argument one build drops is untouched only when
 * every other build writes it without reading it first.
 */

int g(int v);

#ifdef X
#define BUMP(v) ((v) = g(v))
#else
#define BUMP(v) 0
#endif

int f(void)
{
    int v;
    BUMP(v);
    return 0;
}
