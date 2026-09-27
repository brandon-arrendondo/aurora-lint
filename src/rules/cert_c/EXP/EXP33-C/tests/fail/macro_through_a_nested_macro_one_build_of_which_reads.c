/*
 * Rule: EXP33-C
 * Source: custom
 * Status: FAIL - Should trigger EXP33-C violation
 * Description: GET expands through INNER, which assigns its argument when
 * X is defined and passes it to log_value otherwise. Without X, GET(w)
 * reads the uninitialized w. A fact read through a nested macro holds
 * only if every build of that macro agrees.
 */

int f1(void);
void log_value(int v);

#ifdef X
#define INNER(v) ((v) = f1())
#else
#define INNER(v) log_value(v)
#endif

#define GET(v) INNER(v)

int g(void)
{
    int w;
    GET(w);
    return 0;
}
