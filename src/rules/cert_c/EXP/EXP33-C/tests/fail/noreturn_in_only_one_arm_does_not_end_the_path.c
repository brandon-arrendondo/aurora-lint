/*
 * Rule: EXP33-C
 * Source: custom
 * Status: FAIL - Should trigger EXP33-C violation
 * Description: fatal() aborts only when HARD_FAIL is defined; the other
 * build's definition logs and returns, so there the else branch reaches
 * `return v` with v unassigned. A function is noreturn only when every
 * live definition ends the process.
 */

#include <stdlib.h>

void log_msg(const char *m);

#ifdef HARD_FAIL
void fatal(const char *m)
{
    log_msg(m);
    abort();
}
#else
void fatal(const char *m)
{
    log_msg(m);
}
#endif

int get(int x)
{
    int v;
    if (x > 0)
        v = 1;
    else
        fatal("bad argument");
    return v;
}
