/*
 * Rule: EXP33-C
 * Source: custom
 * Status: PASS - Should NOT trigger EXP33-C violation
 * Description: fatal() has a definition per build and each one ends the
 * process, so in either build the else branch never reaches `return v`.
 * abort() and exit() end it only under the library contract.
 * Settings: stdlib_noreturn=true
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
    exit(1);
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
