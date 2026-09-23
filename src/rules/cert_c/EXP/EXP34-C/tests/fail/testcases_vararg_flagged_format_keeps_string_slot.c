/*
 * Rule: EXP34-C
 * Source: testcases
 * Status: FAIL - all three calls put `name` in a `%s` slot, and all three
 *         formats carry printf-only syntax: a space flag, a left-justify
 *         flag, a precision.
 *
 * The regression this pins: each family is read separately, and a family
 * whose syntax the string violates must ABSTAIN rather than report that
 * nothing is known. scanf has no flags and no precision, so its reading of
 * these strings is not a reading of them at all and the printf one stands
 * alone. Collapsing the two cases into one made every flagged or
 * precision-bearing printf format look unresolvable and silently suppressed
 * its `%s` slots -- caught on a real `"% *s %s"`, where the space flag alone
 * hid a genuine `%s`.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

static void log_msg(int level, const char *fmt, ...)
{
    va_list ap;
    (void)level;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

void render(int width)
{
    char *name = malloc(32);

    log_msg(1, "% *s done", -width, name);
    log_msg(1, "%-20s done", name);
    log_msg(1, "%.8s done", name);
}
