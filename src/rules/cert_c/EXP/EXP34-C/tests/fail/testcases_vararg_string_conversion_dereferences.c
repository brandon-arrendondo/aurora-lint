/*
 * Rule: EXP34-C
 * Source: testcases
 * Status: FAIL - `name` is unguarded after malloc and lands in a `%s` slot,
 *         which reads the string it points at. This is the shape the vararg
 *         call-site check exists for, and it is reported in both readings of
 *         the format string: printf's `%s` reads the pointee and scanf's
 *         writes through it.
 *
 * The counterpart to the `%p` and private-conversion pass fixtures: those
 * only prove the model suppresses, and a model that suppressed everything
 * would pass them too. `code` occupies slot 0 (`%d`) and `name` slot 1, so
 * an off-by-one in the format-argument index would move `name` onto the `%d`
 * and silence this.
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

void report_failure(int code)
{
    char *name = malloc(32);

    log_msg(1, "code %d for %s", code, name);
}
