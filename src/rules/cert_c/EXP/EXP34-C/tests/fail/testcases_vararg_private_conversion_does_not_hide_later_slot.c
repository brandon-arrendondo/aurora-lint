/*
 * Rule: EXP34-C
 * Source: testcases
 * Status: FAIL - in both calls the reported pointer sits in a `%s` slot that
 *         follows an implementation-private conversion sqlite's own formatter
 *         defines (`%z`, `%Q`). The private conversion makes its OWN slot
 *         unknown and nothing more.
 *
 * The regression this pins: an unrecognized conversion consumes one argument,
 * because that is what one `va_arg` in a handler does, so the slots after it
 * still line up. Stopping the parse instead -- on the reasoning that an
 * unknown conversion consumes an unknown count -- silenced 36 genuine `%s`
 * slots across the pinned corpora, whose claims would have been true.
 * Declining to report those is narrowing the rule (docs/adr/0001), not fixing
 * a misfire (docs/adr/0005).
 *
 * `%z` also pins the parse itself: `z` is a real C length modifier (`%zu`),
 * so reading the `%` of the following `%s` as `%z`'s conversion character
 * swallowed that `%s` and lost a slot outright.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

static void error_msg(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

void rebuild_statements(void)
{
    char *list = malloc(32);
    char *name = malloc(32);

    error_msg("%z%s%s", list, ", ", name);
    error_msg("DELETE FROM %Q.%s WHERE k=1", "db", name);
}
