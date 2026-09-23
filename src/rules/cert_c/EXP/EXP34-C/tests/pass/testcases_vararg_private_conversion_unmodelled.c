/*
 * Rule: EXP34-C
 * Source: testcases
 * Status: PASS - `%T` and `%#T` are conversions sqlite's own formatter
 *         implements, not C ones. A conversion this model does not recognize
 *         consumes an unknown number of arguments and does an unknown thing
 *         with it, so nothing is claimed about its slot -- and sqlite's
 *         handlers in fact test the pointer (`ALWAYS(pExpr)`, `pToken &&
 *         pToken->n`) before the only dereference.
 *
 * The second call also pins the slot arithmetic: the `%s` takes slot 0 and
 * the `%#T` takes slot 1, so `tok` is only unreported if the unrecognized
 * conversion is matched to the right argument. Only its OWN slot goes
 * unknown -- see tests/fail/testcases_vararg_private_conversion_does_not_
 * hide_later_slot.c for the other half.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

struct token {
    const char *z;
    int n;
};

static void error_msg(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

void resolve_name(int negated)
{
    struct token *tok = malloc(sizeof(*tok));

    error_msg("unknown database %T", tok);
    error_msg("oversized integer: %s%#T", negated ? "-" : "", tok);
}
