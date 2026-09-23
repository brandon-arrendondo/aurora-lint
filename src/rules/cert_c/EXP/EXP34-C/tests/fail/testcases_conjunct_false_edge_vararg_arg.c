/*
 * Rule: EXP34-C
 * Source: testcases (mosquitto src/conf.c config__plugin_load)
 * Status: FAIL - `name` reaches the `report` call on the FALSE edge of
 *         `name && lookup(name)`, which is `!name || !lookup(name)` and so
 *         says nothing about `name`; a NULL `name` flows into a variadic
 *         logging wrapper's `%s`.
 *
 * Two readings of this edge have each lost this finding once:
 *
 *  - Reading `!(name && lookup(name))` as `!name` reported it as a
 *    DEFINITE null (right verdict, wrong reason -- the same misread that
 *    turned `!p || !q` into "both null"; 75162e1b fixed that).
 *  - After that fix the edge correctly joined to PossiblyNull, but the
 *    call-site check reported only DefinitelyNull arguments, so this
 *    finding vanished for one day of history (restored by d8de257a).
 *
 * `report` takes its argument through `...`, so no position-indexed
 * summary can model the parameter and the call-site check is the only
 * place the flow can be seen. The parameter is ASSUMED non-null -- there
 * is no caller in this file to prove otherwise -- so the disjunct stands.
 */

#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static void report(int level, const char *fmt, ...)
{
    va_list ap;
    (void)level;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

static int lookup(const char *name)
{
    return strcmp(name, "known") == 0;
}

int load(const char *name, const char *path)
{
    if (name && lookup(name)) {
        return -1;
    }

    if (!path || !strcmp(path, "")) {
        report(1, "Error: Missing plugin path for plugin name '%s'.", name);
        return -1;
    }
    return 0;
}
