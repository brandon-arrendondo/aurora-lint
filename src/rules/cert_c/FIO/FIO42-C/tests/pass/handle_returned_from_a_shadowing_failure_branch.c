/*
 * Rule: FIO42-C
 *
 * Status: PASS - Should NOT trigger FIO42-C violation
 *
 * The failure branch declares a stream of its own under the same name and
 * returns it; that is another object, not the failed one, so both streams
 * are handed to the caller.
 */
#include <stdio.h>

FILE *open_or_fallback(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        FILE *f = fopen("fallback", "r");
        return f;
    }
    return f;
}
