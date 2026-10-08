/*
 * Rule: MEM31-C
 * Source: real-world regression
 * Status: PASS under the default and strict presets; VIOLATION under pedantic
 * Expect: default=clean strict=clean pedantic=violation
 *
 * `die_keyword` is declared `_Noreturn` with no body in view. The default
 * and strict policies trust the keyword (C11 6.7.4p8; CERT MSC37-C-EX2), so
 * the free() before the call cannot reach the one after the `if`. The
 * pedantic policy accepts only a body verified never to return, so both
 * frees are on one path.
 */

#include <stdlib.h>

static _Noreturn void die_keyword(const char *msg);

void noreturn_keyword(int cond) {
    char *p = malloc(32);
    if (cond) {
        free(p);
        die_keyword("out of memory");
    }
    free(p);
}
