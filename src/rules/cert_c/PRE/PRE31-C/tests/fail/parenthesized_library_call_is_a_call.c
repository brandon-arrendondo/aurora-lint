/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: `(getc)(fp)` calls the function getc, the parentheses only
 * keeping its macro from expanding; reading a character advances the
 * stream, and TWICE evaluates its argument twice.
 */

#include <stdio.h>

#define TWICE(x) ((x) + (x))

int two_chars(FILE *fp) {
    return TWICE((getc)(fp));  // Expect: here
}
