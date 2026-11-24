/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: FAIL - Should trigger CON07-C violation
 * Expect: count=1
 *
 * The operand of `sizeof` is evaluated when its type is a variable length
 * array (C11 6.5.3.4p2), so `n` in `sizeof(char[n])` is read and stored
 * back: two accesses of the shared object.
 */

#include <stddef.h>

static size_t n;

void widen(void) { n = sizeof(char[n]) + 1; }
