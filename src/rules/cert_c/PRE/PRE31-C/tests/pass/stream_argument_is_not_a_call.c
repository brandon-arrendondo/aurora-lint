/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: putc may evaluate its stream argument more than once, but stdout
 * is an object, not a call: reading it again changes nothing, under either
 * preset.
 */

#include <stdio.h>

int emit(int c) {
    return putc(c, stdout);
}
