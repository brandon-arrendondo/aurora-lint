/*
 * Rule: API00-C
 * Source: synthetic
 * Status: PASS under the default preset; VIOLATION under strict
 * Expect: default=clean strict=violation
 *
 * `buf` is never read through here, only handed to free(). free(NULL) does
 * nothing in a hosted environment (C11 7.22.3.3p2), so NULL is a fine value
 * and there is nothing to validate. The strict preset declares a
 * freestanding environment with no library model, where free() is an
 * unknown callee that may dereference its argument.
 */
#include <stdlib.h>

void buffer_release(char *buf)
{
    free(buf);
}
