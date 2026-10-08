/*
 * Rule: API00-C
 * Source: synthetic
 * Status: PASS under the default and strict presets; VIOLATION under pedantic
 * Expect: default=clean strict=clean pedantic=violation
 *
 * `buf` is never read through here, only handed to free(). free(NULL) does
 * nothing in a hosted environment (C11 7.22.3.3p2), so NULL is a fine value
 * and there is nothing to validate. The pedantic preset trusts only a
 * declared library, and this fixture declares none, so free() is an unknown
 * callee that may dereference its argument.
 */
#include <stdlib.h>

void buffer_release(char *buf)
{
    free(buf);
}
