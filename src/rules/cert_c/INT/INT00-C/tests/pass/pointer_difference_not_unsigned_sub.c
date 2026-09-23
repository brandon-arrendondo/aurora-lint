/*
 * Rule: INT00-C
 * Source: task 914 (found reproducing the INT30-C/INT31-C pointer instances)
 * Status: PASS - Should NOT trigger INT00-C violation
 * Reason: `pos - orig_pos` subtracts two POINTERS. Classifying the type by
 *         its specifier made `unsigned char *` start with "unsigned", so a
 *         pointer difference read as an unguarded unsigned subtraction. The
 *         result is a signed ptrdiff_t and cannot wrap that way.
 */

#include <stddef.h>

size_t consumed(unsigned char *pos, unsigned char *orig_pos) {
    return (size_t)(pos - orig_pos);
}

size_t consumed_local(unsigned char *base) {
    unsigned char *walk = base;
    walk += 4;
    return (size_t)(walk - base);
}
