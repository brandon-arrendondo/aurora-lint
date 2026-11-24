/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: FAIL - POSIX's off_t is a signed integer type
 * Expect: count=1
 *
 * `off_t` comes from `<sys/types.h>`, which POSIX requires to be signed, so
 * an offset may be negative, and converting it to `unsigned long long`
 * changes such a value. No typedef in reach says otherwise.
 */

#include <sys/types.h>

unsigned long long as_unsigned(off_t offset)
{
    return (unsigned long long)offset; /* Expect: here */
}
