/*
 * Rule: INT02-C
 * Source: regression
 * Status: FAIL - signed `ssize_t` compared with unsigned `size_t`
 *
 * Both are 64-bit on LP64, so the usual arithmetic conversions turn the
 * signed operand unsigned: a negative `got` (a failed read) compares greater
 * than any `want`.
 */

#include <sys/types.h>

int short_read(ssize_t got, size_t want)
{
    return got < want;
}
