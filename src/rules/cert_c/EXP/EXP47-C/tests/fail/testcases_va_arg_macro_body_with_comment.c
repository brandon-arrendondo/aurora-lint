/*
 * Rule: EXP47-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP47-C violation
 */

/*
 * Rule: EXP47-C - Do not call va_arg with an argument of the incorrect type
 * Status: FAIL
 * Reason: The macro's replacement list reads a char, with a comment between
 *         the arguments. The comment does not end the list.
 */

#include <stdarg.h>

#define NEXT_BYTE(ap) va_arg(ap, /* narrow */ char)

int first(int count, ...) {
    va_list ap;
    va_start(ap, count);
    int value = NEXT_BYTE(ap);
    va_end(ap);
    return value;
}
