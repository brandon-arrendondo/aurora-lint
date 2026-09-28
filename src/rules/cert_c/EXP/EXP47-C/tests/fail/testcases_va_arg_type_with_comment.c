/*
 * Rule: EXP47-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP47-C violation
 */

/*
 * Rule: EXP47-C - Do not call va_arg with an argument of the incorrect type
 * Status: FAIL
 * Reason: The type argument is char with a comment beside it. The comment is not
 *         part of the type, which still promotes to int.
 */

#include <stdarg.h>

int first(int count, ...) {
    va_list ap;
    va_start(ap, count);
    int value = va_arg(ap, char /* one byte */);
    va_end(ap);
    return value;
}
