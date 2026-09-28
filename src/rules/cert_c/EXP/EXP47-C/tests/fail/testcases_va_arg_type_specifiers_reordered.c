/*
 * Rule: EXP47-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP47-C violation
 */

/*
 * Rule: EXP47-C - Do not call va_arg with an argument of the incorrect type
 * Status: FAIL
 * Reason: short signed is the same type as signed short: the specifiers may come
 *         in any order, and it still promotes to int.
 */

#include <stdarg.h>

int first(int count, ...) {
    va_list ap;
    va_start(ap, count);
    int value = va_arg(ap, short signed);
    va_end(ap);
    return value;
}
