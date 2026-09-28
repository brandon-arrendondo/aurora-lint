/*
 * Rule: EXP47-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP47-C violation
 */

/*
 * Rule: EXP47-C - Do not call va_arg with an argument of the incorrect type
 * Status: FAIL
 * Reason: The type argument unsigned short is split across two lines. It is
 *         still unsigned short, which promotes to int.
 */

#include <stdarg.h>

int first(int count, ...) {
    va_list ap;
    va_start(ap, count);
    int value = va_arg(ap, unsigned
                       short);
    va_end(ap);
    return value;
}
