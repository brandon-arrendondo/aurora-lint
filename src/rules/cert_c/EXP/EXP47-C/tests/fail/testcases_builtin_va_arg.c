/*
 * Rule: EXP47-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP47-C violation
 */

/*
 * Rule: EXP47-C - Do not call va_arg with an argument of the incorrect type
 * Status: FAIL
 * Reason: __builtin_va_arg is what <stdarg.h> defines va_arg as. Reading a char
 *         through it is the same defect as through va_arg.
 */

#include <stdarg.h>

int first(int count, ...) {
    va_list ap;
    va_start(ap, count);
    int value = __builtin_va_arg(ap, char);
    va_end(ap);
    return value;
}
