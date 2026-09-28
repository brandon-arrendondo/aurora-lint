/*
 * Rule: EXP47-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP47-C violation
 */

/*
 * Rule: EXP47-C - Do not call va_arg with an argument of the incorrect type
 * Status: FAIL
 * Reason: The macro's replacement list reads a short, which arrives promoted
 *         to int. The defect is written in the macro body, so it is reported
 *         there, at the va_arg itself.
 */

#include <stdarg.h>

#define NEXT_SHORT(ap) \
    va_arg(ap, unsigned short)

int first(int count, ...) {
    va_list ap;
    va_start(ap, count);
    int value = NEXT_SHORT(ap);
    va_end(ap);
    return value;
}
