/*
 * Rule: EXP47-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP47-C violation
 */

/*
 * Rule: EXP47-C - Do not call va_arg with an argument of the incorrect type
 * Status: PASS
 * Reason: The narrow va_arg reads are written only inside comments in the
 *         macros' replacement lists, which call nothing. The one real read
 *         takes an int.
 */

#include <stdarg.h>

#define UNUSED_NOTE(ap) 0 /* va_arg(ap, char) would be undefined here */
#define UNUSED_LINE(ap) 0 // not va_arg(ap, short)
#define NEXT_INT(ap) /* not va_arg(ap, float) */ va_arg(ap, int)

int first(int count, ...) {
    va_list ap;
    va_start(ap, count);
    int value = NEXT_INT(ap) + UNUSED_NOTE(ap) + UNUSED_LINE(ap);
    va_end(ap);
    return value;
}
