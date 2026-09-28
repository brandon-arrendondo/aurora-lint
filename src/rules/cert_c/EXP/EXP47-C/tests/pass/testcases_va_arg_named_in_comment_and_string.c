/*
 * Rule: EXP47-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP47-C violation
 */

/*
 * Rule: EXP47-C - Do not call va_arg with an argument of the incorrect type
 * Status: PASS
 * Reason: Every va_arg call reads a promoted type or a pointer: `char *`
 *         is not `char`. The narrow types appear only inside a comment and a
 *         string literal, which call nothing.
 */

#include <stdarg.h>
#include <stdio.h>

static const char *usage = "never write va_arg(ap, char); read an int";

/* va_arg(ap, float) would be undefined: a float argument arrives as double */
int sum(int count, ...) {
    va_list ap;
    int total = 0;
    va_start(ap, count);
    const char *label = va_arg(ap, char *);
    for (int i = 0; i < count; i++) {
        total += (unsigned char)va_arg(ap, int);
    }
    va_end(ap);
    puts(usage);
    puts(label);
    return total;
}
