/*
 * Rule: MSC39-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MSC39-C violation
 *
 * A function that receives a va_list by value and calls va_arg() on it is
 * permitted; only a caller's later use of its own va_list is a violation.
 */

#include <stdarg.h>
#include <stdio.h>

void print_two(va_list ap) {
    int a = va_arg(ap, int);
    int b = va_arg(ap, int);
    printf("%d %d\n", a, b);
}
