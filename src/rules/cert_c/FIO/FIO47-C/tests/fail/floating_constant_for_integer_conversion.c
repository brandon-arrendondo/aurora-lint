/*
 * Rule: FIO47-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO47-C violation
 *
 * A decimal constant with an exponent, a fraction or a hexadecimal constant
 * with a p exponent is floating (C11 6.4.4.2), and %d takes an int.
 */
#include <stdio.h>

void print_floating_constants(void) {
    printf("%d\n", 1e5);
    printf("%d\n", 2.5);
    printf("%d\n", 0x1p4);
}
