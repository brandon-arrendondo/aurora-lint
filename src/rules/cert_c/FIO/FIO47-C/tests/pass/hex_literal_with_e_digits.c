/*
 * Rule: FIO47-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FIO47-C violation
 *
 * In a hexadecimal constant, e and E are digits, not an exponent: 0xE0,
 * 0xdead and 0x1e5 are integer constants (C11 6.4.4.1). Only a p or P
 * exponent makes a hexadecimal constant floating (C11 6.4.4.2).
 */
#include <stdio.h>

void print_hex_constants(void) {
    printf("%d\n", 0xE0);
    printf("%x\n", 0xdead);
    printf("%d\n", 0x1e5);
    printf("%u\n", 0x1E5u);
    printf("%f\n", 0x1p4);
}
