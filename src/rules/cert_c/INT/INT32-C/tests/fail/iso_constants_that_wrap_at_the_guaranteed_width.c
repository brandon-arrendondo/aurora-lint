/*
 * Rule: INT32-C
 * Source: regression
 * Status: FAIL - no data model is declared
 *
 * Every operand here is an int constant that fits ISO C's guaranteed 16-bit
 * int, so the arithmetic is int arithmetic and the results (1048576,
 * 127 << 24) exceed the 32767 every conforming int holds. A constant above
 * 32767 would be int or long (tests/pass/iso_decimal_constant_takes_the_
 * first_type_that_holds_it.c) and a declared target with a 32-bit int fits
 * these (tests/pass).
 */

long megabyte(void) {
    long size;
    size = 1024 * 1024; /* VIOLATION */
    return size;
}

long loopback(void) {
    long address;
    address = (127 << 24) | 1; /* VIOLATION */
    return address;
}

long product_of_constants_each_16_bit(void) {
    long size;
    size = 30000 * 30000; /* VIOLATION */
    return size;
}
