/*
 * Rule: INT32-C
 * Source: regression
 * Status: PASS - no data model is declared
 *
 * C11 6.4.4.1p5 gives an unsuffixed decimal constant the first of int, long
 * and long long that can represent it. ISO C guarantees int only 16 bits, so
 * a decimal constant above 32767 is int or long: either way wide enough that
 * the arithmetic below cannot overflow, and so is checked at that width
 * instead of at int's 16.
 */

long seconds_per_week(void) {
    long span;
    span = 86400 * 7;
    return span;
}

long microseconds(void) {
    long span;
    span = 5 * 1000000;
    return span;
}

long scaled_remainder(unsigned micros) {
    long span;
    span = (micros % 1000000) * 1000;
    return span;
}

long bounded_year_product(int year) {
    if (year < 0 || year > 3000) {
        return 0;
    }
    return 36525 * (year + 4716);
}

long suffixed(void) {
    long span;
    span = 86400L * 365;
    return span;
}
