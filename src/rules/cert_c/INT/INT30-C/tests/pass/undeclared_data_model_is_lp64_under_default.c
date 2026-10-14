/*
 * Rule: INT30-C
 * Source: regression
 * Status: PASS under the default preset; VIOLATION under strict and pedantic
 * Expect: default=clean strict=violation pedantic=violation
 *
 * No data model is declared. The default preset assumes the common hosted
 * model, LP64, whose unsigned int is 32 bits, so `1U << 31` fits. The strict
 * and pedantic presets credit only the 16 bits ISO C guarantees unsigned int,
 * where the shift wraps.
 */

void widths(unsigned value) {
    value = 1U << 31;
    (void)value;
}
