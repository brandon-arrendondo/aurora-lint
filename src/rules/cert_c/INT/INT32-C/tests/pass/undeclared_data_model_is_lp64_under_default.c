/*
 * Rule: INT32-C
 * Source: regression
 * Status: PASS under the default preset; VIOLATION under strict and pedantic
 * Expect: default=clean strict=violation pedantic=violation
 *
 * No data model is declared. The default preset assumes the common hosted
 * model, LP64, whose int is 32 bits, so `168 << 16` fits. The strict and
 * pedantic presets credit only the 16 bits ISO C guarantees int, where the
 * shift overflows.
 */

void widths(int value) {
    value = 168 << 16;
    (void)value;
}
