/*
 * Rule: INT34-C
 * Status: PASS - Shift amounts fixed at compile time.
 *
 * A shift by a compile-time constant is no more of an INT34-C hazard than a
 * shift by a numeric literal: the amount cannot vary at run time, and an
 * out-of-range constant is visible to the compiler. That holds whether or
 * not sqc can fold the constant to an integer -- PAGE_BITS below expands
 * through a name defined in a header outside the scan, exactly the shape
 * seL4 uses, and EXTERNAL_SHIFT_BITS is declared nowhere in this
 * translation unit at all, so it can only be a macro or enumerator from an
 * unparsed header.
 */

#define PAGE_BITS SOME_ARCH_PAGE_BITS
#define PT_INDEX_BITS SOME_ARCH_PT_INDEX_BITS

unsigned long shift_by_macro_constant(unsigned long x) {
    return x >> PAGE_BITS;
}

unsigned long shift_by_macro_constant_sum(unsigned long x) {
    return x >> (PAGE_BITS + PT_INDEX_BITS);
}

unsigned long shift_by_unparsed_header_constant(unsigned long x) {
    return x << EXTERNAL_SHIFT_BITS;
}

enum page_bits { SMALL_PAGE_BITS = SOME_ARCH_PAGE_BITS };

unsigned long shift_by_enumerator(unsigned long x) {
    return x >> SMALL_PAGE_BITS;
}
