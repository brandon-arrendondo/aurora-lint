/*
 * Rule: INT34-C
 * Status: PASS - Shift amount is a call to a helper whose every return is a
 * compile-time constant.
 *
 * seL4's `pageBitsForSize()` is a `static inline word_t CONST` switch
 * returning one of three enumerators; the enumerators are defined in a
 * generated per-architecture header outside the scan, so the returns are
 * fixed but unfoldable and `FunctionSummary::return_range` stays None.
 * Hoisting the constant-shift-amount reasoning across the call is what
 * settles these: a shift by `pageBitsForSize(sz)` is no more of a runtime
 * hazard than a shift by `12`.
 *
 * `bits_for_level()` is the foldable counterpart, settled by the callee's
 * return range instead.
 */

typedef unsigned long word_t;

static word_t page_bits_for_size(int sz) {
    switch (sz) {
    case 0:
        return seL4_PageBits;
    case 1:
        return seL4_LargePageBits;
    default:
        return ARMSectionBits;
    }
}

static unsigned int bits_for_level(int level) {
    if (level == 0) {
        return 9;
    }
    return 12;
}

word_t frame_base(word_t addr, int sz) {
    return addr >> page_bits_for_size(sz);
}

word_t frame_size(int sz) {
    return 1ul << (page_bits_for_size(sz) - 1);
}

word_t level_mask(word_t x, int level) {
    return x >> bits_for_level(level);
}
