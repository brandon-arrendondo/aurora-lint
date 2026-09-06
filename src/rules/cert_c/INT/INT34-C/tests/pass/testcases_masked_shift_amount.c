/*
 * Rule: INT34-C
 * Status: PASS - Shift amount explicitly clamped with a bitmask.
 *
 * Masking the shift amount with a compile-time constant is the compliant
 * idiom: `n & 31` can only be 0..31. seL4's kernel/cspace.c writes the
 * unfoldable form -- `& MASK(wordRadix)`, with a comment saying it is there
 * "to avoid the case where n_bits = wordBits and guardBits = 0, as it
 * violates the C spec to shift right by more than wordBits-1" -- i.e. the
 * developers already fixed this exact hazard at this exact line.
 */

#define MASK(n) ((1ul << (n)) - 1ul)
#define wordRadix ARCH_WORD_RADIX

unsigned long shift_masked_by_literal(unsigned long x, unsigned int n) {
    return x >> (n & 31);
}

unsigned long shift_masked_by_literal_reversed(unsigned long x, unsigned int n) {
    return x << (31 & n);
}

unsigned long shift_masked_by_macro(unsigned long capptr, unsigned int n_bits,
                                    unsigned int guardBits) {
    return capptr >> ((n_bits - guardBits) & MASK(wordRadix));
}
