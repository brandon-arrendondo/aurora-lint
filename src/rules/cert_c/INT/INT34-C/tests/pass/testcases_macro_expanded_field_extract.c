/*
 * Rule: INT34-C
 * Status: PASS - The bound on the shift amount lives inside a `#define`, or
 * one assignment back, or both.
 *
 * Hardware drivers extract a register field with a function-like macro and
 * shift by it. The mask that bounds the field is written once, in the macro,
 * and the shift site names only the macro -- so the amount reads as an opaque
 * call until the replacement list is expanded. seL4's SMMUv2 driver
 * (`IDR0_NUMSIDB_VAL(reg & IDR0_NUMSIDB)`) and its ARM cache maintenance
 * (`int lbits = LINEBITS(s);`) are both this shape.
 */

#define MASK(n) ((1ul << (n)) - 1ul)
#define LINEBITS(s) (((s) & MASK(3)) + 4)
#define IDR0_NUMSIDB (0xf << 9)
#define IDR0_NUMSIDB_VAL(v) ((v) >> 9)

extern unsigned long read_reg(void);

/* The amount is the invocation itself: (reg & 0x1e00) >> 9 is 0..15. */
unsigned long shift_by_field_extract(unsigned long x, unsigned long reg) {
    return x << IDR0_NUMSIDB_VAL(reg & IDR0_NUMSIDB);
}

/* The invocation is one assignment back, and arithmetic follows it. */
unsigned long shift_by_field_extract_via_local(unsigned long x) {
    unsigned long reg = read_reg();
    int field = IDR0_NUMSIDB_VAL(reg & IDR0_NUMSIDB);
    return x << (field + 1);
}

/* Nested macros: LINEBITS masks with MASK(3), so lbits is 4..11. */
unsigned long shift_by_line_bits(unsigned long x, unsigned long s) {
    int lbits = LINEBITS(s);
    return x << lbits;
}

/* No macro at all -- a local masked and scaled in place is 0..30. */
unsigned long shift_by_masked_local(unsigned long x, unsigned long hw_irq) {
    int bit = ((hw_irq & 0xf) * 2);
    return x << bit;
}
