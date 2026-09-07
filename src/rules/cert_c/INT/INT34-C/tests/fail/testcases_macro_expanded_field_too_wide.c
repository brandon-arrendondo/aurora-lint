/*
 * Rule: INT34-C
 * Status: FAIL - Expanding the macro and resolving the local proves a bound,
 * and the bound is not narrow enough.
 *
 * The negative half of the field-extract case. Following a shift amount back
 * through a `#define` and an assignment must not degrade into "anything with a
 * mask on it somewhere is fine": an eight-bit field still reaches 255, and a
 * local reassigned from an opaque source has no bound at all past that point.
 * seL4's gic_v3 `1 << aff0`, where `MPIDR_AFF0(x)` masks to `0xff`, is the
 * first shape; sqlite's `apndReadMark`, which counts `msbs` down 48, 40, ...
 * 0 with a compound assignment, is the third.
 */

#define MPIDR_AFF0(x) ((x) & 0xff)

extern unsigned long read_reg(void);

/* 0..255 -- wider than any 32-bit operand. */
unsigned long shift_by_wide_field(unsigned long x, unsigned long mpidr) {
    unsigned long aff0 = MPIDR_AFF0(mpidr);
    return x << aff0;
}

/* Bounded, then overwritten from a call with no known range. */
unsigned long shift_by_reassigned_local(unsigned long x, unsigned long reg) {
    unsigned long n = reg & 7;
    n = read_reg();
    return x << n;
}

/* `msbs -= 8` says how the value changes, not what it becomes: the amount
   here runs up to 48, and reading the RHS as the new value would put it at a
   flat 8. */
unsigned long shift_by_compound_assigned_local(const unsigned char *a) {
    int msbs = 56;
    unsigned long mark = 0;
    int i;
    for (i = 1; i < 8; i++) {
        msbs -= 8;
        mark |= ((unsigned long)a[i]) << msbs;
    }
    return mark;
}
