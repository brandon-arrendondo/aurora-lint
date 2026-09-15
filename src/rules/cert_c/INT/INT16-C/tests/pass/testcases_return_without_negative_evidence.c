/*
 * Rule: INT16-C
 * Source: task-follow-up (return-path VRA gate)
 * Status: PASS - signed-to-unsigned return where no value here can be
 * negative
 *
 * Mirrors the assign-path's own "without_negative_evidence" fixture: a
 * signed declaration says a sign CAN be there, but nothing here proves one
 * actually is. Real-world driver: sqlite's WhereLoop.wsFlags (an OR of
 * documented non-negative constants) and result-code returns accounted for
 * ~688 of 710 sqlite FPs before this gate existed.
 */

#define FLAG_A 0x01
#define FLAG_B 0x02

/* An unconstrained int parameter returned as unsigned: nothing says it can
   be negative. */
unsigned int passthrough(int x) {
    return x;
}

/* A flag-OR accumulator built from non-negative constants only. */
unsigned int build_flags(int enable_a, int enable_b) {
    int flags = 0;
    if (enable_a) {
        flags |= FLAG_A;
    }
    if (enable_b) {
        flags |= FLAG_B;
    }
    return flags;
}
