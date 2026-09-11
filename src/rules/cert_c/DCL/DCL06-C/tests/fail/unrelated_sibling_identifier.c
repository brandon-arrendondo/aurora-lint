/*
 * Rule: DCL06-C
 * Source: bmdb-757
 * Status: FAIL - Noncompliant, must not be over-suppressed
 * Description: a sibling identifier in the same call that does NOT echo the
 * literal's own value is an ordinary, unrelated argument -- this must still
 * be flagged, guarding against the DCL06-C-757 sibling-echo exemption
 * over-firing whenever any identifier happens to sit next to a number.
 */

void init_idt_entry(void *idt, int vector, void (*handler)(void));
void int_19(void);

void unrelated_call(void *ctx) {
    init_idt_entry(ctx, 0x37, int_19);
}
