/*
 * Rule: INT10-C
 * Source: task 673 (seL4 real-world FP, x86/kernel/x2apic.c:49, xapic.c:55)
 * Status: PASS - Should NOT trigger INT10-C violation
 *
 * seL4's `interrupt_t` enum has a negative member (`int_invalid = -1`), so
 * the enum's underlying type is genuinely signed overall. But `int_irq_min`
 * is a *different* member of that same enum, set to the macro constant
 * `IRQ_INT_OFFSET` (0x20) -- a value that's provably non-negative at
 * compile time, independent of the enum type's overall signedness. A
 * modulo operand backed by such a constant can't produce a negative
 * remainder, so `int_irq_min % 32` should not be flagged.
 */

#define IRQ_INT_OFFSET 0x20

typedef enum interrupt {
    int_invalid = -1,
    int_irq_min = IRQ_INT_OFFSET, /* First IRQ. */
    int_irq_max = IRQ_INT_OFFSET + 15
} interrupt_t;

int check_aligned(void) {
    return int_irq_min % 32 == 0;
}

int main(void) {
    return 0;
}
