/*
 * Rule: INT10-C
 * Source: task 674 (seL4 real-world FP,
 *         src/plat/bcm2837/machine/intc.c:125 and :127)
 * Status: PASS - Should NOT trigger INT10-C violation
 *
 * `normal_irq` is genuinely declared `int` -- signed, and no typedef chain
 * to walk. What makes it non-negative is the enclosing guard flow: the
 * `else if` is reachable only after `if (irq < NORMAL_IRQ_OFFSET)` took its
 * other branch, so `irq - NORMAL_IRQ_OFFSET >= 0`. Value-range analysis
 * sees that, and a non-negative dividend can't yield a negative remainder
 * (C99 6.5.5p6 truncates toward zero, so `a % b` carries the sign of `a`).
 *
 * NORMAL_IRQ_OFFSET is deliberately written as a macro defined in terms of
 * another macro: refining the guard requires the macro constants to have
 * been folded, which is what makes this fixture also cover the VRA macro
 * plumbing the real seL4 case needed.
 */
// sqc-test: prescan

#define BASIC_IRQ_OFFSET  32
#define NORMAL_IRQ_OFFSET (BASIC_IRQ_OFFSET + 32)

extern int max_irq;
extern unsigned long enable_bits[8];

void mask_interrupt(int irq)
{
    if (irq < BASIC_IRQ_OFFSET) {
        return;
    }

    if (irq < NORMAL_IRQ_OFFSET) {
        enable_bits[0] = 1ul << (irq - BASIC_IRQ_OFFSET);
    } else if (irq <= max_irq) {
        int normal_irq = irq - NORMAL_IRQ_OFFSET;
        int index = normal_irq / 32;
        enable_bits[index] = 1ul << (normal_irq % 32);
    }
}

int main(void) {
    return 0;
}
