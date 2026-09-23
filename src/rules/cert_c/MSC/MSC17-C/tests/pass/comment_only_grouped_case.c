/*
 * Rule: MSC17-C
 * Source: sel4 src/plat/bcm2837/machine/intc.c (task 632)
 * Status: PASS - Should NOT trigger MSC17-C violation
 *
 * An empty grouped case label whose only content is an unrelated comment
 * (not a "fall through" marker) is still empty -- a comment is not a
 * statement, and CERT explicitly allows grouping labels with nothing
 * between them.
 */

void f(int irq) {
  switch (irq) {
  case 1:
    // Not maskable
  case 2:
    // Not currently handled
  case 3:
    return;
  default:
    break;
  }
}
