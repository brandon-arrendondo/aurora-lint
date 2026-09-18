/*
 * Rule: PRE32-C
 * Source: aurora_lint 1284 (sel4 src/machine/capdl.c:335)
 * Status: FAIL - SHOULD trigger PRE32-C violation
 *
 * The counterpart to the pass case: here the callee is ordinary code and the
 * DIRECTIVE IS INSIDE THE ARGUMENT LIST, which is precisely what PRE32-C is
 * for. Pins that the 1284 fix keys on the callee and does not suppress this.
 */

extern int printf(const char *fmt, ...);

void dump(int i, unsigned long target, int irq)
{
    printf("%d: 0x%lx_%lu_irq\n",
           i,
#if defined(ENABLE_SMP_SUPPORT)
           (unsigned long)irq,
#else
           (unsigned long)irq,
#endif
           target);
}
