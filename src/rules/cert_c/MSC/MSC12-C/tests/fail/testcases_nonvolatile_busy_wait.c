/*
 * Rule: MSC12-C
 * Status: FAIL - the same bare-dereference busy-wait shape over a
 *         NON-volatile object. The compiler is free to hoist the read out of
 *         the loop and turn it into an infinite one, so this stays flagged:
 *         seL4's own `while (!timer->tistat);` polls a memory-mapped register
 *         its header never marks volatile, and the conservative answer is
 *         also the right one.
 */

struct timer {
    unsigned int tistat;
};

struct timer *timer = (struct timer *)0x49040000;

void init_timer(void)
{
    while (!timer->tistat);  /* VIOLATION */
}
