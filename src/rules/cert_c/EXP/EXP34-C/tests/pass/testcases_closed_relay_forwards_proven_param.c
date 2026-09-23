/*
 * Rule: EXP34-C
 * Source: testcases
 * Status: PASS - `relay2` is static, its address is taken nowhere, and its
 *         one call site passes `&local`. Its caller set is closed and
 *         complete, so `q` really is non-null, so `apply2`'s parameter
 *         really is too and its guard is dead-defensive.
 *
 * The control for the `fail` fixture next door, which is this shape with
 * `relay2`'s address in a dispatch table. What separates them is whether
 * the relay's own parameter state was PROVEN or merely voted: here every
 * call site of the relay is collected and proves it, so forwarding it is
 * evidence and the inner proof stands. Withdrawing the proof whenever a
 * vote is not a proof must not cost this case.
 */

static void apply2(int *port)
{
    if (port) {
        *port = 1;
    }
    *port = 2;
}

static void relay2(int *q)
{
    apply2(q);
}

void configure(void)
{
    int local = 0;

    relay2(&local);
}
