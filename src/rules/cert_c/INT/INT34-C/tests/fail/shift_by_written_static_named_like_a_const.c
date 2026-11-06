/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - A written static whose name holds "const" is not a constant
 *
 * `gs_constant` is a plain `static int`; its name is not its type. `set`
 * writes 40 to it, so the shift amount is not fixed at its initializer.
 */

static int gs_constant = 3;

void set(void)
{
    gs_constant = 40;
}

int mask(void)
{
    return 1 << gs_constant;
}
