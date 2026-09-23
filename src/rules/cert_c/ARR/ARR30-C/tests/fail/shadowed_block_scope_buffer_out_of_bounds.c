/*
 * Rule: ARR30-C
 * Source: real-world (the mirror image of the valkey-cli shape)
 * Status: FAIL - `buf[5]` indexes the four-byte `buf` declared in its own
 *         block; the 255-byte `buf` declared later in the enclosing block
 *         is a different variable and not yet in scope.
 *
 * The name-keyed prescan kept the LAST declaration (`buf[255]`), so this
 * genuine out-of-bounds write was measured against the wrong buffer and
 * went unreported. Same defect as the PASS twin, other direction: a wrong
 * attribution can hide a real finding as easily as invent one.
 */

int prompt(void)
{
    {
        char buf[4];
        buf[5] = '\0';
    }

    char buf[255];
    buf[0] = '\0';
    return buf[0];
}
