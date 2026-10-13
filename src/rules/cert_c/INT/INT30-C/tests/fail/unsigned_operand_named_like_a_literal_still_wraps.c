/*
 * Rule: INT30-C
 * Source: real-world (companion to
 *         pass/signed_operand_spelled_like_an_unsigned_literal_or_type.c)
 * Status: FAIL - Should trigger INT30-C violation
 * Reason: Reading an operand's type from its declaration rather than its
 *         spelling must keep what the declaration says: `u` declared
 *         `unsigned int` makes the sum unsigned, and a real `u`-suffixed
 *         literal still makes an `int` operand convert to unsigned.
 */

unsigned int index_of(unsigned int u, unsigned int v, unsigned int width)
{
    /* VIOLATION: unsigned addition of declared-unsigned operands may wrap */
    return u + v;
}

unsigned int add_unsigned_literal(int n)
{
    /* VIOLATION: `n` converts to unsigned against the `4000000000u` literal */
    return n + 4000000000u;
}
