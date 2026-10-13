/*
 * Rule: INT30-C
 * Source: real-world (companion to
 *         pass/signed_operand_spelled_like_an_unsigned_literal_or_type.c)
 * Status: FAIL - Should trigger INT30-C violation
 * Reason: Reading an operand's type from its declaration rather than its
 *         spelling must keep what the declaration says: `u` declared
 *         `unsigned int` makes the sum unsigned, and a real `u`-suffixed
 *         literal still makes an `int` operand convert to unsigned. A type
 *         passed to a casting macro is still a type when it resolves to one:
 *         `cast(my_u32, st)` is an `unsigned int` however the parser reads it.
 */

#define cast(t, exp) ((t)(exp))
typedef unsigned int my_u32;

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

my_u32 shift_through_a_casting_macro(int st, int bits)
{
    /* VIOLATION: `cast(my_u32, st)` is unsigned; the shift may lose bits */
    return cast(my_u32, st) << bits;
}
