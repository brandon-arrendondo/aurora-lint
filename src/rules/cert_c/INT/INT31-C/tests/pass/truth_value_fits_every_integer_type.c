/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: PASS - A comparison or `!` is 0 or 1, which every integer type holds
 *
 * The result of a comparison, of `!`, `&&` and `||` is an `int` that is
 * 0 or 1, whatever its operands' types, so converting it narrows nothing
 * and changes no sign.
 */
typedef unsigned long word_t;

unsigned below(word_t mask, word_t x)
{
    return (unsigned)(mask < x);
}

unsigned nonzero(word_t n)
{
    return (unsigned)(n != 0);
}

int failed(long r)
{
    return (int)(r == -1);
}

int is_zero(long r)
{
    return (int)!r;
}

unsigned char both(long a, long b)
{
    return (unsigned char)(a && b);
}
