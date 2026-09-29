/*
 * Rule: INT02-C
 * Source: regression
 * Status: FAIL - signed `long` compared with `long unsigned int`
 *
 * `long unsigned int` is `unsigned long`: the specifier words may be written
 * in any order, and the signed operand is converted to it.
 */

int below(long n, long unsigned int limit)
{
    return n < limit;
}
