/*
 * Rule: INT30-C
 * Source: real-world (companion to pass/unresolvable_alias_has_no_width_to_wrap.c)
 * Status: FAIL - Should trigger INT30-C violation
 * Reason: Declining to call a wrap definite at an UNKNOWN width must not
 *         reach a width that is known: an alias whose chain resolves to
 *         `unsigned int` is 32-bit, and 1486995408 * 100000 =
 *         148,699,540,800,000 definitely wraps it.
 */

typedef unsigned int myu32;
typedef myu32 count_t;

typedef long long i64;
typedef struct DateTime { i64 iJD; } DateTime;

void alias_chain_to_32(void)
{
    DateTime d1;
    d1.iJD = 0;
    /* VIOLATION: count_t -> myu32 -> unsigned int; the product wraps */
    d1.iJD += (count_t)1486995408 * (count_t)100000;
}

void builtin_32(void)
{
    DateTime d1;
    d1.iJD = 0;
    /* VIOLATION: unsigned int arithmetic; the product wraps */
    d1.iJD += (unsigned int)1486995408 * (unsigned int)100000;
}
