/*
 * Rule: INT30-C
 * Source: real-world (sqlite src/date.c:1665/1699
 *         `d1.iJD += (u64)1486995408 * (u64)100000;`)
 * Status: PASS - Should NOT trigger INT30-C violation
 * Reason: The operation's width is decided by its operands' declared types.
 *         `u64` resolves through `sqlite_uint64` to a name defined only in
 *         the generated sqlite3.h the scan never reads, so its width is
 *         unknown -- and the rule reported the product as a DEFINITE wrap
 *         anyway, by falling to the 32-bit floor and observing that
 *         148,699,540,800,000 does not fit it. The floor is right for
 *         proving a fit, never for proving a wrap: a width nobody knows
 *         cannot be definitely exceeded (ADR-0005, ADR-0006). A typedef
 *         chain that does reach a 64-bit spelling is resolved and clean
 *         too, instead of being matched by the alias's own name.
 */

typedef unknown_uint64 sqlite_uint64;   /* the real one lives in sqlite3.h */
typedef sqlite_uint64 u64;

typedef unsigned long long uint64;      /* hostap's shape: u64 -> a 64-bit spelling */
typedef uint64 hostap_u64;

typedef long long i64;
typedef struct DateTime { i64 iJD; } DateTime;

void unresolvable_alias(void)
{
    DateTime d1;
    d1.iJD = 0;
    d1.iJD += (u64)1486995408 * (u64)100000;
}

void alias_chain_to_64(void)
{
    DateTime d1;
    d1.iJD = 0;
    d1.iJD += (hostap_u64)1486995408 * (hostap_u64)100000;
}
