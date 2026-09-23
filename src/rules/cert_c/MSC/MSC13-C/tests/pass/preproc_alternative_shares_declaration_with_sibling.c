/*
 * Rule: MSC13-C
 * Source: mbedtls library/bignum.c mbedtls_int_div_int
 * Status: PASS - Should NOT trigger MSC13-C violation
 *
 * `quotient` is declared once per #if/#else branch (an earlier fix groups those
 * as one liveness entity), but in the first branch it shares its
 * `declaration` node with `dividend`. The group map was keyed by the
 * declaration's start byte alone, so `dividend`'s singleton group and
 * `quotient`'s two-member group collided on one key and whichever the
 * HashMap iterated last won: in about a third of runs `quotient`'s reads
 * (which resolve textually to the #else declaration) no longer counted
 * for the #if one and it was reported unused. Same source, same binary,
 * different answer per process. The key must include the name.
 */

typedef unsigned long mpi_uint;

static mpi_uint div_int(mpi_uint u1, mpi_uint u0, mpi_uint d)
{
#if defined(HAVE_UDBL)
    t_udbl dividend, quotient;
#else
    mpi_uint quotient;
#endif

#if defined(HAVE_UDBL)
    dividend = ((t_udbl) u1 << 32) | u0;
    quotient = dividend / d;
    return (mpi_uint) quotient;
#else
    quotient = u1 + u0 + d;
    return quotient;
#endif
}
