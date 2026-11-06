/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: PASS - Typedefs that name one another have no signedness, and are read quickly
 *
 * Under `X` each of five names is a typedef of each of the others, so no
 * definition reaches an integer type. Each name is read once: following
 * every definition of every name in turn takes exponential time.
 */
#ifdef X
typedef B A; typedef C A; typedef D A; typedef E A;
typedef A B; typedef C B; typedef D B; typedef E B;
typedef A C; typedef B C; typedef D C; typedef E C;
typedef A D; typedef B D; typedef C D; typedef E D;
typedef A E; typedef B E; typedef C E; typedef D E;
#endif

unsigned p(A v)
{
    return (unsigned)v;
}
