/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: PASS - A typedef signed in one arm and unsigned in another has no one signedness
 *
 * `T` is `int` where `WIDE_SIGNED` is defined and `unsigned` elsewhere.
 * Neither conversion has a sign this file can show for every build, so
 * neither is reported as changing one. Taking the first definition read
 * would report one of them in the build that does not have it.
 */
#ifdef WIDE_SIGNED
typedef int T;
#else
typedef unsigned T;
#endif

unsigned long widen(T v)
{
    return (unsigned long)v;
}

int narrow_sign(T v)
{
    return (int)v;
}
