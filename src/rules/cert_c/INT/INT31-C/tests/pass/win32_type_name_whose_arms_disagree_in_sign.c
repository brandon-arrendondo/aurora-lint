/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: PASS - A Win32 name defined with a different sign in each arm has no one sign
 *
 * `LONG` is `int` where `W` is defined and `unsigned` elsewhere. Neither the
 * SDK's reading nor either arm's holds for every build, so the conversion is
 * not reported as changing a sign.
 */

#ifdef W
typedef int LONG;
#else
typedef unsigned LONG;
#endif

int narrow_sign(LONG v)
{
    return (int)v;
}
