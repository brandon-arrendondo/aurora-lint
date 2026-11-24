/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: FAIL - A Win32 type name has the sign the file's own typedef gives it
 * Expect: count=2
 *
 * The Windows SDK makes `LONG` signed and `DWORD` unsigned, but this file
 * defines both itself: `LONG` is `unsigned int` (`unsigned` alone) and
 * `DWORD` is `int`. Converting the unsigned `LONG` to `int`, or the
 * signed `DWORD` to `size_t`, changes the sign. The SDK's reading would
 * see neither conversion, and would report the first function's widening
 * of an unsigned value to `unsigned long` as signed to unsigned.
 */

#include <stddef.h>

typedef unsigned LONG;
typedef int DWORD;

unsigned long widen(LONG v)
{
    return (unsigned long)v;
}

int narrow_sign(LONG v)
{
    return (int)v; /* Expect: here */
}

size_t widen_signed(DWORD v)
{
    return (size_t)v; /* Expect: here */
}
