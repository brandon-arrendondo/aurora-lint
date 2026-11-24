/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: PASS - A Win32 type name the file defines as a type it cannot read is unknown
 *
 * `LONG` is `PLATFORM_LONG` here, which nothing in reach defines, so its
 * sign is unknown. The Windows SDK's signed `LONG` is not this file's
 * `LONG`, and is no fallback for it, so the conversion is not reported as
 * changing a sign.
 */

#include <stddef.h>

typedef PLATFORM_LONG LONG;

size_t widen(LONG v)
{
    return (size_t)v;
}
