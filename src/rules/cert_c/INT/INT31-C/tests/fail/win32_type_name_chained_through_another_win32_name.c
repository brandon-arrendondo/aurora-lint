/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: FAIL - A typedef chain through a Win32 name takes that name's sign
 * Expect: count=1
 *
 * This file's `LONG` is `MYU`, which is `ULONG`, the Windows SDK's unsigned
 * 32-bit type, since nothing here defines `ULONG`. So `LONG` is unsigned,
 * and converting it to `int` changes a value above `INT_MAX`.
 */

typedef ULONG MYU;
typedef MYU LONG;

int narrow_sign(LONG v)
{
    return (int)v; /* Expect: here */
}
