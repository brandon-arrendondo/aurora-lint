/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: FAIL - A Win32 type name nothing here defines keeps the SDK's sign
 * Expect: count=2
 *
 * No file in reach defines `LONG`, so it is the Windows SDK's signed
 * `LONG`, and converting it to `size_t` changes the sign. `size_t` is the
 * standard's whatever a header spells it as (here a compiler builtin no
 * scan reads), so converting it to `int` changes the sign too.
 */

typedef __SIZE_TYPE__ size_t;

size_t widen(LONG v)
{
    return (size_t)v; /* Expect: here */
}

int narrow_sign(size_t v)
{
    return (int)v; /* Expect: here */
}
