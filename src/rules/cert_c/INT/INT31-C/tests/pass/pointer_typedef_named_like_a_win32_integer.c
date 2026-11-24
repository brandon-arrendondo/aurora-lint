/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: PASS - A pointer typedef is no integer, whatever Win32 name it takes
 *
 * Here `LONG` is a pointer to `unsigned`, not the SDK's signed 32-bit type,
 * so converting it is no change of an integer's sign.
 */

typedef unsigned *LONG;

unsigned long address(LONG v)
{
    return (unsigned long)v;
}
