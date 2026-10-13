/*
 * Rule: MSC30-C
 * Status: FAIL - `pick` is a typedef at file scope, but the function's first
 *         statement declares a local function pointer named `pick` (its
 *         initializer makes it a declaration), which hides the typedef. So
 *         `pick(*rand)(x);` is a call through that local, not a declaration
 *         of a local `rand`, and the `rand()` after it is the library's.
 */

#include <stdlib.h>

typedef int pick;
typedef int (*FP)(int);
typedef int (*RF)(void);

FP choose(RF);

int f(int x)
{
    FP (*pick)(RF) = choose;
    pick(*rand)(x);
    return rand();  /* Noncompliant */
}
