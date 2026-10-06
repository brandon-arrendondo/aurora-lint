#include <stddef.h>
#include "globals.h"

/* Pointer arithmetic on a header-declared array: no INT30-C finding. */
char *advance(size_t scanned)
{
    return cmd + scanned;
}

/* Header-declared integer: still an unsigned sum. */
size_t grow(size_t n)
{
    return total + n;
}

/* A local that shares the array's spelling is the local: an unsigned sum. */
unsigned int shadowed(unsigned int cmd, unsigned int n)
{
    return cmd + n;
}

/* The name is an array in one file and an integer in another. */
size_t ambiguous(size_t n)
{
    return shared + n;
}
