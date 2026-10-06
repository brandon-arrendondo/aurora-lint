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

#include "supplicant.h"

/* An array member of an anonymous struct, itself under an #ifdef, in a
 * struct this file receives through a header. */
unsigned char *append_ie(struct supplicant *s, size_t extra)
{
    return s->sme.assoc_req_ie + extra;
}

/* An integer member of the same anonymous struct is still a sum. */
size_t ie_end(struct supplicant *s, size_t extra)
{
    return s->sme.assoc_req_ie_len + extra;
}
