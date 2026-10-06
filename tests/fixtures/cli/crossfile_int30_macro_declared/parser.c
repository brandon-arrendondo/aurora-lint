#include <stddef.h>
#include "globals.h"
#include "defining.h"
#include "broken.h"
#include "notwrapper.h"
#include "conflicting.h"
#include "unicode.h"

/* extern form: pointer arithmetic on a macro-declared array. */
char *advance(size_t scanned)
{
    return cmd + scanned;
}

/* extern form, not an array: an unsigned sum. */
size_t grow(size_t n)
{
    return total + n;
}

/* defining form. */
char *cwd_end(size_t n)
{
    return wd + n;
}

/* The invocation is malformed: nothing is declared, so `junk` is unknown. */
size_t unclosed(size_t junk, size_t n)
{
    return junk + n;
}

/* Not a wrapper: nothing is declared either. */
size_t not_declared(size_t reg, size_t n)
{
    return reg + n;
}

/* Arms disagree: not known to be an array, so the sum is reported. */
size_t arms_disagree(size_t n)
{
    return both + n;
}

/* Declared after non-ASCII text: still an array. */
char *after_unicode(size_t n)
{
    return label + n;
}
