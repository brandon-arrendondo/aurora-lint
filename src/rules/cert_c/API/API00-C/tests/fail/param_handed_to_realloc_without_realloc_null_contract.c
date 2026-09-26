/*
 * Rule: API00-C
 * Source: synthetic
 * Status: FAIL under every preset
 * Settings: realloc_null_is_malloc=false
 *
 * The environment is declared not to honor realloc(NULL, n) as malloc(n),
 * so handing an unvalidated pointer parameter to realloc() takes it on
 * trust.
 */
#include <stdlib.h>

char *buffer_grow(char *buf, size_t n)
{
    return realloc(buf, n);
}
