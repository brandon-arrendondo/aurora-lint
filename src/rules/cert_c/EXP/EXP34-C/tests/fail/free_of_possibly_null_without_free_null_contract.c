/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL under every preset
 * Settings: free_null_is_noop=false
 *
 * The environment is declared not to honor free(NULL) (an in-house
 * allocator that skips the check), so passing a possibly-null pointer to
 * free() is a null dereference even under the default preset.
 */
#include <stdlib.h>

void release_optional(int flag)
{
    char *p = NULL;
    if (flag) {
        p = malloc(16);
    }
    free(p);
}
