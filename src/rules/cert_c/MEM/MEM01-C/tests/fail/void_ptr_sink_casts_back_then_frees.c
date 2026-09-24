/*
 * Description: a freed pointer handed by address to a void * callee that
 * casts it back and frees it again is still used after free
 *
 * The callee never dereferences its parameter in place: it copies a cast of
 * it into a local and dereferences the local, then frees what it loaded --
 * the pointer the caller already freed.
 */
#include <stdlib.h>

static void release(void *ctx)
{
    char **slot = (char **)ctx;
    char *value = *slot;
    free(value);
}

void caller(void)
{
    char *data = malloc(16);
    if (data == NULL) {
        return;
    }
    free(data);
    release(&data);
}
