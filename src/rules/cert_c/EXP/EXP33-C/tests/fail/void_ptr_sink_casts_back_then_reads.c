/*
 * Description: a callee that takes void * and casts it back to its real type
 * in a local before reading through it still reads the caller's object
 *
 * The callee never dereferences its parameter in place: it copies a cast of
 * it into a local and dereferences the local. That is still a read of what
 * the caller passed, so handing it the address of an uninitialized pointer
 * reads an indeterminate value.
 */
#include <stdio.h>

static void sink(void *ctx)
{
    char **slot = (char **)ctx;
    char *value = *slot;
    puts(value);
}

void caller(void)
{
    char *data;
    sink(&data);
}
