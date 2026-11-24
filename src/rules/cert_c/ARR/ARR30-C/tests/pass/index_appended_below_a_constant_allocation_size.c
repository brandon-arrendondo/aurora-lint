/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A guard below a byte buffer's constant allocated size bounds the index
 *
 * `arg` holds `MAX_ARG + 1` bytes. The loop stores at `len` only while
 * `len < MAX_ARG`, and the early return leaves `len` below `MAX_ARG` for
 * the terminator, so neither store passes the end.
 */

#include <stdlib.h>

#define MAX_ARG 64

char *copy_arg(const char *in)
{
    size_t len = 0;
    char *arg = malloc(MAX_ARG + 1);

    if (arg == NULL)
        return NULL;
    while (len < MAX_ARG && *in != 0) {
        arg[len] = *in++;
        len++;
    }
    if (len >= MAX_ARG) {
        free(arg);
        return NULL;
    }
    arg[len] = 0;
    return arg;
}
