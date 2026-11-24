/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A guard proves nothing past the allocated size, or in bytes for wider elements
 * Expect: count=2
 *
 * `text` holds `MAX_ARG` bytes, and `len <= MAX_ARG` admits `len ==
 * MAX_ARG`, one past the end. `words` holds `MAX_ARG + 1` bytes, which is
 * not `MAX_ARG + 1` ints: the guard bounds a byte offset, and `words[n]`
 * is element `n`.
 */

#include <stdlib.h>

#define MAX_ARG 64

void terminate(size_t len)
{
    char *text = malloc(MAX_ARG);

    if (text == NULL || len > MAX_ARG)
        return;
    text[len] = 0; /* Expect: here */
    free(text);
}

void clear(size_t n)
{
    int *words = malloc(MAX_ARG + 1);

    if (words == NULL || n >= MAX_ARG)
        return;
    words[n] = 0; /* Expect: here */
    free(words);
}
