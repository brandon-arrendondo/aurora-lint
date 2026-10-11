/*
 * Rule: STR30-C
 * Source: synthetic
 * Status: PASS - Nothing written through here can point into a literal
 *
 * A const void * buffer is not a string; the distance between two
 * pointers is a number; a function that returns its argument returns
 * whatever the caller passed, here an allocated copy; and a callee's write
 * through one parameter says nothing about another.
 */

#include <stdlib.h>
#include <string.h>

static const char *skip_space(const char *s)
{
    while (*s == ' ')
        s++;
    return s;
}

static void stamp(const void *data, size_t n)
{
    unsigned char *p = (unsigned char *)data + n - 4;
    memset(p, 0, 4);
}

static void join(char *out, const char *in, char *base)
{
    out[in - base] = '\0';
}

void use(char *buf, char *base, size_t n)
{
    char *copy = strdup(buf);
    char *z;
    if (copy == NULL)
        return;
    z = (char *)skip_space(copy);
    z[0] = '\0';
    stamp(buf, n);
    join(buf, "literal", base);
    free(copy);
}
