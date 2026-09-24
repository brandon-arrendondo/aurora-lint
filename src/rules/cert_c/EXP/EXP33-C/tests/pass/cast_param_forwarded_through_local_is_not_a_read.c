/*
 * Description: a callee that casts its void * parameter into a local and only
 * forwards that local to a writer does not read the caller's object
 *
 * Only a dereference of the cast alias counts as the callee reading its
 * parameter. Here the alias is passed on to a helper that fills the buffer,
 * so the caller's uninitialized buffer is written, never read, before use.
 */
#include <string.h>

static void fill(unsigned char *out)
{
    memcpy(out, "abcd", 4);
}

static void forward(void *ctx)
{
    unsigned char *out = (unsigned char *)ctx;
    fill(out);
}

int caller(void)
{
    unsigned char buf[4];
    forward(buf);
    return buf[0];
}
