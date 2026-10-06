/*
 * Rule: MEM30-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM30-C violation
 *
 * The block is released through twelve wrappers, each forwarding its
 * parameter to the next and the last calling free(), and then written.
 * The free reaches the outermost wrapper one wrapper per propagation pass,
 * so the write is seen as a use after free only if the passes run until
 * nothing changes rather than stopping at a fixed count.
 */

#include <stdlib.h>

static void release11(void *p)
{
    free(p);
}

static void release10(void *p)
{
    release11(p);
}

static void release9(void *p)
{
    release10(p);
}

static void release8(void *p)
{
    release9(p);
}

static void release7(void *p)
{
    release8(p);
}

static void release6(void *p)
{
    release7(p);
}

static void release5(void *p)
{
    release6(p);
}

static void release4(void *p)
{
    release5(p);
}

static void release3(void *p)
{
    release4(p);
}

static void release2(void *p)
{
    release3(p);
}

static void release1(void *p)
{
    release2(p);
}

static void release0(void *p)
{
    release1(p);
}

void use_buffer(void)
{
    char *buf = malloc(32);
    if (!buf) {
        return;
    }
    release0(buf);
    buf[0] = 'a';
}
