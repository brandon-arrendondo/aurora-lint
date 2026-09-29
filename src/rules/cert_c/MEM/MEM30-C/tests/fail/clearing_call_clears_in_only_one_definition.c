/*
 * Rule: MEM30-C
 *
 * Status: FAIL - Should trigger MEM30-C violation
 *
 * reset() zeroes the object it is handed in one #if arm only. After
 * free(s.buf), a reset() that zeroes the struct would leave s.buf NULL, but
 * in a build that links the empty definition s.buf still points at the
 * freed block when it is read. A clear forgets a freed pointer only when
 * every definition the call can link with clears.
 */
#include <stdlib.h>
#include <string.h>

struct holder {
    char *buf;
    size_t len;
};

#ifdef KEEP_STATE
static void reset(void *p, size_t n)
{
    (void)p;
    (void)n;
}
#else
static void reset(void *p, size_t n)
{
    memset(p, 0, n);
}
#endif

char read_after_reset(void)
{
    struct holder s;
    s.buf = malloc(16);
    if (s.buf == NULL)
        return 0;
    s.buf[0] = 'x';
    free(s.buf);
    reset(&s, sizeof(s));
    return s.buf[0];
}
