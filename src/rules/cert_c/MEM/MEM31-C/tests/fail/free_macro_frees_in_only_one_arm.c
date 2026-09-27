/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: RELEASE frees its argument only when OWN_BUFFERS is
 * defined; the other build's definition hands it to a logger and keeps
 * nothing, so the block f() allocates is leaked there. A free credits a
 * release against a leak only when every live definition performs it.
 */

#include <stdlib.h>

void log_ptr(void *p);

#ifdef OWN_BUFFERS
#define RELEASE(p) free(p)
#else
#define RELEASE(p) log_ptr(p)
#endif

void f(void)
{
    char *buf = malloc(16);
    if (buf == NULL)
        return;
    buf[0] = 'a';
    RELEASE(buf);
}
