/*
 * Rule: MSC06-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger MSC06-C violation
 *
 * The file defines its own memset(), so a clear calls that function rather
 * than the library's, and the library's dead-store latitude does not apply.
 * The spin loops wait on an _Atomic flag (each access synchronizes), the
 * same written with the _Atomic(T) specifier at file scope and in a block,
 * and a constexpr one (a constant the loop never waits on).
 */
#include <stddef.h>

void use(char *buf);

void *memset(void *s, int c, size_t n)
{
    char *p = s;
    while (n--)
        *p++ = (char)c;
    return s;
}

void own_memset(void)
{
    char pwd[16];
    use(pwd);
    memset(pwd, 0, sizeof pwd);
}

_Atomic int ready;
_Atomic(int) started;
constexpr int never = 0;

void wait_ready(void)
{
    _Atomic(int) local_ready = 0;
    while (ready) {
    }
    while (started) {
    }
    while (local_ready) {
    }
    while (never) {
    }
}
