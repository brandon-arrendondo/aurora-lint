/*
 * Rule: ERR33-C
 * Status: PASS - a signed store compared with a constant cast to an
 * unsigned type of at least its rank is an unsigned comparison, so the -1
 * an encoding error leaves sits above the threshold. The cast type is
 * resolved, not read off its name: a typedef of unsigned long counts, and so
 * does a project's `u8` that is really an unsigned int.
 */

#include <wchar.h>

typedef unsigned long ulen_t;
typedef unsigned int u8;

int f(const char *s, mbstate_t *st) {
    wchar_t wc;
    int n = mbrtowc(&wc, s, 4, st);
    if (n >= (ulen_t)-2) {
        return -1;
    }
    int m = mbrlen(s, 4, st);
    if (m >= (u8)-2) {
        return -1;
    }
    long k = mbrtowc(&wc, s, 4, st);
    if (k > (unsigned long)-3) {
        return -1;
    }
    return n + m + (int)k;
}
