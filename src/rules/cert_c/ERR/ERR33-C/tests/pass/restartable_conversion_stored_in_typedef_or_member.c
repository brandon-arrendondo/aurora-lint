/*
 * Rule: ERR33-C
 * Settings: data_model=lp64
 * Status: PASS - an ordering against a negative constant below -1 tests a
 * restartable conversion stored unsigned. The object's type decides, through
 * a typedef of size_t or of unsigned long, and for a size_t struct member
 * as for a variable: (size_t)-1 sits above every count there.
 */

#include <stddef.h>
#include <wchar.h>

typedef size_t mysz;
typedef unsigned long ulen_t;

struct conv {
    size_t n;
};

int f(const char *s, mbstate_t *st, struct conv *c) {
    wchar_t wc;
    mysz n = mbrtowc(&wc, s, 4, st);
    if (n > -3) {
        return -1;
    }
    ulen_t m = mbrlen(s, 4, st);
    if (m >= -2) {
        return -1;
    }
    c->n = mbrtowc(&wc, s, 4, st);
    if (c->n > -3) {
        return -1;
    }
    return (int)(n + m + c->n);
}
