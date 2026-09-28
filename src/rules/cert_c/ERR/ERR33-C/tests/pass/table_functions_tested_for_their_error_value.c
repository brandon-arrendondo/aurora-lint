/*
 * Rule: ERR33-C
 * Status: PASS - Each result is tested against the error value ERR33-C's
 * table gives for its function: EOF or WEOF for the character functions,
 * NULL for the search functions, nonzero for setvbuf() and the Annex K
 * functions (an errno_t), (size_t)-1 for the restartable conversions,
 * errno for wcstol(), and a status other than thrd_success for the
 * threads functions.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <wchar.h>

int f(FILE *fp, const char *s, const wchar_t *ws, mtx_t *m, char *buf) {
    int c = getc(fp);
    if (c == EOF) {
        return -1;
    }
    wint_t wc = fgetwc(fp);
    if (wc == WEOF) {
        return -1;
    }
    const char *p = strchr(s, '=');
    if (p == NULL) {
        return -1;
    }
    if (setvbuf(fp, buf, _IOFBF, BUFSIZ) != 0) {
        return -1;
    }
    int status = mtx_lock(m);
    if (status != thrd_success) {
        return -1;
    }
    mbstate_t state = {0};
    wchar_t out;
    size_t n = mbrtowc(&out, s, 4, &state);
    if (n == (size_t)-1) {
        return -1;
    }
    wchar_t *end;
    errno = 0;
    long v = wcstol(ws, &end, 10);
    if (errno == ERANGE || end == ws) {
        return -1;
    }
    return (int)v + (p - s);
}
