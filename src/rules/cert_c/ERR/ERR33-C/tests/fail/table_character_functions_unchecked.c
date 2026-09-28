/*
 * Rule: ERR33-C
 * Status: FAIL - getc(), getchar() and putc() return EOF on error, and the
 * wide forms fgetwc(), putwc() and fputws() return WEOF or EOF. None of
 * these results is tested, and the output goes to a file, not the console.
 */

#include <stdio.h>
#include <wchar.h>

void copy(FILE *in, FILE *out, const wchar_t *banner) {
    int c = getc(in);
    putc(c, out);
    int d = getchar();
    wint_t wc = fgetwc(in);
    putwc(L'x', out);
    fputws(banner, out);
    (void)d;
    (void)wc;
}
