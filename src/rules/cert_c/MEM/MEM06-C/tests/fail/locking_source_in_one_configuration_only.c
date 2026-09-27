/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: only the HAVE_MLOCK definition of the source locks the block; the other configuration hands back pageable memory, so a caller's secret is unprotected in that build.
 */

#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#ifdef HAVE_MLOCK
char *secret_buf(size_t n) {
    char *p = malloc(n);
    if (!p) return NULL;
    mlock(p, n);
    return p;
}
#else
char *secret_buf(size_t n) { return malloc(n); }
#endif

void login(const char *salt) {
    char *pw = secret_buf(64);
    fgets(pw, 64, stdin);
    crypt(pw, salt);
    free(pw);
}
