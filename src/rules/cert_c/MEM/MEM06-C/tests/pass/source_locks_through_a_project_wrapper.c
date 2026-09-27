/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: the source function locks its block through a project wrapper before the secret is read into it, so the block it returns is locked.
 */

#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

static void lock_it(char *p, size_t n) { mlock(p, n); }

static char *read_pw(void) {
    char *p = malloc(100);
    if (p == NULL) return NULL;
    lock_it(p, 100);
    fgets(p, 100, stdin);
    return p;
}

void login(const char *salt) {
    char *pw = read_pw();
    crypt(pw, salt);
    free(pw);
}
