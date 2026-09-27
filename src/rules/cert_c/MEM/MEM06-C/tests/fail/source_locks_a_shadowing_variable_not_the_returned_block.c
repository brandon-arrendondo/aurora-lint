/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: read_pw locks an inner `p` that shadows the returned one, so the block it hands back is never locked. The same spelling is a different object.
 */

#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

static char *read_pw(void) {
    char *p = malloc(100);
    if (p == NULL) {
        return NULL;
    }
    {
        char *p = malloc(100);
        mlock(p, 100);
        free(p);
    }
    return p;
}

void login(const char *salt) {
    char *pw = read_pw();
    if (pw == NULL) {
        return;
    }
    if (fgets(pw, 100, stdin) != NULL) {
        crypt(pw, salt);
    }
    free(pw);
}
