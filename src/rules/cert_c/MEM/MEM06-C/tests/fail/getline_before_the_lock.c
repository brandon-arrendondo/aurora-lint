/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: getline fills the block its first argument points at, so reading the password into it before mlock leaves the secret unlocked.
 */

#define _GNU_SOURCE
#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

void check(const char *salt) {
    size_t n = 128;
    char *line = malloc(n);
    if (line == NULL) {
        return;
    }
    if (getline(&line, &n, stdin) < 0) {
        free(line);
        return;
    }
    mlock(line, n);
    crypt(line, salt);
    free(line);
}
