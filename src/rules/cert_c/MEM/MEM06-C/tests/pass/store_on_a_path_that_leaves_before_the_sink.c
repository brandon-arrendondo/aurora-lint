/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: the only store before the lock is on a path that returns before the secret is read or used; the password itself is read after mlock.
 */

#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

void check(const char *salt, int dry_run) {
    char *key = malloc(128);
    if (key == NULL) {
        return;
    }
    if (dry_run) {
        strcpy(key, "dry run");
        puts(key);
        free(key);
        return;
    }
    mlock(key, 128);
    if (fgets(key, 128, stdin) != NULL) {
        crypt(key, salt);
    }
    free(key);
}
