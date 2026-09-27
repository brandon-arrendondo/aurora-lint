/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: one arm locks the block before storing the secret, the other locks the whole process with mlockall first. Every store is covered, each by one kind of protection.
 */

#include <crypt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

void h(const char *typed, const char *salt, int whole_process) {
    char *key = malloc(128);
    if (key == NULL) {
        return;
    }
    if (!whole_process) {
        mlock(key, 128);
        strcpy(key, typed);
    } else {
        mlockall(MCL_CURRENT | MCL_FUTURE);
        strcpy(key, typed);
    }
    crypt(key, salt);
    free(key);
}
