/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: the lock wrapper is a no-op in the configuration without HAVE_MLOCK, so in that build the secret is stored in pageable memory.
 */

#include <crypt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#ifdef HAVE_MLOCK
static void lock_it(char *p, size_t n) { mlock(p, n); }
#else
static void lock_it(char *p, size_t n) { (void)p; (void)n; }
#endif

void h(const char *typed, const char *salt) {
    char *key = malloc(128);
    if (key == NULL) {
        return;
    }
    lock_it(key, 128);
    strcpy(key, typed);
    crypt(key, salt);
    free(key);
}
