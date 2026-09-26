/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: A main that zeroes RLIMIT_CORE protects only what it goes on to call: login() is reached from no main, so its unlocked password is still reported.
 */

#include <sys/resource.h>
#include <crypt.h>
#include <stdlib.h>
#include <string.h>

void login(const char *typed) {
    char *pw = strdup(typed);
    if (!pw) return;
    crypt(pw, "ab");
    free(pw);
}

static void harden(void) { struct rlimit rl = {0, 0}; setrlimit(RLIMIT_CORE, &rl); }

int main(void) { harden(); return 0; }
