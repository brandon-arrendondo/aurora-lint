/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: harden() returns before setrlimit when DEBUG is set, so it does not always disable core dumps.
 */
#include <sys/mman.h>
#include <sys/resource.h>
#include <crypt.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static void harden(void) {
    struct rlimit rl = {0, 0};
    if (getenv("DEBUG")) return;
    setrlimit(RLIMIT_CORE, &rl);
}
static void login(const char *typed) {
    char *copy = strdup(typed);
    crypt(copy, "xx");
    free(copy);
}
int main(int argc, char **argv) {
    harden();
    login(argv[1]);
    return 0;
}
