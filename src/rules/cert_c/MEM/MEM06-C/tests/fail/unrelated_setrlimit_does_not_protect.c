/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: A setrlimit of a different resource, and one that RAISES the core limit, protect nothing; a VirtualLock of another buffer does not lock this one.
 */

#include <sys/resource.h>
#include <windows.h>
#include <crypt.h>
#include <stdlib.h>

static char scratch[64];

int main(int argc, char **argv) {
    struct rlimit files = {256, 256};
    struct rlimit core;
    setrlimit(RLIMIT_NOFILE, &files);
    core.rlim_cur = RLIM_INFINITY;
    core.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &core);

    char *key = (char *)malloc(128);
    if (key == NULL) {
        return 1;
    }
    VirtualLock(scratch, sizeof scratch);
    crypt(key, argv[1]);
    free(key);
    return 0;
}
