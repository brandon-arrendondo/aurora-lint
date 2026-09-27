/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: every configuration of harden() locks the process's memory, one with mlockall directly and the other through a helper, and main calls it before the password is read.
 */

#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

static void lock_all(void) {
    mlockall(MCL_CURRENT | MCL_FUTURE);
}

#ifdef DIRECT
void harden(void) {
    mlockall(MCL_CURRENT | MCL_FUTURE);
}
#else
void harden(void) {
    lock_all();
}
#endif

int main(int argc, char **argv) {
    harden();
    char *pw = malloc(64);
    if (pw == NULL) {
        return 1;
    }
    if (fgets(pw, 64, stdin) != NULL) {
        crypt(pw, argv[argc - 1]);
    }
    free(pw);
    return 0;
}
