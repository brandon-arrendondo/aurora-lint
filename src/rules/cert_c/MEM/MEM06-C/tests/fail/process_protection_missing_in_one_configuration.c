/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: one configuration of harden() locks the process's memory through a helper; the other only logs, so that build leaves the password pageable.
 */

#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

static void lock_all(void) {
    mlockall(MCL_CURRENT | MCL_FUTURE);
}

#ifdef HAVE_MLOCKALL
void harden(void) {
    lock_all();
}
#else
void harden(void) {
    puts("memory locking unavailable");
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
