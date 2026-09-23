/*
 * Rule: MEM30-C
 * Source: task 1360 (sqlite ext/session/changeset.c:247-270, valkey
 *         src/valkey-benchmark.c:351/352/1835 -- adjudicated FP in run 267)
 * Status: PASS - Should NOT trigger MEM30-C violation
 * Reason: A branch that frees and then calls a noreturn function (`exit`,
 *         `abort`, `_Exit`, `longjmp`, a function declared `_Noreturn`)
 *         never reaches the code after the `if` or `switch`: it has no
 *         join edge, exactly like a branch ending in `return`, which the
 *         merge already drops. Its free was being carried to the join
 *         point anyway, so every later use of the pointer read as a
 *         use-after-free and the single legitimate free as a double free.
 */

#include <stdio.h>
#include <stdlib.h>

_Noreturn void fatal(const char *msg);
void use(char *p);

int exit_in_then(int rc)
{
    char *p = malloc(16);
    if (rc != 0) {
        fprintf(stderr, "unable to open\n");
        free(p);
        exit(1);
    }
    use(p);
    free(p);
    return 0;
}

int abort_in_nested_if(int rc, int fatal_err)
{
    char *p = malloc(16);
    if (rc != 0) {
        free(p);
        if (fatal_err)
            abort();
        else
            exit(2);
    }
    use(p);
    free(p);
    return 0;
}

int declared_noreturn(int rc)
{
    char *p = malloc(16);
    if (rc != 0) {
        free(p);
        fatal("bad");
    }
    use(p);
    free(p);
    return 0;
}

int exit_in_switch_arm(int rc)
{
    char *p = malloc(16);
    switch (rc) {
    case 1:
        free(p);
        exit(1);
    case 2:
        break;
    default:
        break;
    }
    use(p);
    free(p);
    return 0;
}
