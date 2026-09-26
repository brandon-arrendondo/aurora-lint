/*
 * Rule: MEM31-C
 * Source: real-world regression (pure-ftpd's _EXIT shape)
 * Status: PASS under the default preset; VIOLATION under strict
 * Expect: default=clean strict=violation
 *
 * _EXIT's GNU noreturn attribute proves nothing (ADR-0015), but its body
 * ends in POSIX _exit(), which a hosted ISO C + POSIX environment never
 * returns from (stdlib_noreturn), so _EXIT is verified noreturn and the
 * free() before it cannot reach the one after the `if`. The strict preset
 * declares no library model, so nothing is known to end the path.
 */

#include <stdlib.h>
#include <unistd.h>

void _EXIT(const int status) __attribute__ ((noreturn));

void _EXIT(const int status)
{
    _exit(status);
}

void release(int fail)
{
    char *p = malloc(32);
    if (fail) {
        free(p);
        _EXIT(EXIT_FAILURE);
    }
    free(p);
}
