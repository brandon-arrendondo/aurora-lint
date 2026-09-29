/*
 * Rule: MEM31-C
 * Source: real-world regression
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: The companion to the PASS case where an early `return`
 * skips the release. Here the only early exit is taken when the pointer is
 * NULL, where there is nothing to release, so `drop` releases every block
 * it is handed and the caller's free() that follows is a second release.
 */
#include <stdlib.h>

static int dropped;

void drop(char *text)
{
    if (text == NULL)
        return;
    dropped++;
    free(text);
}

void report(void)
{
    char *msg = malloc(64);
    if (msg == NULL)
        return;
    drop(msg);
    free(msg);
}
