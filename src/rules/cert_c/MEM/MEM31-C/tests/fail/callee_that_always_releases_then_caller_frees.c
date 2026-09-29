/*
 * Rule: MEM31-C
 * Source: real-world regression
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: The companion to the PASS case where the callee releases its
 * argument on one path only. Here `drop_message` releases it on every path,
 * so the caller's own free() that follows is a second release.
 */
#include <stdlib.h>

static int dropped;

void drop_message(char *text)
{
    dropped++;
    free(text);
}

void report(void)
{
    char *msg = malloc(64);
    if (msg == NULL) {
        return;
    }
    drop_message(msg);
    free(msg);
}
