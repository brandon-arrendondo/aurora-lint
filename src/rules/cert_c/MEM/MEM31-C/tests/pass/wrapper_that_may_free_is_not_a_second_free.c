/*
 * Rule: MEM31-C
 * Source: real-world (valkey networking.c: addReply* frees the client only
 *         on the error path that closes it)
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: `reply` frees its argument on one path only, and says so by
 * its result; the caller stops there. Calling it again on the success path
 * is not a double free, and the analyzer cannot show one either: a double
 * free needs a release the callee's body always performs.
 */
#include <stdlib.h>

struct client {
    int broken;
};

int reply(struct client *c, const char *text)
{
    (void)text;
    if (c->broken) {
        free(c);
        return -1;
    }
    return 0;
}

void describe(struct client *c)
{
    if (reply(c, "commands") < 0) {
        return;
    }
    reply(c, "keys");
}
