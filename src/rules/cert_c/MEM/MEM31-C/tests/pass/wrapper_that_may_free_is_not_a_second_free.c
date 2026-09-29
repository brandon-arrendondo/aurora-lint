/*
 * Rule: MEM31-C
 * Source: real-world (valkey networking.c: addReply* frees the client only
 *         on the error path that closes it)
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: `reply` frees its argument on one path only. Calling it twice
 * on the same pointer is not a double free the analyzer can show: a double
 * free needs a release the callee's body always performs.
 */
#include <stdlib.h>

struct client {
    int broken;
};

void reply(struct client *c, const char *text)
{
    (void)text;
    if (c->broken) {
        free(c);
    }
}

void describe(struct client *c)
{
    reply(c, "commands");
    reply(c, "keys");
}
