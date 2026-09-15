/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * A block stored into a caller's structure has escaped, and a branch that
 * frees-and-nulls the local before leaving disowns only the path it is
 * on. The fall-through path is the pre-branch path, allocations AND
 * escapes included: mosquitto's websockets.c does `u->mosq = mosq;` and
 * then, on each error, `mosquitto_FREE(mosq); u->mosq = NULL; return -1;`,
 * and every later return reported `mosq` leaked once the branch's rebind
 * had dropped the escape record.
 */

#include <stdlib.h>

#define mosquitto_free free
#define mosquitto_FREE(A) do { mosquitto_free(A); (A) = NULL; } while(0)

struct user { struct conn *mosq; };
struct conn { int sock; };

extern int setup(struct conn *c);

int attach(struct user *u, int fail) {
    struct conn *mosq = malloc(sizeof(*mosq));
    if (!mosq) {
        return -1;
    }
    u->mosq = mosq;
    if (fail) {
        mosquitto_FREE(mosq);
        u->mosq = NULL;
        return -1;
    }
    if (setup(mosq)) {
        return -1;
    }
    mosq->sock = 1;
    return 0;
}
