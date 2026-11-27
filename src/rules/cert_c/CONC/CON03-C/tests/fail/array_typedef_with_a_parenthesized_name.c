/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - `digest_t` is this file's own array typedef: the parser
 *         reads `unsigned char (digest_t)[32]` as a function named `char`,
 *         but the typedef still declares `digest_t`, an ordinary object type
 */

#include <pthread.h>

typedef unsigned char (digest_t)[32];

static digest_t last_digest;

void *worker(void *arg) {
    last_digest[0] = 1;
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    last_digest[0] = 2;
    pthread_join(t, 0);
    return last_digest[0];
}
