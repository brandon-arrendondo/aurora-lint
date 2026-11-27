/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - `DECL(conn)` expands to `typedef struct conn_s *conn`,
 *         the `##` joining `n` and `_s` into one name, so `conn` is a
 *         defined type, an ordinary pointer object
 */

#include <pthread.h>

#define DECL(n) typedef struct n##_s *n

DECL(conn);

static conn current;

void *worker(void *arg) {
    current = arg;
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    current = 0;
    pthread_join(t, 0);
    return current != 0;
}
