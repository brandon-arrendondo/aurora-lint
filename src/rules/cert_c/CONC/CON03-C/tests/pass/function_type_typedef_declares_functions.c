/* Rule: CON03-C
 * Source: testcases
 * Status: PASS - a name declared through a typedef for a function type is a
 * function, not a shared variable
 */

#include <pthread.h>

typedef int (transfer_fn)(void *ctx, char *buf, int len);

static transfer_fn plain_recv, plain_send;

void *worker(void *arg) {
    char buf[16];
    plain_recv(arg, buf, (int)sizeof(buf));
    plain_send(arg, buf, (int)sizeof(buf));
    return 0;
}

static int plain_recv(void *ctx, char *buf, int len) { (void)ctx; (void)buf; return len; }
static int plain_send(void *ctx, char *buf, int len) { (void)ctx; (void)buf; return len; }

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    pthread_join(t, 0);
    return 0;
}
