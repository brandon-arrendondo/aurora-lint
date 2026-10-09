/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - a calling-convention macro that carries the `*` makes the
 * typedef a function pointer; the initializer shows the name is an object,
 * since a function cannot be initialized
 */

#include <pthread.h>

#define APIENTRY
#define APIENTRYP APIENTRY *

typedef void (APIENTRYP PFNDRAWPROC)(int count);

static PFNDRAWPROC draw_instanced = 0;

void *render(void *arg) {
    if (draw_instanced)
        draw_instanced(4);
    return 0;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, render, 0);
    pthread_join(t, 0);
    return 0;
}
