/* Rule: CON03-C
 * Source: testcases
 * Status: EXPECTED FAIL - a calling-convention macro that carries the `*`
 * makes the typedef a function pointer, so the uninitialized name is an
 * object. The parse repair blanks the macro, the typedef reads as a function
 * type, and without an initializer the declaration could be a prototype, so
 * CON03-C stays silent (ADR-0006: identity uncertainty).
 */

#include <pthread.h>

#define APIENTRY
#define APIENTRYP APIENTRY *

typedef void (APIENTRYP PFNDRAWPROC)(int count);

static PFNDRAWPROC draw_instanced;

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
