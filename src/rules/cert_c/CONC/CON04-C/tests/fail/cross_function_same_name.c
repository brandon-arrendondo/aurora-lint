#include <threads.h>

int worker(void *arg) {
    return 0;
}

void func_a(void) {
    thrd_t t;
    thrd_create(&t, worker, NULL);
    thrd_join(t, NULL);  /* properly joined in this function */
}

void func_b(void) {
    thrd_t t;
    thrd_create(&t, worker, NULL);
    /* LEAK: never joined or detached in this function -
       must not be masked by func_a's join on its own same-named local */
}
